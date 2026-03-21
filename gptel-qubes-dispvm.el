
(defun gptel-qubes-sandbox--advise-grep (orig-fn regex path &optional glob context-lines)
  "Advice to route grep to sandbox dispvm.
ORIG-FN is `gptel-agent--grep'."
  (if (gptel-qubes-sandbox--ensure-active)
      (let* ((ctx (if (and context-lines (> context-lines 0))
                      (format "-C %d" (min context-lines 15))
                    ""))
             (glob-arg (if glob (format "--include=%s" (shell-quote-argument glob)) ""))
             (cmd (format "grep -rnE %s %s %s %s 2>/dev/null | head -1000"
                          ctx
                          glob-arg
                          (shell-quote-argument regex)
                          (shell-quote-argument path))))
        (let ((result (gptel-qubes-sandbox--exec-sync cmd)))
          (if (string-empty-p result)
              (format "No matches for '%s' in %s" regex path)
            (gptel-qubes-sandbox--tag-dispvm-output result))))
    (gptel-qubes-sandbox--refuse-local "grep")))

(defun gptel-qubes-sandbox--advise-write (orig-fn path filename content)
  "Advice to route file writing to sandbox dispvm.
ORIG-FN is `gptel-agent--write-file'. Uses dynamic heredoc marker."
  (if (gptel-qubes-sandbox--ensure-active)
      (let* ((full-path (concat (file-name-as-directory path) filename))
             (marker (gptel-qubes-sandbox--safe-marker content))
             (cmd (format "mkdir -p %s && cat > %s << '%s'\n%s\n%s"
                          (shell-quote-argument path)
                          (shell-quote-argument full-path)
                          marker
                          content
                          marker)))
        (gptel-qubes-sandbox--exec-sync cmd)
        (format "Created file %s in %s" filename path))
    (gptel-qubes-sandbox--refuse-local "write-file")))

(defun gptel-qubes-sandbox--advise-read (orig-fn filename start-line end-line)
  "Advice to route file reading to sandbox dispvm.
ORIG-FN is `gptel-agent--read-file-lines'."
  (if (gptel-qubes-sandbox--ensure-active)
      (let ((cmd (if (and start-line end-line)
                     (format "sed -n '%d,%dp' %s 2>&1"
                             start-line end-line
                             (shell-quote-argument filename))
                   (format "cat %s 2>&1" (shell-quote-argument filename)))))
        (let ((result (gptel-qubes-sandbox--exec-sync cmd)))
          (if (string-empty-p result)
              (format "Error: File %s is not readable or empty" filename)
            (gptel-qubes-sandbox--tag-dispvm-output result))))
    (gptel-qubes-sandbox--refuse-local "read-file")))

(defun gptel-qubes-sandbox--advise-bash (orig-fn callback command)
  "Advice to route bash execution to sandbox dispvm.
ORIG-FN is `gptel-agent--execute-bash'. CALLBACK receives output string.
Wraps command to capture stderr so the LLM sees error messages.
Output is tagged as untrusted to defend against prompt injection
from compromised dispvm processes."
  (if (gptel-qubes-sandbox--ensure-active)
      (gptel-qubes-sandbox--exec-async
       (concat "{ " command "\n} 2>&1")
       (lambda (output)
         (funcall callback
                  (gptel-qubes-sandbox--tag-dispvm-output
                   (or output "Command timed out"))))
       gptel-dispvm-bash-timeout)
    (gptel-qubes-sandbox--refuse-local "execute-bash")))

(defconst gptel-qubes-sandbox--edit-python-script
  "import sys
with open(sys.argv[1]) as f: content = f.read()
with open(sys.argv[2]) as f: old = f.read().rstrip('\\n')
with open(sys.argv[3]) as f: new = f.read().rstrip('\\n')
count = content.count(old)
if count == 0:
    print('ERROR: old_str not found in file')
    sys.exit(1)
if count > 1:
    print('ERROR: old_str found %d times, must be unique' % count)
    sys.exit(1)
with open(sys.argv[1], 'w') as f:
    f.write(content.replace(old, new, 1))
print('OK: replacement applied')"
  "Python script for exact string replacement in sandbox dispvm.
Reads file path, old string file, new string file from sys.argv.
Strips trailing heredoc newline from old/new before matching.
Verifies exactly one occurrence before replacing.")

(defun gptel-qubes-sandbox--advise-edit (orig-fn path &optional old-str new-str-or-diff diffp)
  "Advice to route file editing to sandbox dispvm.
ORIG-FN is `gptel-agent--edit-files'.
String replacement mode uses Python for exact matching.
Diff mode runs fix-patch-headers in Emacs, then patch in dispvm."
  (if (not (gptel-qubes-sandbox--ensure-active))
      (gptel-qubes-sandbox--refuse-local "edit-files")
    (if (and diffp (not (eq diffp :json-false)))
        ;; Diff/patch mode: fix headers in Emacs, then apply in dispvm
        (let* ((fixed-diff
                (with-temp-buffer
                  (insert new-str-or-diff)
                  ;; Strip markdown fences if present
                  (goto-char (point-min))
                  (when (looking-at "^ *```\\(?:diff\\|patch\\)?\\s-*\n")
                    (delete-region (match-beginning 0) (match-end 0)))
                  (goto-char (point-max))
                  (when (re-search-backward "^ *```\\s-*$" nil t)
                    (delete-region (match-beginning 0) (point-max)))
                  (goto-char (point-min))
                  (gptel-agent--fix-patch-headers)
                  (buffer-string)))
               (marker (gptel-qubes-sandbox--safe-marker fixed-diff))
               ;; Use mktemp instead of hardcoded /tmp/gptel_patch
               (cmd (concat
                     "gptel_pf=$(mktemp) && "
                     (format "cat > \"$gptel_pf\" << '%s'\n%s\n%s\n"
                             marker fixed-diff marker)
                     (format "cd %s && patch -p0 < \"$gptel_pf\" 2>&1; rm -f \"$gptel_pf\""
                             (shell-quote-argument (file-name-directory path))))))
          (gptel-qubes-sandbox--tag-dispvm-output
           (gptel-qubes-sandbox--exec-sync cmd)))
      ;; String replacement mode: use Python helper with mktemp
      (let* ((marker-old (gptel-qubes-sandbox--safe-marker old-str))
             (marker-new (gptel-qubes-sandbox--safe-marker new-str-or-diff))
             (cmd (concat
                   ;; Create temp files with mktemp
                   "gptel_of=$(mktemp) && gptel_nf=$(mktemp) && "
                   ;; Write old_str to temp file
                   (format "cat > \"$gptel_of\" << '%s'\n%s\n%s\n"
                           marker-old old-str marker-old)
                   ;; Write new_str to temp file
                   (format "cat > \"$gptel_nf\" << '%s'\n%s\n%s\n"
                           marker-new new-str-or-diff marker-new)
                   ;; Run Python helper
                   (format "python3 -c %s %s \"$gptel_of\" \"$gptel_nf\"; rm -f \"$gptel_of\" \"$gptel_nf\""
                           (shell-quote-argument gptel-qubes-sandbox--edit-python-script)
                           (shell-quote-argument path)))))
        (gptel-qubes-sandbox--tag-dispvm-output
         (gptel-qubes-sandbox--exec-sync cmd))))))

(defconst gptel-qubes-sandbox--insert-python-script
  "import sys
path, lineno = sys.argv[1], int(sys.argv[2])
content_file = sys.argv[3]
with open(content_file) as f:
    new_text = f.read().rstrip('\\n')
try:
    with open(path) as f:
        lines = f.readlines()
except FileNotFoundError:
    lines = []
suffix = '' if new_text.endswith('\\n') else '\\n'
if lineno == 0:
    lines.insert(0, new_text + suffix)
elif lineno == -1:
    lines.append(new_text + suffix)
else:
    # Match Elisp forward-line semantics: inserts before line (lineno+1) in 1-indexed terms
    lines.insert(lineno, new_text + suffix)
with open(path, 'w') as f:
    f.writelines(lines)
print('OK: inserted at line %d' % lineno)"
  "Python script for multi-line insert at line number in sandbox dispvm.
Reads target file path and line number from sys.argv[1] and sys.argv[2].
Insert content read from file at sys.argv[3] (mktemp path).
Strips heredoc trailing newline, matches Elisp forward-line semantics.")

(defun gptel-qubes-sandbox--advise-insert (orig-fn path line-number new-str)
  "Advice to route file insertion to sandbox dispvm.
ORIG-FN is `gptel-agent--insert-in-file'. Uses Python for multi-line support."
  (if (gptel-qubes-sandbox--ensure-active)
      (let* ((marker (gptel-qubes-sandbox--safe-marker new-str))
             (cmd (concat
                   ;; Create temp file with mktemp
                   "gptel_cf=$(mktemp) && "
                   ;; Write content to temp file
                   (format "cat > \"$gptel_cf\" << '%s'\n%s\n%s\n"
                           marker new-str marker)
                   ;; Run Python helper with temp file as argv[3]
                   (format "python3 -c %s %s %d \"$gptel_cf\"; rm -f \"$gptel_cf\""
                           (shell-quote-argument gptel-qubes-sandbox--insert-python-script)
                           (shell-quote-argument path)
                           line-number))))
        (gptel-qubes-sandbox--tag-dispvm-output
         (gptel-qubes-sandbox--exec-sync cmd)))
    (gptel-qubes-sandbox--refuse-local "insert-in-file")))

;;; ------------------------------------------------------------------
;;; Sandbox mode lifecycle
;;; ------------------------------------------------------------------

(defun gptel-qubes-sandbox--suppress-response-complete (orig-fn &rest args)
  "Advice to suppress dispvm destruction when sandbox is active."
  (unless gptel-qubes-sandbox-active
    (apply orig-fn args)))

(defun gptel-qubes-sandbox--around-sentinel (orig-fn proc event)
  "Advice on dispvm sentinel to handle unexpected death during sandbox.
Calls teardown, sets died-unexpectedly flag, and notifies user.
The died-unexpectedly flag prevents auto-reactivation — user must
explicitly re-activate sandbox to clear it."
  (when gptel-qubes-sandbox-active
    (setq gptel-qubes-sandbox--dispvm-died-unexpectedly t)
    (message "gptel-sandbox: DispVM died unexpectedly — session lost. %s"
             "Tool calls BLOCKED until sandbox re-activated manually.")
    (setq gptel-qubes-sandbox-active nil)
    (setq gptel-qubes-sandbox--dispvm-name nil)
    (gptel-qubes-sandbox--remove-lifecycle-advice)
    ;; Restore tool confirmations
    (when gptel-qubes-sandbox--saved-confirm-tool-calls
      (setq gptel-confirm-tool-calls
            (if (eq gptel-qubes-sandbox--saved-confirm-tool-calls 'gptel-qubes--was-nil)
                nil
              gptel-qubes-sandbox--saved-confirm-tool-calls))
      (setq gptel-qubes-sandbox--saved-confirm-tool-calls nil))
    (gptel-qubes-sandbox--update-indicator)
    (force-mode-line-update t))
  (funcall orig-fn proc event))

(defun gptel-qubes-sandbox--filter-tool-calls (tool-calls)
  "Filter TOOL-CALLS, returning (ALLOWED . BLOCKED-NAMES).
ALLOWED is the list of tool-call entries whose tool name is in
`gptel-qubes-sandbox--allowed-tools'.  BLOCKED-NAMES is a list
of blocked tool name strings.  Blocked tools get an error result
sent back to the LLM via their callback."
  (let ((filtered nil)
        (blocked nil))
    (dolist (tc tool-calls)
      (let* ((tool-spec (car tc))
             (name (gptel-tool-name tool-spec)))
        (if (member name gptel-qubes-sandbox--allowed-tools)
            (push tc filtered)
          (push name blocked)
          ;; Return error to the LLM via process-tool-result callback
          (let ((process-tool-result (nth 2 tc)))
            (funcall process-tool-result
                     (format "BLOCKED: Tool '%s' is not permitted — only sandboxed tools are allowed. Use Bash tool for execution, and file tools (Read/Write/Edit/Grep/Glob) for file operations." name))))))
    (when blocked
      (message "gptel-sandbox: BLOCKED tools: %s" (string-join blocked ", ")))
    (cons (nreverse filtered) blocked)))

(defun gptel-qubes-sandbox--gate-handle-tool-use (orig-fn fsm)
  "Advice on `gptel--handle-tool-use' — the true chokepoint.
This is where gptel dispatches ALL tool calls, including auto-confirmed
ones that skip `gptel--display-tool-calls' and `gptel--accept-tool-calls'.
Filters the :tool-use list in the FSM info to remove blocked tools
BEFORE any execution happens."
  (when-let* ((info (gptel-fsm-info fsm))
              (tool-use (plist-get info :tool-use)))
    (let ((blocked nil))
      (dolist (tc tool-use)
        (let ((name (plist-get tc :name)))
          (unless (or (member name gptel-qubes-sandbox--allowed-tools)
                      (plist-get tc :result)) ;already completed, skip
            (push name blocked)
            ;; Mark as completed with error result so gptel processes it
            (plist-put tc :result
                       (format "BLOCKED: Tool '%s' is not permitted — only sandboxed tools are allowed." name)))))
      (when blocked
        (message "gptel-sandbox: BLOCKED at handle-tool-use: %s"
                 (string-join blocked ", ")))))
  (funcall orig-fn fsm))

(defun gptel-qubes-sandbox--gate-display-tool-calls (orig-fn tool-calls info &optional use-minibuffer)
  "Advice on `gptel--display-tool-calls' — earliest interception point.
Filters blocked tools BEFORE the confirmation UI is shown to the user.
Without this, gptel shows a minibuffer prompt for blocked tools like Eval
before our execution gate can block them."
  (if (not tool-calls)
      (funcall orig-fn tool-calls info use-minibuffer)
    (pcase-let ((`(,allowed . ,_blocked) (gptel-qubes-sandbox--filter-tool-calls tool-calls)))
      (if allowed
          (funcall orig-fn allowed info use-minibuffer)
        ;; All blocked — don't show confirmation UI, but don't orphan the FSM.
        ;; Blocked tools already had process-tool-result called by filter-tool-calls.
        nil))))

(defun gptel-qubes-sandbox--gate-tool-calls (orig-fn &optional tool-calls ov)
  "Advice on `gptel--accept-tool-calls' — defense-in-depth execution gate.
Filters again at dispatch time in case tool calls bypass the display gate
\(e.g. auto-confirmed tools, or direct calls to accept-tool-calls)."
  (if (not tool-calls)
      (funcall orig-fn tool-calls ov)
    (pcase-let ((`(,allowed . ,_blocked) (gptel-qubes-sandbox--filter-tool-calls tool-calls)))
      (if allowed
          (funcall orig-fn allowed ov)
        ;; All blocked — blocked tools already had their callbacks called.
        nil))))

(defun gptel-qubes-sandbox--install-tool-advice ()
  "Install all sandbox security advice.
These are always present when gptel-qubes is set up.

Three security layers:
Layer 1 — Tool advertisement: filter tools sent to the LLM
Layer 2 — Tool execution gate: allowlist check at dispatch time
Layer 3 — Tool routing: sandbox each allowed tool to the dispvm
Plus: request-time system prompt injection (UX, not security)"
  ;; Layer 1: Filter tools sent to the LLM (advertisement)
  (advice-add 'gptel--parse-tools :around #'gptel-qubes-sandbox--advise-parse-tools)
  ;; Layer 2: Gate at the TRUE dispatch chokepoint (handles auto-confirmed tools)
  (advice-add 'gptel--handle-tool-use :around #'gptel-qubes-sandbox--gate-handle-tool-use)
  ;; Layer 2a: Gate BEFORE confirmation UI (prevents user from seeing blocked tools)
  (advice-add 'gptel--display-tool-calls :around #'gptel-qubes-sandbox--gate-display-tool-calls)
  ;; Layer 2b: Gate at accept (defense-in-depth for manual confirmation path)
  (advice-add 'gptel--accept-tool-calls :around #'gptel-qubes-sandbox--gate-tool-calls)
  ;; Layer 3: Route each allowed tool to dispvm (sandbox routing)
  (advice-add 'gptel-agent--execute-bash :around #'gptel-qubes-sandbox--advise-bash)
  (advice-add 'gptel-agent--write-file :around #'gptel-qubes-sandbox--advise-write)
  (advice-add 'gptel-agent--make-directory :around #'gptel-qubes-sandbox--advise-mkdir)
  (advice-add 'gptel-agent--edit-files :around #'gptel-qubes-sandbox--advise-edit)
  (advice-add 'gptel-agent--insert-in-file :around #'gptel-qubes-sandbox--advise-insert)
  (advice-add 'gptel-agent--read-file-lines :around #'gptel-qubes-sandbox--advise-read)
  (advice-add 'gptel-agent--glob :around #'gptel-qubes-sandbox--advise-glob)
  (advice-add 'gptel-agent--grep :around #'gptel-qubes-sandbox--advise-grep)
  ;; System prompt: inject sandbox context at request time
  (advice-add 'gptel--realize-query :around #'gptel-qubes-sandbox--advise-realize-query))

(defun gptel-qubes-sandbox--install-lifecycle-advice ()
  "Install lifecycle advice (response-complete suppression, sentinel).
Only installed when sandbox is actively running."
  (advice-add 'gptel-dispvm--on-response-complete :around
              #'gptel-qubes-sandbox--suppress-response-complete)
  (advice-add 'gptel-dispvm--sentinel :around
              #'gptel-qubes-sandbox--around-sentinel))

(defun gptel-qubes-sandbox--remove-lifecycle-advice ()
  "Remove lifecycle advice."
  (advice-remove 'gptel-dispvm--on-response-complete
                 #'gptel-qubes-sandbox--suppress-response-complete)
  (advice-remove 'gptel-dispvm--sentinel
                 #'gptel-qubes-sandbox--around-sentinel))

(defun gptel-qubes-sandbox--setup ()
  "Activate sandbox mode: launch dispvm, install advice, create working dir.
On error during setup, automatically tears down to prevent broken state.
Clears the died-unexpectedly flag only after successful dispvm launch."
  (condition-case err
      (progn
        (gptel-dispvm--start)
        ;; Clear died flag only AFTER successful launch — if start fails,
        ;; the flag stays set to prevent auto-reactivation retry loops
        (setq gptel-qubes-sandbox--dispvm-died-unexpectedly nil)
        (gptel-qubes-sandbox--install-lifecycle-advice)
        ;; Set active BEFORE disabling confirmations (prevents race where
        ;; confirmations are nil but sandbox-active is nil → local execution
        ;; without confirmation)
        (setq gptel-qubes-sandbox-active t)
        ;; Disable tool call confirmations when auto-confirm is on
        (when gptel-qubes-sandbox-auto-confirm
          (setq gptel-qubes-sandbox--saved-confirm-tool-calls
                (or gptel-confirm-tool-calls 'gptel-qubes--was-nil))
          (setq gptel-confirm-tool-calls nil))
        ;; Get dispvm name
        (setq gptel-qubes-sandbox--dispvm-name
              (gptel-qubes-sandbox--sanitize-hostname
               (gptel-dispvm--exec "hostname" 5)))
        ;; Create working directory in dispvm
        (gptel-qubes-sandbox--exec-sync
         (format "mkdir -p %s" (shell-quote-argument gptel-qubes-sandbox-working-dir)))
        (message "gptel-sandbox: Active (working dir: %s)" gptel-qubes-sandbox-working-dir))
    (error
     (gptel-qubes-sandbox--teardown)
     (signal (car err) (cdr err)))))

(defun gptel-qubes-sandbox--teardown ()
  "Deactivate sandbox mode: remove advice, destroy dispvm.
System prompt injection is request-time so nothing to restore."
  (setq gptel-qubes-sandbox-active nil)
  (setq gptel-qubes-sandbox--dispvm-name nil)
  (gptel-qubes-sandbox--remove-lifecycle-advice)
  ;; Restore tool call confirmations
  (when gptel-qubes-sandbox--saved-confirm-tool-calls
    (setq gptel-confirm-tool-calls
          (if (eq gptel-qubes-sandbox--saved-confirm-tool-calls 'gptel-qubes--was-nil)
              nil
            gptel-qubes-sandbox--saved-confirm-tool-calls))
    (setq gptel-qubes-sandbox--saved-confirm-tool-calls nil))
  (gptel-dispvm--stop)
  (gptel-qubes-sandbox--update-indicator)
  (force-mode-line-update t)
  (message "gptel-sandbox: Deactivated"))

(defvar gptel-qubes-sandbox--indicator-keymap
  (let ((map (make-sparse-keymap)))
    (define-key map [mode-line mouse-1] #'gptel-qubes-sandbox-mode)
    (define-key map [mode-line mouse-3] #'gptel-qubes-sandbox-finalize)
    map)
  "Keymap for sandbox indicator.
Mouse-1: toggle sandbox mode. Mouse-3: finalize (retrieve tar.gz).")

(defvar gptel-qubes-sandbox--indicator-string nil
  "Mode-line construct shown in `global-mode-string' for sandbox toggle.")
(put 'gptel-qubes-sandbox--indicator-string 'risky-local-variable t)

(defun gptel-qubes-sandbox--update-indicator ()
  "Update the sandbox indicator to reflect current state."
  (setq gptel-qubes-sandbox--indicator-string
        (if gptel-qubes-sandbox-active
            (let ((label (if gptel-qubes-sandbox--dispvm-name
                             (format " [Sandbox:ON:%s]" gptel-qubes-sandbox--dispvm-name)
                           " [Sandbox:ON]")))
              `(:propertize ,label
                face (:foreground "orange" :weight bold)
                mouse-face mode-line-highlight
                help-echo "Sandbox ON — click to deactivate\nmouse-3: finalize (retrieve tar.gz)"
                keymap ,gptel-qubes-sandbox--indicator-keymap))
          (if gptel-qubes-sandbox--dispvm-died-unexpectedly
              `(:propertize " [Sandbox:DEAD]"
                face (:foreground "red" :weight bold)
                mouse-face mode-line-highlight
                help-echo "DispVM died unexpectedly — tool calls BLOCKED.\nClick to re-activate sandbox."
                keymap ,gptel-qubes-sandbox--indicator-keymap)
            (if (and gptel-qubes-sandbox-auto-activate
                     (not gptel-qubes-sandbox--manually-disabled))
                `(:propertize " [Sandbox:AUTO]"
                  face (:foreground "cyan" :weight normal)
                  mouse-face mode-line-highlight
                  help-echo "Sandbox AUTO — will activate on first tool call\nmouse-1: activate now"
                  keymap ,gptel-qubes-sandbox--indicator-keymap)
              `(:propertize " [Sandbox:OFF]"
                face (:foreground "red" :weight bold)
                mouse-face mode-line-highlight
                help-echo "Sandbox OFF — tool calls BLOCKED. Click to activate."
                keymap ,gptel-qubes-sandbox--indicator-keymap)))))
  (force-mode-line-update t))

(defun gptel-qubes-sandbox--install-indicator ()
  "Install sandbox indicator into `global-mode-string' (persistent)."
  (unless global-mode-string
    (setq global-mode-string '("")))
  (unless (memq 'gptel-qubes-sandbox--indicator-string global-mode-string)
    (setq global-mode-string
          (append global-mode-string
                  '(gptel-qubes-sandbox--indicator-string))))
  (gptel-qubes-sandbox--update-indicator))

;;;###autoload
(defun gptel-qubes-sandbox--on-agent-start (&rest _args)
  "Hook called after `gptel-agent' starts. Auto-activates sandbox.
System prompt injection is handled at request time by the
`gptel--realize-query' advice, so no buffer scanning needed here."
  (unless gptel-qubes-sandbox-active
    (gptel-qubes-sandbox-mode 1)))

(defun gptel-qubes-sandbox-mode (&optional arg)
  "Toggle sandbox development mode.
When active, all gptel-agent tool calls execute in a Qubes dispvm.
Click the mode-line indicator to toggle.
With ARG, activate if positive, deactivate if negative or zero."
  (interactive "P")
  (let ((enable (if arg (> (prefix-numeric-value arg) 0)
                  (not gptel-qubes-sandbox-active))))
    (if enable
        (progn
          (setq gptel-qubes-sandbox--manually-disabled nil)
          (gptel-qubes-sandbox--setup)
          (gptel-qubes-sandbox--update-indicator)
          (force-mode-line-update t))
      (when gptel-qubes-sandbox-active
        (setq gptel-qubes-sandbox--manually-disabled t)
        (if (y-or-n-p "Retrieve work from sandbox before closing? ")
            (gptel-qubes-sandbox-finalize)
          (gptel-qubes-sandbox--teardown))
        (gptel-qubes-sandbox--update-indicator)
        (force-mode-line-update t)))))

(defun gptel-qubes-sandbox--retrieve-tarball ()
  "Package sandbox working dir as tar.gz and transfer to Emacs AppVM.
Returns the output file path on success, nil on failure."
  ;; Create tar.gz in dispvm
  (let* ((tar-cmd (format "tar czf /tmp/gptel-sandbox-output.tar.gz -C %s . 2>&1"
                          (shell-quote-argument gptel-qubes-sandbox-working-dir)))
         (tar-result (gptel-qubes-sandbox--exec-sync tar-cmd)))
    (gptel-qubes-sandbox--log "OUT" "tar: %s" tar-result)
    ;; Size check
    (let* ((size-str (gptel-qubes-sandbox--exec-sync
                      "stat -c%s /tmp/gptel-sandbox-output.tar.gz 2>/dev/null"))
           (size (string-to-number (string-trim size-str))))
      (when (> size gptel-qubes-sandbox-max-transfer-size)
        (message "gptel-sandbox: tar.gz too large (%d bytes, max %d)"
                 size gptel-qubes-sandbox-max-transfer-size)
        (error "Sandbox output exceeds transfer size limit"))
      ;; Base64 encode and transfer
      (let* ((b64-output (gptel-qubes-sandbox--exec-sync
                          "base64 /tmp/gptel-sandbox-output.tar.gz" 120))
             (output-dir (expand-file-name gptel-qubes-sandbox-output-dir))
             (timestamp (format-time-string "%Y-%m-%d-%H%M%S"))
             (output-file (expand-file-name
                           (format "sandbox-%s-%s.tar.gz"
                                   (or gptel-qubes-sandbox--dispvm-name "unknown")
                                   timestamp)
                           output-dir)))
        ;; Ensure output directory exists
        (make-directory output-dir t)
        ;; Decode and write
        (with-temp-buffer
          (set-buffer-multibyte nil)
          (insert (base64-decode-string (string-trim b64-output)))
          (let ((coding-system-for-write 'binary))
            (write-region (point-min) (point-max) output-file)))
        (message "gptel-sandbox: Output saved to %s (%d bytes)" output-file size)
        (message "gptel-sandbox: SECURITY — Review before running. Extract safely with: mkdir out && tar -xzf %s -C out"
                 output-file)
        output-file))))

;;;###autoload
(defun gptel-qubes-sandbox-finalize ()
  "Package sandbox work as tar.gz and transfer to Emacs AppVM.
Saves to `gptel-qubes-sandbox-output-dir' and destroys the dispvm."
  (interactive)
  (unless gptel-qubes-sandbox-active
    (error "Sandbox mode is not active"))
  (condition-case err
      (let ((output-path (gptel-qubes-sandbox--retrieve-tarball)))
        (when output-path
          (message "gptel-sandbox: Finalized — %s" output-path)))
    (error
     (message "gptel-sandbox: Finalization failed — %s" (error-message-string err))))
  (gptel-qubes-sandbox--teardown))

;;; ------------------------------------------------------------------
;;; Debug helper
;;; ------------------------------------------------------------------

(defun gptel-dispvm--debug (format-string &rest args)
  "Log debug message if `gptel-dispvm-debug' is non-nil."
  (when gptel-dispvm-debug
    (apply #'message (concat "gptel-dispvm-debug: " format-string) args)))

(defun gptel-dispvm--make-marker ()
  "Generate a cryptographic end-marker unlikely to appear in command output."
  (format "GPTEL_END_%s"
          (secure-hash 'sha256
                       (format "%s%s%s%s"
                               (random) (random)
                               (emacs-pid) (current-time)))))

;;; ------------------------------------------------------------------
;;; Async command queue
;;; ------------------------------------------------------------------

(defun gptel-dispvm--exec-queue-next ()
  "Run the next queued command, if any."
  (setq gptel-dispvm--exec-busy nil)
  (when gptel-dispvm--exec-queue
    (let ((entry (pop gptel-dispvm--exec-queue)))
      (apply (car entry) (cdr entry)))))

(defun gptel-dispvm--wrap-callback-for-queue (callback)
  "Wrap CALLBACK so it runs the next queued command after completing."
  (lambda (result)
    (unwind-protect
        (funcall callback result)
      (gptel-dispvm--exec-queue-next))))

;;; ------------------------------------------------------------------
;;; Process management
;;; ------------------------------------------------------------------

(defun gptel-dispvm--filter (proc output)
  (when (buffer-live-p (process-buffer proc))
    (with-current-buffer (process-buffer proc)
      (goto-char (point-max))
      (insert output))))

(defun gptel-dispvm--sentinel (_proc event)
  (let ((msg (string-trim event)))
    (unless (string-match-p "exited abnormally with code 129" msg)
      (message "gptel-dispvm: %s" msg)))
  (setq gptel-dispvm--process nil
        gptel-dispvm--ready nil
        gptel-dispvm--pending-callbacks nil
        gptel-dispvm--exec-queue nil
        gptel-dispvm--exec-busy nil
        gptel-dispvm--needs-drain nil))

;;; ------------------------------------------------------------------
;;; Start / Stop
;;; ------------------------------------------------------------------

(defun gptel-dispvm--start ()
  "Ensure dispVM is running."
  (unless (process-live-p gptel-dispvm--process)
    (gptel-dispvm--launch)))

(defun gptel-dispvm--launch ()
  "Launch a new dispVM."
  (message "gptel-dispvm: Starting...")
  (setq gptel-dispvm--ready nil)
  (let* ((buf (generate-new-buffer " *gptel-dispvm*"))
         (proc (start-process
                "gptel-dispvm" buf
                "qrexec-client-vm" "@dispvm" "qubes.VMShell")))
    (setq gptel-dispvm--process proc)
    (set-process-filter proc #'gptel-dispvm--filter)
    (set-process-sentinel proc #'gptel-dispvm--sentinel)
    (sleep-for 3)
    (unless (process-live-p proc)
      (gptel-dispvm--cleanup)
      (error "gptel-dispvm: Process died during startup"))
    (with-current-buffer buf (erase-buffer))
    (process-send-string proc "echo GPTEL_READY_OK\n")
    (let ((waited 0)
          (max-wait 100))
      (while (and (< waited max-wait)
                  (process-live-p proc)
                  (not (with-current-buffer buf
                         (string-match-p "GPTEL_READY_OK" (buffer-string)))))
        (accept-process-output proc 0.1)
        (sit-for 0.01 t)
        (setq waited (1+ waited)))
      (gptel-dispvm--debug "Launch wait iterations: %d" waited))
    (if (with-current-buffer buf
          (string-match-p "GPTEL_READY_OK" (buffer-string)))
        (progn
          (setq gptel-dispvm--ready t)
          (with-current-buffer buf (erase-buffer))
          (message "gptel-dispvm: Ready"))
      (gptel-dispvm--cleanup)
      (error "gptel-dispvm: Shell not responding"))))

(defun gptel-dispvm--stop ()
  "Stop dispVM."
  (when (process-live-p gptel-dispvm--process)
    (message "gptel-dispvm: Shutting down...")
    (process-send-string gptel-dispvm--process "sudo poweroff\n")
    (run-at-time 3 nil #'gptel-dispvm--cleanup)))

(defun gptel-dispvm--cleanup ()
  (when (process-live-p gptel-dispvm--redlib-process)
    (delete-process gptel-dispvm--redlib-process)
    (setq gptel-dispvm--redlib-process nil))
  (setq gptel-dispvm--redlib-pid nil)
  (when gptel-dispvm--process
    (when (buffer-live-p (process-buffer gptel-dispvm--process))
      (with-current-buffer (process-buffer gptel-dispvm--process)
        (let ((inhibit-read-only t))
          (erase-buffer)))
      (kill-buffer (process-buffer gptel-dispvm--process)))
    (when (process-live-p gptel-dispvm--process)
      (delete-process gptel-dispvm--process)))
  (setq gptel-dispvm--process nil
        gptel-dispvm--ready nil
        gptel-dispvm--exec-queue nil
        gptel-dispvm--exec-busy nil
        gptel-dispvm--needs-drain nil))

(defun gptel-dispvm-force-stop ()
  "Force stop dispVM."
  (interactive)
  (gptel-dispvm--cleanup)
  (message "gptel-dispvm: Force stopped"))

;;; ------------------------------------------------------------------
;;; Execute command
;;; ------------------------------------------------------------------

(defun gptel-dispvm--exec (cmd &optional timeout)
  "Execute CMD in dispVM with optional TIMEOUT."
  (unless (process-live-p gptel-dispvm--process)
    (error "gptel-dispvm: No active connection"))
  ;; Drain shell if a previous command timed out
  (when gptel-dispvm--needs-drain
    (gptel-qubes-sandbox--drain-sync))
  (let* ((timeout (or timeout gptel-dispvm-timeout))
         (marker (gptel-dispvm--make-marker))
         (buf (process-buffer gptel-dispvm--process))
         (max-iterations (* timeout 10)))
    (with-current-buffer buf (erase-buffer))
    (process-send-string
     gptel-dispvm--process
     (format "%s 2>&1; echo %s\n" cmd marker))
    (let ((waited 0))
      (while (and (< waited max-iterations)
                  (process-live-p gptel-dispvm--process)
                  (not (with-current-buffer buf
                         (string-match-p marker (buffer-string)))))
        (accept-process-output gptel-dispvm--process 0.1)
        (sit-for 0.01 t)
        (setq waited (1+ waited)))
      (gptel-dispvm--debug "Exec wait iterations: %d/%d" waited max-iterations))
    (with-current-buffer buf
      (let ((content (buffer-string)))
        (erase-buffer) ;; Clear immediately after extraction to prevent data lingering
        (if (string-match-p marker content)
            (string-trim
             (replace-regexp-in-string (concat marker ".*") "" content))
          (error "gptel-dispvm: Command timed out"))))))

;;; ------------------------------------------------------------------
;;; Async execution
;;; ------------------------------------------------------------------

(defun gptel-dispvm--clear-string (str)
  "Securely clear string STR from memory.
Uses `clear-string' on Emacs 29+ for proper byte-level clearing.
Falls back to `fillarray' on older Emacs — works correctly for unibyte
strings (API tokens are typically ASCII).  For full byte-level clearing
on multibyte strings, Emacs 29+ is recommended."
  (when (stringp str)
    (if (fboundp 'clear-string)
        (clear-string str)
      (fillarray str 0))))

(defun gptel-dispvm--exec-async (cmd callback &optional timeout)
  "Execute CMD in dispVM asynchronously, call CALLBACK with result.
CALLBACK receives the command output string, or nil on timeout."
  (cond
   (gptel-dispvm--exec-busy
    (setq gptel-dispvm--exec-queue
          (append gptel-dispvm--exec-queue
                  (list (list #'gptel-dispvm--exec-async cmd callback timeout)))))
   ((not (process-live-p gptel-dispvm--process))
    (setq gptel-dispvm--exec-busy nil)
    (funcall callback nil))
   (t
    ;; Drain shell if a previous command timed out
    (when gptel-dispvm--needs-drain
      (gptel-qubes-sandbox--drain-sync))
    (setq gptel-dispvm--exec-busy t)
    (let ((wrapped-cb (gptel-dispvm--wrap-callback-for-queue callback)))
      (let* ((timeout (or timeout gptel-dispvm-timeout))
             (marker (gptel-dispvm--make-marker))
             (buf (process-buffer gptel-dispvm--process))
             (proc gptel-dispvm--process)
             (completed nil)
             (timer nil)
             ;; Idle timeout: reset timer on output activity so long-running
             ;; commands (dnf install, compilation) don't time out while
             ;; they're still producing progress output.
             (timeout-fn
              (lambda ()
                (unless completed
                  (setq completed t)
                  (gptel-dispvm--debug "Async exec timed out (cmd length: %d)" (length cmd))
                  (setq gptel-dispvm--needs-drain t)
                  (set-process-filter proc #'gptel-dispvm--filter)
                  (funcall wrapped-cb nil)))))
        (with-current-buffer buf (erase-buffer))
        ;; Install temporary process filter watching for marker
        (set-process-filter proc
          (lambda (p output)
            (when (buffer-live-p (process-buffer p))
              (with-current-buffer (process-buffer p)
                (goto-char (point-max))
                (insert output)
                ;; Reset idle timeout — command is still producing output
                (when (and (not completed) timer)
                  (cancel-timer timer)
                  (setq timer (run-at-time timeout nil timeout-fn)))
                (when (and (not completed)
                           (save-excursion
                             (goto-char (point-min))
                             (search-forward marker nil t)))
                  (setq completed t)
                  (set-process-filter p #'gptel-dispvm--filter)
                  (when timer (cancel-timer timer))
                  (let ((content (buffer-string)))
                    (erase-buffer) ;; Clear after extraction
                    (funcall wrapped-cb
                             (string-trim
                              (replace-regexp-in-string
                               (concat marker ".*") "" content)))))))))
        ;; Initial idle timeout timer
        (setq timer (run-at-time timeout nil timeout-fn))
        ;; Send command - echo marker on its own line so heredoc commands work
        (process-send-string proc (concat cmd "\necho " marker "\n")))))))

(defun gptel-dispvm--exec-with-stdin-async (cmd stdin-data callback &optional timeout)
  "Execute CMD in dispVM asynchronously with STDIN-DATA, call CALLBACK with result.
Uses a handshake protocol: the shell prints GPTEL_STDIN_READY when
it is ready to receive stdin, eliminating the timing race.
CALLBACK receives the command output string, or nil on timeout."
  (cond
   (gptel-dispvm--exec-busy
    (setq gptel-dispvm--exec-queue
          (append gptel-dispvm--exec-queue
                  (list (list #'gptel-dispvm--exec-with-stdin-async cmd stdin-data callback timeout)))))
   ((not (process-live-p gptel-dispvm--process))
    (setq gptel-dispvm--exec-busy nil)
    (funcall callback nil))
   (t
    ;; Drain shell if a previous command timed out
    (when gptel-dispvm--needs-drain
      (gptel-qubes-sandbox--drain-sync))
    (setq gptel-dispvm--exec-busy t)
    (let ((wrapped-cb (gptel-dispvm--wrap-callback-for-queue callback)))
      (let* ((timeout (or timeout gptel-dispvm-timeout))
             (marker (gptel-dispvm--make-marker))
             (ready-marker "GPTEL_STDIN_READY")
             (buf (process-buffer gptel-dispvm--process))
             (proc gptel-dispvm--process)
             (completed nil)
             (timer nil)
             ;; Idle timeout: reset on output activity
             (timeout-fn
              (lambda ()
                (unless completed
                  (setq completed t)
                  (gptel-dispvm--debug "Async exec-stdin timed out (cmd length: %d)" (length cmd))
                  (setq gptel-dispvm--needs-drain t)
                  (set-process-filter proc #'gptel-dispvm--filter)
                  (funcall wrapped-cb nil)))))
        (with-current-buffer buf (erase-buffer))
        ;; Send command — shell will echo GPTEL_STDIN_READY when ready for input
        (process-send-string
         proc
         (format "stty -echo 2>/dev/null; echo %s; read -r GPTEL_HDR; %s <<< \"$GPTEL_HDR\"; stty echo 2>/dev/null\necho %s\n"
                 ready-marker cmd marker))
        ;; Install filter that watches for the ready marker
        (set-process-filter proc
          (lambda (p output)
            (when (buffer-live-p (process-buffer p))
              (with-current-buffer (process-buffer p)
                (goto-char (point-max))
                (insert output)
                ;; Reset idle timeout — activity detected
                (when (and (not completed) timer)
                  (cancel-timer timer)
                  (setq timer (run-at-time timeout nil timeout-fn)))
                (when (and (not completed)
                           (save-excursion
                             (goto-char (point-min))
                             (search-forward ready-marker nil t)))
                  ;; Ready marker seen — erase buffer, send secret, switch to completion filter
                  (erase-buffer)
                  (let ((formatted nil))
                    (unwind-protect
                        (if (not (process-live-p p))
                            ;; Process died — call wrapped-cb with nil
                            (unless completed
                              (setq completed t)
                              (when timer (cancel-timer timer))
                              (funcall wrapped-cb nil))
                          (setq formatted (format "%s\n" stdin-data))
                          (process-send-string p formatted)
                          ;; Install async completion filter
                          (set-process-filter p
                            (lambda (p2 output2)
                              (when (buffer-live-p (process-buffer p2))
                                (with-current-buffer (process-buffer p2)
                                  (goto-char (point-max))
                                  (insert output2)
                                  ;; Reset idle timeout — command still producing output
                                  (when (and (not completed) timer)
                                    (cancel-timer timer)
                                    (setq timer (run-at-time timeout nil timeout-fn)))
                                  (when (and (not completed)
                                             (save-excursion
                                               (goto-char (point-min))
                                               (search-forward marker nil t)))
                                    (setq completed t)
                                    (set-process-filter p2 #'gptel-dispvm--filter)
                                    (when timer (cancel-timer timer))
                                    (let ((content (buffer-string)))
                                      (erase-buffer) ;; Clear after extraction
                                      (funcall wrapped-cb
                                               (string-trim
                                                (replace-regexp-in-string
                                                 (concat marker ".*") "" content))))))))))
                      ;; Always clear secrets, even on error or dead process
                      (gptel-dispvm--clear-string stdin-data)
                      (gptel-dispvm--clear-string formatted))))))))
        ;; Initial idle timeout timer
        (setq timer (run-at-time timeout nil timeout-fn)))))))


;;; ------------------------------------------------------------------
;;; Async launch
;;; ------------------------------------------------------------------

(defun gptel-dispvm--launch-async ()
  "Launch a new dispVM asynchronously."
  (message "gptel-dispvm: Starting...")
  (setq gptel-dispvm--ready nil)
  (let* ((buf (generate-new-buffer " *gptel-dispvm*"))
         (proc (start-process
                "gptel-dispvm" buf
                "qrexec-client-vm" "@dispvm" "qubes.VMShell")))
    (setq gptel-dispvm--process proc)
    (set-process-filter proc #'gptel-dispvm--filter)
    (set-process-sentinel proc #'gptel-dispvm--sentinel)
    ;; Schedule ready check after 3 seconds (replaces blocking sleep-for)
    (run-at-time
     3 nil
     (lambda ()
       (if (not (process-live-p proc))
           (progn
             (gptel-dispvm--cleanup)
             (setq gptel-dispvm--pending-callbacks nil)
             (message "gptel-dispvm: Process died during startup"))
         (with-current-buffer buf (erase-buffer))
         (process-send-string proc "echo GPTEL_READY_OK\n")
         ;; Install filter watching for ready marker
         (let ((ready-timer nil))
           (set-process-filter proc
             (lambda (p output)
               (when (buffer-live-p (process-buffer p))
                 (with-current-buffer (process-buffer p)
                   (goto-char (point-max))
                   (insert output)
                   (when (save-excursion
                           (goto-char (point-min))
                           (search-forward "GPTEL_READY_OK" nil t))
                     (set-process-filter p #'gptel-dispvm--filter)
                     (when ready-timer (cancel-timer ready-timer))
                     (setq gptel-dispvm--ready t)
                     (with-current-buffer (process-buffer p) (erase-buffer))
                     (message "gptel-dispvm: Ready")
                     ;; Flush pending callbacks
                     (let ((callbacks (nreverse gptel-dispvm--pending-callbacks)))
                       (setq gptel-dispvm--pending-callbacks nil)
                       (dolist (cb callbacks)
                         (condition-case err
                             (funcall cb)
                           (error
                            (gptel-dispvm--debug "Pending callback error: %s"
                                                 (error-message-string err)))))))))))
           ;; Timeout for ready check (10 seconds)
           (setq ready-timer
                 (run-at-time
                  10 nil
                  (lambda ()
                    (unless gptel-dispvm--ready
                      (set-process-filter proc #'gptel-dispvm--filter)
                      (gptel-dispvm--cleanup)
                      (setq gptel-dispvm--pending-callbacks nil)
                      (message "gptel-dispvm: Shell not responding (async)")))))))))))

(defun gptel-dispvm--ensure-started-async (callback)
  "Ensure dispVM is running, then call CALLBACK.
If VM is ready, CALLBACK is called immediately.
If VM is starting, CALLBACK is queued.
If VM needs launching, CALLBACK is queued and launch begins."
  (cond
   ;; VM running and ready - call immediately
   ((and (process-live-p gptel-dispvm--process) gptel-dispvm--ready)
    (funcall callback))
   ;; VM starting - queue callback
   ((process-live-p gptel-dispvm--process)
    (push callback gptel-dispvm--pending-callbacks))
   ;; Need to launch
   (t
    (push callback gptel-dispvm--pending-callbacks)
    (gptel-dispvm--launch-async))))

;;; ------------------------------------------------------------------
;;; Kagi API search
;;; ------------------------------------------------------------------

(defun gptel-dispvm--get-kagi-token ()
  "Get Kagi API token from authinfo (returns a unibyte copy for safe clearing).
Returns a unibyte string so `fillarray' on Emacs < 29 properly zeros all bytes."
  (let ((auth (auth-source-search :host "kagi.com" :max 1)))
    (when auth
      (let ((secret (plist-get (car auth) :secret)))
        (when-let ((val (if (functionp secret)
                            (funcall secret)
                          secret)))
          (encode-coding-string val 'utf-8))))))

(defun gptel-dispvm--parse-kagi-results (json-str)
  "Parse Kagi JSON response into list of (:url URL :excerpt TEXT)."
  (condition-case err
      (let* ((json (json-read-from-string json-str))
             (data (cdr (assq 'data json)))
             (results '())
             (max-results 5)
             (count 0))
        (seq-do
         (lambda (item)
           (when (< count max-results)
             (let ((url (cdr (assq 'url item)))
                   (snippet (or (cdr (assq 'snippet item))
                                (cdr (assq 'title item))
                                "No excerpt")))
               (when url
                 (push (list :url url :excerpt snippet) results)
                 (setq count (1+ count))))))
         data)
        (or (nreverse results)
            (list (list :url "" :excerpt "No results found"))))
    (error
     (gptel-dispvm--debug "Kagi parse error: %s" (error-message-string err))
     (list (list :url "" :excerpt "Failed to parse Kagi response")))))

(defun gptel-dispvm--exec-with-stdin (cmd stdin-data &optional timeout)
  "Execute CMD in dispVM, passing STDIN-DATA via stdin securely.
Uses a handshake protocol: the shell prints GPTEL_STDIN_READY when
it is ready to receive stdin, eliminating the timing race."
  (unless (process-live-p gptel-dispvm--process)
    (error "gptel-dispvm: No active connection"))
  (let* ((timeout (or timeout gptel-dispvm-timeout))
         (marker (gptel-dispvm--make-marker))
         (ready-marker "GPTEL_STDIN_READY")
         (buf (process-buffer gptel-dispvm--process))
         (orig-filter (process-filter gptel-dispvm--process))
         (max-iterations (* timeout 10))
         (formatted nil))
    (with-current-buffer buf (erase-buffer))
    (unwind-protect
        (progn
          ;; Send command — keep orig-filter so we can see the ready marker
          (process-send-string
           gptel-dispvm--process
           (format "stty -echo 2>/dev/null; echo %s; read -r GPTEL_HDR; %s <<< \"$GPTEL_HDR\"; stty echo 2>/dev/null; echo %s\n"
                   ready-marker cmd marker))
          ;; Poll for GPTEL_STDIN_READY
          (let ((waited 0))
            (while (and (< waited max-iterations)
                        (process-live-p gptel-dispvm--process)
                        (not (with-current-buffer buf
                               (string-match-p ready-marker (buffer-string)))))
              (accept-process-output gptel-dispvm--process 0.1)
              (sit-for 0.01 t)
              (setq waited (1+ waited)))
            (gptel-dispvm--debug "Exec-stdin ready-wait iterations: %d/%d" waited max-iterations))
          (unless (with-current-buffer buf
                    (string-match-p ready-marker (buffer-string)))
            (error "gptel-dispvm: Shell did not become ready for stdin"))
          ;; Ready marker seen — suppress echo, erase buffer, send secret
          (set-process-filter gptel-dispvm--process #'ignore)
          (with-current-buffer buf (erase-buffer))
          (set-process-filter gptel-dispvm--process orig-filter)
          (setq formatted (format "%s\n" stdin-data))
          (process-send-string gptel-dispvm--process formatted))
      ;; Always restore filter and clear secrets
      (set-process-filter gptel-dispvm--process orig-filter)
      (gptel-dispvm--clear-string stdin-data)
      (gptel-dispvm--clear-string formatted))
    ;; Poll for end marker
    (let ((waited 0))
      (while (and (< waited max-iterations)
                  (process-live-p gptel-dispvm--process)
                  (not (with-current-buffer buf
                         (string-match-p marker (buffer-string)))))
        (accept-process-output gptel-dispvm--process 0.1)
        (sit-for 0.01 t)
        (setq waited (1+ waited)))
      (gptel-dispvm--debug "Exec-stdin wait iterations: %d/%d" waited max-iterations))
    (with-current-buffer buf
      (let ((content (buffer-string)))
        (erase-buffer) ;; Clear immediately after extraction to prevent data lingering
        (if (string-match-p marker content)
            (string-trim
             (replace-regexp-in-string (concat marker ".*") "" content))
          (error "gptel-dispvm: Command timed out"))))))

(defun gptel-dispvm-kagi-search (query)
  "Search Kagi for QUERY via dispVM - secure token handling."
  (message "gptel-dispvm: Searching Kagi for '%s'..." query)
  (let ((token (gptel-dispvm--get-kagi-token))
        (header nil))
    (unless token
      (error "gptel-dispvm: No Kagi token found in authinfo"))
    (unwind-protect
        (let* ((encoded-query (url-hexify-string query))
               (url (format "https://kagi.com/api/v0/search?q=%s&limit=5" encoded-query)))
          (setq header (format "Authorization: Bot %s" token))
          (gptel-dispvm--clear-string token)
          (let ((response (gptel-dispvm--exec-with-stdin
                           (format "curl -sL -H @- %s 2>/dev/null"
                                   (shell-quote-argument url))
                           header 20)))
            ;; Erase process buffer immediately — contains authenticated API response
            (when (and gptel-dispvm--process
                       (buffer-live-p (process-buffer gptel-dispvm--process)))
              (with-current-buffer (process-buffer gptel-dispvm--process)
                (erase-buffer)))
            (if (string-empty-p response)
                (list (list :url "" :excerpt (format "No results for: %s" query)))
              (gptel-dispvm--parse-kagi-results response))))
      (gptel-dispvm--clear-string token)
      (gptel-dispvm--clear-string header))))

;;; ------------------------------------------------------------------
;;; DuckDuckGo search (no API token required)
;;; ------------------------------------------------------------------

(defun gptel-dispvm--parse-ddg-html (html-str)
  "Parse DuckDuckGo Lite HTML response into list of (:url URL :excerpt TEXT).
DDG Lite uses single quotes on class attributes and puts href before class:
  <a rel=\"nofollow\" href=\"//duckduckgo.com/l/?uddg=URL&amp;rut=...\" class=\\='result-link\\='>Title</a>"
  (gptel-dispvm--debug "Parsing DDG HTML (%d bytes)" (length html-str))
  (let ((results '())
        (pos 0)
        (max-iterations 20)
        (iteration 0))
    ;; Match <a> tags with class='result-link' (single OR double quotes)
    (while (and (< (length results) 5)
                (< iteration max-iterations)
                (string-match "<a [^>]*class=['\"]result-link['\"][^>]*>"
                              html-str pos))
      (setq iteration (1+ iteration))
      (let* ((tag (match-string 0 html-str))
             (tag-end (match-end 0))
             ;; Extract href from within the matched <a> tag
             (href (when (string-match "href=\"\\([^\"]+\\)\"" tag)
                     (match-string 1 tag)))
             ;; Resolve DDG redirect: real URL is in the uddg= parameter
             (real-url (when href
                         (if (string-match "uddg=\\([^&\"]+\\)" href)
                             (url-unhex-string (match-string 1 href))
                           href)))
             ;; Title: strip inline HTML tags between <a ...> and </a>
             (title (let ((close (string-match "</a>" html-str tag-end)))
                      (if close
                          (string-trim
                           (replace-regexp-in-string
                            "<[^>]*>" ""
                            (substring html-str tag-end close)))
                        "No title")))
             ;; Snippet from the next result-snippet cell
             (snippet
              (if (string-match "class=['\"]result-snippet['\"][^>]*>"
                                html-str tag-end)
                  (let ((snip-start (match-end 0)))
                    (if (string-match "</td>" html-str snip-start)
                        (string-trim
                         (replace-regexp-in-string
                          "<[^>]*>" ""
                          (substring html-str snip-start (match-beginning 0))))
                      ""))
                "")))
        (setq pos tag-end)
        (when (and real-url
                   (not (string-empty-p real-url))
                   (not (string-match-p "duckduckgo\\.com" real-url)))
          (push (list :url real-url
                      :excerpt (if (string-empty-p snippet) title
                                 (format "%s - %s" title snippet)))
                results))))
    (when (>= iteration max-iterations)
      (gptel-dispvm--debug "DDG parse hit max iterations"))
    (gptel-dispvm--debug "DDG parse complete: %d results" (length results))
    (or (nreverse results)
        (list (list :url "" :excerpt "No results found")))))

(defun gptel-dispvm-ddg-search (query)
  "Search DuckDuckGo for QUERY via dispVM (no token required)."
  (message "gptel-dispvm: Searching DuckDuckGo for '%s'..." query)
  (let* ((encoded-query (url-hexify-string query))
         (url (format "https://lite.duckduckgo.com/lite/?q=%s" encoded-query))
         (ua "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0")
         (cmd (format "curl -sL -A %s %s 2>/dev/null"
                      (shell-quote-argument ua)
                      (shell-quote-argument url)))
         (response (condition-case err
                       (gptel-dispvm--exec cmd 20)
                     (error
                      (gptel-dispvm--debug "DDG fetch error: %s" (error-message-string err))
                      ""))))
    (gptel-dispvm--debug "DDG raw response: %d bytes" (length response))
    (if (string-empty-p response)
        (list (list :url "" :excerpt (format "No results for: %s" query)))
      (gptel-dispvm--parse-ddg-html response))))

;;; ------------------------------------------------------------------
;;; DDG dispVM parsing (Python-first, HTML-fallback)
;;; ------------------------------------------------------------------

(defconst gptel-dispvm--ddg-parser-script
  "import sys, re, json
from urllib.parse import unquote
with open(sys.argv[1]) as f:
    html = f.read()
results = []
for m in re.finditer(r'<a\\s[^>]*class=.result-link.[^>]*>', html):
    tag = m.group(0)
    href_m = re.search(r'href=\"([^\"]+)\"', tag)
    if not href_m:
        continue
    href = href_m.group(1)
    url = href
    uddg_m = re.search(r'uddg=([^&\"]+)', href)
    if uddg_m:
        url = unquote(uddg_m.group(1))
    if 'duckduckgo.com' in url:
        continue
    rest = html[m.end():]
    close_m = re.search(r'</a>', rest)
    title = re.sub(r'<[^>]*>', '', rest[:close_m.start()]).strip() if close_m else ''
    snip = ''
    snip_m = re.search(r'class=.result-snippet.[^>]*>(.*?)</td>', rest, re.DOTALL)
    if snip_m:
        snip = re.sub(r'<[^>]*>', '', snip_m.group(1)).strip()
    results.append({'url': url, 'title': title, 'snippet': snip})
    if len(results) >= 5:
        break
for r in results:
    print(json.dumps(r))"
  "Python script for parsing DDG Lite HTML inside the dispVM.
Reads HTML from a file (sys.argv[1]), extracts result-link anchors,
resolves uddg= redirects, and outputs JSON lines.")

(defconst gptel-dispvm--content-extractor-script
  "import sys
from html.parser import HTMLParser

max_chars = int(sys.argv[2]) if len(sys.argv) > 2 else 8000

REMOVE_TAGS = frozenset([
    'script', 'style', 'nav', 'footer', 'header', 'aside',
    'iframe', 'svg', 'noscript', 'form', 'button',
])

VOID_TAGS = frozenset([
    'area', 'base', 'br', 'col', 'embed', 'hr', 'img',
    'input', 'link', 'meta', 'source', 'track', 'wbr',
])

NOISE_PATTERNS = [
    'cookie', 'banner', 'sidebar', 'menu', 'advertisement',
    'popup', 'modal', 'newsletter', 'social', 'share',
    'comment', 'related', 'recommended', 'promo',
]

class Extractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self._skip_depth = 0
        self._article_text = []
        self._main_text = []
        self._body_text = []
        self._in_article = 0
        self._in_main = 0
        self._in_body = 0

    def _is_noise(self, attrs):
        for attr, val in attrs:
            if val and attr in ('class', 'id'):
                val_lower = val.lower()
                for pat in NOISE_PATTERNS:
                    if pat in val_lower:
                        return True
        return False

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if self._skip_depth > 0:
            if tag not in VOID_TAGS:
                self._skip_depth += 1
            return
        if tag in REMOVE_TAGS or self._is_noise(attrs):
            self._skip_depth = 1
            return
        if tag == 'article':
            self._in_article += 1
        elif tag == 'main':
            self._in_main += 1
        elif tag == 'body':
            self._in_body += 1

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self._skip_depth > 0:
            self._skip_depth -= 1
            return
        if tag == 'article':
            self._in_article = max(0, self._in_article - 1)
        elif tag == 'main':
            self._in_main = max(0, self._in_main - 1)
        elif tag == 'body':
            self._in_body = max(0, self._in_body - 1)

    def handle_data(self, data):
        if self._skip_depth > 0:
            return
        text = ' '.join(data.split())
        if not text:
            return
        if self._in_article > 0:
            self._article_text.append(text)
        if self._in_main > 0:
            self._main_text.append(text)
        if self._in_body > 0:
            self._body_text.append(text)

    def get_text(self):
        for candidate in [self._article_text, self._main_text, self._body_text]:
            joined = ' '.join(candidate)
            if len(joined) > 200:
                return joined[:max_chars]
        # fallback: return whatever we have
        all_text = self._article_text or self._main_text or self._body_text
        return ' '.join(all_text)[:max_chars]

with open(sys.argv[1], 'rb') as f:
    html = f.read().decode('utf-8', errors='replace')

parser = Extractor()
try:
    parser.feed(html)
except Exception:
    pass
result = parser.get_text()
if result:
    print(result)
else:
    sys.exit(1)"
  "Python script for extracting meaningful content from HTML pages.
Reads HTML from a file (sys.argv[1]), strips noise elements (nav, footer,
scripts, ads), prioritizes <article>/<main> content, falls back to <body>.
Max chars taken from sys.argv[2] (default 8000).
Uses only html.parser from stdlib — no external dependencies.
Exits non-zero if no content extracted, triggering w3m fallback.")

(defun gptel-dispvm--ddg-dispvm-cmd (url ua)
  "Build shell command for DDG search with in-dispVM Python parsing.
Falls back to raw HTML with GPTEL_RAW_HTML prefix when python3 is unavailable.
Appends GPTEL_HTTP_STATUS:<code> line for rate-limit detection."
  (concat
   (format "tmpf=$(mktemp); http_code=$(curl -sL --max-time 15 -o \"$tmpf\" -w '%%{http_code}' -A %s %s); "
           (shell-quote-argument ua)
           (shell-quote-argument url))
   "if command -v python3 >/dev/null 2>&1; then\n"
   "python3 - \"$tmpf\" << 'GPTEL_PYEOF'\n"
   gptel-dispvm--ddg-parser-script "\n"
   "GPTEL_PYEOF\n"
   "else\necho GPTEL_RAW_HTML\ncat \"$tmpf\"\nfi\n"
   "echo \"GPTEL_HTTP_STATUS:$http_code\"\n"
   "rm -f \"$tmpf\""))

(defun gptel-dispvm--fetch-url-dispvm-cmd (url ua)
  "Build shell command to fetch URL and extract content in dispVM.
Uses curl + Python content extractor, falls back to w3m if python3 unavailable.
UA is the User-Agent string."
  (let ((w3m-fallback
         (format "timeout 15 w3m %s -o user_agent=%s %s 2>/dev/null | head -c %d\n"
                 (gptel-dispvm--w3m-options-string)
                 (shell-quote-argument ua)
                 (shell-quote-argument url)
                 gptel-dispvm-fetch-max-chars)))
    (concat
     (format "tmpf=$(mktemp); curl -sL --max-time 15 -A %s %s 2>/dev/null | head -c 200000 > \"$tmpf\"; "
             (shell-quote-argument ua)
             (shell-quote-argument url))
     "if command -v python3 >/dev/null 2>&1; then\n"
     (format "if ! python3 - \"$tmpf\" %d << 'GPTEL_PYEOF'\n"
             gptel-dispvm-fetch-max-chars)
     gptel-dispvm--content-extractor-script "\n"
     "GPTEL_PYEOF\n"
     "then\n"
     w3m-fallback
     "fi\n"
     "else\n"
     w3m-fallback
     "fi\n"
     "rm -f \"$tmpf\"")))

(defun gptel-dispvm--parse-ddg-json (output)
  "Parse JSON-lines OUTPUT from the DDG Python parser.
Returns list of (:url URL :excerpt TEXT) plists."
  (condition-case err
      (let ((results '()))
        (dolist (line (split-string output "\n" t))
          (when (string-prefix-p "{" (string-trim line))
            (let* ((obj (json-read-from-string line))
                   (url (cdr (assq 'url obj)))
                   (title (or (cdr (assq 'title obj)) ""))
                   (snippet (or (cdr (assq 'snippet obj)) "")))
              (when url
                (push (list :url url
                            :excerpt (if (string-empty-p snippet)
                                         title
                                       (format "%s - %s" title snippet)))
                      results)))))
        (or (nreverse results)
            (list (list :url "" :excerpt "No results found"))))
    (error
     (gptel-dispvm--debug "DDG JSON parse error: %s" (error-message-string err))
     (list (list :url "" :excerpt "Failed to parse DDG results")))))

;;; ------------------------------------------------------------------
;;; VPN reconnect for DDG rate-limit evasion
;;; ------------------------------------------------------------------

(defun gptel-dispvm--vpn-reconnect ()
  "Reconnect Mullvad VPN to get a fresh IP for DDG searches.
Picks a random country from `gptel-dispvm-vpn-countries', validates it,
and sends it via qrexec to the VPN VM.  Runs locally in the Emacs AppVM,
not through the dispVM.
Returns the exit code of qrexec-client-vm (0 = success)."
  (let ((countries gptel-dispvm-vpn-countries))
    (unless countries
      (error "gptel-dispvm: No VPN countries configured"))
    (let* ((country (nth (random (length countries)) countries)))
      (unless (and country (string-match-p "\\`[a-z]\\{2\\}\\'" country))
        (gptel-dispvm--debug "VPN reconnect: invalid country code: %s" country)
        (error "gptel-dispvm: Invalid VPN country code: %s" country))
      (gptel-dispvm--debug "VPN reconnect: switching to %s via %s"
                            country gptel-dispvm-vpn-vm)
      (message "gptel-dispvm: Reconnecting VPN (%s)..." country)
      (let ((exit-code
             (with-temp-buffer
               (insert country "\n")
               (call-process-region (point-min) (point-max)
                                    "qrexec-client-vm" nil nil nil
                                    gptel-dispvm-vpn-vm
                                    "qubes.MullvadReconnect"))))
        (if (= exit-code 0)
            (gptel-dispvm--debug "VPN reconnect: success (country: %s)" country)
          (gptel-dispvm--debug "VPN reconnect: FAILED (exit code %d)" exit-code))
        exit-code))))

;;; ------------------------------------------------------------------
;;; Async search
;;; ------------------------------------------------------------------

(defun gptel-dispvm--ddg-search-async (query callback &optional retried)
  "Search DuckDuckGo for QUERY asynchronously via dispVM.
Calls CALLBACK with list of (:url URL :excerpt TEXT) results.
Uses Python parser in dispVM when available, falls back to Emacs HTML parsing.
Enforces `gptel-dispvm-ddg-search-delay' between searches to avoid rate limiting.
RETRIED is a retry counter (default 0): 0=first attempt, 1=first retry,
2=final retry after VPN reconnect."
  (let ((delay-needed
         (when gptel-dispvm--ddg-last-search-time
           (let ((elapsed (float-time
                           (time-subtract (current-time)
                                          gptel-dispvm--ddg-last-search-time))))
             (when (< elapsed gptel-dispvm-ddg-search-delay)
               (- gptel-dispvm-ddg-search-delay elapsed))))))
    (if delay-needed
        (progn
          (gptel-dispvm--debug "DDG rate-limit pacing: waiting %.1fs" delay-needed)
          (run-at-time delay-needed nil
                       #'gptel-dispvm--ddg-search-async query callback retried))
      (setq gptel-dispvm--ddg-last-search-time (current-time))
      (message "gptel-dispvm: Searching DuckDuckGo for '%s'%s..." query
               (pcase (or retried 0)
                 (0 "")
                 (1 " (retry)")
                 (2 " (retry after VPN reconnect)")
                 (_ " (retry)")))
      (let* ((encoded-query (url-hexify-string query))
             (url (format "https://lite.duckduckgo.com/lite/?q=%s" encoded-query))
             (ua "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0")
             (cmd (gptel-dispvm--ddg-dispvm-cmd url ua)))
        (gptel-dispvm--exec-async
         cmd
         (lambda (result)
           (if (null result)
               (funcall callback
                        (list (list :url "" :excerpt (format "Search timed out for: %s" query))))
             (let* ((http-status (when (string-match "GPTEL_HTTP_STATUS:\\([0-9]+\\)" result)
                                   (match-string 1 result)))
                    (clean-result (replace-regexp-in-string
                                   "\n?GPTEL_HTTP_STATUS:[0-9]+" "" result)))
               (gptel-dispvm--debug "DDG response (%d bytes, HTTP %s)"
                                    (length clean-result) (or http-status "?"))
               (when (and http-status (not (string= http-status "200")))
                 (gptel-dispvm--debug "DDG non-200 status: %s (possible rate limit)" http-status))
               (let ((retry-count (or retried 0))
                     (should-retry
                      (or (string-empty-p clean-result)
                          (and http-status (not (string= http-status "200"))))))
                 (cond
                  ;; First failure: simple retry after delay
                  ((and should-retry (= retry-count 0))
                   (gptel-dispvm--debug "DDG empty/non-200 response, retrying in %.1fs"
                                        gptel-dispvm-ddg-retry-delay)
                   (run-at-time gptel-dispvm-ddg-retry-delay nil
                                #'gptel-dispvm--ddg-search-async
                                query callback 1))
                  ;; Second failure: reconnect VPN, then final retry
                  ((and should-retry (= retry-count 1))
                   (gptel-dispvm--debug "DDG still failing, attempting VPN reconnect")
                   (let ((vpn-ok (condition-case err
                                     (= (gptel-dispvm--vpn-reconnect) 0)
                                   (error
                                    (gptel-dispvm--debug "VPN reconnect error: %s"
                                                         (error-message-string err))
                                    nil))))
                     (if vpn-ok
                         (progn
                           (gptel-dispvm--debug "VPN reconnected, retrying in %.1fs"
                                                gptel-dispvm-vpn-reconnect-delay)
                           (run-at-time gptel-dispvm-vpn-reconnect-delay nil
                                        #'gptel-dispvm--ddg-search-async
                                        query callback 2))
                       ;; VPN reconnect failed — give up
                       (gptel-dispvm--debug "VPN reconnect failed, giving up")
                       (funcall callback
                                (list (list :url ""
                                            :excerpt (format "DDG rate-limited, VPN reconnect failed for: %s"
                                                             query)))))))
                  ;; Success or exhausted retries — parse what we have
                  (t
                   (let ((parsed
                          (if (string-prefix-p "GPTEL_RAW_HTML" clean-result)
                              (progn
                                (gptel-dispvm--debug "DDG raw fallback: python3 not available in dispVM")
                                (gptel-dispvm--parse-ddg-html
                                 (substring clean-result (length "GPTEL_RAW_HTML"))))
                            (gptel-dispvm--parse-ddg-json clean-result))))
                     (funcall callback parsed))))))))
         20)))))

(defun gptel-dispvm--kagi-search-async (query callback)
  "Search Kagi for QUERY asynchronously via dispVM.
Calls CALLBACK with list of (:url URL :excerpt TEXT) results."
  (message "gptel-dispvm: Searching Kagi for '%s'..." query)
  (let ((token (gptel-dispvm--get-kagi-token)))
    (unless token
      (funcall callback (list (list :url "" :excerpt "No Kagi token found in authinfo")))
      (error "gptel-dispvm: No Kagi token found in authinfo"))
    (let* ((encoded-query (url-hexify-string query))
           (url (format "https://kagi.com/api/v0/search?q=%s&limit=5" encoded-query))
           (header (format "Authorization: Bot %s" token)))
      ;; Clear original token copy immediately
      (gptel-dispvm--clear-string token)
      (gptel-dispvm--exec-with-stdin-async
       (format "curl -sL -H @- %s 2>/dev/null" (shell-quote-argument url))
       header
       (lambda (result)
         ;; Erase process buffer immediately — contains authenticated API response
         (when (and gptel-dispvm--process
                    (buffer-live-p (process-buffer gptel-dispvm--process)))
           (with-current-buffer (process-buffer gptel-dispvm--process)
             (erase-buffer)))
         (if (or (null result) (string-empty-p (or result "")))
             (funcall callback
                      (list (list :url "" :excerpt (format "No results for: %s" query))))
           (funcall callback (gptel-dispvm--parse-kagi-results result))))
       20))))

;;; ------------------------------------------------------------------
;;; Async URL fetch
;;; ------------------------------------------------------------------

(defun gptel-dispvm--validate-url (url)
  "Validate that URL uses http or https scheme.
Rejects file://, ftp://, and other schemes to prevent local file access."
  (unless (string-match-p "\\`https?://" url)
    (error "gptel-dispvm: Refusing non-HTTP URL: %s" url)))

(defun gptel-dispvm--fetch-url-async (url callback)
  "Fetch URL content asynchronously.
Uses local Redlib for Reddit, dispVM for others.
Calls CALLBACK with content string."
  (gptel-dispvm--validate-url url)
  (if (gptel-dispvm--reddit-url-p url)
      (let ((tunnel-was-running (or (process-live-p gptel-dispvm--redlib-process)
                                    (gptel-dispvm--redlib-port-active-p))))
        (unless tunnel-was-running
          (gptel-dispvm-redlib-start))
        (let ((fetch-fn
               (lambda ()
                 (if (not (or (process-live-p gptel-dispvm--redlib-process)
                              (gptel-dispvm--redlib-port-active-p)))
                     (progn
                       (gptel-dispvm--debug "Redlib tunnel not reachable on port %d for: %s"
                                            gptel-dispvm-redlib-port url)
                       (funcall callback
                                (format "Redlib tunnel failed, cannot fetch Reddit URL: %s" url)))
                   (let* ((redlib-url (gptel-dispvm--reddit-to-redlib url))
                          (result (gptel-dispvm--fetch-local redlib-url)))
                     (message "gptel-dispvm: Fetched Reddit via Redlib")
                     (funcall callback
                              (if (> (length result) 50)
                                  result
                                (format "No content from Redlib for: %s" url))))))))
          (if tunnel-was-running
              (funcall fetch-fn)
            ;; Wait for tunnel to establish
            (run-at-time 1 nil fetch-fn))))
    (message "gptel-dispvm: Fetching '%s' via dispVM..." url)
    (let* ((ua "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0")
           (cmd (gptel-dispvm--fetch-url-dispvm-cmd url ua)))
      (gptel-dispvm--exec-async
       cmd
       (lambda (result)
         (if (and result (> (length result) 50))
             (funcall callback (string-trim result))
           (funcall callback (format "No readable content from: %s" url))))
       20))))

;;; ------------------------------------------------------------------
;;; Unified web search dispatcher
;;; ------------------------------------------------------------------

(defun gptel-dispvm-web-search (query)
  "Search web for QUERY using configured search engine.
Uses `gptel-dispvm-search-engine' to determine which engine to use."
  (pcase gptel-dispvm-search-engine
    ('kagi (gptel-dispvm-kagi-search query))
    ('duckduckgo (gptel-dispvm-ddg-search query))
    (_ (gptel-dispvm-ddg-search query))))

(defun gptel-dispvm-set-search-engine (engine)
  "Set the search engine to ENGINE (kagi or duckduckgo)."
  (interactive
   (list (intern (completing-read "Search engine: " '("duckduckgo" "kagi") nil t))))
  (setq gptel-dispvm-search-engine engine)
  (message "gptel-dispvm: Search engine set to %s" engine))

;;; ------------------------------------------------------------------
;;; Local Redlib connection (Emacs VM → Redlib VM via qrexec)
;;; ------------------------------------------------------------------

(defcustom gptel-dispvm-redlib-vm "redlib"
  "Name of VM running Redlib instance."
  :type 'string
  :group 'gptel)
(put 'gptel-dispvm-redlib-vm 'risky-local-variable t)

(defcustom gptel-dispvm-redlib-port 8080
  "Local port for Redlib tunnel."
  :type 'integer
  :group 'gptel)
(put 'gptel-dispvm-redlib-port 'risky-local-variable t)

(defun gptel-dispvm--redlib-port-active-p ()
  "Check if Redlib port is already accepting connections."
  (condition-case nil
      (let ((proc (make-network-process
                   :name "gptel-redlib-test"
                   :host "127.0.0.1"
                   :service gptel-dispvm-redlib-port)))
        (delete-process proc)
        t)
    (error nil)))

(defun gptel-dispvm--verify-tunnel-pid (pid)
  "Verify PID is a live socat process we launched."
  (when (and pid (integerp pid))
    (let ((cmdline (condition-case nil
                       (with-temp-buffer
                         (insert-file-contents
                          (format "/proc/%d/cmdline" pid))
                         (buffer-string))
                     (error nil))))
      (and cmdline (string-match-p "socat" cmdline)))))

(defun gptel-dispvm-redlib-start ()
  "Start socat tunnel to Redlib VM via qrexec.
Detects and adopts orphaned tunnels already listening on the port."
  (interactive)
  (cond
   ((process-live-p gptel-dispvm--redlib-process)
    (message "gptel-dispvm: Redlib tunnel already running"))
   ((gptel-dispvm--redlib-port-active-p)
    (if (and gptel-dispvm--redlib-pid
             (gptel-dispvm--verify-tunnel-pid gptel-dispvm--redlib-pid))
        (progn
          (gptel-dispvm--debug "Port %d in use by our tunnel (PID %d), adopting"
                               gptel-dispvm-redlib-port gptel-dispvm--redlib-pid)
          (message "gptel-dispvm: Redlib tunnel already active on port %d (verified, adopted)"
                   gptel-dispvm-redlib-port))
      (gptel-dispvm--debug "Port %d in use by unknown process, refusing to adopt"
                           gptel-dispvm-redlib-port)
      (message "gptel-dispvm: WARNING - port %d occupied by unknown process, not adopting"
               gptel-dispvm-redlib-port)))
   (t
    (let* ((cmd (format "socat TCP-LISTEN:%d,bind=127.0.0.1,fork,reuseaddr EXEC:'qrexec-client-vm %s qubes.ConnectTCP+%d'"
                        gptel-dispvm-redlib-port
                        (shell-quote-argument gptel-dispvm-redlib-vm)
                        gptel-dispvm-redlib-port))
           (proc (start-process-shell-command "gptel-redlib-tunnel" nil cmd)))
      (setq gptel-dispvm--redlib-process proc)
      (setq gptel-dispvm--redlib-pid (process-id proc))
      (set-process-sentinel proc
                            (lambda (_p event)
                              (setq gptel-dispvm--redlib-process nil
                                    gptel-dispvm--redlib-pid nil)
                              (unless (string-match-p "killed" event)
                                (message "gptel-dispvm: Redlib tunnel %s" (string-trim event)))))
      (message "gptel-dispvm: Redlib tunnel started on port %d" gptel-dispvm-redlib-port)))))

(defun gptel-dispvm-redlib-stop ()
  "Stop the Redlib tunnel."
  (interactive)
  (when (process-live-p gptel-dispvm--redlib-process)
    (delete-process gptel-dispvm--redlib-process)
    (setq gptel-dispvm--redlib-process nil)
    (setq gptel-dispvm--redlib-pid nil)
    (message "gptel-dispvm: Redlib tunnel stopped")))

(defun gptel-dispvm-redlib-status ()
  "Check if Redlib tunnel is running."
  (interactive)
  (message "gptel-dispvm: Redlib tunnel %s"
           (cond
            ((process-live-p gptel-dispvm--redlib-process) "running")
            ((gptel-dispvm--redlib-port-active-p)
             (format "active on port %d (orphaned)" gptel-dispvm-redlib-port))
            (t "not running"))))

;;; ------------------------------------------------------------------
;;; URL fetch
;;; ------------------------------------------------------------------

(defun gptel-dispvm--reddit-url-p (url)
  "Check if URL is a Reddit URL."
  (string-match-p "\\`https?://\\(?:www\\.\\|old\\.\\|new\\.\\)?reddit\\.com/" url))

(defun gptel-dispvm--reddit-to-redlib (url)
  "Convert Reddit URL to local Redlib URL."
  (let ((path (replace-regexp-in-string
               "https?://\\(?:www\\.\\|old\\.\\|new\\.\\)?reddit\\.com"
               ""
               url)))
    (format "http://127.0.0.1:%d%s" gptel-dispvm-redlib-port path)))

(defcustom gptel-dispvm-w3m-options '("-dump" "-T" "text/html" "-O" "utf-8")
  "Default options for w3m scraping as a list of arguments.
Each element is a separate command-line argument."
  :type '(repeat string)
  :group 'gptel)
(put 'gptel-dispvm-w3m-options 'risky-local-variable t)

(defun gptel-dispvm--w3m-options-string ()
  "Return `gptel-dispvm-w3m-options' as a shell-safe string.
Each option is individually shell-quoted to prevent injection."
  (mapconcat #'shell-quote-argument gptel-dispvm-w3m-options " "))

(defun gptel-dispvm--fetch-local (url)
  "Fetch URL locally using w3m (for Redlib)."
  (let* ((ua "Mozilla/5.0 (X11; Linux x86_64; rv:128.0)")
         (result
          (with-temp-buffer
            (apply #'call-process "w3m" nil t nil
                   (append gptel-dispvm-w3m-options
                           (list "-o" (format "user_agent=%s" ua)
                                 url)))
            (buffer-substring-no-properties
             (point-min)
             (min (point-max)
                  (+ (point-min) gptel-dispvm-fetch-max-chars))))))
    (string-trim result)))

(defun gptel-dispvm-fetch-url (url)
  "Fetch URL content. Uses local Redlib for Reddit, dispVM for others."
  (gptel-dispvm--validate-url url)
  (if (gptel-dispvm--reddit-url-p url)
      (progn
        (unless (process-live-p gptel-dispvm--redlib-process)
          (gptel-dispvm-redlib-start)
          (sleep-for 1))
        (let* ((redlib-url (gptel-dispvm--reddit-to-redlib url))
               (result (gptel-dispvm--fetch-local redlib-url)))
          (message "gptel-dispvm: Fetched Reddit via Redlib")
          (if (> (length result) 50)
              result
            (format "No content from Redlib for: %s" url))))
    (message "gptel-dispvm: Fetching '%s' via dispVM..." url)
    (let* ((ua "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0")
           (cmd (gptel-dispvm--fetch-url-dispvm-cmd url ua))
           (result (condition-case err
                       (gptel-dispvm--exec cmd 20)
                     (error
                      (gptel-dispvm--debug "URL fetch error: %s" (error-message-string err))
                      ""))))
      (if (> (length result) 50)
          (string-trim result)
        (format "No readable content from: %s" url)))))

;;; ------------------------------------------------------------------
;;; Untrusted web content tagging
;;; ------------------------------------------------------------------

(defun gptel-dispvm--tag-web-content (text)
  "Wrap TEXT in untrusted-web-content tags for prompt injection defense.
Sanitizes any occurrences of the tag itself within TEXT to prevent breakout.
Uses \\s- (Emacs syntax class for whitespace) to catch whitespace-padded variants."
  (let ((sanitized (replace-regexp-in-string
                    "</?\\s-*untrusted-web-content\\s-*>" "[filtered-tag]" text t)))
    (format "<untrusted-web-content>\n%s\n</untrusted-web-content>" sanitized)))

(defun gptel-dispvm--tag-search-results (results)
  "Wrap web-sourced search result excerpts in untrusted content tags.
Only tags results with a non-empty :url (skips error/fallback entries)."
  (mapcar (lambda (r)
            (if (and (plist-get r :url)
                     (not (string-empty-p (plist-get r :url))))
                (list :url (plist-get r :url)
                      :excerpt (gptel-dispvm--tag-web-content
                                (plist-get r :excerpt)))
              r))
          results))

(defun gptel-qubes-sandbox--tag-dispvm-output (text)
  "Wrap TEXT in untrusted-dispvm-output tags for prompt injection defense.
Applied to all tool results returned from the sandbox dispvm.
Sanitizes any occurrences of the tag itself within TEXT to prevent breakout.
Uses \\s- (Emacs syntax class for whitespace) to catch whitespace-padded variants."
  (if (and text (not (string-empty-p text)))
      (let ((sanitized (replace-regexp-in-string
                        "</?\\s-*untrusted-dispvm-output\\s-*>" "[filtered-tag]" text t)))
        (format "<untrusted-dispvm-output>\n%s\n</untrusted-dispvm-output>" sanitized))
    (or text "")))

;;; ------------------------------------------------------------------
;;; gptel-agent integration
;;; ------------------------------------------------------------------

(defun gptel-dispvm--around-web-search (orig-fn callback query &optional count)
  "Advice for web search through dispVM (async).
Wraps web content in untrusted-web-content tags for prompt injection defense."
  (ignore orig-fn count)
  (gptel-dispvm--ensure-started-async
   (lambda ()
     (let ((search-fn (pcase gptel-dispvm-search-engine
                        ('kagi #'gptel-dispvm--kagi-search-async)
                        (_ #'gptel-dispvm--ddg-search-async))))
       (funcall search-fn query
                (lambda (results)
                  (funcall callback
                           (gptel-dispvm--tag-search-results results))))))))

(defun gptel-dispvm--around-read-url (orig-fn callback url &rest args)
  "Advice to fetch URLs through dispVM (async).
Wraps web content in untrusted-web-content tags for prompt injection defense."
  (ignore orig-fn args)
  (let ((wrapped-callback
         (lambda (content)
           (funcall callback
                    (if (and content (> (length content) 50))
                        (gptel-dispvm--tag-web-content content)
                      content)))))
    (if (gptel-dispvm--reddit-url-p url)
        (gptel-dispvm--fetch-url-async url wrapped-callback)
      (gptel-dispvm--ensure-started-async
       (lambda ()
         (gptel-dispvm--fetch-url-async url wrapped-callback))))))

(defun gptel-dispvm--on-response-complete (&rest _args)
  "Stop dispVM and Redlib tunnel when gptel response is complete."
  (when (process-live-p gptel-dispvm--process)
    (run-at-time 1 nil #'gptel-dispvm--stop))
  (when (process-live-p gptel-dispvm--redlib-process)
    (run-at-time 2 nil #'gptel-dispvm-redlib-stop)))

(defun gptel-dispvm-setup-agent ()
  "Set up gptel-agent to use dispVM for web operations."
  (interactive)
  (advice-add 'gptel-agent--web-search-eww
              :around #'gptel-dispvm--around-web-search)
  (advice-add 'gptel-agent--read-url
              :around #'gptel-dispvm--around-read-url)
  (add-hook 'gptel-post-response-functions #'gptel-dispvm--on-response-complete)
  ;; Install tool advice (always present for sandbox interception)
  (gptel-qubes-sandbox--install-tool-advice)
  ;; Install persistent sandbox toggle indicator in mode line
  (gptel-qubes-sandbox--install-indicator)
  ;; Always hook sandbox auto-start — tool calls are never allowed locally,
  ;; so the sandbox must activate before any agent tool call executes
  (advice-add 'gptel-agent :after #'gptel-qubes-sandbox--on-agent-start)
  (message "gptel-dispvm: Agent web operations now use dispVM (engine: %s)"
           gptel-dispvm-search-engine))

(defun gptel-dispvm-restore-original ()
  "Remove dispVM web search advice from gptel-agent.
Only removes the web search and URL fetching advice.
Tool advice (bash, read, write, edit, etc.) is NEVER removed —
it is the security boundary that prevents local execution."
  (interactive)
  (when gptel-qubes-sandbox-active
    (gptel-qubes-sandbox--teardown))
  (advice-remove 'gptel-agent--web-search-eww
                 #'gptel-dispvm--around-web-search)
  (advice-remove 'gptel-agent--read-url
                 #'gptel-dispvm--around-read-url)
  (remove-hook 'gptel-post-response-functions #'gptel-dispvm--on-response-complete)
  (gptel-dispvm--cleanup)
  (message "gptel-dispvm: Web search advice removed. Tool sandbox enforcement remains active."))

(provide 'gptel-qubes-dispvm)
;;; gptel-qubes-dispvm.el ends here
