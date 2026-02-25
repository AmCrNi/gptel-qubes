;;; gptel-qubes-dispvm.el --- DispVM web for gptel-agent -*- lexical-binding: t; -*-
;; 1. The AppVM with Emacs doesn't have access to the internet.
;; 2. The Ollama server is running in the local network and doesn't have access to the internet.
;; 3. Kagi is a web search engine used where its token is stored in an encrypted authinfo file.
;; 4. gptel-agent performs a query by starting a dispVM, which has access to the internet.
;; 5. Because Reddit doesn't like a VPN, I use qrexec to connect to the local redlib in a dedicated AppVM - just for Reddit queries.
;; 6. DuckDuckGo rate-limit resilience: captures HTTP status, enforces inter-search delay, retries on empty/non-200 responses.
;; 7. Prompt injection defense: all web content returned to LLM is wrapped in <untrusted-web-content> tags.
;; 8. Once the agent finishes the response, the dispVM is shut down and the redlib socat is closed.
;; 9. Kagi token security:
;; - Token not in ps/cmdline
;; - Token not echoed to buffer
;; - Token cleared from Emacs memory
;; - Auth-source cache preserved
;; - Token isolated to dispVM

(require 'gptel)
(require 'subr-x)
(require 'auth-source)
(require 'json)

;;; ------------------------------------------------------------------
;;; Variables
;;; ------------------------------------------------------------------

(defvar gptel-dispvm--process nil)
(defvar gptel-dispvm--ready nil)
(defvar gptel-dispvm--redlib-process nil
  "Process for the socat tunnel to Redlib.")
(defvar gptel-dispvm--redlib-pid nil
  "PID of the socat tunnel process we launched, for orphan verification.")
(defvar gptel-dispvm--pending-callbacks nil
  "Callbacks queued during async VM startup.")

(defvar gptel-dispvm--exec-queue nil
  "Queue of (FUNCTION . ARGS) for serialized command execution.")
(defvar gptel-dispvm--exec-busy nil
  "Non-nil when an async command is in progress.")


(defcustom gptel-dispvm-timeout 30
  "Timeout in seconds for dispVM commands."
  :type 'integer
  :group 'gptel)

(defcustom gptel-dispvm-search-engine 'duckduckgo
  "Default search engine to use.
Options are `kagi' (requires API token) or `duckduckgo' (no token needed)."
  :type '(choice (const :tag "DuckDuckGo (no token)" duckduckgo)
                 (const :tag "Kagi (requires token)" kagi))
  :group 'gptel)

(defcustom gptel-dispvm-ddg-search-delay 5.0
  "Minimum seconds between DuckDuckGo searches to avoid rate limiting."
  :type 'number
  :group 'gptel)

(defvar gptel-dispvm--ddg-last-search-time nil
  "Timestamp of the last DuckDuckGo search, for rate-limit pacing.")

(defcustom gptel-dispvm-ddg-retry-delay 10.0
  "Seconds to wait before retrying a failed DuckDuckGo search."
  :type 'number
  :group 'gptel)

(defcustom gptel-dispvm-debug nil
  "Enable debug messages for troubleshooting."
  :type 'boolean
  :group 'gptel)

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
        gptel-dispvm--exec-busy nil))

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
        gptel-dispvm--exec-busy nil))

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
        (if (string-match-p marker content)
            (string-trim
             (replace-regexp-in-string (concat marker ".*") "" content))
          (error "gptel-dispvm: Command timed out"))))))

;;; ------------------------------------------------------------------
;;; Async execution
;;; ------------------------------------------------------------------

(defun gptel-dispvm--clear-string (str)
  "Securely clear string STR from memory."
  (when (stringp str)
    (if (fboundp 'clear-string)
        (clear-string str)
      (fillarray str 0))))

(defun gptel-dispvm--exec-async (cmd callback &optional timeout)
  "Execute CMD in dispVM asynchronously, call CALLBACK with result.
CALLBACK receives the command output string, or nil on timeout."
  (if gptel-dispvm--exec-busy
      (setq gptel-dispvm--exec-queue
            (append gptel-dispvm--exec-queue
                    (list (list #'gptel-dispvm--exec-async cmd callback timeout))))
    (unless (process-live-p gptel-dispvm--process)
      (setq gptel-dispvm--exec-busy nil)
      (funcall callback nil)
      (error "gptel-dispvm: No active connection"))
    (setq gptel-dispvm--exec-busy t)
    (let ((wrapped-cb (gptel-dispvm--wrap-callback-for-queue callback)))
      (let* ((timeout (or timeout gptel-dispvm-timeout))
             (marker (gptel-dispvm--make-marker))
             (buf (process-buffer gptel-dispvm--process))
             (proc gptel-dispvm--process)
             (completed nil)
             (timer nil))
        (with-current-buffer buf (erase-buffer))
        ;; Install temporary process filter watching for marker
        (set-process-filter proc
          (lambda (p output)
            (when (buffer-live-p (process-buffer p))
              (with-current-buffer (process-buffer p)
                (goto-char (point-max))
                (insert output)
                (when (and (not completed)
                           (save-excursion
                             (goto-char (point-min))
                             (search-forward marker nil t)))
                  (setq completed t)
                  (set-process-filter p #'gptel-dispvm--filter)
                  (when timer (cancel-timer timer))
                  (let ((content (buffer-string)))
                    (funcall wrapped-cb
                             (string-trim
                              (replace-regexp-in-string
                               (concat marker ".*") "" content)))))))))
        ;; Timeout timer
        (setq timer
              (run-at-time timeout nil
                           (lambda ()
                             (unless completed
                               (setq completed t)
                               (gptel-dispvm--debug "Async exec timed out (cmd length: %d)" (length cmd))
                               (set-process-filter proc #'gptel-dispvm--filter)
                               (funcall wrapped-cb nil)))))
        ;; Send command - echo marker on its own line so heredoc commands work
        (process-send-string proc (concat cmd "\necho " marker "\n"))))))

(defun gptel-dispvm--exec-with-stdin-async (cmd stdin-data callback &optional timeout)
  "Execute CMD in dispVM asynchronously with STDIN-DATA, call CALLBACK with result.
Uses a handshake protocol: the shell prints GPTEL_STDIN_READY when
it is ready to receive stdin, eliminating the timing race.
CALLBACK receives the command output string, or nil on timeout."
  (if gptel-dispvm--exec-busy
      (setq gptel-dispvm--exec-queue
            (append gptel-dispvm--exec-queue
                    (list (list #'gptel-dispvm--exec-with-stdin-async cmd stdin-data callback timeout))))
    (unless (process-live-p gptel-dispvm--process)
      (setq gptel-dispvm--exec-busy nil)
      (funcall callback nil)
      (error "gptel-dispvm: No active connection"))
    (setq gptel-dispvm--exec-busy t)
    (let ((wrapped-cb (gptel-dispvm--wrap-callback-for-queue callback)))
      (let* ((timeout (or timeout gptel-dispvm-timeout))
             (marker (gptel-dispvm--make-marker))
             (ready-marker "GPTEL_STDIN_READY")
             (buf (process-buffer gptel-dispvm--process))
             (proc gptel-dispvm--process)
             (completed nil)
             (timer nil))
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
                                  (when (and (not completed)
                                             (save-excursion
                                               (goto-char (point-min))
                                               (search-forward marker nil t)))
                                    (setq completed t)
                                    (set-process-filter p2 #'gptel-dispvm--filter)
                                    (when timer (cancel-timer timer))
                                    (let ((content (buffer-string)))
                                      (funcall wrapped-cb
                                               (string-trim
                                                (replace-regexp-in-string
                                                 (concat marker ".*") "" content))))))))))
                      ;; Always clear secrets, even on error or dead process
                      (gptel-dispvm--clear-string stdin-data)
                      (gptel-dispvm--clear-string formatted))))))))
        ;; Timeout timer
        (setq timer
              (run-at-time timeout nil
                           (lambda ()
                             (unless completed
                               (setq completed t)
                               (gptel-dispvm--debug "Async exec-stdin timed out (cmd length: %d)" (length cmd))
                               (set-process-filter proc #'gptel-dispvm--filter)
                               (funcall wrapped-cb nil)))))))))

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
  "Get Kagi API token from authinfo (returns a copy for safe clearing)."
  (let ((auth (auth-source-search :host "kagi.com" :max 1)))
    (when auth
      (let ((secret (plist-get (car auth) :secret)))
        (when-let ((val (if (functionp secret)
                            (funcall secret)
                          secret)))
          (copy-sequence val))))))

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
;;; Async search
;;; ------------------------------------------------------------------

(defun gptel-dispvm--ddg-search-async (query callback &optional retried)
  "Search DuckDuckGo for QUERY asynchronously via dispVM.
Calls CALLBACK with list of (:url URL :excerpt TEXT) results.
Uses Python parser in dispVM when available, falls back to Emacs HTML parsing.
Enforces `gptel-dispvm-ddg-search-delay' between searches to avoid rate limiting.
Retries once on empty response unless RETRIED is non-nil."
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
               (if retried " (retry)" ""))
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
               (if (and (not retried)
                        (or (string-empty-p clean-result)
                            (and http-status (not (string= http-status "200")))))
                   ;; Empty or non-200 response and haven't retried — retry after delay
                   (progn
                     (gptel-dispvm--debug "DDG empty response, retrying in %.1fs"
                                          gptel-dispvm-ddg-retry-delay)
                     (run-at-time gptel-dispvm-ddg-retry-delay nil
                                  #'gptel-dispvm--ddg-search-async
                                  query callback t))
                 ;; Parse results (or return empty on retry)
                 (let ((parsed
                        (if (string-prefix-p "GPTEL_RAW_HTML" clean-result)
                            (progn
                              (gptel-dispvm--debug "DDG raw fallback: python3 not available in dispVM")
                              (gptel-dispvm--parse-ddg-html
                               (substring clean-result (length "GPTEL_RAW_HTML"))))
                          (gptel-dispvm--parse-ddg-json clean-result))))
                   (funcall callback parsed))))))
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

(defun gptel-dispvm--fetch-url-async (url callback)
  "Fetch URL content asynchronously.
Uses local Redlib for Reddit, dispVM for others.
Calls CALLBACK with content string."
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
           (cmd (format "timeout 15 w3m %s -o user_agent=%s %s 2>/dev/null | head -c 8000"
                        gptel-dispvm-w3m-options
                        (shell-quote-argument ua)
                        (shell-quote-argument url))))
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

(defcustom gptel-dispvm-w3m-options "-dump -T text/html -O utf-8"
  "Default options for w3m scraping."
  :type 'string
  :group 'gptel)
(put 'gptel-dispvm-w3m-options 'risky-local-variable t)

(defun gptel-dispvm--fetch-local (url)
  "Fetch URL locally using w3m (for Redlib)."
  (let* ((ua "Mozilla/5.0 (X11; Linux x86_64; rv:128.0)")
         (cmd (format "timeout 15 w3m %s -o user_agent=%s %s 2>/dev/null | head -c 8000"
                      gptel-dispvm-w3m-options
                      (shell-quote-argument ua)
                      (shell-quote-argument url))))
    (string-trim (shell-command-to-string cmd))))

(defun gptel-dispvm-fetch-url (url)
  "Fetch URL content. Uses local Redlib for Reddit, dispVM for others."
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
           (cmd (format "timeout 15 w3m %s -o user_agent=%s %s 2>/dev/null | head -c 8000"
                        gptel-dispvm-w3m-options
                        (shell-quote-argument ua)
                        (shell-quote-argument url)))
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
  "Wrap TEXT in untrusted-web-content tags for prompt injection defense."
  (format "<untrusted-web-content>\n%s\n</untrusted-web-content>" text))

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
  (message "gptel-dispvm: Agent web operations now use dispVM (engine: %s)"
           gptel-dispvm-search-engine))

(defun gptel-dispvm-restore-original ()
  "Remove dispVM advice from gptel-agent."
  (interactive)
  (advice-remove 'gptel-agent--web-search-eww
                 #'gptel-dispvm--around-web-search)
  (advice-remove 'gptel-agent--read-url
                 #'gptel-dispvm--around-read-url)
  (remove-hook 'gptel-post-response-functions #'gptel-dispvm--on-response-complete)
  (gptel-dispvm--cleanup)
  (message "gptel-dispvm: Restored original web functions"))

(provide 'gptel-qubes-dispvm)
;;; gptel-qubes-dispvm.el ends here
