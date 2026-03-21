# gptel-qubes
Reasonably secure LLM integration with emacs

Fully vibecoded.

## Features

### Web Search via DispVM

Incorporates gptel-agent for web search via disposable VMs (dispvms).

1. The AppVM with Emacs doesn't have access to the internet.
2. The Ollama server is running in the local network and doesn't have access to the internet.
3. Kagi is a web search engine used where its token is stored in an encrypted authinfo file.
4. gptel-agent performs a query by starting a dispVM, which has access to the internet.
5. Because Reddit doesn't like VPN, I use qrexec to connect to the local redlib in a dedicated AppVM - just for Reddit queries.
6. DuckDuckGo rate-limit resilience: captures HTTP status, enforces inter-search delay, retries on empty/non-200 responses, auto-reconnects VPN on persistent rate limiting.
7. Prompt injection defense: all web content returned to LLM is wrapped in `<untrusted-web-content>` tags with tag-breakout sanitization.
8. Once the agent finishes the response, the dispVM is shut down and the redlib socat is closed.
9. Kagi token security:
   - Token not in ps/cmdline
   - Token not echoed to buffer
   - Token cleared from Emacs memory
   - Auth-source cache preserved
   - Token isolated to dispVM
10. Smart content extraction: fetched web pages are processed with a Python html.parser script that strips navigation, footers, ads, and noise elements, extracting only article/main content. Falls back to w3m if python3 is unavailable.
11. URL scheme validation: only http/https URLs are accepted, preventing local file access.
12. All security-sensitive defcustoms are marked `risky-local-variable` to prevent `.dir-locals.el` attacks.

### Sandbox Development Mode

Enables the LLM agent to develop complete applications inside an isolated, ephemeral Qubes dispvm. The agent can never execute code, read files, or access data on the Emacs AppVM. All execution is confined to the disposable VM.

**Usage:**
1. `M-x gptel-qubes-sandbox-mode` — activate sandbox mode (launches dispvm)
2. Use gptel-agent normally — ask it to build something
3. `M-x gptel-qubes-sandbox-finalize` — package output as tar.gz and transfer back
4. Or toggle off with `M-x gptel-qubes-sandbox-mode` again (prompts to retrieve work first)

**How it works:**
- All tool calls are intercepted via Emacs advice and routed to the dispvm shell
- File writes use heredocs with cryptographic (SHA-256) markers to prevent delimiter collision
- File edits use a Python helper for exact string matching (not regex) with uniqueness verification
- File inserts use a Python helper for multi-line support matching Elisp semantics
- Bash commands run asynchronously with callback handling
- The system prompt is injected at request time (immune to preset switching)
- The dispvm persists across agent turns (not destroyed per-response like websearch)
- A `*gptel-sandbox-log*` buffer logs all commands and outputs for visibility

**Configuration:**
- `gptel-qubes-sandbox-output-dir` — where tar.gz files are saved (default: `~/Downloads/gptel-sandbox/`)
- `gptel-qubes-sandbox-working-dir` — working directory inside dispvm (default: `/home/user/project`)
- `gptel-qubes-sandbox-max-transfer-size` — max tar.gz size for transfer (default: 10MB)
- `gptel-qubes-sandbox-auto-confirm` — skip tool call confirmations in sandbox (default: t)
- `gptel-qubes-sandbox-auto-activate` — auto-activate sandbox on agent start (default: t)

### Security Architecture

The sandbox enforces strict isolation through four independent layers. Each layer is unconditional once `gptel-dispvm-setup-agent` is called — no configuration can weaken them.

**Layer 1 — Tool advertisement filtering** (`gptel--parse-tools` advice)

Only tools on the allowlist are sent to the LLM. The LLM never sees Eval, Agent, Skill, or introspection tools — it cannot call what it does not know exists. This is an allowlist, not a blocklist: new tools added to gptel-agent are blocked by default.

Allowed tools: `Bash`, `Write`, `Read`, `Edit`, `Insert`, `Mkdir`, `Glob`, `Grep`, `WebSearch`, `WebFetch`, `YouTube`, `TodoWrite`.

**Layer 2 — Tool execution gates** (three interception points)

Even if the LLM somehow calls a blocked tool (e.g., from conversation history), it is caught and blocked at every possible dispatch path in gptel:

- `gptel--handle-tool-use` — the true chokepoint where ALL tool calls are dispatched, including auto-confirmed ones. Blocked tools are marked with an error result before any execution.
- `gptel--display-tool-calls` — filters before the confirmation UI is shown to the user.
- `gptel--accept-tool-calls` — defense-in-depth gate at manual dispatch.

**Layer 3 — Tool routing enforcement** (8 individual `:around` advice functions)

Every allowed tool (Bash, Read, Write, Edit, Insert, Mkdir, Glob, Grep) is individually intercepted and routed to the dispvm. If the sandbox is not active, execution is refused with a hard error — there is no fallback to local execution. The `(funcall orig-fn ...)` path has been completely eliminated from all tool advice functions.

**Layer 4 — Qubes VM isolation**

The dispvm is ephemeral, communicates only via qrexec pipes, and cannot initiate connections back to the AppVM. The dispvm filesystem is destroyed when the session ends.

**Request-time system prompt injection** (`gptel--realize-query` advice)

The sandbox context (Fedora/dnf, working directory, etc.) is appended to `gptel--system-message` in the prompt buffer right before every API request. This is immune to preset switching. Note: this is UX guidance only — the four layers above are the security boundary, not the prompt.

**Security invariants:**
- The agent can NEVER execute code on the Emacs AppVM
- The agent can NEVER read files from the Emacs AppVM
- The agent can NEVER access Emacs variables, functions, or runtime state
- No `funcall orig-fn` exists in any tool advice function — local execution path is eliminated
- All layers are unconditional — no flag or setting can disable them once installed
- All layers use an allowlist — unknown/new tools are blocked by default
- If the dispvm dies, the `[Sandbox:DEAD]` indicator appears and tool calls are blocked until manual re-activation

**DispVM death handling:**
- The sentinel sets `gptel-qubes-sandbox--dispvm-died-unexpectedly`
- Auto-reactivation is suppressed to avoid masking systemic issues
- User must explicitly re-activate via `M-x gptel-qubes-sandbox-mode`
- Mode-line shows red `[Sandbox:DEAD]` for immediate visibility

**Known limitations / risks:**
- The dispvm has internet access — the LLM could download external code (but there's no sensitive data in a fresh dispvm)
- **Conversation context exfiltration:** The LLM has full access to the conversation context (including any code or secrets the user pastes) AND can execute bash with internet access in the dispvm. A prompt injection (via web search results or compromised dispvm output) could instruct the LLM to exfiltrate conversation content via `curl` or similar. **Mitigation:** Avoid pasting sensitive secrets (API keys, passwords) into conversations when using sandbox mode with internet-connected dispvms. Tool results are now wrapped in `<untrusted-dispvm-output>` tags to help the LLM distinguish trusted from untrusted content.
- The tar.gz output is not automatically reviewed — extract into an empty directory (`mkdir out && tar -xzf file.tar.gz -C out`) and inspect before running
- Tool result strings from the dispvm are wrapped in `<untrusted-dispvm-output>` tags (analogous to `<untrusted-web-content>` for web search) to defend against prompt injection from compromised dispvm processes
- Agent definition files (`.md`/`.org`) with `:pre`/`:post` hooks execute elisp at load time — ensure agent files come from trusted sources

## Architecture

### Web Search Mode

```
                        QUBES OS                          local net
+------------------------------------------------------+  +----------------+
|                                                      |  |  OLLAMA        |
|  NO INTERNET                                         |  |  (no internet) |
|  +----------------------+                      +---- |->|                |
|  | AppVM: EMACS         |                      |     |  | Ollama Server  |
|  | (local-net-13)       |                      |     |  | (local LLM)    |
|  |                      |                      |     |  +----------------+
|  | +------------------+ |                      |     |
|  | |  gptel-agent     |<|----------------------+     |
|  | |                  | |                            |
|  | | +~~~~~~~~~~~~~~+ | |  TOKEN SECURITY:           |
|  | | : authinfo.gpg : +-|--+  - Not in ps/cmdline    |
|  | | : (encrypted)  : | |  |  - Not echoed to buf    |
|  | | +~~~~~~~~~~~~~~+ | |  |  - Cleared from memory  |
|  | +--+----------+----+ |  |  - Isolated to dispVM   |
|  +----+----------+------+  |                         |
|       |          |          |                        |
|       |          |          |  qrexec                |
|       | qrexec   | qrexec  |  (VPN reconnect)        |
|       | (launch) | (token)  |                        |
|       |          |          |                        |
|       |          |  +-------v-------------------+    |
|       |          |  | sys-vpn-mullvad-42        |    |
|       |          |  | (Mullvad VPN)             |    |
|       |          |  |                           |    |
|       |          |  | Auto-reconnect on DDG     |    |
|       |          |  | rate limit:               |    |
|       |          |  |  - Random country         |    |
|       |          |  |  - mullvad reconnect      |    |
|       |          |  +-------+-------------------+    |
|       |          |          |                        |
|       |          |          | netVM for dispVM       |
|       |          |          |                        |
|  +----v----------v----------v----+  +-------------+  |
|  | DispVM [EPHEMERAL, INTERNET]  |  | REDLIB      |  |
|  |                               |  | CLIENT      |  |
|  | +---------+  +-----------+    |  | (Reddit)    |  |
|  | |  KAGI   |  | DUCKDUCKGO|    |  +------+------+  |
|  | |(primary)|  | (fallback)|    |         |         |
|  | +----+----+  +-----+----+     |   qrexec + socat  |
|  |      |             |          |         |         |
|  |      |       +-----+------+   |   +-----+         |
|  |      |       | Rate-limit |   |   |               |
|  |      |       | resilience:|   |   |               |
|  |      |       | - HTTP chk |   |   |               |
|  |      |       | - Delay    |   |   |               |
|  |      |       | - Retry    |   |   |               |
|  |      |       | - VPN reco.|   |   |               |
|  |      |       +-----+------+   |   |               |
|  |      |             |          |   |               |
|  | +----+-------------+---+      |   |               |
|  | | Content extraction:  |      |   |               |
|  | | - curl + Python html |      |   |               |
|  | |   parser (strip junk)|      |   |               |
|  | | - w3m fallback       |      |   |               |
|  | +----------------------+      |   |               |
|  | +------------------------+    |   |               |
|  | | <untrusted-web-content>|    |   |               |
|  | | (prompt inj. defense   |    |   |               |
|  | |  + tag sanitization)   |    |   |               |
|  | +------------------------+    |   |               |
|  |                               |   |               |
|  | ** Destroyed on completion ** |   |               |
|  +-----+-------------+----+------+   |               |
|        |             |    |          |               |
|        v             v    |          v               |
|  +-----------+ +--------+ |  +------------------+    |
|  | api.kagi. | | ddg.   | |  | AppVM: REDLIB    |    |
|  | com       | | com    | |  | [DEDICATED]      |    |
|  +-----+-----+ +---+----+ |  | redlib (Reddit   |    |
|        |            |     |  | frontend)        |    |
|        |            |     |  +--------+---------+    |
|        |            |     |           |              |
+--------+------------+-----+-----------+--------------+
         |            |                 |
         v            v                 v
~~~~ I N T E R N E T ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
         |            |                 |
    api.kagi.com  duckduckgo.com    reddit.com
                                 (via local redlib,
                                  bypasses VPN block)
```

### Sandbox Development Mode

```
                        QUBES OS                          local net
+------------------------------------------------------+  +----------------+
|                                                      |  |  OLLAMA        |
|  NO INTERNET                                         |  |  (no internet) |
|  +------------------------------+              +---- |->|                |
|  | AppVM: EMACS                 |              |     |  | Ollama Server  |
|  | (local-net-13)               |              |     |  | (local LLM)    |
|  |                              |              |     |  +----------------+
|  | +---------------------------+|              |     |
|  | |  gptel-agent              ||              |     |
|  | |                           |<--------------+     |
|  | |  SECURITY LAYERS:         ||                    |
|  | |                           ||                    |
|  | |  L1: parse-tools advice   ||                    |
|  | |    LLM only sees allowed  ||                    |
|  | |    tools (allowlist)      ||                    |
|  | |           |               ||                    |
|  | |  L2: handle-tool-use gate ||                    |
|  | |    Blocks non-allowed at  ||                    |
|  | |    true dispatch point    ||                    |
|  | |    (incl. auto-confirmed) ||                    |
|  | |           |               ||                    |
|  | |  L3: :around advice on    ||                    |
|  | |    each tool function     ||                    |
|  | |    Routes to dispvm OR    ||                    |
|  | |    hard error (no local   ||                    |
|  | |    fallthrough exists)    ||                    |
|  | +--+------------------------+|                    |
|  |    |                         |                    |
|  |    | qrexec (qubes.VMShell)  |                    |
|  |    | bidirectional shell     |                    |
|  |    |                         |                    |
|  | +--v------------------------+---+                 |
|  | | DispVM [EPHEMERAL, INTERNET]  |                 |
|  | |                               |                 |
|  | | /home/user/project/           |                 |
|  | |  ├── <application files>      |                 |
|  | |  ├── INSTALL.md               |                 |
|  | |  └── README.md                |                 |
|  | |                               |                 |
|  | | - Fedora-based (dnf only)     |                 |
|  | | - Full dev environment        |                 |
|  | | - Internet for deps & docs    |                 |
|  | | - Persists across agent turns |                 |
|  | |                               |                 |
|  | | ** Destroyed on deactivate ** |                 |
|  | +------+------------------------+                 |
|  |        |                                          |
|  |        | tar.gz + base64 via                      |
|  |        | existing qrexec pipe                     |
|  |        |                                          |
|  | +------v-----------------------+                  |
|  | | ~/Downloads/gptel-sandbox/   |                  |
|  | | sandbox-YYYY-MM-DD-HHMMSS.   |                  |
|  | | tar.gz                       |                  |
|  | +------------------------------+                  |
|  +---------------------------------------------------+
```
