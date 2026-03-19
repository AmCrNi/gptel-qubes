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

Enables the LLM agent to develop complete applications inside an isolated, ephemeral Qubes dispvm. All gptel-agent tool calls (write, edit, mkdir, bash, glob, grep, insert, read) are routed through the dispvm when sandbox mode is active. The agent can install packages, write code, run tests, and iterate — all inside the disposable VM. When done, the output is packaged as a tar.gz and transferred back to the Emacs AppVM.

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
- The system prompt is augmented to tell the LLM it's working inside a disposable VM
- The dispvm persists across agent turns (not destroyed per-response like websearch)
- A `*gptel-sandbox-log*` buffer logs all commands and outputs for visibility

**Configuration:**
- `gptel-qubes-sandbox-output-dir` — where tar.gz files are saved (default: `~/Downloads/gptel-sandbox/`)
- `gptel-qubes-sandbox-working-dir` — working directory inside dispvm (default: `/home/user/project`)
- `gptel-qubes-sandbox-max-transfer-size` — max tar.gz size for transfer (default: 10MB)
- `gptel-qubes-sandbox-auto-confirm` — skip tool call confirmations in sandbox (default: t)

**Security properties:**
- All code executes in an ephemeral Qubes dispvm — destroyed when sandbox mode is deactivated
- No access to the host AppVM filesystem or data
- Heredoc delimiters use SHA-256 cryptographic markers — no collision with file content
- All file paths are shell-quoted — no shell injection
- Output is packaged as tar.gz and saved to disk — not auto-executed
- If the dispvm dies unexpectedly, sandbox mode auto-deactivates and the user is notified

**Known limitations / risks:**
- The dispvm has internet access — the LLM could download external code (but there's no sensitive data in a fresh dispvm)
- The tar.gz output is not automatically reviewed — inspect before extracting and running
- Tool result strings from the dispvm are not wrapped in `<untrusted-content>` tags (unlike websearch)
- Setting `gptel-confirm-tool-calls` to nil for faster iteration means the LLM runs tools without human review

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
|  | |  Tool calls intercepted   ||                    |
|  | |  via :around advice:      ||                    |
|  | |  - Write (heredoc+SHA256) ||                    |
|  | |  - Edit  (Python helper)  ||                    |
|  | |  - Insert(Python helper)  ||                    |
|  | |  - Bash  (async callback) ||                    |
|  | |  - Read  (cat/sed)        ||                    |
|  | |  - Mkdir, Glob, Grep      ||                    |
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
|  | | - apt-get install on the fly  |                 |
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
