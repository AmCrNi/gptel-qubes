# gptel-qubes
Reasonably secure LLM integration with emacs

Fully vibecoded.

Incorporates gptel-agent for web search via dispvm.

1. The AppVM with Emacs doesn't have access to the internet.
2. The Ollama server is running in the local network and doesn't have access to the internet.
3. Kagi is a web search engine used where its token is stored in an encrypted authinfo file.
4. gptel-agent performs a query by starting a dispVM, which has access to the internet.
5. Because Reddit doesn't like VPN, I use qrexec to connect to the local redlib in a dedicated AppVM - just for Reddit queries.
6. DuckDuckGo rate-limit resilience: captures HTTP status, enforces inter-search delay, retries on empty/non-200 responses.
7. Prompt injection defense: all web content returned to LLM is wrapped in <untrusted-web-content> tags.
8. Once the agent finishes the response, the dispVM is shut down and the redlib socat is closed.
9. Kagi token security:
- Token not in ps/cmdline
- Token not echoed to buffer
- Token cleared from Emacs memory
- Auth-source cache preserved
- Token isolated to dispVM

```
                          QUBES OS
+==========================================================================+
|                                                                          |
|       NO INTERNET                                                        |                          NO INTERNET
|  +------------------------+                                              |                    +--------------------+
|  |    AppVM: EMACS        |                                              |          local net |   Local OLLAMA     |
|  |                        |                                +--------------------------------->|                    |
|  |  +------------------+  |                                |             |                    |  +---------------+ |
|  |  |   gptel-agent    |  |                                |             |                    |  | Ollama Server | |
|  |  |                  |<-|--------------------------------+             |                    |  | (local LLM)   | |
|  |  | +~~~~~~~~~~~~~~+ |  |                                              |                    |  +---------------+ |
|  |  | : authinfo.gpg : +--|---------------------------------+            |                    +--------------------+
|  |  | : (Kagi token, : |  |                                 |            |
|  |  | :  encrypted)  : |  |  TOKEN SECURITY:                |            |
|  |  | +~~~~~~~~~~~~~~+ |  |  - Not in ps / cmdline          |            |
|  |  +---+---------+----+  |  - Not echoed to buffer         |            |
|  |      |         |       |  - Cleared from Emacs memory    |            |
|  +------+---------+-------+  - Auth-source cache preserved  |            |
|         |         |          - Isolated to DispVM only      |            |
|         |         |                                         |            |
|  qrexec |         | qrexec                                  |            |
| (launch)|         | (token via stdin — never on cmdline)    |            |
|         |         |                                         v            |
|  +------v---------v---------------------------+   +------------------+   |       
|  |     DispVM   [EPHEMERAL · HAS INTERNET]    |   |  REDLIB CLIENT   |   |       
|  |                                            |   |  (Reddit only)   |   |       
|  |   +------------+   +--------------+        |   +---------+--------+   |                     
|  |   |    KAGI    |   |  DUCKDUCKGO  |        |             |            |                     
|  |   |  (primary) |   |  (fallback)  |        |      qrexec + socat      |                     
|  |   +------+-----+   +------+-------+        |             |            |              
|  |          |                |                |             |            |              
|  |          |          +-----+--------+       |     +------ +            |              
|  |          |          | Rate-limit   |       |     |                    |
|  |          |          | resilience:  |       |     |                    |
|  |          |          | · HTTP check |       |     |                    |
|  |          |          | · Delay      |       |     |                    |
|  |          |          | · Retry on   |       |     |                    |
|  |          |          |   empty/!200 |       |     |                    |
|  |          |          +-----+--------+       |     |                    |
|  |          |                |                |     |                    |
|  |   +------+----------------+---+            |     |                    |
|  |   | <untrusted-web-content>   |            |     |                    |
|  |   | (prompt injection defense)|            |     |                    |
|  |   +---------------------------+            |     |                    |
|  |                                            |     |                    |
|  |   ** Destroyed when agent finishes **      |     |                    |
|  |   ** Socat closed on completion **         |     |                    |
|  +-------+--------------+------+--------------+     |                    |
|          |              |      |                    |                    |
|          |              |      |                    |                    |
|          v              v      |                    v                    |
|    +-----------+ +-----------+ |     +---------------------------+       |
|    |api.kagi.  | |duckduckgo | |     |   AppVM: REDLIB           |       |
|    |com        | |.com       | |     |   [DEDICATED]             |       |
|    +-----+-----+ +-----+-----+ |     |                           |       |
|          |             |       |     |  +---------------------+  |       |
|          |             |       |     |  | redlib (self-hosted |  |       |
|          |             |       |     |  | Reddit frontend)    |  |       |
|          |             |       |     |  +----------+----------+  |       |
|          |             |       |     |             |             |       |
|          |             |       |     +-------------+-------------+       |
|          |             |       |                   |                     |
+==========+=============+=======+===================+=====================+
           |             |                           |
           v             v                           v
 ~~~~~~~~~~~~~~~~~~~ I N T E R N E T ~~~~~~~~~~~~~~~~~~~~~~~~~~~
           |             |                           |
      api.kagi.com  duckduckgo.com              reddit.com
                                             (bypasses VPN block
                                              via local redlib)

```
