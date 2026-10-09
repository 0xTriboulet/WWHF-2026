# silent_copilot.exe — headless M365 Copilot prompt/response client

> **Code-flow diagram:** `flow.html` — full mermaid flowchart of the binary,
> derived 1:1 from the current source (open in a browser; renders via the mermaid CDN).

Send a prompt to M365 Copilot (Sydney / `substrate.office.com` Chathub) with no
UI, and print the reply to stdout. Everything it needs is discovered at run
time.

## Usage

```
silent_copilot.exe [--trace] [prompt words...]
```

Sends the prompt to M365 Copilot and prints the model's reply to **stdout**.
All progress (token harvest, launch mode, WebSocket state) goes to stderr, so
stdout is a clean reply-only channel — `2>nul` leaves nothing but the reply.
Prompt words given as separate arguments are joined with spaces; run with
no prompt to send the built-in default (`hello from silent_copilot`).

```
silent_copilot.exe "what is on my calendar today?"     # reply on stdout
silent_copilot.exe --trace "hello"                      # + WS frames on stderr and
                                                        #   silent_copilot_dbg.log next to the exe
```

**By default the binary writes nothing to disk.** `--trace` enables
WS-frame dumps on stderr and the `silent_copilot_dbg.log` launch diagnostics
file next to the exe (the flag propagates into the hidden-launch child when
one is spawned). TLS is provided by Windows' inbox Schannel (SSPI), so no
third-party runtime ships with it (imports = OS DLLs only, incl.
Secur32.dll). Exit `0` on reply, `1` on failure.

### Requirements

- **Microsoft 365 Copilot** — licensed tenant/user and the M365 Copilot
  desktop app (`M365Copilot.exe`) installed. The user must be signed in: the
  binary harvests the live JWE access token from the app's process memory.
  If the app isn't running, the binary launches it invisibly inside the
  signed-in user's interactive session and harvests the fresh token.
- **An interactive logon session for the target user** — any packaged WinUI
  app needs one (that's also where the hidden launch puts the app). Over SSH
  this works when a console session for that user exists (check with
  `query session`). For autonomous bring-up after reboot, configure
  `AutoAdminLogon` for that user.
- **Outbound HTTPS to `substrate.office.com:443`** — the M365 Substrate
  Chathub endpoint (WebSocket over TLS; TLS-intercepting proxies will break
  the session).
- **Windows 10/11 with inbox Schannel** — TLS 1.2/1.3 via SSPI
  (`Secur32.dll`); cert chain validated against the Windows trust store.
  No third-party TLS library, no bundled DLLs.
- Nothing is hardcoded to a machine: tokens, tenant/session ids and feature
  variants are all recovered at run time from the victim app's memory.

## How it works (no hardcoded machine data)

1. **Harvest.** Scans `M365Copilot.exe` and any `msedgewebview2.exe` process
   memory (region-accurate `ReadProcessMemory`) for:
   - JWE access tokens (begin `eyJhbGciOiJkaXIi` = `{"alg":"dir"}`),
   - the session-tenant GUID (hex-tail `aaaaaaaaaaaa`),
   - the optional feature "variants" blob (`EnableMcpServerWidgets,...`).
   Tokens are deduped; each is tried with a **fresh client-generated
   conversation id** (substrate creates the conversation for it).
2. **Wire.** TLS via Windows Schannel (SNI `substrate.office.com`, cert chain
   validated against the Windows trust store via `SCH_CRED_AUTO_CRED_VALIDATION`),
   plain WebSocket
   client (masked frames, ping/pong, fragmented frames, 16/64-bit lengths) with
   the SignalR JSON hub handshake + `chat` stream invocation. Replies are parsed
   from the `messages` array of `type:1` frames (last message text wins) and the
   completion `result.message` of `type:2`/`type:3` frames (suggestion texts,
   which nest deeper, are ignored). `\uXXXX` incl. surrogate pairs decode to
   UTF-8.
3. **Bootstrap when M365Copilot is not running.** Finds the interactive session
   owned by the current user (WTS), then starts M365Copilot there **invisibly**:
   - fast path: borrow that session's user token (`DuplicateTokenEx`) +
     `CreateProcessWithTokenW` (ensures the Secondary Logon service is up);
   - fallback: Task Scheduler COM (`TASK_LOGON_INTERACTIVE_TOKEN`, task is
     deleted again once a session materializes);
   - a `--launch-hide` instance of this same exe (GUI subsystem, so no console)
     activates the app's AUMID and hides every window it creates via out-of-
     context WinEvent hooks + a 500 ms `EnumWindows` backstop.

## Gates

`build.sh` compiles with `-std=c89 -Wall -Wextra -Werror -O2` and runs
`clang-tidy` (bugprone/cert/misc/clang-analyzer/concurrency/portability/
performance; `misc-include-cleaner` disabled — umbrella `windows.h` is the
canonical Win32 pattern).

## Verified

- Over SSH as `steve-user` on a Win11 VM: app running or not; correct replies
  for multiple independent prompts; exit 0; stdout-only channel confirmed with
  `2>nul`.
- Across full machine restarts: fresh boot with no M365Copilot running ->
  hidden launch (verified `VISIBLE_WINDOWS=0` for the app's process) -> fresh
  tokens harvested -> coherent reply, every artifact re-resolved at run time.

## Environment note

The verified flow assumes an interactive logon session exists for the target
user (any packaged WinUI app requires one). For autonomous bring-up on the test
VM, `AutoAdminLogon` was configured for the console session.
