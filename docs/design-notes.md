# Design notes

The original overview and comparison sections from the README. Back to the [README](../README.md).

## What it does

| | Job | What you get |
|---|---|---|
| **Select** | What leaves the daily driver | Allowlisted domains and named secrets only |
| **Seal** | AES-256-GCM end to end | Replay-protected frames. Nothing moves until you opt in |
| **Sync** | Source machine to agent host | Cookies and auth state land where the agent runs |
| **Watch** | Expiry and health | Doctor and status. Brigade pantry station wires checks |

## How it works

agentpantry is a single binary that takes on one of two roles, chosen by
subcommand.

The source runs on your daily driver. It watches the Chromium cookie store for
changes, copies the locked SQLite file to a temporary path, and decrypts each
value using the keyring passphrase from the freedesktop Secret Service (falling
back to Chromium's fixed "peanuts" key when no keyring is present). The
decrypted cookies are normalized into a snapshot, filtered through your domain
allow/deny policy, and diffed against the last snapshot so only changes move.
Each diff is JSON-encoded, sealed in an AES-256-GCM frame carrying a monotonic
replay counter, and written length-prefixed onto a stream.

The sink runs on your agent's machine. It opens each frame, rejects any frame
whose counter is not strictly greater than the last accepted one, and applies
the diff to its configured surfaces. The default sink surface is a plaintext
sidecar SQLite database that holds the current cookie set. Opt-in surfaces and
adapters can also write secrets, browser stores, Netscape cookie files, GitHub
CLI auth, OpenClaw provider profiles, and a Hermes Agent bundle.

### Source-to-sink flow

<p align="center"><em>The generated source-to-sink plate in the README is rebuilt from <code>docs/assets/workflows/source-sink.json</code>.</em></p>

The transport is just a byte stream, so the link can be a TCP connection over a
trusted network or a piped stdio channel through a tunnel. The encryption and
framing do not care which.

## Why not something else?

- **A password manager or secret vault** (1Password, Bitwarden, Vault) stores
  credentials and hands them out on request. Agent Pantry does not store your
  logins. It mirrors live browser session state and named secrets from a machine
  where you are already logged in to the machine your agent runs on, so tools
  that read local cookie stores and config files wake up authenticated.
- **A hosted session or cookie service** runs in someone else's cloud and asks
  you to trust their storage. Agent Pantry is a single local Go binary with no
  daemon and no server: it moves bytes between two machines you control over a
  link you choose, and the encryption and framing do not care whether that link
  is a LAN socket, a VPN, or stdio piped over SSH.
- **Committing cookies and tokens into dotfiles** (or pasting a token into an
  agent's config) drifts the moment a session refreshes and tends to leak the
  value into git history, logs, and shell history. Agent Pantry re-syncs on file
  events and a timer, sends only the diff, never logs values, and seals every
  frame with a replay counter so a captured frame cannot be replayed into another
  session.
- **Each agent harness reinventing auth** means every runtime grows its own
  glue. Agent Pantry writes the native files Codex, Claude Code, OpenClaw,
  Hermes Agent, the GitHub CLI, and curl-family tools already read, so the
  harness needs no Agent Pantry awareness.
