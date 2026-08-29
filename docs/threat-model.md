# agentpantry threat model

agentpantry mirrors a user's own authenticated browser sessions and secrets from
a source machine to a sink machine they also control. This document states what
the design protects, what the operator must do for those guarantees to hold, and
what is explicitly out of scope.

## What is protected

- **Channel confidentiality, integrity, and authentication.** Every frame is
  AES-256-GCM. Both ends load the same pre-shared key (`keygen`, stored `0600`).
  An attacker on the network path cannot read, modify, or forge frames without
  the key.
- **Cross-session replay.** Each connection begins with a random session salt; the
  per-session AES key is derived via HKDF(preSharedKey, salt). A frame captured
  from one session fails authentication on another. Over TCP the sink issues a
  fresh salt per connection, so an attacker cannot force salt reuse.
- **In-session replay / reordering.** A monotonic per-frame counter (bound as AEAD
  additional data) is rejected if it does not advance.
- **Opt-in scope.** Cookies sync only for domains in the allow list (empty allow
  = nothing). Secrets sync only from the configured `secrets_dir`, optionally
  narrowed by a secret-name allow/deny policy.
- **localStorage is opt-in and narrow.** `localStorage` capture is off by
  default, enabled per browser with `capture_localstorage` on a `kind = "cdp"`
  source only (disk profiles cannot be read safely while the browser holds the
  lock). Each item's origin is checked against the same deny-wins domain allow
  list before it is captured or sent, and a non-http(s) origin is dropped.
  Values are session secrets and are never logged, on either end or in CDP error
  text.
- **On-disk perms.** The pre-shared key, plaintext sidecar, secret files,
  receipt logs, and adapter outputs are `0600`; directories `0700`.
- **Sync receipts attest event and digest, not confidentiality.** When
  `[receipts]` is enabled, each successful send or apply appends one JSON line
  with timestamp, this node's configured identity (default: hostname), event
  type, a value-free payload digest, a monotonic `seq`, the previous receipt
  hash, and an HMAC derived from the PSK. A `0600` tip file beside the log
  (`receipts.head`) stores the last seq and hash so a deleted or truncated log
  fails `receipts verify`. The transport is PSK-only: identity is asserted by
  the writer, not proven (`source_id` and `sink_id` both name this node). Receipts never contain cookie values, secret values,
  or localStorage values. They do not authenticate against a compromised
  signer key, and they do not keep synced material confidential. `payload_hash`
  is hashed, not confidential: hosts and secret names in the summary are
  guessable by recomputation.
- **Desktop app targets fail closed.** `desktop-app=codex|claude --dry-run`
  reads profile, lock, and cookie-path metadata only. It does not open the app's
  cookie database. Actual restore and read-back verification are rejected until
  agentpantry has a supported injection bridge or can prove that the app is
  stopped, its schema and encryption are compatible, a private backup can be
  made, and read-back verification is available. The refusal directs the
  operator to stop the app, inspect with `--dry-run`, leave the profile
  unchanged, retain the sidecar, and use an existing supported target.
- **Ephemeral env injection is memory-only for one child.** `agentpantry run`
  loads already-synced named secrets into memory, re-filters them with
  deny-wins `[secret_names]`, and starts one command with those values in the
  environment. It never writes values to a staging file and adds no network
  listener. Loader and interpreter variables (`PATH`, `LD_PRELOAD`,
  `NODE_OPTIONS`, `PYTHONPATH`, and similar) are refused so a synced name
  cannot hijack the child. On Unix, SIGINT and SIGTERM to the wrapper are
  forwarded to the child so a signaled wrapper does not leave a secret-bearing
  process running. On Windows, signals are not forwarded. Handshake, PSK, and
  frame crypto are unchanged.

## Operator responsibilities

These are required for the guarantees above to hold:

- **Bind the sink to loopback** (`127.0.0.1`) or to a trusted private network
  (for example a VPN such as Tailscale/WireGuard or an SSH tunnel). The default
  is loopback; `doctor` and `agentpantry sink` startup both warn on a wider
  bind.
- **Keep the pre-shared key secret.** Anyone with the key can send frames to the
  sink. Copy it over a secure channel and keep it `0600`.
- **Treat a CDP debugging port as sensitive.** `kind = "cdp"` requires launching
  Chrome with `--remote-debugging-port`, which grants full browser control to
  anything that can reach it; bind it to loopback only.
- **Prefer `run` over disk when the consumer can take env vars.** Keep
  `[secret_names]` deny-wins tight; `run` has no bypass flags. Do not log child
  argv in a way that echoes secret values (names are fine). A compromised sink
  account still sees whatever was synced, whether via files or env.

## Key lifecycle checklist

One consolidated pass over the transport pre-shared key (PSK) and its derived
session keys, from creation to retirement. Each row states what the code
actually does today. Where a property is not implemented, the row says so
instead of implying it. This checklist covers transport keys only. Browser and
vault keys (the Secret Service passphrase or "peanuts" fallback for Linux
Chromium, the DPAPI-unwrapped AES key from `Local State` on Windows, the 0600
key file for a KeePassXC-backed secret store) are separate key material with
their own lifecycles and are out of scope here.

| Stage | What the code does | Operator action |
|---|---|---|
| **PSK generation** | `agentpantry keygen` writes a random 32-byte key (`crypto/rand`) as 64 hex chars to `psk.key` (default `$XDG_CONFIG_HOME/agentpantry/psk.key`, or `~/.config/agentpantry/psk.key` when `XDG_CONFIG_HOME` is unset), mode 0600, via an atomic same-directory temp-file write that refuses symlinked paths. With `--backup` (the default) an existing key is first copied to `psk.key.bak.<UTC timestamp>`, also 0600. (`internal/keyfile`, `internal/privfile`, `cmd/agentpantry`) | Generate on the sink, then copy the file to the source over a secure channel. Both ends load the same file. |
| **File permissions** | Key, old-key, and backup files are created with mode 0600 (the temp file is created 0600, then renamed, with no window at a looser mode). Parent directories are created 0700. On non-Windows, `Load` rejects a key file whose mode grants any group/other bits, checked on the open descriptor. Windows does not enforce Unix 0600 semantics, and the load-time mode check is skipped there. (`internal/keyfile/keyfile.go`) | Keep the key at 0600 and off shared storage. `doctor` verifies that the key exists and is 32 bytes, plus mode 0600 on non-Windows. |
| **Rotation window** | `agentpantry rotate-key` (sink) preserves the current key at `psk.key.old` (0600) and writes a fresh key. A second rotation is refused while one is in progress. The sink re-reads the key files per connection, so a running sink picks up the rotation without a restart and accepts new connections under either key. It tries the new key first, and the first authenticated frame pins the session to that key. An old-key session logs a warning. `rotate-key -finish` deletes `psk.key.old` and ends the window. (`internal/keyfile`, `internal/transport/fallback.go`, `cmd/agentpantry`) | Finish promptly: until `-finish`, a holder of the old key is still accepted. `doctor` and `status` show a rotation in progress. |
| **Session-key lifetime** | Each connection opens with a fresh random 16-byte salt. Over TCP the sink issues it, while over `--stdio` the source does. The connection derives a per-session 32-byte AES-256-GCM key via HKDF-SHA256(PSK, salt, info `"agentpantry/v1 session"`). The key lives only inside that connection's sealer/opener and is dropped when the connection closes. A new connection means a new salt and a new key. During a rotation both candidate session keys are derived from the same salt. (`internal/transport/handshake.go`, `envelope.go`) | None. Never make the salt static or reuse a session key. |
| **Zeroization** | **Not implemented.** Neither the PSK, the derived session keys, nor browser/vault keys are overwritten in memory. They are ordinary Go byte slices released to the garbage collector when no longer referenced. There are no zeroize/wipe calls in the codebase. | Do not rely on memory scrubbing. Protect key material at rest (0600, host access control) and assume key bytes may persist in process memory while the process runs. |
| **Recovery** | There is no escrow or recovery path for a lost PSK. `keygen` on the sink is the blunt recovery path: stop or close existing sink sessions, redistribute the replacement PSK, then restart persistent sources (they load the key once at startup). Unlike `rotate-key`, the sink accepts only the new key from that moment, so sources still holding the old key stop authenticating. (`cmd/agentpantry`, README "Rotating the pre-shared key") | On suspected exposure, prefer `rotate-key` for zero-downtime rotation, finish it promptly, and delete any `psk.key.bak.*` files: they are live retired key material. |

Explicit limitations that follow from the above (detailed in the tradeoffs
section below): no forward secrecy, because the PSK is long-lived. Old-key
acceptance lasts for the rotation grace window. `--stdio` gets session
separation from the salt but relies on the surrounding channel (for example
SSH) for replay protection. Retired key material on disk (`psk.key.old`,
`psk.key.bak.*`) stays sensitive until the operator deletes it.

## Not protected / tradeoffs

- **The plaintext sidecar is cleartext at rest** on the sink. Treat the sink as a
  secret store; restrict access to the sink account. The real-Chrome re-encrypt
  surface avoids cleartext cookies but the secrets and adapter outputs may still
  be cleartext on disk by design (tools need to read them).
- **Enabling `localStorage` capture widens what leaves the source browser.** When
  turned on, a broader class of in-browser secrets (auth tokens, refresh tokens,
  device IDs) is mirrored, not just cookies. It is opt-in, off by default,
  CDP-only, and gated by the domain allow list so the blast radius stays
  deliberate. Captured `localStorage` is cleartext at rest in the sidecar and the
  storageState file, like cookies. `sessionStorage`, IndexedDB, service worker
  state, and cache remain out of scope.
- **A compromised source or sink host** sees the synced sessions. agentpantry
  protects the link, not a compromised endpoint.
- **Desktop app detection is heuristic.** The default Codex and Claude profile
  paths follow each OS user-config convention. A Chromium cookie filename does
  not establish encryption compatibility, and an absent Electron singleton
  lock does not prove the app is stopped. The current adapter reports those
  limits and performs no app write.
- **Pre-auth connection slots on the sink.** The sink serves at most 32 concurrent
  TCP connections, each held up to 30 seconds waiting for the first
  authenticated frame before the connection is closed. A peer that can reach the
  bind address without the PSK can occupy all slots for that window and delay
  legitimate sources from connecting. This is a residual availability risk, not a
  confidentiality breach; keep the sink on loopback or a trusted private
  network (see operator responsibilities above).
- **Cookie names and hosts may appear in logs.** The source warns on stderr when
  synced cookies are near expiry (`cookie name@host expires ...`). `inventory
  --json` includes `name` and `host` for near-expiry rows. Cookie values and
  `localStorage` values are never logged. Sync receipts hash identifiers into
  `payload_hash` and store only that digest (`payload_hash` is hashed, not
  confidential). They still leak that a sync happened, when, and the asserted
  local identity.
- **No forward secrecy.** The pre-shared key is long-lived; if it leaks, past
  captured ciphertext from the same key is at risk (the session salt separates
  sessions but is derived from the same long-lived key). Rotation is
  operator-driven via `agentpantry rotate-key` on the sink: it writes a fresh
  key and preserves the previous one beside it, the sink accepts new
  connections under either key, and `rotate-key -finish` retires the old key
  once the source has been updated. During that grace window a holder of the
  old key is still accepted, so finish promptly; `doctor` and `status` surface
  the in-progress state. Rotation does not protect ciphertext already captured
  under the old key. The preserved old-key file is 0600 and removed by
  `-finish`.
- **`--stdio` replay protection relies on the underlying channel.** Over a one-way
  pipe the source issues the salt, which gives session-key separation but not
  standalone replay protection; run it inside an authenticated, integrity-
  protected channel such as SSH.
- **Not a password manager.** Secrets are relayed and written to the surfaces you
  enable; agentpantry is not a vault of record.
- **Ephemeral env injection is visible to local inspectors.** Any local process
  that can `ptrace`, read `/proc/<pid>/environ`, or inspect the child on Windows
  while it runs can see the injected values. The wrapper holds secret bytes in
  memory for the invocation; zeroization is not implemented (same as PSK and
  session keys). `run` does not shrink secrets already written by the on-disk
  `secrets` surface.
