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
- **On-disk perms.** The pre-shared key, plaintext sidecar, secret files, and
  adapter outputs are `0600`; directories `0700`.
- **Desktop app targets fail closed.** `desktop-app=codex|claude --dry-run`
  reads profile, lock, and cookie-path metadata only. It does not open the app's
  cookie database. Actual restore and read-back verification are rejected until
  agentpantry has a supported injection bridge or can prove that the app is
  stopped, its schema and encryption are compatible, a private backup can be
  made, and read-back verification is available. The refusal directs the
  operator to stop the app, inspect with `--dry-run`, leave the profile
  unchanged, retain the sidecar, and use an existing supported target.

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
