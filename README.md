# agentpantry

Keep your agent's machine authenticated. agentpantry mirrors authenticated
browser sessions from your daily-driver (source) to the machine your agent runs
on (sink), encrypted over any reachable network path, so your agent runtime
wakes up logged in.

Cross-platform reimagining of agentcookie. Phase 1 supports Linux Chromium on
both ends.

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
the diff to its surfaces. Phase 1 ships one surface: a plaintext sidecar
SQLite database that holds the current cookie set.

```
daily driver (source)                          agent machine (sink)
---------------------                          --------------------
Chromium Cookies DB
        |
   decrypt + normalize
        |
   domain allow/deny filter
        |
   diff vs last snapshot
        |
   AES-256-GCM seal  --- TCP or stdio --->  open + replay check
                                                    |
                                              apply diff
                                                    |
                                            plaintext sidecar SQLite
```

The transport is just a byte stream, so the link can be a TCP connection over a
trusted network or a piped stdio channel through a tunnel. The encryption and
framing do not care which.

## Quickstart

### On the sink (agent machine)
    agentpantry init --role sink
    agentpantry keygen
    # copy ~/.config/agentpantry/psk.key to the source machine
    # edit config.toml: set peer to the bind address, e.g. 0.0.0.0:8787 over your VPN
    agentpantry sink

### On the source (daily driver)
    agentpantry init --role source
    # copy the psk.key from the sink into ~/.config/agentpantry/psk.key
    # edit config.toml: set peer to the sink address, add a [[browsers]] block and allow domains
    agentpantry source

Both ends must hold the same pre-shared key. Generate it once on the sink with
`agentpantry keygen` and copy the file to the source. Run `agentpantry status`
on either machine to print the active role, peer, key path, surfaces, and the
configured allow/deny domains. To run the source or sink as a persistent
background service, use `agentpantry install-service`, which writes a systemd
user unit and prints the commands to enable it.

## Security

- Domains are opt-in. Nothing syncs until you add it to `domains.allow`. An
  empty allow list permits nothing, and a `domains.deny` entry overrides any
  allow match.
- The sidecar SQLite is plaintext, mode 0600. Treat the sink like a secret
  store: anyone who can read that file can impersonate the synced sessions.
- The pre-shared key file is written 0600 and must be kept off shared storage.
- Cookie values are never logged. They live only in memory, in the encrypted
  frames on the wire, and in the sidecar.
- Transport is AES-256-GCM with a shared key; run it over Tailscale, Twingate,
  a LAN you trust, or an SSH tunnel.

## Status

Phase 1 (v0.1). Roadmap: real-Chrome re-encrypt surface, secrets bus, per-CLI
adapters, Firefox, Windows.
