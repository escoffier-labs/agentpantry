# Key management and pairing

Session handshake, short-code pairing, and pre-shared key rotation. The threat-model view of the same material is in [threat-model.md](threat-model.md). Back to the [README](../README.md).

## Hardening

The transport begins each connection with a session-salt handshake (the sink
issues a fresh random salt over TCP, the source issues it over `--stdio`) and
derives a per-session AES-256 key from the pre-shared key via HKDF, so a frame
captured from one session cannot be replayed into another.

### Pairing with a short code

`agentpantry pair` is an additive setup mode that bootstraps `psk.key` so you
do not have to copy the 64-hex file by hand. It does not replace the
session-salt handshake or HKDF session keys.

    # on the sink (prints a one-time XXXX-XXXX code and waits)
    agentpantry pair --role sink [--bind 127.0.0.1:8787] [--config PATH]

    # on the source (same code, out of band)
    agentpantry pair --role source --code ABCD-EFGH --peer 127.0.0.1:8787

Compare the `confirmation:` fingerprint printed on both ends before the first
sync. The pairing listener defaults to `127.0.0.1:8787` and does not inherit
the sink config `peer` (that field is the sync bind and is often
`0.0.0.0:8787`). Pass `-bind` to listen elsewhere. A non-loopback or empty-host
address (`:8787`) prints a warning. The listener is short-lived (two minutes,
three failed SPAKE2 code attempts, at most four concurrent exchanges) and
should stay on loopback or a trusted private network. Treat the code as a
one-time password. Re-pairing backs up an
existing key like `keygen`. Use `rotate-key` for zero-downtime rotation.
Pairing refuses to start while a rotation grace file (`psk.key.old`) exists.
Manual `keygen` plus a secure copy remains supported.

Secret syncing can be
narrowed with a `[secret_names]` allow/deny policy (exact names, deny overrides
allow, an empty allow permits everything in the `secrets_dir`). `make gosec`
runs the security scanner, `make vuln` runs govulncheck, and
`make fuzz PKG=... FUZZ=...` runs the fuzz targets for the untrusted-input
parsers.

### Rotating the pre-shared key

`agentpantry rotate-key` rotates the key with no sync downtime. Run it on the
sink: it writes a fresh `psk.key` and preserves the previous key beside it as
`psk.key.old`. The sink accepts new connections under either key (and logs a
warning when a peer still uses the old one), so the source keeps syncing while
you distribute the new key:

    agentpantry rotate-key            # on the sink
    # copy the new psk.key to the source over a secure channel
    # restart the source, or let it reconnect
    agentpantry rotate-key -finish    # on the sink, retires psk.key.old

Key path resolution, in order: `-key` when set, else `key_path` from
`-config` when that file exists and sets one, else the config dir's
`psk.key`. Pass `-key` when you generated the file with `keygen -out`
and it is not the path in config. The same `-key` applies to `-finish`.
It only selects the file and does not change the dual-key grace window.

`doctor` and `status` show a rotation in progress, and a running sink picks up
the rotation without a restart. Finish promptly: until `-finish`, a holder of
the old key is still accepted. `keygen` remains the blunt instrument. It backs
up an existing key beside itself as `psk.key.bak.<timestamp>` before replacing
it (pass `--backup=false` to skip that), but unlike `rotate-key` the sink
accepts only the new key from that moment on. After replacement, stop existing
sink sessions (or close their connections), distribute the new PSK to peers,
then restart persistent sources. They load the key once at startup, so a
running source keeps sealing with the old key until restarted. Delete
`psk.key.bak.*` files once a rotation is confirmed, especially one prompted by
suspected key exposure: they hold retired key material.
