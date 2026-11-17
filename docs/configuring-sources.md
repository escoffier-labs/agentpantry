# Configuring sources and browsers

Detail that used to sit under the README Quickstart: the `[[browsers]]` kinds, Windows notes, app-bound Chrome over CDP, and key setup. For the short path, see the [README Quickstart](../README.md#quickstart).

`init` writes a commented config that walks through each field, including
commented `[[browsers]]` examples for both `chromium` and `cdp` (it refuses to
overwrite an existing config unless you pass `--force`), and `doctor` validates
the result before you rely on it, warning about misspelled or misplaced config
keys instead of ignoring them.

A `[[browsers]]` entry takes a `kind`: `chromium` (Chrome, Chromium, Brave, Edge:
decrypted via the Secret Service with a `peanuts` fallback) or `firefox` (reads
plaintext cookies from the profile's `cookies.sqlite`, so no keyring is needed).
Point `cookie_path` at the profile's cookie store. A source configured with only
Firefox browsers skips the keyring check in `agentpantry doctor`.

On Windows, `kind = "chromium"` decrypts `v10` cookies using the DPAPI-unwrapped
key from the profile's `Local State`. `agentpantry install-service` on Windows
prints a Scheduled Task command (agentpantry is a console app, so it runs as a
logon task rather than an SCM service). A Windows sink supports the sidecar,
secrets, and adapter surfaces, plus the real-Chrome re-encrypt surface described
next.

A Windows sink can also use the real-Chrome re-encrypt surface (`chrome`): it
writes synced cookies into the target Chrome Cookies store as `v10` AES-256-GCM,
encrypted with the sink's own DPAPI-unwrapped key. Use it against a not-running,
pre-app-bound, or dedicated automation profile. An app-bound (version 127+)
profile may prefer `v20`, so v10 writes are best treated as a legacy/automation
path.

For app-bound Chrome (version 127+, `v20` cookies) where the key is no longer
recoverable from `Local State`, use `kind = "cdp"`: launch Chrome with
`--remote-debugging-port=9222` (bound to loopback, ideally a dedicated automation
profile) and set `url = "http://127.0.0.1:9222"` on the browser entry. agentpantry
asks Chrome for the cookies over the DevTools Protocol, so Chrome performs its own
authorized decryption. The debugging port grants full browser control, so keep it
on loopback and treat it as sensitive. A `cdp` reader syncs at startup, on
other browsers' file events, and on the `resync_seconds` poll, which defaults
to 60 seconds for a CDP source when unset. For an operator-export run that
should refresh the sink once and return control to a wrapper, run
`agentpantry source --once`: it reads the CDP source, applies the same policies,
updates source state, closes the connection, and exits 0 after a successful
initial sync.

Both ends must hold the same pre-shared key. Generate it once on the sink with
`agentpantry keygen` and copy the file to the source, or bootstrap it with
`agentpantry pair` (SPAKE2 short code: compare the printed confirmation
fingerprint on both ends before the first sync). Run `agentpantry status`
on either machine to print the active role, peer, key path, surfaces, and the
configured allow/deny domains. To run the source or sink as a persistent
background service, use `agentpantry install-service`, which writes a systemd
user unit and prints the commands to enable it.

The `examples/` directory has copyable source and sink configs for Chromium,
Firefox, CDP, local script-driven captures, Hermes Agent, GitHub CLI, OpenClaw,
and SSH stdio transport.
