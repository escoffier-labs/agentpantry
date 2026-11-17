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

## 1Password service account

Use a dedicated read-only service account granted access to one dedicated vault.
Every vault readable by the token is in its blast radius. The tag selects items
inside that vault. It does not restrict the token's authority.

Install 1Password CLI 2.18.0 or later. Store the service-account token in a private
regular file owned by the running user, with no group or other permission bits
on Unix. On Windows, grant access only to the current user, SYSTEM and
Administrators. Do not put the token in TOML, command arguments or the parent's
environment.

```toml
[onepassword]
vault = "Agent Pantry"
tag = "agentpantry"
token_file = "~/.config/agentpantry/op-token"
field = "password"
op_path = "/usr/bin/op" # optional, otherwise resolved once from PATH
poll_seconds = 300
max_items = 200
max_value_bytes = 65536
```

All 8 keys are case-sensitive. Unknown keys and blank required strings fail
configuration loading. Polling has a minimum of 60 seconds. If `resync_seconds`
is 0, the source timer uses `poll_seconds`. File events and faster source timers
serve the cached inventory until the next poll deadline.

The CLI path is resolved once to an absolute canonical regular file. On Unix,
the binary and all its parent directories must have no group or other write
bits. Windows checks ACLs for write grants. Each execution checks file identity,
size and modification time against the pinned binary. An upgrade requires a
source restart.

A poll resolves the vault to an ID and pins it for the reader's lifetime. It
lists that whole vault, matches exact tag elements locally, and fetches the
configured field only for new or changed item versions. Item titles become
secret names under the existing deny-wins `[secret_names]` policy. Missing or
ambiguous fields, invalid names, duplicate titles, list/get failures and limits
fail the whole read. Cross-source name collisions suppress the secret diff.
The sink retains its previous secrets on failures.

During one uninterrupted 1Password reader lifetime, an absent name is deleted
only after 2 independently successful polls. Cached
reads do not confirm a deletion. Renaming a title exports the new name while
retaining the old value until the second successful absence confirms its delete.
An empty selected set after a non-empty successful poll fails the reader and
keeps all prior secrets. The diagnostic names the vault ID and tag. An empty
first poll is allowed. To deliberately remove everything, remove the
`[onepassword]` section and restart the source with the same config/state path.
The next successful secret read sends explicit deletes for its persisted names.
If another item claims a name still held by an absent
item, the old value stays exported until the second successful absence confirms
release of the name. Duplicate titles in a single selected set still fail.
Rate limits fail the read and defer another attempt for one poll interval.

Each call has a 20-second timeout. A whole poll has a 120-second timeout.
Stdout is capped at 4 MiB and stderr at 64 KiB. Values default to 64 KiB each.
The complete retained inventory must stay below 4 MiB, including JSON encoding.
`max_items` counts the whole vault, including unselected items. Its maximum is
10,000. `max_value_bytes` cannot exceed 4 MiB. `poll_seconds` cannot exceed 86,400.

`doctor` checks the binary, version, token file and live vault inventory, and
reports the tagged item count without fetching field values. It warns when the
source timer default applies and when the selected set is empty. It reports the
whole vault item count against `max_items`. `source --dry-run` discloses the vault,
tag and field, with `token_file: configured` and `op_path: configured|auto`.
It omits token and binary paths, does not open the token file, and never runs `op`.
On Windows a rejected token diagnostic includes exact PowerShell `icacls.exe`
commands to reset the ACL and restrict access to the current user. Owners may
be the current user, SYSTEM or BUILTIN\Administrators. The DACL may grant access
only to those principals.

## Secret removal across restarts

The source's existing `state.json`, beside the resolved config file, stores a
sorted `exported_secrets` list. It contains names only, never secret values, and
is written atomically with mode 0600. Keep that state path when restarting a
source or editing its configuration.

After a successful secret read and successful frame write, the source records
the complete set of names it exported. On restart or reconnect, it loads those
names as a deletion baseline while keeping the value snapshot empty. Every
currently produced secret is resent as an upsert, including an empty value.
A previously exported name that no reader now produces becomes an explicit
sink delete. This applies to removing `secrets_dir`, KeePass or `[onepassword]`
from the configuration, and to untagging individual entries. The 1Password
empty-selection rule still applies while that section remains configured.

Reader errors and cross-source collisions retain the previous names and send
no secret deletes. A missing state file is a clean first run. An unreadable or
corrupt state file produces a warning and supplies no deletion baseline. It is
rewritten only after a fully successful secret read. If a frame is needed, its
write must succeed first. State-write failures are reported as sync errors.

Older state files contain no exported names. Complete a successful sync with
this version before removing a source. Without a readable names baseline, the
source cannot identify old sink secrets for deletion. Reader caches and
absence-confirmation counters remain in memory. After restart, a fully
successful read reconciles the persisted names directly. Cookie and secret values
are never restored from this state file.
