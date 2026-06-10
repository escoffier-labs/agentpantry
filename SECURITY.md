# Security Policy

## Supported versions

agentpantry is pre-1.0. Security fixes land on the latest `master`; there are no
backported release branches yet.

## Reporting a vulnerability

Please report suspected vulnerabilities privately via a GitHub security advisory
on this repository ("Report a vulnerability" under the Security tab) rather than
opening a public issue. Include a description, affected version or commit, and a
reproduction if you have one. We aim to acknowledge reports promptly and will
coordinate a fix and disclosure timeline with you.

## Posture summary

agentpantry moves your own authenticated browser sessions and secrets between
your own machines over a channel encrypted and authenticated with a pre-shared
key (AES-256-GCM, per-session key derived via HKDF). It is an operator tool, not
a password manager: secrets pass through and land on the sink in the surfaces you
enable. See [docs/threat-model.md](docs/threat-model.md) for what the design does
and does not protect, and the operator responsibilities that the guarantees
depend on.

## Release artifacts

Tagged GitHub releases include platform archives, SHA-256 checksums, a source
SPDX SBOM, and GitHub artifact provenance attestations. Verify downloaded
archives against `checksums.txt` before installing them.

## Key rotation

Rotate the pre-shared key with `agentpantry rotate-key`; no sync downtime is
needed. Run it on the sink: it writes a fresh `psk.key`, keeps the previous key
beside it as `psk.key.old`, and accepts connections under either key during the
grace window (the new key is tried first, and old-key sessions are logged).
Copy the new `psk.key` to the source over a secure channel, restart the source
or let it reconnect, then run `agentpantry rotate-key -finish` on the sink to
retire `psk.key.old`. Finish promptly: until `-finish`, a holder of the old key
is still accepted. `doctor` and `status` both show a rotation in progress.

`agentpantry keygen` remains the stop-the-world alternative (the sink accepts
only the new key from that moment on, so stop both endpoints first); it backs
up an existing key as `psk.key.bak.<timestamp>` by default. If a rotation was
prompted by suspected key exposure, delete any `psk.key.bak.*` files on both
machines once the rotation is complete: they are live PSK history.
(`rotate-key -finish` already removes its own `psk.key.old`.)
