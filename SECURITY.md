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

Stop both endpoints before rotating the pre-shared key. Run `agentpantry keygen`
on one endpoint, copy the new key file to the peer over a secure channel, confirm
both files are mode `0600`, then restart both endpoints. `keygen` backs up an
existing key by default before replacing it.
