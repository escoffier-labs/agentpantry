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
