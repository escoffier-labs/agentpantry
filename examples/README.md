# Agent Pantry Examples

These examples are starting points. Copy the one closest to your setup into
`~/.config/agentpantry/config.toml`, edit paths and domains, then run
`agentpantry doctor` before starting the source or sink.

Use the same `psk.key` on both machines. Generate it on one side with
`agentpantry keygen`, copy it over a secure channel, and keep it mode `0600`.

## Files

- `source-chromium.toml`: Linux Chromium-family source.
- `source-firefox.toml`: Firefox source.
- `source-cdp.toml`: Chrome DevTools Protocol source for app-bound Chrome.
- `source-local-none.toml`: source-side doctor config for local script-driven captures.
- `sink-hermes.toml`: Sink with the default sidecar plus a Hermes Agent bundle.
- `sink-gh-openclaw.toml`: Sink adapters for GitHub CLI and OpenClaw.
- `stdio-ssh.md`: Source-to-sink transport over SSH stdio.
