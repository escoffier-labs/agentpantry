# Proposal: ephemeral env injection (`agentpantry run -- <cmd>`)

Date: 2026-08-08
Issue: [#51](https://github.com/escoffier-labs/agentpantry/issues/51)
Status: **proposal / not approved for implementation**

## Summary

Add a sink-side wrapper that loads already-synced named secrets into a child
process environment for the lifetime of that process, then exits. Pattern from
1Password CLI `op run`: secrets stay memory-only for the invocation and are not
staged to a temporary file first.

Today the sink's `secrets` surface writes each secret as a `0600` file under
`secrets_dir` (`internal/surface/secretdir.go`). That is correct for tools that
must read files, but it leaves high-value material on disk after the agent
session. `agentpantry run` is the least-privilege alternative for command-line
consumers: inject, exec, discard. It directly supports per-session access and is
preferred over any local secret-serving API (see issue #54), because it reduces
disk and network exposure instead of adding a listening socket.

Deny-wins `[secret_names]` policy must still apply to what is injected. An empty
allow continues to mean "all names present in the synced secret set" (the
`secrets_dir` / KeePass opt-in already happened on the source), and an explicit
deny always wins (`internal/policy/names.go`).

## Threat model

Reference: `docs/threat-model.md`.

### What changes

- New retrieval path on the sink: secrets move from the local secret store into
  a child process environment for one invocation.
- No new network listener. No change to transport handshake, PSK lifecycle, or
  frame crypto.
- Optional reduction of disk residency if operators stop writing a permanent
  `secrets` surface for names that only need env injection (design choice; see
  open questions).

### Newly exposed

- Any local process that can `ptrace`, read `/proc/<pid>/environ`, or otherwise
  inspect the child while it runs can see the injected values. That is the same
  class of risk as any env-based secret tool; document it.
- The wrapper process itself briefly holds secret bytes in memory. Zeroization
  is already listed as **not implemented** in the threat model for PSK/session
  keys; the same honesty applies here.
- Misconfigured allow lists still sync secrets to the sink; `run` only
  re-filters what it injects. It does not shrink what already landed on disk via
  the `secrets` surface.

### Operator responsibilities

- Prefer `run` over writing secrets to disk when the consumer can take env vars.
- Keep `[secret_names]` deny-wins tight; do not add bypass flags.
- Do not log child argv in a way that echoes secret values (names are fine;
  values never).
- Treat the sink host as a secret store still: a compromised sink account sees
  whatever was synced, whether via files or env.

### Threat-model doc updates (when approved)

A future implementation PR should add a short subsection under "What is
protected" / "Not protected" covering ephemeral env injection: memory-only for
the child lifetime, no network surface, residual `/proc` and ptrace exposure,
and the relationship to the on-disk `secrets` surface. This feature does **not**
require an AGENTS.md handshake rewrite; it is not a transport change.

## Interface sketch

No code in this proposal. Shape only.

### CLI

```text
agentpantry run [flags] -- <command> [args...]
```

Suggested flags (names open to bikeshed):

| Flag | Intent |
|---|---|
| `--config PATH` | Sink config (same default as other subcommands). |
| `--secret NAME` | Inject only these names (repeatable). If omitted, inject every synced name that passes `[secret_names]`. |
| `--env NAME=ENVVAR` | Map secret `NAME` to environment variable `ENVVAR` (repeatable). Default: uppercase sanitized secret name. |
| `--from-dir PATH` | Optional override of where to read secret files (default: sink `secrets_dir`). Needed if secrets were written by the existing surface. |
| `--dry-run` | Print which env vars would be set (names only), then exit without exec. |

Behavior:

1. Load sink config and `[secret_names]` policy.
2. Resolve the secret set from the sink secret store (initially: files under
   `secrets_dir` already written by the `secrets` surface; a later iteration may
   read an in-memory or sidecar-backed store if one exists).
3. Filter by deny-wins policy and any `--secret` allowlist.
4. Build an env block; never write values to a temp file.
5. `exec` (or spawn-and-wait) the command with that env; exit with the child's
   status.
6. On any policy or I/O error before exec, fail closed with nonzero status and
   no partial injection.

### Non-goals for v1

- Serving cookies or localStorage via env.
- A daemon that keeps secrets resident between runs.
- Replacing the `secrets` surface (it remains for file-consuming tools).

## Open questions

1. **Source of truth for values:** must `run` require the on-disk `secrets`
   surface first, or should it read from a sidecar / internal store so operators
   can disable file writes entirely?
2. **Exec vs spawn:** prefer `syscall.Exec` (replace process) or spawn-and-wait
   (preserve wrapper for status / cleanup messaging)?
3. **Name-to-env sanitization:** exact rules for characters that are legal secret
   names but illegal in env var names.
4. **Overlap with #54:** confirm product guidance that `run` ships before any
   loopback API, and that docs steer agents toward `run` by default.
5. **Windows:** `/proc` exposure notes differ; confirm env inheritance and ACL
   expectations for the Windows build.

## Status

**proposal / not approved for implementation.** Design discussion and maintainer
sign-off on the open questions come before any code.
