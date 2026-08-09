# Proposal: loopback token-authenticated read-only secret API

Date: 2026-08-08
Issue: [#54](https://github.com/escoffier-labs/agentpantry/issues/54)
Status: **proposal / not approved for implementation**

## Prefer #51 first

**Ship ephemeral env injection ([#51](https://github.com/escoffier-labs/agentpantry/issues/51) /
`docs/proposals/2026-08-08-ephemeral-env-injection.md`) before this API.**
`agentpantry run -- <cmd>` reduces disk and network exposure. A listening secret
API adds a retrieval surface on the sink. Issue #54 and operator experience both
say: prefer env injection; only add `serve` when agents truly need on-demand
HTTP reads that `run` cannot cover.

## AGENTS.md gate (blocking)

This feature opens a new secret-retrieval surface. Before implementation:

1. Add a dedicated entry to `docs/threat-model.md` covering the serve surface,
   token lifecycle, loopback bind, and residual risks (including agent abuse of
   an unprotected local endpoint).
2. Obtain **explicit maintainer / operator sign-off** per `AGENTS.md` security
   invariants and the issue gate text.

**Do not start implementation without that sign-off.** This proposal is not that
sign-off. (Handshake/PSK invariants are unchanged, but the threat model and
operator contract still must be rewritten for the new surface.)

## Summary

Add an opt-in `sink serve` (name TBD) subcommand that exposes already-synced
named secrets over a **loopback-only**, **per-invocation-token-authenticated**,
**read-only** HTTP API for on-demand agent retrieval. Pattern from Bitwarden CLI
`bw serve`.

Hard mandates if accepted:

- Bind loopback only (reject non-loopback binds; warn/fail like sink peer bind
  hygiene).
- Token auth on every secret-bearing response; token is per serve invocation
  (or short-lived), not a long-lived global API key checked into agent configs.
- Read-only: no write, delete, or config mutation via the API.
- Deny-wins `[secret_names]` enforcement on every lookup (same
  `internal/policy/names.go` contract as sync).
- Threat-model entry before merge of implementation.

## Threat model

Reference: `docs/threat-model.md` (plaintext sidecar / secrets at rest on sink;
compromised endpoint; loopback bind operator duty).

### What changes

- New local HTTP listener on the sink process (or a dedicated serve process)
  that can return secret **values** to any client that presents the token and
  can reach the loopback port.
- No change to transport handshake, session salt, or HKDF.
- Widens sink retrieval options beyond files (`secrets` surface) and beyond
  proposed `run` env injection.

### Newly exposed

- **Local HTTP secret oracle.** Anything on the sink that learns the token and
  port can exfiltrate permitted secrets. Agents, malware, and other local users
  in shared multi-user setups are in scope for the abuse case the issue calls
  out.
- **Token leakage** via process listings, agent prompts, shell history, or log
  lines if operators paste the token into durable config.
- **Metadata via API errors / list endpoints** (secret names enumeration) if a
  list route exists.
- Residual: loopback is not a full isolation boundary on all OS configurations
  (e.g. other local principals); document that.

### Operator responsibilities

- Prefer `#51` `run` when it suffices.
- Never bind serve off loopback; never disable token auth.
- Treat the per-invocation token as a session secret: print once, pass via env
  to the agent, do not commit it.
- Keep `[secret_names]` deny-wins tight; empty allow still means all synced
  names in the store.
- Stop the serve process when the agent session ends.
- Restrict sink login access; compromised sink account defeats loopback + token.

### Required threat-model updates (before implementation)

Must document:

- New "local secret HTTP API" surface: loopback, token, read-only, deny-wins.
- Explicit comparison to `run` (lower exposure) and on-disk `secrets` surface.
- Token generation, display, lifetime, and revocation (process exit).
- Agent-abuse residual risk and why unauthenticated local endpoints are
  forbidden.
- Logging rules: never log token or secret values; names only if necessary.

## Interface sketch

No code. Shape only.

### CLI

```text
agentpantry sink serve [--config PATH] [--bind 127.0.0.1:PORT]
```

On start:

1. Refuse bind addresses that are not loopback.
2. Generate a high-entropy token; print it once to stderr (or a dedicated fd),
   never to the receipt log or status JSON.
3. Listen; serve until SIGINT/SIGTERM.

Suggested routes (read-only):

| Method | Path | Behavior |
|---|---|---|
| `GET` | `/health` | Liveness; no secrets; may omit token or accept token. |
| `GET` | `/v1/secrets` | List **names** only (policy-filtered); requires token. |
| `GET` | `/v1/secrets/{name}` | Return secret value if permitted; 404 on deny/missing without value oracle beyond existence policy TBD. |

Auth: `Authorization: Bearer <token>` (or `X-Agentpantry-Token`). Missing or
wrong token: `401`, no body differentiation that leaks names.

Response shape (illustrative):

```json
{ "name": "gh_token", "value": "..." }
```

### Config

```toml
# sink config fragment (all optional; serve remains explicit CLI opt-in)
[serve]
# bind = "127.0.0.1:0"   # port 0 = ephemeral; print chosen port at start
# allow_names = []       # extra narrow allow; still deny-wins with [secret_names]
```

### Non-goals

- Write/update/delete secrets over HTTP.
- Cookie or localStorage serving in v1.
- TLS on loopback (token + loopback; revisit if bind ever widens, which v1
  forbids).
- Compatibility with Bitwarden's exact route schema (inspiration only).

## Open questions

1. **Ordering vs #51:** confirm implementation freeze on #54 until #51 is
   available (or explicitly waived by maintainer).
2. **Existence oracle:** should denied and missing names both return identical
   `404`?
3. **Token delivery:** stderr vs stdout vs `AGENTPANTRY_SERVE_TOKEN` env for the
   parent only.
4. **Process model:** subcommand of long-running `sink`, or standalone process
   that only reads `secrets_dir`?
5. **List endpoint:** omit entirely to reduce name enumeration?
6. **Rate limiting:** needed on loopback against local agent spray?
7. **Sign-off artifact:** threat-model PR + issue comment, matching #52's gate
   discipline?

## Status

**proposal / not approved for implementation.** Blocked on (a) preference for
#51, (b) threat-model entry, and (c) explicit AGENTS.md-style maintainer
sign-off before any serve listener code.
