# Proposal: PAKE (SPAKE2) short-code pairing

Date: 2026-08-08
Issue: [#52](https://github.com/escoffier-labs/agentpantry/issues/52)
Status: **implemented additively** (issue #52). Session-salt handshake and
HKDF session keys are unchanged; see `docs/threat-model.md` Pairing section.

## AGENTS.md gate (blocking)

Changing the handshake or key-establishment story requires:

1. A rewrite (or substantive update) of `docs/threat-model.md`, and
2. **Explicit maintainer / operator sign-off**

per `AGENTS.md` ("Security Invariants"): session-salt handshake plus HKDF
per-session keys must not be weakened, and intentional changes here need matching
threat-model updates plus sign-off. **Do not start implementation without that
sign-off.** This proposal is not that sign-off.

## Summary

Offer an additive setup mode that bootstraps the long-lived pre-shared key (PSK)
via a password-authenticated key exchange (SPAKE2) using a short one-time code,
instead of manually copying a 64-hex `psk.key` between machines. Pattern from
Magic Wormhole.

Strictly additive constraints from the issue and current code:

- After pairing, normal sync still performs the session-salt handshake
  (`internal/transport/handshake.go`: `SendSalt` / `RecvSalt`, 16-byte salt).
- Per-session keys still derive via HKDF-SHA256(PSK, salt, info
  `"agentpantry/v1 session"`) in `internal/transport/envelope.go`.
- Preserve `--stdio` salt-direction inversion: over TCP the sink issues the salt
  (`cmd/agentpantry` sink listen path); over `--stdio` the source issues it.
- Never pin a static or reused session key. Never skip the salt handshake on
  production paths.
- Manual `keygen` + secure copy remains supported forever.

Why: short codes cut setup friction and reduce mishandling of a long-lived PSK
file during first bootstrap. Any ECDH/PAKE construction adds peer-key-validation
requirements the current PSK path does not have (see issue citations).

## Threat model

Reference: `docs/threat-model.md` (key lifecycle checklist, "No forward secrecy",
operator PSK responsibilities).

### What changes

- New **pairing** phase before a durable PSK exists on both ends.
- An online pairing channel (likely the same TCP peer address, or a short-lived
  pairing listener) exchanges SPAKE2 messages authenticated by the short code.
- On success, both ends write a normal `psk.key` (`0600`, existing
  `internal/keyfile` hardening) and subsequent connections use today's handshake
  unchanged.

### Newly exposed

- **Short-code online guessing** during the pairing window (wormhole-style rate
  limits, attempt caps, and short TTL are mandatory design elements).
- **Wrong-peer / MitM during pairing** if the operator mistypes or shares the
  code with the wrong machine; SPAKE2 detects password mismatch but the operator
  must still compare a confirmation fingerprint (or equivalent) before accepting
  the written PSK.
- Pairing traffic is a new pre-auth protocol surface on the bind address (related
  to the existing "pre-auth connection slots" residual risk).
- Does **not** by itself add forward secrecy to later sync sessions; the
  resulting artifact is still a long-lived PSK unless a future design changes
  that (out of scope here).

### Operator responsibilities

- Run pairing only on loopback or a trusted private network (same bind guidance
  as today's sink).
- Treat the short code like a one-time password: out-of-band, short-lived, never
  reused.
- Verify the post-pairing confirmation string on both ends before first sync.
- After pairing, rotate or re-pair if the code or confirmation was exposed.
- Existing duties still apply: keep `psk.key` secret, finish `rotate-key`
  windows promptly.

### Required threat-model updates (before or with implementation)

The rewrite must at least cover:

- Pairing as a distinct phase vs steady-state sync.
- SPAKE2 (or chosen PAKE) assumptions, code entropy, attempt limits, TTL.
- Confirmation / peer-validation step (new vs today's "copy the same file").
- Explicit statement that session-salt + HKDF invariants are unchanged after
  pairing.
- Interaction with `rotate-key`, `keygen`, and `psk.key.bak.*` backups.
- Residual risks: code guessing, pairing MitM, no FS for the long-lived PSK.

## Interface sketch

No code. Shape only.

### CLI (additive)

```text
# On sink (generates code, waits for peer)
agentpantry pair --role sink [--config PATH] [--bind ADDR]

# On source (enters code)
agentpantry pair --role source --code WORD-WORD [--config PATH] [--peer ADDR]
```

Alternate UX (open): single `agentpantry pair` that prints a code on one side and
prompts on the other, similar to wormhole.

On success:

1. Derive or agree a 32-byte PSK.
2. Write `psk.key` via existing keyfile atomic `0600` path (refuse symlinks).
3. Print a short confirmation fingerprint (e.g. hex of SHA-256(PSK) truncated)
   on both ends for operator compare.
4. Exit. Normal `source` / `sink` thereafter.

### Protocol outline (pairing only)

1. Operator starts sink-side pair; tool displays a short code (word-list or
   Crockford base32; entropy budget TBD).
2. Source-side pair connects to the pairing endpoint and runs SPAKE2 with the
   code as the password.
3. Both sides derive a shared secret; map it into a 32-byte PSK (HKDF with a
   distinct info string from `"agentpantry/v1 session"`, e.g.
   `"agentpantry/v1 pair-psk"`).
4. Exchange and display confirmation digests; abort without writing `psk.key` on
   mismatch or operator cancel.
5. Tear down the pairing listener. Steady-state sync never uses the short code
   again.

### Non-goals

- Replacing session-salt handshake with PAKE every connection.
- QR codes, relay servers, or public wormhole mailboxes in v1 (local/VPN only
  unless a later proposal argues otherwise).
- Changing `--stdio` salt direction.

## Open questions

1. **PAKE library / construction:** SPAKE2+ vs alternatives available in pure Go
   without cgo; constant-time and safe-curve requirements.
2. **Code format and entropy:** word list length, hyphenation, TTL, max attempts
   before lockout.
3. **Transport for pairing messages:** reuse framed TCP on the sink peer port
   with a distinct first message type, vs a dedicated ephemeral port.
4. **Confirmation UX:** how much fingerprint to show; whether to require an
   explicit `--accept` after compare.
5. **Rotation story:** does re-pair replace `rotate-key`, or only bootstrap?
6. **stdio pairing:** is out-of-band code + TCP pair enough, or do we need a
   stdio pairing mode?
7. **Maintainer sign-off artifact:** comment on #52, checklist in the
   threat-model PR, or both?

## Status

Implemented as `agentpantry pair` / `internal/pair`. Threat-model pairing
section records the new setup phase. The session-salt handshake file was not
changed.
