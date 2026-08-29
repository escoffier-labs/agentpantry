# Proposal: local hash-chained sync receipts

Date: 2026-08-08
Issue: [#53](https://github.com/escoffier-labs/agentpantry/issues/53)
Status: **implemented** (opt-in `[receipts]`, HMAC-SHA256 from the PSK, source
and sink, JSON Lines; see `internal/receipt` and `agentpantry receipts`)

## Summary

Emit a lightweight, local, append-only receipt for each successful sync (and
selected related events) so operators have tamper-evident provenance without
logging cookie or secret values. Each receipt records that a sync happened and
over what content digest, chained to the previous receipt, and signed so a
later rewrite of the log is detectable with the verification key.

Schema inspiration (local hash chain only; no blockchain layer): digital
heritage / embedded provenance papers cited in #53. Aligns with integrity and
provenance objectives in NIST CSF 2.0. Useful as citable evidence in
Brigade-style workflows: "this sink applied snapshot digest X at time T."

Today agentpantry logs operational messages and may mention cookie *names* and
hosts near expiry (`docs/threat-model.md`), but it does not keep a structured,
hash-chained audit of sync events. This proposal adds that, still with a hard
ban on secret and cookie *values* in the receipt stream.

## Threat model

Reference: `docs/threat-model.md`.

### What changes

- New local artifact on source and/or sink: an append-only receipt log.
- Integrity of the *log* becomes an operator-visible property (hash chain +
  signature). This does not change channel crypto, deny-wins policy, or PSK
  lifecycle.

### Newly exposed

- **Metadata leakage in the receipt file:** timestamps, role identity strings,
  event types, content hashes, and previous-event pointers. Hashes must be over
  canonical payloads that do **not** embed secret bytes in a recoverable way;
  prefer hashing already-diffed structural digests (counts, names, domain set
  hashes) rather than raw frames.
- An attacker with write access to the sink account can append fake receipts
  unless signatures use a key the attacker lacks; with only the same account
  key, receipts prove tamper-evidence against casual edits, not against a fully
  compromised host (consistent with "compromised endpoint sees everything").
- Disk growth of the receipt log (rotation / retention policy needed).

### Operator responsibilities

- Keep receipt files mode `0600` / directory `0700`, same posture as other
  agentpantry state.
- Treat receipt content as sensitive metadata even though values are withheld.
- On suspected host compromise, do not trust local receipts alone; export or
  mirror them off-box if they must serve as evidence.
- Configure retention so logs do not grow without bound.

### Threat-model doc updates (when approved)

Add a short "Sync receipts" note under protected / not-protected:

- What is attested (event occurred, payload digest, chain continuity).
- What is not (confidentiality of synced material; authenticity against a
  compromised signer key).
- Explicit: receipts never contain cookie values, secret values, or
  localStorage values.

No AGENTS.md handshake gate: this does not change session-salt or HKDF
invariants. Still worth a maintainer look before enabling by default.

## Interface sketch

No code. Shape only.

### Config (sink and/or source)

```toml
[receipts]
enabled = false          # opt-in
path = ""                # default under agentpantry state dir
# signing_key = ""       # path to ed25519 seed or similar; TBD
```

### Receipt record (JSON Lines or length-prefixed JSON, one event per line)

Illustrative fields:

| Field | Meaning |
|---|---|
| `v` | Schema version (integer). |
| `ts` | UTC timestamp (RFC 3339). |
| `role` | `source` or `sink`. |
| `peer_id` | Stable operator-chosen label or key fingerprint prefix (not a secret value). |
| `event` | e.g. `sync.apply`, `sync.send`, `rotate.begin`, `rotate.finish`. |
| `payload_hash` | Hex SHA-256 of a canonical, value-free summary of the applied/sent diff. |
| `prev_hash` | Hex SHA-256 of the previous receipt bytes (or zeros for genesis). |
| `sig` | Signature over the canonical encoding of the fields above. |

Canonical **payload summary** (hashed into `payload_hash`) should include only
safe material, for example:

- counts of cookie upserts/deletes
- sorted cookie host+name pairs (no values), or a hash thereof
- sorted secret *names* (no values)
- localStorage origin hosts (no values), when applicable
- protocol / snapshot sequence identifiers already used internally, if any

### CLI

```text
agentpantry receipts verify [--config PATH] [--path PATH]
agentpantry receipts show [--last N] [--json]
```

`verify` walks the chain, checks `prev_hash` links, and verifies signatures.
Failure is nonzero exit. `show` prints metadata only.

### Emission points

- Sink: after a diff is successfully applied to all configured surfaces.
- Source (optional): after a successful send of a non-empty diff.
- Key lifecycle (optional): `rotate-key` begin/finish as separate event types.

### Non-goals

- Distributed consensus or public blockchain anchoring.
- Shipping receipt contents to a remote SIEM in v1 (operators can ship the file).
- Logging secret or cookie values under any flag.

## Open questions

1. **Default on or off?** Opt-in is safer for metadata; evidence workflows may
   want opt-out once stable.
2. **Signing key:** reuse a derivative of the PSK (binds receipts to the
   transport key, but couples rotation), vs a separate ed25519 key file.
3. **Source, sink, or both?** Sink-only may be enough for "what landed here."
4. **Canonical payload summary:** exact field set so hashes are stable across
   versions.
5. **Rotation / compaction:** how to truncate while keeping a verifiable seal
   of the discarded prefix.
6. **Interaction with `--once` and empty diffs:** emit a receipt for no-op
   syncs, or only when something applied?

## Status

**implemented.** Decisions: opt-in (`enabled = false`); HMAC-SHA256 via
HKDF(PSK, info `agentpantry/v1 receipt mac`); source and sink; receipts only
for non-empty send/apply; JSON Lines.
