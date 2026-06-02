# agentpantry T1 - design (security hardening)

Status: approved (autonomous scope per goal directive), ready for implementation planning
Date: 2026-06-01
Builds on: P1-P7. Hardening track 1 of 4.

## 1. Goal

Close real security gaps:

1. **Cross-connection replay**: add a per-connection session salt so frames from
   one session never authenticate on another.
2. **Secret-name policy**: an allow/deny filter on secret names, mirroring the
   cookie domain policy.
3. **govulncheck**: a make target (and a clean baseline run) for dependency CVEs.
4. **Fuzzing**: Go native fuzz targets for the untrusted-input parsers.

## 2. Replay fix: per-session salt + HKDF

Today `NewOpener` starts `lastCounter=0` and the sink builds a fresh `Opener`
per connection, so a frame captured from a past session (counter > 0) replays
into a new connection and authenticates. Fix by binding every session to a fresh
random salt:

- `NewSealer(key, salt []byte)` and `NewOpener(key, salt []byte)` derive a
  per-session 32-byte key: `sessionKey = HKDF-SHA256(key, salt, info="agentpantry/v1 session")`
  (golang.org/x/crypto/hkdf), then AES-256-GCM as today. The counter+random-nonce
  in-session replay/ordering mechanism is unchanged.
- A frame sealed under session salt A cannot be opened under salt B: the derived
  keys differ, so GCM authentication fails. Replaying a whole past session into a
  new TCP connection fails because the sink generates a fresh, unpredictable salt
  for each connection (the attacker cannot make the sink reuse an old salt).

### Handshake primitives (`internal/transport/handshake.go`)

- `const SaltLen = 16`
- `SendSalt(w io.Writer) ([]byte, error)`: read 16 random bytes, `WriteFrame` them,
  return the salt.
- `RecvSalt(r io.Reader) ([]byte, error)`: `ReadFrame`, require `len == SaltLen`,
  return the salt.

The salt frame is sent in the clear (it is a public nonce; HKDF with the secret
PSK is what produces the session key).

### Who issues the salt (by transport)

- **TCP** (bidirectional, the default): the SINK issues the salt (a fresh
  challenge it controls), giving full cross-connection replay protection.
  - sink: `salt = SendSalt(conn)` then `NewOpener(key, salt)` then `Serve`.
  - source: `salt = RecvSalt(conn)` then `NewSealer(key, salt)` then push frames.
- **--stdio** (one-way shell pipe, cannot round-trip a challenge): the SOURCE
  issues the salt as the first frame. This still gives per-session key separation
  (different sessions use different keys), but full-session replay over a raw
  one-way channel is not prevented by the salt alone; `--stdio` relies on the
  underlying channel (SSH: authenticated, integrity-protected, not replayable by a
  network attacker) for that. Documented in the threat model (T3) and README.
  - source --stdio: `salt = SendSalt(os.Stdout)` then `NewSealer(key, salt)` then push.
  - sink --stdio: `salt = RecvSalt(os.Stdin)` then `NewOpener(key, salt)` then `Serve`.

This is an intentional breaking transport change: the frame stream now begins
with a salt frame, so both ends must run the new build. Pre-1.0, same binary both
ends. Noted in CHANGELOG.

## 3. Secret-name policy

- `policy.Names{ Allow, Deny []string }` with exact-name matching:
  `Permit(name) bool` returns false if `name` is in Deny; otherwise true if Allow
  is empty (the `secrets_dir` is already the opt-in) or `name` is in Allow.
  (Deny overrides Allow. Empty Allow = permit all, unlike the cookie domain
  policy whose empty Allow permits nothing, because configuring `secrets_dir` is
  itself the opt-in for secrets.)
- Config: `SecretNames policy.Names` (`toml:"secret_names"`), additive.
- `source.Syncer` gains `SecretPolicy policy.Names`; `SyncOnce` filters gathered
  secrets by `Permit(name)` before building the snapshot. The CLI wires
  `c.SecretNames`.

## 4. govulncheck

Add a `Makefile` with `build`, `test`, `vet`, `windows` (GOOS=windows build),
`vuln` (`go run golang.org/x/vuln/cmd/govulncheck@latest ./...`), and `fuzz`
targets. Run `vuln` once and record a clean baseline (fix or document any
finding). The GitHub Actions wiring is T3; this track adds the local target and
the clean baseline.

## 5. Fuzz targets

Go native fuzzing (`func FuzzXxx(f *testing.F)`), each asserting "no panic / no
crash" on arbitrary input (and round-trip where meaningful). They execute their
seed corpus under normal `go test`:

- `internal/wire`: `FuzzPayloadUnmarshal` - `json.Unmarshal` arbitrary bytes into
  `wire.Payload`; must not panic.
- `internal/transport`: `FuzzOpen` - `Open` arbitrary bytes with a fixed
  key+salt opener; must not panic (errors are fine).
- `internal/surface`: refactor the Netscape seed line-parse into an exported-
  to-package `parseNetscapeLine(line string) (netscapeRow, bool)` and
  `FuzzParseNetscapeLine` - must not panic.
- `internal/vault`: `FuzzDecryptValue` - `DecryptValue(arbitrary, "pass")`; must
  not panic.
- `internal/wincrypto`: `FuzzDecryptV10GCM` - `DecryptV10GCM(arbitrary, 32-byte
  key)`; must not panic.

## 6. Security notes

- The salt is public; secrecy rests on the PSK via HKDF. The salt provides
  session-key separation and (for TCP) sink-driven freshness.
- No secret/cookie values logged (unchanged).
- Secret-name policy is an additional filter, not a replacement for the
  `secrets_dir` opt-in.

## 7. Testing

- transport: `NewSealer(key,salt)`/`NewOpener(key,salt)` round-trip with matching
  salt; DIFFERENT salts fail to open (the replay fix, asserted directly);
  `SendSalt`/`RecvSalt` round-trip over an `io.Pipe`/buffer; wrong salt length
  rejected.
- policy: `Names.Permit` - deny overrides, empty allow permits all, non-empty
  allow whitelists.
- source: secret-name policy filters secrets in `SyncOnce` (denied name absent
  from the payload).
- All existing tests/integration updated to pass a fixed test salt to
  `NewSealer`/`NewOpener`.
- fuzz targets run their seed corpus under `go test`.
- `make vuln` clean.

## 8. Out of scope

Full Noise/mTLS handshake, key rotation, at-rest encryption of the sidecar
(documented as a tradeoff in T3's threat model instead).
