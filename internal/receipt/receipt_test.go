package receipt

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/config"
	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/secret"
	"github.com/escoffier-labs/agentpantry/internal/webstorage"
	"github.com/escoffier-labs/agentpantry/internal/wire"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	k, err := hex.DecodeString(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func testPayload() wire.Payload {
	return wire.Payload{
		Cookies: cookie.Diff{
			Upserts: []cookie.Cookie{{Host: "example.com", Name: "sid", Path: "/", Value: "cookie-secret-value"}},
			Deletes: []string{cookie.Key(cookie.Cookie{Host: "example.com", Name: "old", Path: "/"})},
		},
		Secrets: secret.Diff{
			Upserts: []secret.Secret{{Name: "api_token", Value: "super-secret-token"}},
			Deletes: []string{"retired"},
		},
		Storage: webstorage.Diff{
			Upserts: []webstorage.Item{{Origin: "https://example.com", Key: "session", Value: "localstorage-secret"}},
		},
	}
}

func testLog(t *testing.T, now time.Time) *Log {
	t.Helper()
	return &Log{
		Path:     filepath.Join(t.TempDir(), "receipts.jsonl"),
		Key:      testKey(t),
		Role:     "source",
		SourceID: "source",
		SinkID:   "127.0.0.1:8787",
		Now:      func() time.Time { return now },
	}
}

func TestAppendChainsAndVerify(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	log := testLog(t, now)
	p := testPayload()
	if err := log.Append(EventSend, p); err != nil {
		t.Fatal(err)
	}
	if err := log.Append(EventSend, p); err != nil {
		t.Fatal(err)
	}
	n, err := Verify(log.Path, log.Key)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("got %d records, want 2", n)
	}
	recs, err := ReadAll(log.Path)
	if err != nil {
		t.Fatal(err)
	}
	if recs[0].PrevHash != GenesisPrev {
		t.Fatalf("genesis prev_hash: %s", recs[0].PrevHash)
	}
	if recs[1].PrevHash == GenesisPrev || recs[1].PrevHash == recs[0].PrevHash {
		t.Fatalf("second prev_hash must point at first record, got %s", recs[1].PrevHash)
	}
	if recs[0].Event != EventSend || recs[0].Role != "source" {
		t.Fatalf("record metadata: %+v", recs[0])
	}
	if recs[0].SourceID != "source" || recs[0].SinkID != "127.0.0.1:8787" {
		t.Fatalf("identities: %+v", recs[0])
	}
	if recs[0].PayloadHash != recs[1].PayloadHash {
		t.Fatal("same payload must produce the same content hash")
	}
}

func TestReceiptsNeverContainValues(t *testing.T) {
	log := testLog(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	p := testPayload()
	if err := log.Append(EventApply, p); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(log.Path)
	if err != nil {
		t.Fatal(err)
	}
	if ContainsSensitive(raw, "cookie-secret-value", "super-secret-token", "localstorage-secret") {
		t.Fatalf("receipt file leaked secret material:\n%s", raw)
	}
	// Identifiers (names/hosts) are hashed into payload_hash, not stored.
	if bytesContainsAny(raw, "cookie-secret-value", "super-secret-token", "localstorage-secret", `"value"`) {
		t.Fatalf("receipt must not store values or a value field:\n%s", raw)
	}
}

func bytesContainsAny(raw []byte, needles ...string) bool {
	s := string(raw)
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func TestPayloadHashIgnoresValuesAndIsStable(t *testing.T) {
	a := testPayload()
	b := testPayload()
	b.Cookies.Upserts[0].Value = "different-cookie"
	b.Secrets.Upserts[0].Value = "different-secret"
	b.Storage.Upserts[0].Value = "different-storage"
	ha, err := PayloadHash(a)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := PayloadHash(b)
	if err != nil {
		t.Fatal(err)
	}
	if ha != hb {
		t.Fatal("payload hash must ignore cookie/secret/storage values")
	}
	c := a
	c.Cookies.Upserts[0].Name = "other"
	hc, err := PayloadHash(c)
	if err != nil {
		t.Fatal(err)
	}
	if ha == hc {
		t.Fatal("renaming a cookie slot must change the payload hash")
	}
}

func TestVerifyDetectsBrokenChain(t *testing.T) {
	log := testLog(t, time.Unix(1, 0).UTC())
	p := testPayload()
	if err := log.Append(EventSend, p); err != nil {
		t.Fatal(err)
	}
	if err := log.Append(EventSend, p); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(log.Path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	var rec Record
	if err := json.Unmarshal([]byte(lines[1]), &rec); err != nil {
		t.Fatal(err)
	}
	rec.PrevHash = GenesisPrev
	tampered, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	// Resign so the failure is the chain link, not the MAC.
	macKey, err := DeriveMACKey(log.Key)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sign(macKey, rec)
	if err != nil {
		t.Fatal(err)
	}
	rec.Sig = sig
	tampered, err = json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(log.Path, []byte(lines[0]+"\n"+string(tampered)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(log.Path, log.Key); err == nil || !strings.Contains(err.Error(), "prev_hash") {
		t.Fatalf("want prev_hash mismatch, got %v", err)
	}
}

func TestVerifyDetectsBadSignature(t *testing.T) {
	log := testLog(t, time.Unix(2, 0).UTC())
	if err := log.Append(EventSend, testPayload()); err != nil {
		t.Fatal(err)
	}
	other := make([]byte, 32)
	other[0] = 0xff
	if _, err := Verify(log.Path, other); err == nil {
		t.Fatal("foreign key must fail verify")
	}
	raw, err := os.ReadFile(log.Path)
	if err != nil {
		t.Fatal(err)
	}
	var rec Record
	if err := json.Unmarshal(bytesTrimNL(raw), &rec); err != nil {
		t.Fatal(err)
	}
	rec.TS = "2099-01-01T00:00:00Z"
	body, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(log.Path, append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(log.Path, log.Key); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("want signature mismatch, got %v", err)
	}
}

func bytesTrimNL(b []byte) []byte {
	return []byte(strings.TrimRight(string(b), "\n"))
}

func TestVerifyAcceptsOldKeyDuringRotation(t *testing.T) {
	log := testLog(t, time.Unix(3, 0).UTC())
	if err := log.Append(EventSend, testPayload()); err != nil {
		t.Fatal(err)
	}
	old := log.Key
	newKey := make([]byte, 32)
	newKey[31] = 0x01
	log.Key = newKey
	log.Now = func() time.Time { return time.Unix(4, 0).UTC() }
	if err := log.Append(EventSend, testPayload()); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(log.Path, newKey, old); err != nil {
		t.Fatalf("rotation window must accept either key: %v", err)
	}
}

func TestVerifyEmptyAndMissing(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope.jsonl")
	n, err := Verify(missing, testKey(t))
	if err != nil || n != 0 {
		t.Fatalf("missing file: n=%d err=%v", n, err)
	}
	empty := filepath.Join(dir, "empty.jsonl")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	n, err = Verify(empty, testKey(t))
	if err != nil || n != 0 {
		t.Fatalf("empty file: n=%d err=%v", n, err)
	}
}

func TestAppendRefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "receipts.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	log := &Log{Path: link, Key: testKey(t), Role: "sink", SourceID: "source", SinkID: "peer"}
	if err := log.Append(EventApply, testPayload()); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("want symlink refusal, got %v", err)
	}
}

func TestAppendCreatesPrivateFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix modes are not enforced on windows")
	}
	log := testLog(t, time.Unix(5, 0).UTC())
	if err := log.Append(EventSend, testPayload()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(log.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("want 0600, got %v", info.Mode().Perm())
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	line := []byte(`{"v":1,"ts":"2026-01-01T00:00:00Z","role":"source","source_id":"s","sink_id":"k","event":"sync.send","payload_hash":"` + strings.Repeat("a", 64) + `","prev_hash":"` + GenesisPrev + `","sig":"` + strings.Repeat("b", 64) + `","value":"nope"}`)
	if _, err := parseRecord(line); err == nil {
		t.Fatal("unknown fields must be rejected so values cannot be smuggled in")
	}
}

func TestResolvePath(t *testing.T) {
	c := config.Config{}
	cfg := filepath.Join("cfgdir", "config.toml")
	got := ResolvePath(c, cfg)
	if got != filepath.Join("cfgdir", "receipts.jsonl") {
		t.Fatalf("default beside config: %s", got)
	}
	c.Receipts.Path = filepath.Join("var", "receipts.jsonl")
	if ResolvePath(c, cfg) != c.Receipts.Path {
		t.Fatal("explicit path must win")
	}
}

func TestCheckPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "receipts.jsonl")
	if err := CheckPath(path, func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if err := CheckPath(path, func(string) bool { return false }); err == nil {
		t.Fatal("unwritable parent of a missing file must fail")
	}
	if err := os.WriteFile(path, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckPath(path, func(string) bool { return false }); err != nil {
		t.Fatalf("existing regular file must pass: %v", err)
	}
}
