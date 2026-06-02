package wincrypto

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func key32() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func TestV10GCMRoundTrip(t *testing.T) {
	enc, err := EncryptV10GCM("session-token", key32())
	if err != nil {
		t.Fatal(err)
	}
	if string(enc[:3]) != "v10" {
		t.Fatalf("want v10 prefix, got %q", string(enc[:3]))
	}
	got, err := DecryptV10GCM(enc, key32())
	if err != nil {
		t.Fatal(err)
	}
	if got != "session-token" {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

func TestV10GCMWrongKeyFails(t *testing.T) {
	enc, _ := EncryptV10GCM("secret", key32())
	bad := key32()
	bad[0] ^= 0xff
	if _, err := DecryptV10GCM(enc, bad); err == nil {
		t.Fatal("wrong key must fail authentication")
	}
}

func TestV10GCMRejectsShortOrNonV10(t *testing.T) {
	if _, err := DecryptV10GCM([]byte("xx"), key32()); err == nil {
		t.Fatal("short input must error")
	}
	if _, err := DecryptV10GCM([]byte("v11abc"), key32()); err == nil {
		t.Fatal("non-v10 prefix must error")
	}
}

func TestParseLocalStateKey(t *testing.T) {
	wrapped := []byte("WRAPPED-KEY-BYTES")
	raw := append([]byte("DPAPI"), wrapped...)
	ls := map[string]any{"os_crypt": map[string]any{"encrypted_key": base64.StdEncoding.EncodeToString(raw)}}
	b, _ := json.Marshal(ls)

	got, err := ParseLocalStateKey(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(wrapped) {
		t.Fatalf("want %q, got %q", wrapped, got)
	}
}

func TestParseLocalStateKeyErrors(t *testing.T) {
	if _, err := ParseLocalStateKey([]byte(`{}`)); err == nil {
		t.Fatal("missing key must error")
	}
	noPrefix := map[string]any{"os_crypt": map[string]any{"encrypted_key": base64.StdEncoding.EncodeToString([]byte("NODPAPIhere"))}}
	b, _ := json.Marshal(noPrefix)
	if _, err := ParseLocalStateKey(b); err == nil {
		t.Fatal("missing DPAPI prefix must error")
	}
}
