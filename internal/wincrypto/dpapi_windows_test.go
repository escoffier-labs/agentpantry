//go:build windows

package wincrypto

import (
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// cryptProtect wraps bytes with DPAPI (the inverse of UnwrapDPAPI) for testing.
func cryptProtect(b []byte) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, 0, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	res := make([]byte, out.Size)
	copy(res, unsafe.Slice(out.Data, out.Size))
	return res, nil
}

func TestDPAPIRoundTrip(t *testing.T) {
	secret := []byte("a-32-byte-aes-key-for-dpapi-test")
	wrapped, err := cryptProtect(secret)
	if err != nil {
		t.Fatalf("CryptProtectData: %v", err)
	}
	got, err := UnwrapDPAPI(wrapped)
	if err != nil {
		t.Fatalf("UnwrapDPAPI: %v", err)
	}
	if string(got) != string(secret) {
		t.Fatalf("round trip mismatch: got %q want %q", got, secret)
	}
}

// TestRealLocalStateKey validates the full key-derivation chain against a real
// Chromium Local State file when AGENTPANTRY_LOCALSTATE points at one.
func TestRealLocalStateKey(t *testing.T) {
	path := os.Getenv("AGENTPANTRY_LOCALSTATE")
	if path == "" {
		t.Skip("set AGENTPANTRY_LOCALSTATE to a real Local State path to run")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := ParseLocalStateKey(b)
	if err != nil {
		t.Fatalf("ParseLocalStateKey: %v", err)
	}
	key, err := UnwrapDPAPI(wrapped)
	if err != nil {
		t.Fatalf("UnwrapDPAPI: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("expected a 32-byte AES key, got %d bytes", len(key))
	}
}
