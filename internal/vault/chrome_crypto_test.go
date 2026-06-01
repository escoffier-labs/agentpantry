package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// encryptChrome mirrors Chromium's Linux scheme, for test fixtures only.
func encryptChrome(prefix, passphrase, value string) []byte {
	key := pbkdf2.Key([]byte(passphrase), []byte("saltysalt"), 1, 16, sha1.New)
	block, _ := aes.NewCipher(key)
	iv := bytes.Repeat([]byte{' '}, 16)
	pad := 16 - len(value)%16
	padded := append([]byte(value), bytes.Repeat([]byte{byte(pad)}, pad)...)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	return append([]byte(prefix), ct...)
}

func TestDecryptValueV11(t *testing.T) {
	enc := encryptChrome("v11", "keyring-pass", "session-token-123")
	got, err := DecryptValue(enc, "keyring-pass")
	if err != nil {
		t.Fatal(err)
	}
	if got != "session-token-123" {
		t.Fatalf("got %q", got)
	}
}

func TestDecryptValueV10UsesPeanuts(t *testing.T) {
	enc := encryptChrome("v10", "peanuts", "abc")
	got, err := DecryptValue(enc, "ignored-for-v10")
	if err != nil {
		t.Fatal(err)
	}
	if got != "abc" {
		t.Fatalf("got %q", got)
	}
}

func TestDecryptValuePlaintextPassthrough(t *testing.T) {
	got, err := DecryptValue([]byte("plainvalue"), "x")
	if err != nil {
		t.Fatal(err)
	}
	if got != "plainvalue" {
		t.Fatalf("got %q", got)
	}
}

func TestEncryptValueRoundTripsWithDecrypt(t *testing.T) {
	enc, err := EncryptValue("session-token-xyz", "keyring-pass")
	if err != nil {
		t.Fatal(err)
	}
	if string(enc[:3]) != "v11" {
		t.Fatalf("want v11 prefix, got %q", string(enc[:3]))
	}
	got, err := DecryptValue(enc, "keyring-pass")
	if err != nil {
		t.Fatal(err)
	}
	if got != "session-token-xyz" {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

func TestEncryptForTestStillMatchesDecrypt(t *testing.T) {
	// v10 fixture path must still decrypt under peanuts.
	enc := EncryptForTest("v10", "peanuts", "abc")
	got, err := DecryptValue(enc, "ignored")
	if err != nil || got != "abc" {
		t.Fatalf("v10 fixture broke: got %q err %v", got, err)
	}
}
