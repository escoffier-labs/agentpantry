package wincrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// ParseLocalStateKey extracts os_crypt.encrypted_key from a Chromium Local State
// JSON, base64-decodes it, and strips the 5-byte "DPAPI" prefix, returning the
// still-DPAPI-wrapped key. Unwrapping (Windows-only) is UnwrapDPAPI.
func ParseLocalStateKey(localStateJSON []byte) ([]byte, error) {
	var ls struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(localStateJSON, &ls); err != nil {
		return nil, err
	}
	if ls.OSCrypt.EncryptedKey == "" {
		return nil, errors.New("os_crypt.encrypted_key missing in Local State")
	}
	raw, err := base64.StdEncoding.DecodeString(ls.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted_key: %w", err)
	}
	if len(raw) < 5 || string(raw[:5]) != "DPAPI" {
		return nil, errors.New("encrypted_key missing DPAPI prefix")
	}
	return raw[5:], nil
}

// DecryptV10GCM decrypts a Windows Chromium v10 cookie value:
// "v10" || 12-byte nonce || ciphertext+tag, AES-256-GCM with a 32-byte key.
func DecryptV10GCM(enc, key []byte) (string, error) {
	if len(enc) < 3 || string(enc[:3]) != "v10" {
		return "", errors.New("not a v10 GCM value")
	}
	if len(key) != 32 {
		return "", fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	body := enc[3:]
	if len(body) < 12+16 {
		return "", errors.New("v10 value too short")
	}
	nonce, ct := body[:12], body[12:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// EncryptV10GCM is the inverse of DecryptV10GCM.
func EncryptV10GCM(plaintext string, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, []byte(plaintext), nil)
	out := make([]byte, 0, 3+len(nonce)+len(ct))
	out = append(out, "v10"...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}
