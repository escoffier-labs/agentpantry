package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"

	"golang.org/x/crypto/pbkdf2"
)

// EncryptForTest mirrors Chromium's Linux scheme so other packages' tests can
// build fixtures. It is exported only for tests but lives in a normal file to
// keep it importable across packages.
func EncryptForTest(prefix, passphrase, value string) []byte {
	key := pbkdf2.Key([]byte(passphrase), []byte("saltysalt"), 1, 16, sha1.New)
	block, _ := aes.NewCipher(key)
	iv := bytes.Repeat([]byte{' '}, 16)
	pad := 16 - len(value)%16
	padded := append([]byte(value), bytes.Repeat([]byte{byte(pad)}, pad)...)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	return append([]byte(prefix), ct...)
}
