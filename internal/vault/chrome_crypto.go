package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1" // #nosec G505 -- Chromium Linux cookie encryption derives keys with PBKDF2-HMAC-SHA1 for compatibility.
	"errors"

	"golang.org/x/crypto/pbkdf2"
)

func deriveKey(passphrase string) []byte {
	return pbkdf2.Key([]byte(passphrase), []byte("saltysalt"), 1, 16, sha1.New)
}

func pkcs7Unpad(b []byte) ([]byte, error) {
	if len(b) == 0 || len(b)%16 != 0 {
		return nil, errors.New("invalid padded length")
	}
	pad := int(b[len(b)-1])
	if pad == 0 || pad > 16 || pad > len(b) {
		return nil, errors.New("invalid pkcs7 padding")
	}
	return b[:len(b)-pad], nil
}

// DecryptValue decrypts a Chromium Linux encrypted_value. v10 uses the fixed
// "peanuts" passphrase; v11 uses keyringPass. Unprefixed input is plaintext.
func DecryptValue(enc []byte, keyringPass string) (string, error) {
	if len(enc) < 3 {
		return string(enc), nil
	}
	prefix := string(enc[:3])
	var passphrase string
	switch prefix {
	case "v10":
		passphrase = "peanuts"
	case "v11":
		passphrase = keyringPass
	default:
		return string(enc), nil // not encrypted
	}

	ct := enc[3:]
	if len(ct) == 0 || len(ct)%16 != 0 {
		return "", errors.New("ciphertext not a multiple of block size")
	}
	block, err := aes.NewCipher(deriveKey(passphrase))
	if err != nil {
		return "", err
	}
	iv := bytes.Repeat([]byte{' '}, 16)
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	pt, err = pkcs7Unpad(pt)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

func pkcs7Pad(b []byte) []byte {
	pad := 16 - len(b)%16
	return append(b, bytes.Repeat([]byte{byte(pad)}, pad)...)
}

// EncryptValue produces a v11-prefixed AES-128-CBC ciphertext for a Chromium
// Linux store, using keyringPass. It is the inverse of DecryptValue for v11.
func EncryptValue(plaintext, keyringPass string) ([]byte, error) {
	block, err := aes.NewCipher(deriveKey(keyringPass))
	if err != nil {
		return nil, err
	}
	iv := bytes.Repeat([]byte{' '}, 16)
	padded := pkcs7Pad([]byte(plaintext))
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	return append([]byte("v11"), ct...), nil
}
