package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
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
