package transport

import (
	"crypto/rand"
	"fmt"
	"io"
)

// SaltLen is the per-session salt length.
const SaltLen = 16

// SendSalt generates a random session salt and writes it as one frame.
func SendSalt(w io.Writer) ([]byte, error) {
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if err := WriteFrame(w, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// RecvSalt reads one frame and validates it as a session salt.
func RecvSalt(r io.Reader) ([]byte, error) {
	salt, err := ReadFrame(r)
	if err != nil {
		return nil, err
	}
	if len(salt) != SaltLen {
		return nil, fmt.Errorf("invalid session salt length %d", len(salt))
	}
	return salt, nil
}
