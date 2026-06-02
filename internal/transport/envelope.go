package transport

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const counterLen = 8

// deriveSessionKey mixes the pre-shared key with a per-session salt so frames
// from one session never authenticate on another.
func deriveSessionKey(key, salt []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	r := hkdf.New(sha256.New, key, salt, []byte("agentpantry/v1 session"))
	sk := make([]byte, 32)
	if _, err := io.ReadFull(r, sk); err != nil {
		return nil, err
	}
	return sk, nil
}

func newAEAD(key, salt []byte) (cipher.AEAD, error) {
	sk, err := deriveSessionKey(key, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(sk)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Sealer encrypts outbound frames with a monotonically increasing counter.
type Sealer struct {
	aead    cipher.AEAD
	counter uint64
}

func NewSealer(key, salt []byte) (*Sealer, error) {
	a, err := newAEAD(key, salt)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: a}, nil
}

// Seal produces counter || nonce || ciphertext.
func (s *Sealer) Seal(plaintext []byte) ([]byte, error) {
	s.counter++
	hdr := make([]byte, counterLen)
	binary.BigEndian.PutUint64(hdr, s.counter)

	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := s.aead.Seal(nil, nonce, plaintext, hdr)

	frame := make([]byte, 0, counterLen+len(nonce)+len(ct))
	frame = append(frame, hdr...)
	frame = append(frame, nonce...)
	frame = append(frame, ct...)
	return frame, nil
}

// Opener decrypts inbound frames and rejects replays.
type Opener struct {
	aead        cipher.AEAD
	lastCounter uint64
}

func NewOpener(key, salt []byte) (*Opener, error) {
	a, err := newAEAD(key, salt)
	if err != nil {
		return nil, err
	}
	return &Opener{aead: a}, nil
}

func (o *Opener) Open(frame []byte) ([]byte, error) {
	ns := o.aead.NonceSize()
	if len(frame) < counterLen+ns {
		return nil, errors.New("frame too short")
	}
	hdr := frame[:counterLen]
	nonce := frame[counterLen : counterLen+ns]
	ct := frame[counterLen+ns:]

	counter := binary.BigEndian.Uint64(hdr)
	if counter <= o.lastCounter {
		return nil, fmt.Errorf("replay detected: counter %d <= last %d", counter, o.lastCounter)
	}
	pt, err := o.aead.Open(nil, nonce, ct, hdr)
	if err != nil {
		return nil, err
	}
	o.lastCounter = counter
	return pt, nil
}
