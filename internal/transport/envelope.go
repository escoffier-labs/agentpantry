package transport

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

const counterLen = 8

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
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

func NewSealer(key []byte) (*Sealer, error) {
	a, err := newAEAD(key)
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

func NewOpener(key []byte) (*Opener, error) {
	a, err := newAEAD(key)
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
