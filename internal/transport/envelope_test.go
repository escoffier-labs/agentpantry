package transport

import (
	"bytes"
	"testing"
)

func key32() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func TestSealOpenRoundTrip(t *testing.T) {
	s, err := NewSealer(key32())
	if err != nil {
		t.Fatal(err)
	}
	o, err := NewOpener(key32())
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello cookies")
	frame, err := s.Seal(msg)
	if err != nil {
		t.Fatal(err)
	}
	out, err := o.Open(frame)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, msg) {
		t.Fatalf("round trip mismatch: %q", out)
	}
}

func TestOpenRejectsReplay(t *testing.T) {
	s, _ := NewSealer(key32())
	o, _ := NewOpener(key32())
	f1, _ := s.Seal([]byte("one"))
	if _, err := o.Open(f1); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Open(f1); err == nil {
		t.Fatal("replayed frame must be rejected")
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	s, _ := NewSealer(key32())
	bad := key32()
	bad[0] ^= 0xff
	o, _ := NewOpener(bad)
	f, _ := s.Seal([]byte("secret"))
	if _, err := o.Open(f); err == nil {
		t.Fatal("frame under wrong key must fail authentication")
	}
}
