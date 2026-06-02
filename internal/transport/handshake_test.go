package transport

import (
	"bytes"
	"testing"
)

func TestSendRecvSaltRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	sent, err := SendSalt(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(sent) != SaltLen {
		t.Fatalf("want %d-byte salt, got %d", SaltLen, len(sent))
	}
	got, err := RecvSalt(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sent, got) {
		t.Fatal("recv salt != sent salt")
	}
}

func TestRecvSaltRejectsWrongLength(t *testing.T) {
	var buf bytes.Buffer
	WriteFrame(&buf, []byte("short"))
	if _, err := RecvSalt(&buf); err == nil {
		t.Fatal("wrong-length salt must be rejected")
	}
}
