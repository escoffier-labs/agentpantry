package transport

import (
	"bytes"
	"testing"
)

func TestWriteReadFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	want := [][]byte{[]byte("alpha"), []byte("beta"), {}}
	for _, f := range want {
		if err := WriteFrame(&buf, f); err != nil {
			t.Fatal(err)
		}
	}
	for i, w := range want {
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if !bytes.Equal(got, w) {
			t.Fatalf("frame %d: got %q want %q", i, got, w)
		}
	}
}

func TestReadFrameRejectsOversized(t *testing.T) {
	var buf bytes.Buffer
	// length prefix claiming 5 GiB
	buf.Write([]byte{0xff, 0xff, 0xff, 0xff})
	if _, err := ReadFrame(&buf); err == nil {
		t.Fatal("oversized frame must be rejected")
	}
}

func TestWriteFrameRejectsOversized(t *testing.T) {
	payload := make([]byte, maxFrame+1)
	if err := WriteFrame(&bytes.Buffer{}, payload); err == nil {
		t.Fatal("oversized frame must be rejected")
	}
}

func TestFrameCapIsRealisticForDiffPayloads(t *testing.T) {
	// The cap bounds the allocation an unauthenticated peer can force per
	// frame; it must stay far below the old 64 MiB.
	payload := make([]byte, 8<<20+1)
	if err := WriteFrame(&bytes.Buffer{}, payload); err == nil {
		t.Fatal("frames above 8 MiB must be rejected")
	}
}
