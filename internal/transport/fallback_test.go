package transport

import (
	"bytes"
	"testing"
)

func oldKey32() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(200 - i)
	}
	return k
}

func thirdKey32() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(7 * i)
	}
	return k
}

func TestFallbackOpenerPrimaryKey(t *testing.T) {
	s, _ := NewSealer(key32(), salt16())
	fallbacks := 0
	o, err := NewFallbackOpener(key32(), oldKey32(), salt16())
	if err != nil {
		t.Fatal(err)
	}
	o.OnFallback = func() { fallbacks++ }
	msg := []byte("fresh key")
	frame, _ := s.Seal(msg)
	out, err := o.Open(frame)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, msg) {
		t.Fatalf("round trip mismatch: %q", out)
	}
	if fallbacks != 0 {
		t.Fatalf("primary-key session must not fire OnFallback, fired %d times", fallbacks)
	}
}

func TestFallbackOpenerOldKeyFiresOnFallbackOnce(t *testing.T) {
	s, _ := NewSealer(oldKey32(), salt16())
	fallbacks := 0
	o, err := NewFallbackOpener(key32(), oldKey32(), salt16())
	if err != nil {
		t.Fatal(err)
	}
	o.OnFallback = func() { fallbacks++ }
	for i, msg := range [][]byte{[]byte("one"), []byte("two"), []byte("three")} {
		frame, _ := s.Seal(msg)
		out, err := o.Open(frame)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if !bytes.Equal(out, msg) {
			t.Fatalf("frame %d mismatch: %q", i, out)
		}
	}
	if fallbacks != 1 {
		t.Fatalf("OnFallback must fire exactly once per session, fired %d times", fallbacks)
	}
}

func TestFallbackOpenerRejectsThirdKey(t *testing.T) {
	s, _ := NewSealer(thirdKey32(), salt16())
	o, _ := NewFallbackOpener(key32(), oldKey32(), salt16())
	frame, _ := s.Seal([]byte("intruder"))
	if _, err := o.Open(frame); err == nil {
		t.Fatal("frame under an unknown key must not open")
	}
}

func TestFallbackOpenerNoSwitchAfterPinningPrimary(t *testing.T) {
	newSealer, _ := NewSealer(key32(), salt16())
	oldSealer, _ := NewSealer(oldKey32(), salt16())
	o, _ := NewFallbackOpener(key32(), oldKey32(), salt16())

	f1, _ := newSealer.Seal([]byte("pin to primary"))
	if _, err := o.Open(f1); err != nil {
		t.Fatal(err)
	}
	// Advance the old sealer's counter past the opener's so a counter check
	// alone cannot be what rejects it.
	_, _ = oldSealer.Seal([]byte("skip"))
	f2, _ := oldSealer.Seal([]byte("late old-key frame"))
	if _, err := o.Open(f2); err == nil {
		t.Fatal("session pinned to the primary key must reject old-key frames")
	}
}

func TestFallbackOpenerReplayRejectedAfterPinning(t *testing.T) {
	s, _ := NewSealer(oldKey32(), salt16())
	o, _ := NewFallbackOpener(key32(), oldKey32(), salt16())
	f1, _ := s.Seal([]byte("one"))
	if _, err := o.Open(f1); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Open(f1); err == nil {
		t.Fatal("replayed frame must be rejected after pinning to the fallback key")
	}
}

func TestFallbackOpenerProbeDoesNotAdvanceCounters(t *testing.T) {
	// A failed probe against the primary opener must not consume the frame's
	// counter there: a session that pins the fallback key after several frames
	// would otherwise diverge from single-opener replay semantics.
	s, _ := NewSealer(oldKey32(), salt16())
	o, _ := NewFallbackOpener(key32(), oldKey32(), salt16())
	for i := 0; i < 3; i++ {
		frame, _ := s.Seal([]byte("probe"))
		if _, err := o.Open(frame); err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
	}
}

func TestNewFallbackOpenerRejectsBadKeys(t *testing.T) {
	if _, err := NewFallbackOpener([]byte("short"), oldKey32(), salt16()); err == nil {
		t.Fatal("short primary key must error")
	}
	if _, err := NewFallbackOpener(key32(), []byte("short"), salt16()); err == nil {
		t.Fatal("short fallback key must error")
	}
}
