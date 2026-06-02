package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fixedClock struct{ t time.Time }

func (f fixedClock) Now() time.Time { return f.t }

func TestSaveLoadRoundTripAndPerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	in := State{LastSyncUnix: 1700000000, LastSentUnix: 1700000000, Cookies: 3, Secrets: 1}
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state file must be 0600, got %v", info.Mode().Perm())
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("round trip mismatch: %+v vs %+v", out, in)
	}
}

func TestLoadMissingIsZeroValue(t *testing.T) {
	out, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("missing state must not error, got %v", err)
	}
	if out != (State{}) {
		t.Fatalf("missing state must be zero value, got %+v", out)
	}
}

func TestRealClockNonZero(t *testing.T) {
	if (RealClock{}).Now().IsZero() {
		t.Fatal("real clock must return a real time")
	}
}
