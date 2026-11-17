package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/privfile"
)

// TombstoneTTL bounds replay lifetime. Capacity eviction can shorten it.
const TombstoneTTL = 7 * 24 * time.Hour

// MaxTombstones bounds retained deletion names.
const MaxTombstones = 1000

// MaxStateBytes bounds serialized state, including its binding and names.
const MaxStateBytes = 4 << 20

// Tombstone retains a deleted name for bounded replay after a lost sink apply.
type Tombstone struct {
	Name        string `json:"name"`
	ExpiresUnix int64  `json:"expires_unix"`
}

// State holds status and bound deletion metadata. It never holds secret values.
type State struct {
	Binding         *Binding    `json:"binding,omitempty"`
	Tombstones      []Tombstone `json:"tombstones,omitempty"`
	ExportedSecrets []string    `json:"exported_secrets"` // sorted names only, after a successful secret commit
	LastSyncUnix    int64       `json:"last_sync_unix"`   // last successful SyncOnce cycle
	LastSentUnix    int64       `json:"last_sent_unix"`   // last cycle that sent a frame
	Cookies         int         `json:"cookies"`          // cookie upserts in the last sent frame
	Secrets         int         `json:"secrets"`          // secret upserts in the last sent frame
	Storage         int         `json:"storage"`          // localStorage upserts in the last sent frame
}

// Clock yields the current time; injected so tests are deterministic.
type Clock interface {
	Now() time.Time
}

// RealClock is the production clock.
type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now() }

// Load reads state from path. A missing file is the zero value, not an error.
func Load(path string) (State, error) {
	f, err := os.Open(path) // #nosec G304 -- state path is derived from the operator-selected config path.
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return State{}, nil
		}
		return State{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return State{}, err
	}
	if !info.Mode().IsRegular() {
		return State{}, errors.New("source state must be a regular file")
	}
	if info.Size() > MaxStateBytes {
		return State{}, errors.New("source state exceeds 4 MiB limit")
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxStateBytes+1))
	if err != nil {
		return State{}, err
	}

	return decode(b)
}

func decode(b []byte) (State, error) {
	var s State
	if len(b) > MaxStateBytes {
		return State{}, errors.New("source state exceeds 4 MiB limit")
	}
	b = bytes.TrimSpace(b)
	if len(b) == 0 || b[0] != '{' {
		return State{}, errors.New("invalid source state object")
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return State{}, err
	}

	var dropped int
	s.Tombstones, dropped = CapTombstones(s.Tombstones)
	WarnDroppedTombstones(dropped)
	return s, nil
}

// Save writes state to path as 0600 JSON.
func Save(path string, s State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	s.ExportedSecrets = append([]string{}, s.ExportedSecrets...)
	sort.Strings(s.ExportedSecrets)
	var dropped int
	s.Tombstones, dropped = CapTombstones(s.Tombstones)
	sort.Slice(s.Tombstones, func(i, j int) bool { return s.Tombstones[i].Name < s.Tombstones[j].Name })
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if len(b) > MaxStateBytes {
		return errors.New("source state exceeds 4 MiB limit")
	}
	if err := privfile.Write(path, b); err != nil {
		return err
	}
	WarnDroppedTombstones(dropped)
	return nil
}

// CapTombstones retains the newest first-send deadlines with deterministic ties.
func CapTombstones(in []Tombstone) ([]Tombstone, int) {
	out := append([]Tombstone(nil), in...)
	if len(out) <= MaxTombstones {
		return out, 0
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ExpiresUnix == out[j].ExpiresUnix {
			return out[i].Name < out[j].Name
		}
		return out[i].ExpiresUnix < out[j].ExpiresUnix
	})
	dropped := len(out) - MaxTombstones
	return append([]Tombstone(nil), out[dropped:]...), dropped
}
func WarnDroppedTombstones(count int) {
	if count > 0 {
		fmt.Fprintf(os.Stderr, "agentpantry: warning: dropped %d oldest secret deletion tombstone(s), limit %d\n", count, MaxTombstones)
	}
}
