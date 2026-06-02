package state

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// State records what the source last did, for `status` to report.
type State struct {
	LastSyncUnix int64 `json:"last_sync_unix"` // last successful SyncOnce cycle
	LastSentUnix int64 `json:"last_sent_unix"` // last cycle that sent a frame
	Cookies      int   `json:"cookies"`        // cookie upserts in the last sent frame
	Secrets      int   `json:"secrets"`        // secret upserts in the last sent frame
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
	var s State
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return State{}, nil
		}
		return State{}, err
	}
	if len(b) == 0 {
		return State{}, nil
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return State{}, err
	}
	return s, nil
}

// Save writes state to path as 0600 JSON.
func Save(path string, s State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
