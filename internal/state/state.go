package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/privfile"
)

// State records source status and the names last exported. Secret values never belong here.
type State struct {
	ExportedSecrets []string `json:"exported_secrets"` // sorted names only, after a successful secret commit
	LastSyncUnix    int64    `json:"last_sync_unix"`   // last successful SyncOnce cycle
	LastSentUnix    int64    `json:"last_sent_unix"`   // last cycle that sent a frame
	Cookies         int      `json:"cookies"`          // cookie upserts in the last sent frame
	Secrets         int      `json:"secrets"`          // secret upserts in the last sent frame
	Storage         int      `json:"storage"`          // localStorage upserts in the last sent frame
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
	b, err := os.ReadFile(path) // #nosec G304 -- state path is derived from the operator-selected config path.
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return State{}, nil
		}
		return State{}, err
	}
	return decode(b)
}

func decode(b []byte) (State, error) {
	var s State
	b = bytes.TrimSpace(b)
	if len(b) == 0 || b[0] != '{' {
		return State{}, errors.New("invalid source state object")
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
	s.ExportedSecrets = append([]string{}, s.ExportedSecrets...)
	sort.Strings(s.ExportedSecrets)
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return privfile.Write(path, b)
}
