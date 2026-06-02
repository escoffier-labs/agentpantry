package surface

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/escoffier-labs/agentpantry/internal/secret"
)

// OpenClawAuth merges provider profiles into an OpenClaw auth-profiles.json.
// The `profiles` field is an OBJECT keyed by "<provider>:default" (NOT an array).
type OpenClawAuth struct {
	path     string
	profiles map[string]string // secretName -> profileKey
}

func NewOpenClawAuth(path string, profiles map[string]string) (*OpenClawAuth, error) {
	if len(profiles) == 0 {
		return nil, fmt.Errorf("openclaw adapter requires a profiles mapping")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return &OpenClawAuth{path: path, profiles: profiles}, nil
}

func (o *OpenClawAuth) ApplySecrets(d secret.Diff) error {
	bySecret := map[string]string{}
	for _, s := range d.Upserts {
		bySecret[s.Name] = s.Value
	}

	doc := map[string]json.RawMessage{}
	if b, err := os.ReadFile(o.path); err == nil {
		if e := json.Unmarshal(b, &doc); e != nil {
			return fmt.Errorf("parse existing %s: %w", o.path, e)
		}
	} else if !os.IsNotExist(err) {
		// Refuse to clobber a file that exists but cannot be read.
		return fmt.Errorf("read existing %s: %w", o.path, err)
	}
	if doc == nil {
		doc = map[string]json.RawMessage{}
	}
	profiles := map[string]json.RawMessage{}
	if raw, ok := doc["profiles"]; ok {
		if e := json.Unmarshal(raw, &profiles); e != nil {
			return fmt.Errorf("parse profiles in %s: %w", o.path, e)
		}
	}

	skipped, changed := 0, false
	for secretName, profileKey := range o.profiles {
		val, ok := bySecret[secretName]
		if !ok {
			continue
		}
		if !json.Valid([]byte(val)) {
			skipped++
			continue
		}
		profiles[profileKey] = json.RawMessage(val)
		changed = true
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "agentpantry: skipped %d openclaw profile secret(s) with invalid JSON\n", skipped)
	}
	if !changed {
		return nil
	}

	pb, err := json.Marshal(profiles)
	if err != nil {
		return err
	}
	doc["profiles"] = pb
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(o.path, out, 0o600)
}
