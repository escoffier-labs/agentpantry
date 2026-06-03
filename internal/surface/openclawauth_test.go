package surface

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/secret"
)

func TestOpenClawAuthMergesProfileObject(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth-profiles.json")
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	// Existing file with another profile that must survive.
	os.WriteFile(path, []byte(`{"profiles":{"openai-codex:default":{"type":"oauth"}}}`), 0o600)

	o, err := NewOpenClawAuth(path, map[string]string{"anthropic_secret": "anthropic:default"})
	if err != nil {
		t.Fatal(err)
	}
	val := `{"type":"oauth","token":"sk-ant-xyz"}`
	if err := o.ApplySecrets(secret.Diff{Upserts: []secret.Secret{{Name: "anthropic_secret", Value: val}}}); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("want 0600, got %v", info.Mode().Perm())
	}
	b, _ := os.ReadFile(path)
	var doc struct {
		Profiles map[string]json.RawMessage `json:"profiles"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc.Profiles["openai-codex:default"]; !ok {
		t.Fatal("existing profile clobbered")
	}
	if _, ok := doc.Profiles["anthropic:default"]; !ok {
		t.Fatal("new profile not written")
	}
}

func TestOpenClawAuthTightensExistingPerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth-profiles.json")
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"profiles":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	o, err := NewOpenClawAuth(path, map[string]string{"anthropic_secret": "anthropic:default"})
	if err != nil {
		t.Fatal(err)
	}
	if err := o.ApplySecrets(secret.Diff{Upserts: []secret.Secret{{Name: "anthropic_secret", Value: `{"type":"oauth"}`}}}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("auth file must be tightened to 0600, got %v", info.Mode().Perm())
	}
}

func TestOpenClawAuthSkipsInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth-profiles.json")
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	o, _ := NewOpenClawAuth(path, map[string]string{"bad": "x:default"})
	if err := o.ApplySecrets(secret.Diff{Upserts: []secret.Secret{{Name: "bad", Value: "not json"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("invalid-JSON secret must not write a file")
	}
}

func TestOpenClawAuthRefusesToClobberUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	path := filepath.Join(t.TempDir(), "auth-profiles.json")
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, []byte(`{"profiles":{"openai-codex:default":{"type":"oauth"}}}`), 0o600)
	os.Chmod(path, 0o000)
	t.Cleanup(func() { os.Chmod(path, 0o600) })

	o, _ := NewOpenClawAuth(path, map[string]string{"anthropic_secret": "anthropic:default"})
	err := o.ApplySecrets(secret.Diff{Upserts: []secret.Secret{{Name: "anthropic_secret", Value: `{"type":"oauth"}`}}})
	if err == nil {
		t.Fatal("must error on an unreadable existing file rather than clobber it")
	}
}
