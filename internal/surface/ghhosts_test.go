package surface

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/secret"
)

func TestGHHostsMergesPreservingOtherHosts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.yml")
	// Pre-existing file with an unrelated host.
	os.WriteFile(path, []byte("enterprise.example:\n    oauth_token: keep-me\n    user: someone\n"), 0o600)

	g, err := NewGHHosts(path, "gh_token", "github.com", "octocat")
	if err != nil {
		t.Fatal(err)
	}
	if err := g.ApplySecrets(secret.Diff{Upserts: []secret.Secret{{Name: "gh_token", Value: "ghp_new"}}}); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("want 0600, got %v", info.Mode().Perm())
	}
	body, _ := os.ReadFile(path)
	s := string(body)
	if !strings.Contains(s, "ghp_new") || !strings.Contains(s, "github.com") {
		t.Fatalf("token not written: %q", s)
	}
	if !strings.Contains(s, "keep-me") {
		t.Fatalf("unrelated host clobbered: %q", s)
	}
}

func TestGHHostsUpsertOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.yml")
	g, _ := NewGHHosts(path, "gh_token", "github.com", "")
	// A delete (or unrelated secret) must not write anything.
	if err := g.ApplySecrets(secret.Diff{Deletes: []string{"gh_token"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("delete must not create the hosts file")
	}
}
