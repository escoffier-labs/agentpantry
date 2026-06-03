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
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
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

func TestGHHostsTightensExistingPerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.yml")
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("github.com:\n    oauth_token: old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	g, err := NewGHHosts(path, "gh_token", "github.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := g.ApplySecrets(secret.Diff{Upserts: []secret.Secret{{Name: "gh_token", Value: "ghp_new"}}}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("hosts file must be tightened to 0600, got %v", info.Mode().Perm())
	}
}

func TestGHHostsUpsertOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.yml")
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	g, _ := NewGHHosts(path, "gh_token", "github.com", "")
	// A delete (or unrelated secret) must not write anything.
	if err := g.ApplySecrets(secret.Diff{Deletes: []string{"gh_token"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("delete must not create the hosts file")
	}
}

func TestGHHostsRefusesToClobberUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	path := filepath.Join(t.TempDir(), "hosts.yml")
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, []byte("enterprise.example:\n    oauth_token: keep-me\n"), 0o600)
	os.Chmod(path, 0o000)
	t.Cleanup(func() { os.Chmod(path, 0o600) })

	g, _ := NewGHHosts(path, "gh_token", "github.com", "")
	err := g.ApplySecrets(secret.Diff{Upserts: []secret.Secret{{Name: "gh_token", Value: "ghp_new"}}})
	if err == nil {
		t.Fatal("must error on an unreadable existing file rather than clobber it")
	}
}
