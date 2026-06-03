package surface

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/secret"
)

func TestSecretDirWriteDeleteAndPerms(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")
	s, err := NewSecretDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ApplySecrets(secret.Diff{Upserts: []secret.Secret{{Name: "gh", Value: "tok"}}}); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "gh")
	data, err := os.ReadFile(p)
	if err != nil || string(data) != "tok" {
		t.Fatalf("secret not written: %v / %q", err, data)
	}
	info, _ := os.Stat(p)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("secret file must be 0600, got %v", info.Mode().Perm())
	}
	if err := s.ApplySecrets(secret.Diff{Deletes: []string{"gh"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("secret file should be deleted")
	}
}

func TestSecretDirTightensExistingPerms(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "gh")
	if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := NewSecretDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ApplySecrets(secret.Diff{Upserts: []secret.Secret{{Name: "gh", Value: "tok"}}}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("secret file must be tightened to 0600, got %v", info.Mode().Perm())
	}
}

func TestSecretDirTightensExistingDirPerms(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSecretDir(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("secret dir must be tightened to 0700, got %v", info.Mode().Perm())
	}
}

func TestSecretDirRefusesExistingSymlink(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")
	s, err := NewSecretDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "gh")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := s.ApplySecrets(secret.Diff{Upserts: []secret.Secret{{Name: "gh", Value: "tok"}}}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "keep" {
		t.Fatalf("symlink target was overwritten: %q", data)
	}
}

func TestSecretDirRejectsUnsafeNames(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")
	s, _ := NewSecretDir(dir)
	// traversal attempt must be skipped, not written outside the dir.
	err := s.ApplySecrets(secret.Diff{Upserts: []secret.Secret{
		{Name: "../evil", Value: "x"},
		{Name: "a/b", Value: "y"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "evil")); !os.IsNotExist(err) {
		t.Fatal("traversal escaped the secrets dir")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("no unsafe-named secrets should be written, found %d", len(entries))
	}
}

func TestSecretDirSkipsNulNameWithoutError(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")
	s, err := NewSecretDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	err = s.ApplySecrets(secret.Diff{Upserts: []secret.Secret{
		{Name: "bad\x00name", Value: "x"},
		{Name: "good", Value: "ok"},
	}})
	if err != nil {
		t.Fatalf("one bad secret must not fail the whole apply: %v", err)
	}
	good, err := os.ReadFile(filepath.Join(dir, "good"))
	if err != nil || string(good) != "ok" {
		t.Fatalf("valid secret should still be written: %v / %q", err, good)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("only the valid secret should be written, found %d", len(entries))
	}
}
