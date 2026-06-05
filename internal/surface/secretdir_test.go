package surface

import (
	"os"
	"path/filepath"
	"runtime"
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
	assertPerm(t, p, 0o600)
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
	assertPerm(t, p, 0o600)
}

func TestSecretDirTightensExistingDirPerms(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSecretDir(dir); err != nil {
		t.Fatal(err)
	}
	assertPerm(t, dir, 0o700)
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

func TestSecretDirReturnsWriteErrors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("read-only directory modes do not block writes on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	dir := filepath.Join(t.TempDir(), "secrets")
	s, err := NewSecretDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	err = s.ApplySecrets(secret.Diff{Upserts: []secret.Secret{{Name: "gh", Value: "tok"}}})
	if err == nil {
		t.Fatal("a real write failure must be reported, not silently skipped")
	}
}

func TestSecretDirReturnsDeleteErrors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("read-only directory modes do not block deletes on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	dir := filepath.Join(t.TempDir(), "secrets")
	s, err := NewSecretDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "gh"), []byte("tok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	err = s.ApplySecrets(secret.Diff{Deletes: []string{"gh"}})
	if err == nil {
		t.Fatal("a real delete failure must be reported, not silently skipped")
	}
}
