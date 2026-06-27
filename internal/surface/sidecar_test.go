package surface

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	_ "modernc.org/sqlite"
)

func countRows(t *testing.T, path string) int {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM cookies`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSidecarApplyUpsertThenDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sidecar.db")
	s, err := NewSidecar(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	c := cookie.Cookie{Host: "a.com", Name: "x", Path: "/", Value: "1", IsSecure: true}
	if err := s.Apply(cookie.Diff{Upserts: []cookie.Cookie{c}}); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, path); n != 1 {
		t.Fatalf("after upsert want 1 row, got %d", n)
	}

	// Re-upsert same key with new value must not duplicate.
	c.Value = "2"
	if err := s.Apply(cookie.Diff{Upserts: []cookie.Cookie{c}}); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, path); n != 1 {
		t.Fatalf("after re-upsert want 1 row, got %d", n)
	}

	if err := s.Apply(cookie.Diff{Deletes: []string{cookie.Key(c)}}); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, path); n != 0 {
		t.Fatalf("after delete want 0 rows, got %d", n)
	}
}

func TestOpenSidecarReadOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sidecar.db")

	// Missing store: a not-exist error the caller can detect.
	if _, err := OpenSidecarReadOnly(path); !os.IsNotExist(err) {
		t.Fatalf("missing store want IsNotExist, got %v", err)
	}

	// Seed a real store, then read it back read-only.
	w, err := NewSidecar(path)
	if err != nil {
		t.Fatal(err)
	}
	c := cookie.Cookie{Host: "a.com", Name: "x", Path: "/", Value: "1", ExpiresUTC: 0}
	if err := w.Apply(cookie.Diff{Upserts: []cookie.Cookie{c}}); err != nil {
		t.Fatal(err)
	}
	w.Close()

	r, err := OpenSidecarReadOnly(path)
	if err != nil {
		t.Fatalf("open read-only: %v", err)
	}
	defer r.Close()
	got, err := r.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Host != "a.com" || got[0].Name != "x" {
		t.Fatalf("List returned %+v, want one a.com/x cookie", got)
	}

	// A regular SQLite file without a cookies table is not a sidecar store, and
	// opening it must not create the schema (read-only).
	other := filepath.Join(dir, "other.db")
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSidecarReadOnly(other); err == nil {
		t.Fatal("want error opening a non-sidecar file")
	}
	if info, _ := os.Stat(other); info.Size() != 0 {
		t.Fatalf("read-only open mutated a non-store file: size %d", info.Size())
	}
}

func TestOpenSidecarReadOnlyRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere.db")
	s, err := NewSidecar(target) // a real store behind the link
	if err != nil {
		t.Fatal(err)
	}
	s.Close() // release the handle so Windows can clean up the temp dir
	link := filepath.Join(dir, "link.db")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := OpenSidecarReadOnly(link); err == nil {
		t.Fatal("must refuse to open a sidecar through a symlink")
	}
}

func TestNewSidecarRefusesSymlinkPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere.db")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "sidecar.db")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := NewSidecar(path); err == nil {
		t.Fatal("must refuse to open the sidecar DB through a symlink")
	}
}
