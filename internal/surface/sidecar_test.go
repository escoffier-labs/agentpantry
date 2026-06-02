package surface

import (
	"database/sql"
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
