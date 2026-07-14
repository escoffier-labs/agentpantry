package surface

import (
	"path/filepath"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/webstorage"
)

func TestSidecarStorageRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sidecar.db")
	s, err := NewSidecar(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.ApplyStorage(webstorage.Diff{Upserts: []webstorage.Item{
		{Origin: "https://a.com", Key: "k", Value: "v"},
		{Origin: "https://a.com", Key: "k2", Value: "v2"},
		{Origin: "https://b.com", Key: "x", Value: "y"},
	}}); err != nil {
		t.Fatal(err)
	}
	items, err := s.ListStorage()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Fatalf("ListStorage = %d items, want 3", len(items))
	}

	// Update one, delete another.
	if err := s.ApplyStorage(webstorage.Diff{
		Upserts: []webstorage.Item{{Origin: "https://a.com", Key: "k", Value: "CHANGED"}},
		Deletes: []string{webstorage.Key(webstorage.Item{Origin: "https://a.com", Key: "k2"})},
	}); err != nil {
		t.Fatal(err)
	}
	items, err = s.ListStorage()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, it := range items {
		got[it.Origin+"|"+it.Key] = it.Value
	}
	if len(got) != 2 || got["https://a.com|k"] != "CHANGED" || got["https://b.com|x"] != "y" {
		t.Fatalf("after update+delete: %v", got)
	}
	if _, gone := got["https://a.com|k2"]; gone {
		t.Fatal("deleted item still present")
	}
}

// An older sidecar that predates the localstorage table must read as empty, not
// error, so a read path (restore/inventory) still works against it.
func TestSidecarListStorageMissingTableEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sidecar.db")
	s, err := NewSidecar(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() // close before TempDir cleanup; Windows cannot delete an open file
	if _, err := s.db.Exec(`DROP TABLE localstorage`); err != nil {
		t.Fatal(err)
	}
	items, err := s.ListStorage()
	if err != nil {
		t.Fatalf("ListStorage on a table-less sidecar must not error: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("want 0 items, got %d", len(items))
	}
}
