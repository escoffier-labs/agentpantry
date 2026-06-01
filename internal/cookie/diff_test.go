package cookie

import "testing"

func TestDiffFromDetectsUpsertsAndDeletes(t *testing.T) {
	prev := NewSnapshot([]Cookie{
		{Host: "a.com", Name: "x", Path: "/", Value: "1"},
		{Host: "b.com", Name: "y", Path: "/", Value: "2"},
	})
	cur := NewSnapshot([]Cookie{
		{Host: "a.com", Name: "x", Path: "/", Value: "CHANGED"}, // upsert (value changed)
		{Host: "c.com", Name: "z", Path: "/", Value: "3"},       // upsert (new)
		// b.com/y removed -> delete
	})

	d := cur.DiffFrom(prev)

	if len(d.Upserts) != 2 {
		t.Fatalf("want 2 upserts, got %d", len(d.Upserts))
	}
	if len(d.Deletes) != 1 || d.Deletes[0] != Key(Cookie{Host: "b.com", Name: "y", Path: "/"}) {
		t.Fatalf("want delete of b.com/y, got %v", d.Deletes)
	}
}

func TestDiffFromNilPrevTreatsAllAsUpserts(t *testing.T) {
	cur := NewSnapshot([]Cookie{{Host: "a.com", Name: "x", Path: "/"}})
	d := cur.DiffFrom(Snapshot{})
	if len(d.Upserts) != 1 || len(d.Deletes) != 0 {
		t.Fatalf("want 1 upsert 0 deletes, got %d/%d", len(d.Upserts), len(d.Deletes))
	}
}
