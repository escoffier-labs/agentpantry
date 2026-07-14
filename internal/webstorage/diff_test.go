package webstorage

import "testing"

func TestDiffFromUpsertsChangesAndDeletes(t *testing.T) {
	prev := NewSnapshot([]Item{
		{Origin: "https://a.com", Key: "tok", Value: "1"},
		{Origin: "https://a.com", Key: "gone", Value: "x"},
	})
	cur := NewSnapshot([]Item{
		{Origin: "https://a.com", Key: "tok", Value: "CHANGED"}, // changed
		{Origin: "https://b.com", Key: "new", Value: "2"},       // new
	})
	d := cur.DiffFrom(prev)
	if len(d.Upserts) != 2 {
		t.Fatalf("upserts = %d, want 2 (changed + new): %+v", len(d.Upserts), d.Upserts)
	}
	if len(d.Deletes) != 1 || d.Deletes[0] != Key(Item{Origin: "https://a.com", Key: "gone"}) {
		t.Fatalf("deletes = %v, want [a.com\\x00gone]", d.Deletes)
	}
}

func TestDiffFromUnchangedIsEmpty(t *testing.T) {
	s := NewSnapshot([]Item{{Origin: "https://a.com", Key: "tok", Value: "1"}})
	if !s.DiffFrom(s).IsEmpty() {
		t.Fatal("diff of a snapshot against itself must be empty")
	}
}

func TestIsEmpty(t *testing.T) {
	if !(Diff{}).IsEmpty() {
		t.Fatal("zero diff must be empty")
	}
	if (Diff{Upserts: []Item{{Origin: "https://a.com", Key: "k", Value: "v"}}}).IsEmpty() {
		t.Fatal("populated diff must not be empty")
	}
}
