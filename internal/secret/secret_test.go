package secret

import "testing"

func TestDiffFromUpsertsAndDeletes(t *testing.T) {
	prev := NewSnapshot([]Secret{{Name: "gh", Value: "1"}, {Name: "npm", Value: "2"}})
	cur := NewSnapshot([]Secret{{Name: "gh", Value: "CHANGED"}, {Name: "aws", Value: "3"}})
	d := cur.DiffFrom(prev)
	if len(d.Upserts) != 2 {
		t.Fatalf("want 2 upserts, got %d", len(d.Upserts))
	}
	if len(d.Deletes) != 1 || d.Deletes[0] != "npm" {
		t.Fatalf("want delete npm, got %v", d.Deletes)
	}
}

func TestIsEmpty(t *testing.T) {
	if !(Diff{}).IsEmpty() {
		t.Fatal("zero diff must be empty")
	}
}
