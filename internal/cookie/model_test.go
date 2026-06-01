package cookie

import "testing"

func TestKeyIsStableAndUnique(t *testing.T) {
	a := Cookie{Host: "example.com", Name: "sid", Path: "/"}
	b := Cookie{Host: "example.com", Name: "sid", Path: "/"}
	c := Cookie{Host: "example.com", Name: "sid", Path: "/app"}

	if Key(a) != Key(b) {
		t.Fatalf("identical cookies must share a key: %q vs %q", Key(a), Key(b))
	}
	if Key(a) == Key(c) {
		t.Fatalf("different path must change key")
	}
}
