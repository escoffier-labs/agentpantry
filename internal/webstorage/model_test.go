package webstorage

import "testing"

func TestKeyAndNewSnapshotDedup(t *testing.T) {
	items := []Item{
		{Origin: "https://a.com", Key: "tok", Value: "1"},
		{Origin: "https://a.com", Key: "tok", Value: "2"}, // same slot, later wins
		{Origin: "https://b.com", Key: "tok", Value: "3"},
	}
	s := NewSnapshot(items)
	if len(s.Items) != 2 {
		t.Fatalf("snapshot size = %d, want 2 (deduped)", len(s.Items))
	}
	if got := s.Items[Key(Item{Origin: "https://a.com", Key: "tok"})].Value; got != "2" {
		t.Fatalf("a.com tok = %q, want 2 (last write wins)", got)
	}
}

func TestOriginHost(t *testing.T) {
	cases := []struct {
		origin   string
		wantHost string
		wantOK   bool
	}{
		{"https://github.com", "github.com", true},
		{"http://localhost:3000", "localhost", true},
		{"https://sub.example.com:443", "sub.example.com", true},
		{"chrome-extension://abcdef", "", false},
		{"about:blank", "", false},
		{"file:///etc/passwd", "", false},
		{"https://", "", false},
		{"not a url", "", false},
	}
	for _, tc := range cases {
		host, ok := OriginHost(tc.origin)
		if host != tc.wantHost || ok != tc.wantOK {
			t.Fatalf("OriginHost(%q) = (%q, %v), want (%q, %v)", tc.origin, host, ok, tc.wantHost, tc.wantOK)
		}
	}
}
