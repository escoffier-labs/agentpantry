package webstorage

import (
	"strings"
	"testing"
)

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

func TestValidateOriginExactCanonicalContract(t *testing.T) {
	accepted := []string{
		"https://example.com",
		"http://example.com",
		"https://example.com:8443",
		"https://127.0.0.1",
		"https://[::1]",
		"http://example.com:8080",
		"https://192.0.2.1",
		"https://[2001:db8::1]",
	}
	rejected := []string{
		"https://user:secret@example.com",
		"https://example.com/path",
		"https://example.com?x=1",
		"https://example.com#frag",
		"https://example.com/",
		"HTTPS://example.com",
		"https://EXAMPLE.com",
		"https://example.com:443",
		"http://example.com:80",
		"https://example.com:0443",
		"http://example.com:080",
		"https://example.com:08443",
		"https://example.com:0",
		"http://example.com:65536",
		"https://éxample.com",
		"https://example.com.",
		"https://example..com",
		"https://.example.com",
		"https://127.0.0.01",
		"https://127.1",
		"https://2130706433",
		"https://0x7f000001",
		"https://256.0.0.1",
		// mixed-label hosts: numeric final label routes WHATWG parsing through IPv4
		"https://foo.123",
		"https://a.0x1",
		"https://[0:0:0:0:0:0:0:1]",
		"https://[::ffff:127.0.0.1]",
		"https://[::ffff:7f00:1]",
		"https://[::1%25eth0]",
		"blob:opaque",
		"file:///etc/passwd",
		"data:text/plain,hello",
		"about:blank",
		"ftp://example.com",
		"not-a-url",
	}
	for _, origin := range accepted {
		if err := ValidateOrigin(origin); err != nil {
			t.Errorf("accepted origin %q rejected: %v", origin, err)
		}
	}
	for _, origin := range rejected {
		err := ValidateOrigin(origin)
		if err == nil {
			t.Errorf("rejected origin %q must be rejected", origin)
			continue
		}
		msg := err.Error()
		if strings.Contains(msg, "secret") || strings.Contains(msg, "user") {
			t.Errorf("ValidateOrigin error leaked credential material: %v", err)
		}
		if strings.Contains(msg, origin) {
			t.Errorf("ValidateOrigin error echoed storage origin: %v", err)
		}
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
		{"https://example.com:8443", "example.com", true},
		{"https://192.0.2.1", "192.0.2.1", true},
		{"https://[2001:db8::1]", "2001:db8::1", true},
		{"https://127.0.0.1", "127.0.0.1", true},
		{"https://[::1]", "::1", true},
		{"https://user:secret@example.com", "", false},
		{"https://example.com/path", "", false},
		{"https://example.com?x=1", "", false},
		{"https://example.com#frag", "", false},
		{"https://example.com/", "", false},
		{"HTTPS://example.com", "", false},
		{"https://EXAMPLE.com", "", false},
		{"https://sub.example.com:443", "", false},
		{"https://[0:0:0:0:0:0:0:1]", "", false},
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
		if strings.Contains(tc.origin, "secret") || strings.Contains(tc.origin, "user:") {
			if ok {
				t.Fatalf("OriginHost accepted credentialed origin")
			}
			if strings.Contains(host, "secret") || strings.Contains(host, "user") {
				t.Fatalf("OriginHost leaked credential material in host %q", host)
			}
		}
	}
}
