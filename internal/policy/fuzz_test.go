package policy

import (
	"strings"
	"testing"
)

func splitEntries(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\x00")
}

// FuzzDenyWins exercises Domain.Permit and Names.Permit: whenever host/name
// matches a Deny entry, Permit must return false regardless of Allow.
func FuzzDenyWins(f *testing.F) {
	// empty lists — no deny match, invariant vacuously holds
	f.Add("github.com", "", "")
	// leading-dot deny entry matching a subdomain host
	f.Add("api.github.com", "github.com", ".github.com")
	// trailing dot on host and deny entry
	f.Add("example.com.", "", "example.com")
	f.Add("sub.example.com", "", "example.com.")
	// IDN / punycode shapes
	f.Add("münchen.de", "münchen.de", "münchen.de")
	f.Add("xn--mnchen-3ya.de", "", "xn--mnchen-3ya.de")
	// deny wins over allow when both match
	f.Add("secret.example.com", "secret.example.com", "secret.example.com")
	f.Add("api.github.com", ".github.com\x00github.com", "github.com")

	f.Fuzz(func(t *testing.T, host string, allowRaw string, denyRaw string) {
		allow := splitEntries(allowRaw)
		deny := splitEntries(denyRaw)

		d := Domain{Allow: allow, Deny: deny}
		if anyMatch(host, deny) && d.Permit(host) {
			t.Fatalf("Domain deny-wins violated: host=%q allow=%v deny=%v", host, allow, deny)
		}

		n := Names{Allow: allow, Deny: deny}
		if contains(deny, host) && n.Permit(host) {
			t.Fatalf("Names deny-wins violated: name=%q allow=%v deny=%v", host, allow, deny)
		}
	})
}
