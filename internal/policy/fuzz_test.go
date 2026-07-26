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

// refMatches restates the documented host/entry rule independently of matches():
// equality after trimming one leading dot from each side, or host being a
// dot-separated subdomain of entry. Nothing else is normalized, so a trailing
// dot is part of the label and an IDN never equals its punycode form.
func refMatches(host, entry string) bool {
	h := strings.TrimPrefix(host, ".")
	e := strings.TrimPrefix(entry, ".")
	return h == e || strings.HasSuffix(h, "."+e)
}

func refAnyMatch(host string, entries []string) bool {
	for _, e := range entries {
		if refMatches(host, e) {
			return true
		}
	}
	return false
}

func refContains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

// refPermitDomain is the full Domain contract: deny wins, and a host must match
// Allow to sync at all.
func refPermitDomain(host string, allow, deny []string) bool {
	if refAnyMatch(host, deny) {
		return false
	}
	return refAnyMatch(host, allow)
}

// refPermitNames is the full Names contract: deny wins, and an empty Allow
// permits everything (the configured secrets_dir is the opt-in).
func refPermitNames(name string, allow, deny []string) bool {
	if refContains(deny, name) {
		return false
	}
	return len(allow) == 0 || refContains(allow, name)
}

// denySeeds pairs each corpus entry with what it is meant to exercise, so a
// regression in matching shows up as a failed expectation rather than silently
// making the fuzz callback vacuous.
var denySeeds = []struct {
	desc, host, allowRaw, denyRaw string
	// wantDenyMatch is whether host is expected to match the deny list under
	// Domain's subdomain rule.
	wantDenyMatch bool
}{
	{"empty lists", "github.com", "", "", false},
	{"leading-dot deny entry matches subdomain", "api.github.com", "github.com", ".github.com", true},
	// A trailing dot is not stripped, so an FQDN host matches neither list. That
	// fails closed for Domain, which requires an Allow match.
	{"trailing dot on host does not match", "example.com.", "", "example.com", false},
	{"trailing dot on deny entry does not match", "sub.example.com", "", "example.com.", false},
	// IDN and punycode are distinct strings; no Unicode normalization happens.
	{"IDN matches itself", "münchen.de", "münchen.de", "münchen.de", true},
	{"punycode does not match its IDN form", "xn--mnchen-3ya.de", "", "münchen.de", false},
	{"deny wins over an identical allow", "secret.example.com", "secret.example.com", "secret.example.com", true},
	{"deny wins over two matching allow entries", "api.github.com", ".github.com\x00github.com", "github.com", true},
}

// TestDenyWinsSeedsMatchAsIntended pins the matching behavior each fuzz seed is
// chosen to cover. Without it, a regression in matches() would turn those seeds
// into no-ops inside FuzzDenyWins instead of failing.
func TestDenyWinsSeedsMatchAsIntended(t *testing.T) {
	for _, s := range denySeeds {
		deny := splitEntries(s.denyRaw)
		if got := anyMatch(s.host, deny); got != s.wantDenyMatch {
			t.Errorf("%s: anyMatch(%q, %v) = %v, want %v", s.desc, s.host, deny, got, s.wantDenyMatch)
		}
		if !s.wantDenyMatch {
			continue
		}
		d := Domain{Allow: splitEntries(s.allowRaw), Deny: deny}
		if d.Permit(s.host) {
			t.Errorf("%s: Domain.Permit(%q) = true, want false (deny wins)", s.desc, s.host)
		}
	}
}

// FuzzDenyWins checks Domain.Permit and Names.Permit against reference
// implementations of their documented contracts. Asserting the whole contract
// rather than only the deny half keeps the callback from going vacuous: every
// input exercises an equality, and a regression in matches() or contains()
// makes the two sides disagree.
func FuzzDenyWins(f *testing.F) {
	for _, s := range denySeeds {
		f.Add(s.host, s.allowRaw, s.denyRaw)
	}

	f.Fuzz(func(t *testing.T, host string, allowRaw string, denyRaw string) {
		allow := splitEntries(allowRaw)
		deny := splitEntries(denyRaw)

		d := Domain{Allow: allow, Deny: deny}
		if got, want := d.Permit(host), refPermitDomain(host, allow, deny); got != want {
			t.Fatalf("Domain.Permit(%q) = %v, want %v: allow=%v deny=%v", host, got, want, allow, deny)
		}
		if refAnyMatch(host, deny) && d.Permit(host) {
			t.Fatalf("Domain deny-wins violated: host=%q allow=%v deny=%v", host, allow, deny)
		}

		n := Names{Allow: allow, Deny: deny}
		if got, want := n.Permit(host), refPermitNames(host, allow, deny); got != want {
			t.Fatalf("Names.Permit(%q) = %v, want %v: allow=%v deny=%v", host, got, want, allow, deny)
		}
		if refContains(deny, host) && n.Permit(host) {
			t.Fatalf("Names deny-wins violated: name=%q allow=%v deny=%v", host, allow, deny)
		}
	})
}
