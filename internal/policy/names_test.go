package policy

import "testing"

func TestNamesPermit(t *testing.T) {
	d := Names{Deny: []string{"bad"}}
	if !d.Permit("anything") {
		t.Fatal("empty allow must permit all")
	}
	if d.Permit("bad") {
		t.Fatal("deny must block")
	}
	a := Names{Allow: []string{"gh_token"}, Deny: []string{"gh_token"}}
	if a.Permit("gh_token") {
		t.Fatal("deny overrides allow")
	}
	w := Names{Allow: []string{"gh_token"}}
	if !w.Permit("gh_token") || w.Permit("other") {
		t.Fatal("non-empty allow is a whitelist")
	}
}
