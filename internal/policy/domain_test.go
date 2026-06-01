package policy

import "testing"

func TestPermit(t *testing.T) {
	d := Domain{
		Allow: []string{"github.com", "example.com"},
		Deny:  []string{"secret.example.com"},
	}
	cases := map[string]bool{
		"github.com":         true,
		"api.github.com":     true,  // subdomain of allowed
		"example.com":        true,
		"secret.example.com": false, // denied explicitly
		"bank.com":           false, // not in allow
		"notgithub.com":      false, // not a dot-boundary subdomain
	}
	for host, want := range cases {
		if got := d.Permit(host); got != want {
			t.Errorf("Permit(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestEmptyAllowPermitsNothing(t *testing.T) {
	if (Domain{}).Permit("github.com") {
		t.Fatal("empty allow list must permit nothing")
	}
}
