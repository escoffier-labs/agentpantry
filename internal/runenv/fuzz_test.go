package runenv

import (
	"strings"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/policy"
	"github.com/escoffier-labs/agentpantry/internal/secret"
)

func FuzzSanitizeEnvName(f *testing.F) {
	for _, s := range []string{"gh_token", "123", "a-b", "_", "Ä", "", "already_OK"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		env, err := SanitizeEnvName(name)
		if err != nil {
			if name != "" {
				t.Fatalf("SanitizeEnvName(%q) unexpectedly failed: %v", name, err)
			}
			return
		}
		if !ValidEnvName(env) {
			t.Fatalf("SanitizeEnvName(%q) = %q, which is not a valid env name", name, env)
		}
	})
}

func FuzzPlanDenyWins(f *testing.F) {
	f.Add("gh_token", "tok", "", "gh_token")
	f.Add("keep", "v", "keep", "drop")
	f.Add("x", "y", "", "")
	f.Add("path", "/bin", "", "")
	f.Add("ld_preload", "x.so", "", "")
	f.Fuzz(func(t *testing.T, name, value, allowRaw, denyRaw string) {
		if name == "" || strings.IndexByte(name, 0) >= 0 {
			return
		}
		pol := policy.Names{Allow: splitEntries(allowRaw), Deny: splitEntries(denyRaw)}
		bindings, err := Plan([]secret.Secret{{Name: name, Value: value}}, pol, nil, nil)
		if err != nil {
			if pol.Permit(name) && strings.IndexByte(value, 0) < 0 {
				if env, serr := SanitizeEnvName(name); serr == nil && !ReservedEnvName(env) {
					t.Fatalf("Plan failed for permitted secret %q: %v", name, err)
				}
			}
			return
		}
		if env, serr := SanitizeEnvName(name); serr == nil && ReservedEnvName(env) {
			t.Fatalf("reserved env %s was injected from %q", env, name)
		}
		if !pol.Permit(name) && len(bindings) != 0 {
			t.Fatalf("denied secret %q was injected: %+v", name, bindings)
		}
		if pol.Permit(name) && strings.IndexByte(value, 0) < 0 {
			if len(bindings) != 1 || bindings[0].Name != name || bindings[0].Value != value {
				t.Fatalf("permitted secret not injected as-is: %+v", bindings)
			}
		}
	})
}

func splitEntries(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\x00")
}
