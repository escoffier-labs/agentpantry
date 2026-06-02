package policy

// Names is an exact-match allow/deny policy over secret names.
type Names struct {
	Allow []string `toml:"allow"`
	Deny  []string `toml:"deny"`
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

// Permit reports whether a secret named name may sync. Deny overrides Allow; an
// empty Allow permits all (the configured secrets_dir is the opt-in).
func (n Names) Permit(name string) bool {
	if contains(n.Deny, name) {
		return false
	}
	if len(n.Allow) == 0 {
		return true
	}
	return contains(n.Allow, name)
}
