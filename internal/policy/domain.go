package policy

import "strings"

// Domain is an allow/deny policy over cookie host names.
type Domain struct {
	Allow []string `toml:"allow"`
	Deny  []string `toml:"deny"`
}

func matches(host, entry string) bool {
	host = strings.TrimPrefix(host, ".")
	entry = strings.TrimPrefix(entry, ".")
	if host == entry {
		return true
	}
	return strings.HasSuffix(host, "."+entry)
}

func anyMatch(host string, entries []string) bool {
	for _, e := range entries {
		if matches(host, e) {
			return true
		}
	}
	return false
}

// Permit reports whether cookies for host may sync. Deny overrides Allow.
func (d Domain) Permit(host string) bool {
	if anyMatch(host, d.Deny) {
		return false
	}
	return anyMatch(host, d.Allow)
}
