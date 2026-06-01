package secret

// Secret is a named secret value carried separately from cookies.
type Secret struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Key identifies a secret by name.
func Key(s Secret) string { return s.Name }

// Snapshot is the set of secrets at one point in time, keyed by Name.
type Snapshot struct {
	Secrets map[string]Secret
}

// NewSnapshot builds a Snapshot from a slice.
func NewSnapshot(ss []Secret) Snapshot {
	m := make(map[string]Secret, len(ss))
	for _, s := range ss {
		m[Key(s)] = s
	}
	return Snapshot{Secrets: m}
}
