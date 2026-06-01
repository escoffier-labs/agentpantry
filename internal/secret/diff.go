package secret

// Diff describes the change from a previous snapshot to the current one.
type Diff struct {
	Upserts []Secret `json:"upserts"`
	Deletes []string `json:"deletes"` // Names
}

// IsEmpty reports whether the diff carries no changes.
func (d Diff) IsEmpty() bool {
	return len(d.Upserts) == 0 && len(d.Deletes) == 0
}

// DiffFrom returns the changes needed to turn prev into s.
func (s Snapshot) DiffFrom(prev Snapshot) Diff {
	var d Diff
	for k, v := range s.Secrets {
		old, ok := prev.Secrets[k]
		if !ok || old != v {
			d.Upserts = append(d.Upserts, v)
		}
	}
	for k := range prev.Secrets {
		if _, ok := s.Secrets[k]; !ok {
			d.Deletes = append(d.Deletes, k)
		}
	}
	return d
}
