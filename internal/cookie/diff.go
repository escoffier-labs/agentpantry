package cookie

// Diff describes the change from a previous snapshot to the current one.
type Diff struct {
	Upserts []Cookie `json:"upserts"`
	Deletes []string `json:"deletes"` // Key() values
}

// IsEmpty reports whether the diff carries no changes.
func (d Diff) IsEmpty() bool {
	return len(d.Upserts) == 0 && len(d.Deletes) == 0
}

// DiffFrom returns the changes needed to turn prev into s.
func (s Snapshot) DiffFrom(prev Snapshot) Diff {
	var d Diff
	for k, c := range s.Cookies {
		old, ok := prev.Cookies[k]
		if !ok || old != c {
			d.Upserts = append(d.Upserts, c)
		}
	}
	for k := range prev.Cookies {
		if _, ok := s.Cookies[k]; !ok {
			d.Deletes = append(d.Deletes, k)
		}
	}
	return d
}
