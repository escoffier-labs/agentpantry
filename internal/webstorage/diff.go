package webstorage

// Diff describes the change from a previous snapshot to the current one.
type Diff struct {
	Upserts []Item   `json:"upserts"`
	Deletes []string `json:"deletes"` // Key() values
}

// IsEmpty reports whether the diff carries no changes.
func (d Diff) IsEmpty() bool {
	return len(d.Upserts) == 0 && len(d.Deletes) == 0
}

// DiffFrom returns the changes needed to turn prev into s.
func (s Snapshot) DiffFrom(prev Snapshot) Diff {
	var d Diff
	for k, it := range s.Items {
		old, ok := prev.Items[k]
		if !ok || old != it {
			d.Upserts = append(d.Upserts, it)
		}
	}
	for k := range prev.Items {
		if _, ok := s.Items[k]; !ok {
			d.Deletes = append(d.Deletes, k)
		}
	}
	return d
}
