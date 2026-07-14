// Package webstorage models browser localStorage as origin-keyed items that sync
// alongside cookies and secrets in the same sealed frame. It is the twin of the
// cookie and secret packages. sessionStorage, IndexedDB, and other web storage
// are out of scope.
package webstorage

import "net/url"

// Item is one localStorage entry for one origin. Value is a session secret
// (tokens live here), so it is treated like a cookie value: never logged.
type Item struct {
	Origin string `json:"origin"` // scheme://host[:port], e.g. https://github.com
	Key    string `json:"key"`
	Value  string `json:"value"`
}

// Key identifies a localStorage slot by origin and key.
func Key(i Item) string { return i.Origin + "\x00" + i.Key }

// Snapshot is the set of localStorage items observed at one point in time,
// keyed by Key.
type Snapshot struct {
	Items map[string]Item
}

// NewSnapshot builds a Snapshot from a slice; a repeated origin+key keeps the
// last item so the result is deterministic.
func NewSnapshot(items []Item) Snapshot {
	m := make(map[string]Item, len(items))
	for _, it := range items {
		m[Key(it)] = it
	}
	return Snapshot{Items: m}
}

// OriginHost returns the hostname of an http(s) origin for domain-policy checks.
// It reports false for a non-http(s) origin (e.g. chrome-extension://) or one
// with no host, so such origins are dropped before they can sync.
func OriginHost(origin string) (string, bool) {
	u, err := url.Parse(origin)
	if err != nil {
		return "", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	host := u.Hostname()
	if host == "" {
		return "", false
	}
	return host, true
}
