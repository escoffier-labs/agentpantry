package cookie

// Cookie is the normalized, decrypted form that crosses the vault boundary.
type Cookie struct {
	Host       string `json:"host"`
	Name       string `json:"name"`
	Value      string `json:"value"`
	Path       string `json:"path"`
	ExpiresUTC int64  `json:"expires_utc"`
	IsSecure   bool   `json:"is_secure"`
	IsHTTPOnly bool   `json:"is_httponly"`
	SameSite   int    `json:"samesite"`
}

// Key uniquely identifies a cookie slot by host, name, and path.
func Key(c Cookie) string {
	return c.Host + "\x00" + c.Name + "\x00" + c.Path
}

// Snapshot is the set of cookies observed at one point in time, keyed by Key.
type Snapshot struct {
	Cookies map[string]Cookie
}

// NewSnapshot builds a Snapshot from a slice of cookies.
func NewSnapshot(cs []Cookie) Snapshot {
	m := make(map[string]Cookie, len(cs))
	for _, c := range cs {
		m[Key(c)] = c
	}
	return Snapshot{Cookies: m}
}
