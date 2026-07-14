package surface

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/privfile"
	"github.com/escoffier-labs/agentpantry/internal/webstorage"
)

// storageStateCookie is one cookie in a Playwright/Puppeteer storageState file.
// Expires is Unix seconds, or -1 for a session cookie, matching Playwright's
// own output. SameSite is "Strict", "Lax", or "None".
type storageStateCookie struct {
	Name     string  `json:"name"`
	Value    string  `json:"value"`
	Domain   string  `json:"domain"`
	Path     string  `json:"path"`
	Expires  float64 `json:"expires"`
	HTTPOnly bool    `json:"httpOnly"`
	Secure   bool    `json:"secure"`
	SameSite string  `json:"sameSite"`
}

// storageStateKV is one localStorage entry in a storageState origin.
type storageStateKV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// storageStateOrigin is one origin's localStorage in a storageState file.
type storageStateOrigin struct {
	Origin       string           `json:"origin"`
	LocalStorage []storageStateKV `json:"localStorage"`
}

// storageStateFile is the on-disk Playwright storageState shape consumed by
// browser.newContext({ storageState }).
type storageStateFile struct {
	Cookies []storageStateCookie `json:"cookies"`
	Origins []storageStateOrigin `json:"origins"`
}

// StorageState writes a Playwright/Puppeteer storageState JSON file so a headless
// or headed automation browser wakes up authenticated without replaying a login.
// It manages both the cookies array and the origins (localStorage) array, and
// seeds from its own file so a restart keeps rows the source has not re-sent.
type StorageState struct {
	path    string
	cookies map[string]storageStateCookie // keyed by cookie.Key
	origins map[string]map[string]string  // origin -> (localStorage key -> value)
}

// NewStorageState opens (and seeds from) a storageState file at path, creating
// nothing until the first Apply.
func NewStorageState(path string) (*StorageState, error) {
	if err := ensureSafeOutputDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	s := &StorageState{
		path:    path,
		cookies: map[string]storageStateCookie{},
		origins: map[string]map[string]string{},
	}
	if err := s.seed(); err != nil {
		return nil, err
	}
	return s, nil
}

// seed loads an existing storageState so a sink restart does not drop entries the
// source has not re-sent and a restore merges into, rather than clobbers, a file
// another automation run wrote. A non-JSON file is refused rather than
// overwritten, so pointing --to at the wrong path fails loudly.
func (s *StorageState) seed() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil // an empty file (e.g. touch'd) starts fresh
	}
	var f storageStateFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("existing %s is not a storageState JSON file; refusing to overwrite it: %w", s.path, err)
	}
	for _, c := range f.Cookies {
		s.cookies[storageKey(c)] = c
	}
	for _, o := range f.Origins {
		if o.Origin == "" {
			continue
		}
		m := s.origins[o.Origin]
		if m == nil {
			m = map[string]string{}
			s.origins[o.Origin] = m
		}
		for _, kv := range o.LocalStorage {
			m[kv.Name] = kv.Value
		}
	}
	return nil
}

func storageKey(c storageStateCookie) string {
	return cookie.Key(cookie.Cookie{Host: c.Domain, Name: c.Name, Path: c.Path})
}

func toStorageStateCookie(c cookie.Cookie) storageStateCookie {
	expires := float64(-1) // Playwright's sentinel for a session cookie
	if c.ExpiresUTC > 0 {
		expires = float64(cookie.ExpiresUnix(c.ExpiresUTC))
	}
	return storageStateCookie{
		Name:     c.Name,
		Value:    c.Value,
		Domain:   c.Host,
		Path:     c.Path,
		Expires:  expires,
		HTTPOnly: c.IsHTTPOnly,
		Secure:   c.IsSecure,
		SameSite: sameSiteName(c.SameSite),
	}
}

func sameSiteName(code int) string {
	switch code {
	case 2:
		return "Strict"
	case 1:
		return "Lax"
	default:
		return "None"
	}
}

// Apply upserts and deletes cookies, then rewrites the file.
func (s *StorageState) Apply(d cookie.Diff) error {
	for _, c := range d.Upserts {
		sc := toStorageStateCookie(c)
		s.cookies[storageKey(sc)] = sc
	}
	for _, k := range d.Deletes {
		delete(s.cookies, k)
	}
	return s.write()
}

// ApplyStorage upserts and deletes localStorage entries by origin, then rewrites
// the file, so a synced session's origins[].localStorage is materialized for
// Playwright/Puppeteer to restore.
func (s *StorageState) ApplyStorage(d webstorage.Diff) error {
	for _, it := range d.Upserts {
		m := s.origins[it.Origin]
		if m == nil {
			m = map[string]string{}
			s.origins[it.Origin] = m
		}
		m[it.Key] = it.Value
	}
	for _, k := range d.Deletes {
		origin, key, ok := strings.Cut(k, "\x00")
		if !ok {
			continue
		}
		if m := s.origins[origin]; m != nil {
			delete(m, key)
			if len(m) == 0 {
				delete(s.origins, origin)
			}
		}
	}
	return s.write()
}

func (s *StorageState) write() error {
	cookieKeys := make([]string, 0, len(s.cookies))
	for k := range s.cookies {
		cookieKeys = append(cookieKeys, k)
	}
	sort.Strings(cookieKeys)
	cookies := make([]storageStateCookie, 0, len(cookieKeys))
	for _, k := range cookieKeys {
		cookies = append(cookies, s.cookies[k])
	}

	originKeys := make([]string, 0, len(s.origins))
	for o := range s.origins {
		originKeys = append(originKeys, o)
	}
	sort.Strings(originKeys)
	origins := make([]storageStateOrigin, 0, len(originKeys))
	for _, o := range originKeys {
		m := s.origins[o]
		names := make([]string, 0, len(m))
		for n := range m {
			names = append(names, n)
		}
		sort.Strings(names)
		kvs := make([]storageStateKV, 0, len(names))
		for _, n := range names {
			kvs = append(kvs, storageStateKV{Name: n, Value: m[n]})
		}
		origins = append(origins, storageStateOrigin{Origin: o, LocalStorage: kvs})
	}

	data, err := json.MarshalIndent(storageStateFile{Cookies: cookies, Origins: origins}, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return privfile.Write(s.path, data)
}
