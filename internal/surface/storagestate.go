package surface

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/privfile"
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

// storageStateFile is the on-disk Playwright storageState shape consumed by
// browser.newContext({ storageState }). Origins carries per-origin localStorage;
// agentpantry does not capture localStorage yet, so any existing origins are
// preserved verbatim rather than dropped, and a fresh file gets an empty array.
type storageStateFile struct {
	Cookies []storageStateCookie `json:"cookies"`
	Origins json.RawMessage      `json:"origins"`
}

// StorageState writes a Playwright/Puppeteer storageState JSON file so a headless
// or headed automation browser wakes up authenticated without replaying a login.
// It manages the cookies array and leaves the origins (localStorage) array
// unchanged, so localStorage a previous automation run captured survives a
// cookie refresh.
type StorageState struct {
	path    string
	cookies map[string]storageStateCookie // keyed by cookie.Key
	origins json.RawMessage
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
		origins: json.RawMessage("[]"),
	}
	if err := s.seed(); err != nil {
		return nil, err
	}
	return s, nil
}

// seed loads an existing storageState so a sink restart does not drop cookies the
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
	if len(bytes.TrimSpace(f.Origins)) > 0 {
		s.origins = append(json.RawMessage(nil), f.Origins...)
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

func (s *StorageState) write() error {
	keys := make([]string, 0, len(s.cookies))
	for k := range s.cookies {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	cookies := make([]storageStateCookie, 0, len(keys))
	for _, k := range keys {
		cookies = append(cookies, s.cookies[k])
	}
	origins := s.origins
	if len(bytes.TrimSpace(origins)) == 0 {
		origins = json.RawMessage("[]")
	}
	data, err := json.MarshalIndent(storageStateFile{Cookies: cookies, Origins: origins}, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return privfile.Write(s.path, data)
}
