package surface

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
)

// safeStatePath returns a state.json path inside a 0700 temp dir, satisfying the
// surface's refusal to write into a group/world-writable directory.
func safeStatePath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod tempdir: %v", err)
	}
	return filepath.Join(dir, "state.json")
}

// decodeStorageState reads a written storageState file back into a generic map so
// tests assert on the exact JSON the Playwright loader will see.
func decodeStorageState(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal %s: %v\n%s", path, err, data)
	}
	return out
}

func TestStorageStateWritesPlaywrightShape(t *testing.T) {
	path := safeStatePath(t)
	ss, err := NewStorageState(path)
	if err != nil {
		t.Fatalf("NewStorageState: %v", err)
	}
	// A persistent, secure, httpOnly Lax cookie and a session cookie.
	persistent := cookie.Cookie{
		Host: ".example.com", Name: "sid", Value: "abc", Path: "/",
		ExpiresUTC: cookie.ExpiresFromUnix(4102444800), // year 2100
		IsSecure:   true, IsHTTPOnly: true, SameSite: 1,
	}
	session := cookie.Cookie{
		Host: "app.example.com", Name: "csrf", Value: "xyz", Path: "/login",
		ExpiresUTC: 0, IsSecure: false, IsHTTPOnly: false, SameSite: 0,
	}
	if err := ss.Apply(cookie.Diff{Upserts: []cookie.Cookie{persistent, session}}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	out := decodeStorageState(t, path)
	cookies, ok := out["cookies"].([]any)
	if !ok || len(cookies) != 2 {
		t.Fatalf("cookies = %v, want 2 entries", out["cookies"])
	}
	if _, ok := out["origins"].([]any); !ok {
		t.Fatalf("origins = %v, want an (empty) array", out["origins"])
	}

	byName := map[string]map[string]any{}
	for _, c := range cookies {
		m := c.(map[string]any)
		byName[m["name"].(string)] = m
	}

	sid := byName["sid"]
	if sid["value"] != "abc" || sid["domain"] != ".example.com" || sid["path"] != "/" {
		t.Fatalf("sid fields wrong: %v", sid)
	}
	if sid["secure"] != true || sid["httpOnly"] != true || sid["sameSite"] != "Lax" {
		t.Fatalf("sid flags wrong: %v", sid)
	}
	if sid["expires"].(float64) != 4102444800 {
		t.Fatalf("sid expires = %v, want 4102444800", sid["expires"])
	}

	csrf := byName["csrf"]
	if csrf["sameSite"] != "None" {
		t.Fatalf("csrf sameSite = %v, want None", csrf["sameSite"])
	}
	if csrf["expires"].(float64) != -1 {
		t.Fatalf("session cookie expires = %v, want -1", csrf["expires"])
	}
}

func TestStorageStateModeIs0600(t *testing.T) {
	path := safeStatePath(t)
	ss, err := NewStorageState(path)
	if err != nil {
		t.Fatalf("NewStorageState: %v", err)
	}
	if err := ss.Apply(cookie.Diff{Upserts: []cookie.Cookie{{Host: "e.com", Name: "a", Value: "b", Path: "/"}}}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %o, want 600", perm)
	}
}

// A restore into an existing storageState must merge cookies and preserve
// localStorage origins that a prior automation run captured, not drop them.
func TestStorageStatePreservesOriginsAndMergesCookies(t *testing.T) {
	path := safeStatePath(t)
	seedDoc := `{
  "cookies": [
    {"name":"old","value":"1","domain":"e.com","path":"/","expires":-1,"httpOnly":false,"secure":false,"sameSite":"Lax"}
  ],
  "origins": [
    {"origin":"https://e.com","localStorage":[{"name":"token","value":"keep-me"}]}
  ]
}`
	if err := os.WriteFile(path, []byte(seedDoc), 0o600); err != nil {
		t.Fatalf("seed write: %v", err)
	}

	ss, err := NewStorageState(path)
	if err != nil {
		t.Fatalf("NewStorageState: %v", err)
	}
	if err := ss.Apply(cookie.Diff{Upserts: []cookie.Cookie{{Host: "e.com", Name: "new", Value: "2", Path: "/", SameSite: 1}}}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	out := decodeStorageState(t, path)
	if got := len(out["cookies"].([]any)); got != 2 {
		t.Fatalf("cookies = %d, want 2 (merged old + new)", got)
	}
	origins := out["origins"].([]any)
	if len(origins) != 1 {
		t.Fatalf("origins dropped: %v", origins)
	}
	ls := origins[0].(map[string]any)["localStorage"].([]any)
	if ls[0].(map[string]any)["value"] != "keep-me" {
		t.Fatalf("localStorage value not preserved: %v", origins)
	}
}

func TestStorageStateDeleteRemovesCookie(t *testing.T) {
	path := safeStatePath(t)
	ss, err := NewStorageState(path)
	if err != nil {
		t.Fatalf("NewStorageState: %v", err)
	}
	c := cookie.Cookie{Host: "e.com", Name: "a", Value: "b", Path: "/"}
	if err := ss.Apply(cookie.Diff{Upserts: []cookie.Cookie{c}}); err != nil {
		t.Fatalf("Apply upsert: %v", err)
	}
	if err := ss.Apply(cookie.Diff{Deletes: []string{cookie.Key(c)}}); err != nil {
		t.Fatalf("Apply delete: %v", err)
	}
	out := decodeStorageState(t, path)
	if got := len(out["cookies"].([]any)); got != 0 {
		t.Fatalf("cookies = %d after delete, want 0", got)
	}
}

func TestStorageStateRefusesForeignFile(t *testing.T) {
	path := safeStatePath(t)
	if err := os.WriteFile(path, []byte("this is not json\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := NewStorageState(path); err == nil {
		t.Fatal("NewStorageState accepted a non-JSON file; want refusal")
	}
}

func TestStorageStateEmptyFileStartsFresh(t *testing.T) {
	path := safeStatePath(t)
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	ss, err := NewStorageState(path)
	if err != nil {
		t.Fatalf("NewStorageState on empty file: %v", err)
	}
	if err := ss.Apply(cookie.Diff{Upserts: []cookie.Cookie{{Host: "e.com", Name: "a", Value: "b", Path: "/", SameSite: 2}}}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	out := decodeStorageState(t, path)
	if got := len(out["cookies"].([]any)); got != 1 {
		t.Fatalf("cookies = %d, want 1", got)
	}
}
