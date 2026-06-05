package surface

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
)

func TestNetscapeWriteDeleteAndPerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cookies.txt")
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	n, err := NewNetscape(path)
	if err != nil {
		t.Fatal(err)
	}
	c := cookie.Cookie{Host: ".github.com", Name: "sid", Path: "/", Value: "v", IsSecure: true, ExpiresUTC: cookie.ExpiresFromUnix(1637000000)}
	if err := n.Apply(cookie.Diff{Upserts: []cookie.Cookie{c}}); err != nil {
		t.Fatal(err)
	}
	assertPerm(t, path, 0o600)
	body, _ := os.ReadFile(path)
	line := ""
	for _, l := range strings.Split(string(body), "\n") {
		if strings.Contains(l, "sid") {
			line = l
		}
	}
	cols := strings.Split(line, "\t")
	if len(cols) != 7 {
		t.Fatalf("want 7 tab cols, got %d (%q)", len(cols), line)
	}
	if cols[0] != ".github.com" || cols[1] != "TRUE" || cols[3] != "TRUE" || cols[4] != "1637000000" || cols[5] != "sid" || cols[6] != "v" {
		t.Fatalf("unexpected netscape line: %q", line)
	}

	if err := n.Apply(cookie.Diff{Deletes: []string{cookie.Key(c)}}); err != nil {
		t.Fatal(err)
	}
	body, _ = os.ReadFile(path)
	if strings.Contains(string(body), "sid") {
		t.Fatal("cookie not deleted from file")
	}
}

func TestNetscapeSeedsFromExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cookies.txt")
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	// Pre-existing file (simulating a sink that restarted).
	os.WriteFile(path, []byte("# Netscape HTTP Cookie File\nexample.com\tFALSE\t/\tFALSE\t0\told\tval\n"), 0o600)
	n, err := NewNetscape(path)
	if err != nil {
		t.Fatal(err)
	}
	// Apply a new cookie; the seeded one must survive.
	c := cookie.Cookie{Host: "new.com", Name: "n", Path: "/", Value: "1"}
	if err := n.Apply(cookie.Diff{Upserts: []cookie.Cookie{c}}); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), "old") || !strings.Contains(string(body), "new.com") {
		t.Fatalf("seed lost on restart: %q", body)
	}
}

func TestNetscapeTightensExistingPerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cookies.txt")
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("# Netscape HTTP Cookie File\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	n, err := NewNetscape(path)
	if err != nil {
		t.Fatal(err)
	}
	c := cookie.Cookie{Host: "github.com", Name: "sid", Path: "/", Value: "v"}
	if err := n.Apply(cookie.Diff{Upserts: []cookie.Cookie{c}}); err != nil {
		t.Fatal(err)
	}
	assertPerm(t, path, 0o600)
}

func TestNetscapeRejectsWorldWritableParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the world-writable dir check is unix-only; ACLs govern access on windows")
	}
	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.MkdirAll(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if _, err := NewNetscape(filepath.Join(dir, "cookies.txt")); err == nil {
		t.Fatal("world-writable adapter parent must be rejected")
	}
}
