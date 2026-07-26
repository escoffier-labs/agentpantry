//go:build windows

package vault

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// writeLocalStateFixture creates a non-empty placeholder Local State file.
// Discovery only needs the path to exist; content is not parsed here.
func writeLocalStateFixture(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "Local State")
	if err := os.WriteFile(path, []byte(`{"os_crypt":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// standardChromeCookiePath builds the verified Windows Chrome cookie layout
// under root: <root>/<User Data>/<Profile>/Network/Cookies.
func standardChromeCookiePath(t *testing.T, root string) string {
	t.Helper()
	cookiePath := filepath.Join(root, "User Data", "Default", "Network", "Cookies")
	if err := os.MkdirAll(filepath.Dir(cookiePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cookiePath, []byte("cookies"), 0o600); err != nil {
		t.Fatal(err)
	}
	return cookiePath
}

func TestLocalStatePathStandardLayoutFound(t *testing.T) {
	root := t.TempDir()
	cookiePath := standardChromeCookiePath(t, root)
	want := writeLocalStateFixture(t, filepath.Join(root, "User Data"))

	got, err := localStatePath(cookiePath)
	if err != nil {
		t.Fatalf("localStatePath: %v", err)
	}
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestLocalStatePathExactNLevelBoundFound(t *testing.T) {
	// Local State at the furthest allowed ancestor (User Data): level index
	// localStateMaxLevels-1 after starting at Network. Deeper placement would
	// be outside the bound.
	root := t.TempDir()
	cookiePath := standardChromeCookiePath(t, root)
	want := writeLocalStateFixture(t, filepath.Join(root, "User Data"))

	got, err := localStatePath(cookiePath)
	if err != nil {
		t.Fatalf("localStatePath at exact bound: %v", err)
	}
	if got != want {
		t.Fatalf("got %q, want %q (Local State at level %d)", got, want, localStateMaxLevels-1)
	}

	// One level beyond the bound must not be discovered.
	beyondRoot := t.TempDir()
	beyondCookie := standardChromeCookiePath(t, beyondRoot)
	// Place Local State above User Data (would need a 3rd parent walk).
	writeLocalStateFixture(t, beyondRoot)
	if _, err := localStatePath(beyondCookie); err == nil {
		t.Fatal("expected error when Local State is beyond N-level bound")
	}
}

func TestLocalStatePathAbsentExplicitMessage(t *testing.T) {
	root := t.TempDir()
	cookiePath := standardChromeCookiePath(t, root)

	_, err := localStatePath(cookiePath)
	if err == nil {
		t.Fatal("expected error when Local State is absent")
	}
	// Exact phrase required by issue #43.
	wantSub := "Local State not found within " + strconv.Itoa(localStateMaxLevels) + " levels of " + cookiePath
	if !strings.Contains(err.Error(), wantSub) {
		t.Fatalf("error %q does not contain %q", err.Error(), wantSub)
	}
}

func TestLocalStatePathNoGuessedPath(t *testing.T) {
	root := t.TempDir()
	cookiePath := standardChromeCookiePath(t, root)

	path, err := localStatePath(cookiePath)
	if err == nil {
		t.Fatalf("expected error, got guessed path %q", path)
	}
	if path != "" {
		t.Fatalf("on error, path must be empty (no guess); got %q", path)
	}
	// Former behavior guessed Network/Local State (Dir(cookiePath)/Local State)
	// and later failed on read with an opaque error. The new path must not do that.
	if strings.Contains(err.Error(), "read Local State") {
		t.Fatalf("must not defer to opaque read error; got %v", err)
	}
	if !strings.Contains(err.Error(), cookiePath) {
		t.Fatalf("error should name cookiePath, got %v", err)
	}
}
