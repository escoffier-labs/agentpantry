package surface

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/secret"
)

func TestHermesBundleWritesCookiesSecretsAndManifest(t *testing.T) {
	root := filepath.Join(t.TempDir(), "hermes", "agentpantry")
	h, err := NewHermesBundle(root)
	if err != nil {
		t.Fatal(err)
	}

	c := cookie.Cookie{
		Host:       ".example.com",
		Name:       "sid",
		Value:      "cookie-value",
		Path:       "/",
		ExpiresUTC: cookie.ExpiresFromUnix(1_637_000_000),
		IsSecure:   true,
	}
	if err := h.Apply(cookie.Diff{Upserts: []cookie.Cookie{c}}); err != nil {
		t.Fatal(err)
	}
	if err := h.ApplySecrets(secret.Diff{Upserts: []secret.Secret{{Name: "api_token", Value: "secret-value"}}}); err != nil {
		t.Fatal(err)
	}

	manifest, err := os.ReadFile(filepath.Join(root, "agentpantry.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifest), "agentpantry.hermes-bundle.v1") {
		t.Fatalf("manifest missing schema: %s", manifest)
	}
	cookies, err := os.ReadFile(filepath.Join(root, "cookies.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cookies), ".example.com\tTRUE\t/\tTRUE\t1637000000\tsid\tcookie-value") {
		t.Fatalf("cookie not written in netscape format: %s", cookies)
	}
	secretValue, err := os.ReadFile(filepath.Join(root, "secrets", "api_token"))
	if err != nil {
		t.Fatal(err)
	}
	if string(secretValue) != "secret-value" {
		t.Fatalf("secret mismatch: %q", secretValue)
	}
	assertPerm(t, filepath.Join(root, "agentpantry.json"), 0o600)
	assertPerm(t, filepath.Join(root, "cookies.txt"), 0o600)
	assertPerm(t, filepath.Join(root, "secrets", "api_token"), 0o600)
	assertPerm(t, root, 0o700)
	assertPerm(t, filepath.Join(root, "secrets"), 0o700)
}

func TestHermesBundleDeletesOwnedSecretAndCookie(t *testing.T) {
	root := filepath.Join(t.TempDir(), "agentpantry")
	h, err := NewHermesBundle(root)
	if err != nil {
		t.Fatal(err)
	}
	c := cookie.Cookie{Host: "example.com", Name: "sid", Path: "/", Value: "v"}
	if err := h.Apply(cookie.Diff{Upserts: []cookie.Cookie{c}}); err != nil {
		t.Fatal(err)
	}
	if err := h.ApplySecrets(secret.Diff{Upserts: []secret.Secret{{Name: "api_token", Value: "secret-value"}}}); err != nil {
		t.Fatal(err)
	}
	if err := h.Apply(cookie.Diff{Deletes: []string{cookie.Key(c)}}); err != nil {
		t.Fatal(err)
	}
	if err := h.ApplySecrets(secret.Diff{Deletes: []string{"api_token"}}); err != nil {
		t.Fatal(err)
	}
	cookies, err := os.ReadFile(filepath.Join(root, "cookies.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cookies), "example.com") {
		t.Fatalf("deleted cookie remained: %s", cookies)
	}
	if _, err := os.Stat(filepath.Join(root, "secrets", "api_token")); !os.IsNotExist(err) {
		t.Fatalf("deleted secret remained or unexpected stat error: %v", err)
	}
}

func TestHermesBundleRejectsEmptyPath(t *testing.T) {
	if _, err := NewHermesBundle(""); err == nil {
		t.Fatal("empty path must fail")
	}
}

func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return // Go synthesizes 0666/0777 modes on Windows; ACLs govern access there.
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s perms got %v want %v", path, got, want)
	}
}
