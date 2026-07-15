package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
)

func TestParseRestoreTarget(t *testing.T) {
	cases := []struct {
		spec        string
		wantKind    restoreTargetKind
		wantPath    string
		wantProfile string
		wantApp     string
	}{
		{spec: "netscape=/tmp/cookies.txt", wantKind: restoreTargetNetscape, wantPath: "/tmp/cookies.txt"},
		{spec: "chromium=/tmp/Profile", wantKind: restoreTargetChromium, wantProfile: "/tmp/Profile"},
		{spec: "storagestate=/tmp/state.json", wantKind: restoreTargetStorageState, wantPath: "/tmp/state.json"},
		{spec: "cdp=http://127.0.0.1:9222", wantKind: restoreTargetCDP, wantPath: "http://127.0.0.1:9222"},
		{spec: "desktop-app=codex", wantKind: restoreTargetDesktopApp, wantApp: "codex"},
		{spec: "desktop-app=claude", wantKind: restoreTargetDesktopApp, wantApp: "claude"},
	}
	for _, tc := range cases {
		got, err := parseRestoreTarget(tc.spec)
		if err != nil {
			t.Fatalf("parseRestoreTarget(%q): %v", tc.spec, err)
		}
		if got.kind != tc.wantKind || got.path != tc.wantPath || got.profileDir != tc.wantProfile || got.app != tc.wantApp {
			t.Fatalf("parseRestoreTarget(%q) = %+v, want kind %v path %q profile %q app %q",
				tc.spec, got, tc.wantKind, tc.wantPath, tc.wantProfile, tc.wantApp)
		}
	}
}

func TestDesktopAppProfilePathUsesPlatformUserConfigDirectory(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "xdg-config"))
	t.Setenv("APPDATA", filepath.Join(root, "appdata"))

	configDir, err := os.UserConfigDir()
	if err != nil {
		t.Fatalf("user config dir on %s: %v", runtime.GOOS, err)
	}
	want := filepath.Join(configDir, "Codex")
	got := desktopAppProfilePath(desktopApps["codex"])
	if got != want {
		t.Fatalf("profile path on %s = %q, want %q", runtime.GOOS, got, want)
	}
	if !strings.HasPrefix(got, root) {
		t.Fatalf("profile path on %s ignored platform config environment: %q", runtime.GOOS, got)
	}
}

func TestInspectDesktopAppProfileReportsLockAndCookieCandidate(t *testing.T) {
	profile := t.TempDir()
	if err := os.Mkdir(filepath.Join(profile, "Network"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profile, "Network", "Cookies"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profile, "SingletonLock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	target := restoreTarget{kind: restoreTargetDesktopApp, app: "codex"}
	got := inspectDesktopAppProfile(target, profile)
	if got.ProfileState != "found" {
		t.Fatalf("profile state = %q, want found", got.ProfileState)
	}
	if got.ProcessState != "possibly running (profile lock present)" {
		t.Fatalf("process state = %q", got.ProcessState)
	}
	if got.CookieStore != filepath.Join(profile, "Network", "Cookies") {
		t.Fatalf("cookie store = %q", got.CookieStore)
	}
	if got.CookieLayout != "candidate found (encryption compatibility unverified)" {
		t.Fatalf("cookie layout = %q", got.CookieLayout)
	}
	if got.InjectionMethod != "unavailable" {
		t.Fatalf("injection method = %q", got.InjectionMethod)
	}
	if !strings.Contains(got.WriteResult, "no supported Codex session injection or read-back bridge; no files written") {
		t.Fatalf("write result = %q", got.WriteResult)
	}
}

func TestInspectDesktopAppProfileReportsUnknownWhenLockProbeFails(t *testing.T) {
	profile := t.TempDir()
	target := restoreTarget{kind: restoreTargetDesktopApp, app: "codex"}
	got := inspectDesktopAppProfileWithLstat(target, profile, func(path string) (os.FileInfo, error) {
		if filepath.Base(path) == "SingletonLock" {
			return nil, os.ErrPermission
		}
		return os.Lstat(path)
	})
	if got.ProcessState != "unknown (profile lock probe failed)" {
		t.Fatalf("process state = %q", got.ProcessState)
	}
}

func TestInspectDesktopAppProfileReportsUnavailableWhenCookieProbeFails(t *testing.T) {
	profile := t.TempDir()
	target := restoreTarget{kind: restoreTargetDesktopApp, app: "claude"}
	cookiePath := filepath.Join(profile, "Network", "Cookies")
	got := inspectDesktopAppProfileWithLstat(target, profile, func(path string) (os.FileInfo, error) {
		if path == cookiePath {
			return nil, os.ErrPermission
		}
		return os.Lstat(path)
	})
	if got.CookieStore != cookiePath {
		t.Fatalf("cookie store = %q, want %q", got.CookieStore, cookiePath)
	}
	if got.CookieLayout != "unavailable (cookie store probe failed)" {
		t.Fatalf("cookie layout = %q", got.CookieLayout)
	}
}

func TestInspectDesktopAppProfileSkipsNonRegularCookieCandidate(t *testing.T) {
	profile := t.TempDir()
	network := filepath.Join(profile, "Network")
	if err := os.MkdirAll(filepath.Join(network, "Cookies"), 0o700); err != nil {
		t.Fatal(err)
	}
	fallback := filepath.Join(profile, "Cookies")
	if err := os.WriteFile(fallback, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}

	target := restoreTarget{kind: restoreTargetDesktopApp, app: "claude"}
	got := inspectDesktopAppProfile(target, profile)

	if got.ProfileState != "found" {
		t.Fatalf("profile state = %q, want found", got.ProfileState)
	}
	if got.CookieStore != fallback {
		t.Fatalf("cookie store = %q, want fallback %q", got.CookieStore, fallback)
	}
	if got.CookieLayout != "candidate found (encryption compatibility unverified)" {
		t.Fatalf("cookie layout = %q", got.CookieLayout)
	}
}

func TestDesktopAppRestoreRefusalGivesSafeRecoverySteps(t *testing.T) {
	target, err := parseRestoreTarget("desktop-app=claude")
	if err != nil {
		t.Fatal(err)
	}
	got := desktopAppRestoreRefusal(target)
	for _, want := range []string{
		"no supported Claude session injection or read-back bridge",
		"no files written",
		"Stop Claude completely, remove --verify if present, then rerun with --dry-run to inspect the offline profile",
		"Do not edit the profile",
		"cookie schema and encryption are compatible",
		"create a private backup",
		"verify names and counts through read-back",
		"keep the sidecar backup",
		"storagestate=<path>",
		"chromium=<profile-dir>",
		"cdp=<loopback-http-url>",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("refusal missing %q:\n%s", want, got)
		}
	}
}

func TestRestoreApplyStorageStateWritesPlaywrightFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod tempdir: %v", err)
	}
	path := filepath.Join(dir, "state.json")
	target, err := parseRestoreTarget("storagestate=" + path)
	if err != nil {
		t.Fatalf("parseRestoreTarget: %v", err)
	}
	cookies := []cookie.Cookie{
		{Host: "github.com", Name: "user_session", Value: "sekret", Path: "/", IsSecure: true, IsHTTPOnly: true, SameSite: 1},
	}
	if _, _, err := restoreApply(context.Background(), target, cookies, nil); err != nil {
		t.Fatalf("restoreApply: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var doc struct {
		Cookies []map[string]any `json:"cookies"`
		Origins []any            `json:"origins"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, data)
	}
	if len(doc.Cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(doc.Cookies))
	}
	if doc.Origins == nil {
		t.Fatalf("origins should be an empty array, got null:\n%s", data)
	}
	if doc.Cookies[0]["name"] != "user_session" || doc.Cookies[0]["sameSite"] != "Lax" {
		t.Fatalf("cookie fields wrong: %v", doc.Cookies[0])
	}
}

func TestParseRestoreTargetRejectsInvalidSpecs(t *testing.T) {
	for _, spec := range []string{"", "netscape=", "chromium=", "storagestate=", "cdp=", "desktop-app=", "desktop-app=other", "cdp=http://198.51.100.10:9222", "chrome=/tmp/Profile", "/tmp/cookies.txt"} {
		if _, err := parseRestoreTarget(spec); err == nil {
			t.Fatalf("parseRestoreTarget(%q) succeeded, want error", spec)
		}
	}
}

func TestRestoreVerifyRowsCountsMissingByDomainAndNamesOnly(t *testing.T) {
	expected := []cookie.Cookie{
		{Host: "example.com", Name: "sid", Path: "/", Value: "secret-a"},
		{Host: "example.com", Name: "prefs", Path: "/", Value: "secret-b"},
		{Host: "api.example.com", Name: "sid", Path: "/", Value: "secret-c"},
	}
	present := []cookie.Cookie{
		{Host: "example.com", Name: "sid", Path: "/", Value: "different-value"},
	}
	rows, missing := restoreVerifyRows(expected, present)
	if missing != 2 {
		t.Fatalf("missing = %d, want 2", missing)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2: %+v", len(rows), rows)
	}
	if rows[0].Domain != "example.com" || rows[0].Expected != 2 || rows[0].Present != 1 {
		t.Fatalf("unexpected first row: %+v", rows[0])
	}
	if rows[1].Domain != "api.example.com" || rows[1].Expected != 1 || rows[1].Present != 0 {
		t.Fatalf("unexpected second row: %+v", rows[1])
	}
	for _, row := range rows {
		for _, name := range row.Names {
			if name == "secret-a" || name == "secret-b" || name == "secret-c" {
				t.Fatalf("verification row leaked a value: %+v", rows)
			}
		}
	}
}
