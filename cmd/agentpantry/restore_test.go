package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
)

func TestParseRestoreTarget(t *testing.T) {
	cases := []struct {
		spec        string
		wantKind    restoreTargetKind
		wantPath    string
		wantProfile string
	}{
		{spec: "netscape=/tmp/cookies.txt", wantKind: restoreTargetNetscape, wantPath: "/tmp/cookies.txt"},
		{spec: "chromium=/tmp/Profile", wantKind: restoreTargetChromium, wantProfile: "/tmp/Profile"},
		{spec: "storagestate=/tmp/state.json", wantKind: restoreTargetStorageState, wantPath: "/tmp/state.json"},
		{spec: "cdp=http://127.0.0.1:9222", wantKind: restoreTargetCDP, wantPath: "http://127.0.0.1:9222"},
	}
	for _, tc := range cases {
		got, err := parseRestoreTarget(tc.spec)
		if err != nil {
			t.Fatalf("parseRestoreTarget(%q): %v", tc.spec, err)
		}
		if got.kind != tc.wantKind || got.path != tc.wantPath || got.profileDir != tc.wantProfile {
			t.Fatalf("parseRestoreTarget(%q) = %+v, want kind %v path %q profile %q",
				tc.spec, got, tc.wantKind, tc.wantPath, tc.wantProfile)
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
	if _, err := restoreApply(context.Background(), target, cookies, nil); err != nil {
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
	for _, spec := range []string{"", "netscape=", "chromium=", "storagestate=", "cdp=", "cdp=http://198.51.100.10:9222", "chrome=/tmp/Profile", "/tmp/cookies.txt"} {
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
