package main

import (
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

func TestParseRestoreTargetRejectsInvalidSpecs(t *testing.T) {
	for _, spec := range []string{"", "netscape=", "chromium=", "cdp=", "cdp=http://198.51.100.10:9222", "chrome=/tmp/Profile", "/tmp/cookies.txt"} {
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
