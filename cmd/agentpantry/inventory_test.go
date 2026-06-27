package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/surface"
)

// writeStore builds a sidecar store with a known mix of cookies: two on one
// host (one near expiry, one far) and a session-only cookie on another.
func writeStore(t *testing.T, path string, now time.Time) {
	t.Helper()
	sc, err := surface.NewSidecar(path)
	if err != nil {
		t.Fatalf("new sidecar: %v", err)
	}
	cookies := []cookie.Cookie{
		{Host: "example.com", Name: "near", Path: "/", Value: "v",
			ExpiresUTC: cookie.ExpiresFromUnix(now.Add(5 * 24 * time.Hour).Unix())},
		{Host: "example.com", Name: "far", Path: "/", Value: "v",
			ExpiresUTC: cookie.ExpiresFromUnix(now.Add(100 * 24 * time.Hour).Unix())},
		{Host: "auth.example.org", Name: "sess", Path: "/", Value: "v", ExpiresUTC: 0},
	}
	if err := sc.Apply(cookie.Diff{Upserts: cookies}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := sc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestInventoryJSON(t *testing.T) {
	bin := buildBin(t)
	store := filepath.Join(t.TempDir(), "sidecar.db")
	writeStore(t, store, time.Now())

	code, stdout, stderr := runCmd(t, bin, "inventory", "--json", "--store", store, "--expiry-days", "14")
	if code != 0 {
		t.Fatalf("inventory exit %d: %s", code, stderr)
	}

	var payload struct {
		Total       int `json:"total"`
		Persistent  int `json:"persistent"`
		SessionOnly int `json:"session_only"`
		Hosts       []struct {
			Host  string `json:"host"`
			Count int    `json:"count"`
		} `json:"hosts"`
		NearExpiryDays int `json:"near_expiry_days"`
		NearExpiry     []struct {
			Host    string `json:"host"`
			Name    string `json:"name"`
			Expires string `json:"expires"`
		} `json:"near_expiry"`
	}
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if payload.Total != 3 {
		t.Fatalf("want total 3, got %d", payload.Total)
	}
	if payload.Persistent != 2 || payload.SessionOnly != 1 {
		t.Fatalf("want 2 persistent / 1 session, got %d / %d", payload.Persistent, payload.SessionOnly)
	}
	if payload.NearExpiryDays != 14 {
		t.Fatalf("want near_expiry_days 14, got %d", payload.NearExpiryDays)
	}
	// Hosts are sorted by count desc: example.com (2) then auth.example.org (1).
	if len(payload.Hosts) != 2 || payload.Hosts[0].Host != "example.com" || payload.Hosts[0].Count != 2 {
		t.Fatalf("want example.com first with count 2, got %+v", payload.Hosts)
	}
	// Only the in-window persistent cookie is near-expiry; far and session are not.
	if len(payload.NearExpiry) != 1 || payload.NearExpiry[0].Name != "near" || payload.NearExpiry[0].Host != "example.com" {
		t.Fatalf("want one near-expiry cookie named 'near' on example.com, got %+v", payload.NearExpiry)
	}
	if payload.NearExpiry[0].Expires == "" {
		t.Fatalf("near-expiry entry missing decoded expires date")
	}
}

func TestInventoryHumanOutput(t *testing.T) {
	bin := buildBin(t)
	store := filepath.Join(t.TempDir(), "sidecar.db")
	writeStore(t, store, time.Now())

	code, stdout, stderr := runCmd(t, bin, "inventory", "--store", store)
	if code != 0 {
		t.Fatalf("inventory exit %d: %s", code, stderr)
	}
	for _, want := range []string{"cookies:  3", "example.com", "auth.example.org", "near-expiry"} {
		if !contains(stdout, want) {
			t.Fatalf("human output missing %q:\n%s", want, stdout)
		}
	}
}

func TestInventoryMissingStore(t *testing.T) {
	bin := buildBin(t)
	missing := filepath.Join(t.TempDir(), "nope.db")
	code, _, stderr := runCmd(t, bin, "inventory", "--json", "--store", missing)
	if code != 2 {
		t.Fatalf("want exit 2 for a missing store, got %d (%s)", code, stderr)
	}
}

// inventory must be read-only: pointing it at an existing file that is not a
// sidecar store must fail without creating schema or otherwise mutating it.
func TestInventoryDoesNotMutateNonStore(t *testing.T) {
	bin := buildBin(t)
	other := filepath.Join(t.TempDir(), "not-a-store.db")
	if err := os.WriteFile(other, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCmd(t, bin, "inventory", "--store", other)
	if code == 0 {
		t.Fatalf("want non-zero exit for a non-sidecar file, got 0")
	}
	info, err := os.Stat(other)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("inventory mutated a non-store file: size is now %d (%s)", info.Size(), stderr)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
