package main

import (
	"os"
	"path/filepath"
	"testing"
)

const sourceConfigTOML = `role = "source"
peer = "127.0.0.1:8787"
key_path = "%[1]s/psk.key"

[[browsers]]
kind = "cdp"
profile = "live"
url = "http://127.0.0.1:9228"

[domains]
allow = ["glassdoor.com", "indeed.com", "lever.co"]
deny = []
`

const sinkConfigTOML = `role = "sink"
peer = "127.0.0.1:8787"
key_path = "%[1]s/psk.key"
surfaces = ["sidecar"]
sidecar_path = "%[2]s"

[[adapters]]
type = "netscape"
path = "%[2]s.cookies.txt"
`

// status -all exists because the canonical config can report "never synced"
// while the per-profile configs are captured daily. It must describe what each
// profile is actually wired to.
func TestSummarizeProfiles(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "psk.key")
	if err := os.WriteFile(keyPath, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("jobs.source.toml", sourceConfigTOML)
	write("jobs.sink.toml", sinkConfigTOML)
	// A default-path sink cannot be resolved from another process, so it must be
	// reported as unresolved rather than as an empty store.
	write("openclaw.sink.toml", `role = "sink"
peer = "127.0.0.1:8787"
key_path = "`+keyPath+`"
surfaces = ["sidecar"]
`)

	rows, err := summarizeProfiles(dir)
	if err != nil {
		t.Fatalf("summarizeProfiles: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(rows))
	}

	byName := map[string]profileSummary{}
	for _, r := range rows {
		byName[r.Profile] = r
	}

	src, ok := byName["jobs.source"]
	if !ok {
		t.Fatal("missing source row")
	}
	if src.Role != "source" {
		t.Fatalf("role = %q", src.Role)
	}
	if len(src.Lanes) != 1 || src.Lanes[0] != "cdp http://127.0.0.1:9228" {
		t.Fatalf("lanes = %v", src.Lanes)
	}
	if src.Domains != 3 {
		t.Fatalf("domains = %d, want 3", src.Domains)
	}
	if src.Cookies != nil {
		t.Fatal("a source config must not report a cookie count")
	}

	sink, ok := byName["jobs.sink"]
	if !ok {
		t.Fatal("missing sink row")
	}
	if sink.Adapters != 1 {
		t.Fatalf("adapters = %d, want 1", sink.Adapters)
	}
	// The store path is configured but the file does not exist yet, so no count
	// is claimed and no error is raised.
	if sink.Store == "" {
		t.Fatal("configured store path should be reported")
	}
	if sink.Cookies != nil {
		t.Fatalf("absent store must not report cookies, got %d", *sink.Cookies)
	}

	def, ok := byName["openclaw.sink"]
	if !ok {
		t.Fatal("missing default-path sink row")
	}
	if def.Store != "" {
		t.Fatalf("default-path sink must not claim a store, got %q", def.Store)
	}
	if def.StoreNote == "" {
		t.Fatal("default-path sink should explain why the store is unresolved")
	}
}

func TestSummarizeProfilesEmptyDir(t *testing.T) {
	rows, err := summarizeProfiles(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("got %d rows, want 0", len(rows))
	}
}
