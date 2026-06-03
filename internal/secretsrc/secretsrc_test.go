package secretsrc

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDirReaderReadsFilesSkipsDirsAndDotfiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "gh_token"), []byte("ghp_abc"), 0o600)
	os.WriteFile(filepath.Join(dir, ".hidden"), []byte("nope"), 0o600)
	os.MkdirAll(filepath.Join(dir, "subdir"), 0o700)

	r := &DirReader{Dir: dir}
	secs, err := r.ReadSecrets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(secs) != 1 {
		t.Fatalf("want 1 secret, got %d (%+v)", len(secs), secs)
	}
	if secs[0].Name != "gh_token" || secs[0].Value != "ghp_abc" {
		t.Fatalf("unexpected secret: %+v", secs[0])
	}
}

func TestDirReaderSkipsSymlinks(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("do-not-read"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "linked_secret")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	r := &DirReader{Dir: dir}
	secs, err := r.ReadSecrets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(secs) != 0 {
		t.Fatalf("symlink must be skipped, got %+v", secs)
	}
}

func TestDirReaderMissingDirErrors(t *testing.T) {
	r := &DirReader{Dir: filepath.Join(t.TempDir(), "nope")}
	_, err := r.ReadSecrets(context.Background())
	if err == nil {
		t.Fatal("missing dir should return an error so the sink keeps its synced secrets")
	}
}
