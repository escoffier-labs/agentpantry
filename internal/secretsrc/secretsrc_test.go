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

func TestDirReaderMissingDirIsEmpty(t *testing.T) {
	r := &DirReader{Dir: filepath.Join(t.TempDir(), "nope")}
	secs, err := r.ReadSecrets(context.Background())
	if err != nil || len(secs) != 0 {
		t.Fatalf("missing dir should yield no secrets and no error, got %v / %d", err, len(secs))
	}
}
