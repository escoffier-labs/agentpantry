//go:build !windows

package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolvedConfigDoesNotRetainWorkingDirectoryAlias(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "real")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "current")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "source.toml")
	if err := os.WriteFile(cfg, []byte(`role="source"`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	t.Setenv("PWD", alias)
	got, err := ResolveConfig("source.toml")
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("relative config retained lexical working-directory alias")
	}
}
