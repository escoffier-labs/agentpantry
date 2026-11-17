package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTailnetLoadValidation(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		ok         bool
	}{
		{"empty", "[tailnet]", false}, {"blank", "[tailnet]\nallow_nodes=[\"\"]", false},
		{"blank-tag", `[tailnet]
allow_tags=[" "]`, false},
		{"bad-user", "[tailnet]\nallow_user_ids=[\"alice\"]", false},
		{"unknown", "[tailnet]\nallow_nodes=[\"node\"]\nrequire=false", false},
		{"valid", "[tailnet]\nallow_nodes=[\"node\"]\nallow_user_ids=[\"123\"]", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "config.toml")
			if e := os.WriteFile(p, []byte(tc.body), 0600); e != nil {
				t.Fatal(e)
			}
			_, _, e := LoadChecked(p)
			if (e == nil) != tc.ok {
				t.Fatal(e)
			}
		})
	}
}

func FuzzTailnetLoadChecked(f *testing.F) {
	for _, seed := range []string{`[tailnet]
allow_nodes=["node"]`, `[tailnet]`, `[tailnet]
allow_tags=[""]`, `[tailnet]
allow_user_ids=["123"]`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 16384 {
			return
		}
		path := filepath.Join(t.TempDir(), "config.toml")
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		c, _, err := LoadChecked(path)
		if err == nil && c.Tailnet != nil {
			if err := c.Tailnet.Validate(); err != nil {
				t.Fatal("load accepted invalid selectors:", err)
			}
		}
	})
}
