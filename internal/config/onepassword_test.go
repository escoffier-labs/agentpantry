package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOnePasswordConfig(t *testing.T) {
	base := "[onepassword]\nvault='dedicated'\ntag='agentpantry'\nfield='password'\ntoken_file='/fixture/token'\n"
	for _, tc := range []struct {
		name, text string
		fail       bool
	}{{"defaults", base, false}, {"unknown", base + "typo=true\n", true}, {"case section", strings.Replace(base, "onepassword", "OnePassword", 1), true}, {"case key", strings.Replace(base, "vault=", "Vault=", 1), true}, {"blank", strings.Replace(base, "tag='agentpantry'", "tag=''", 1), true}, {"poll floor", base + "poll_seconds=59\n", true}, {"explicit", base + "poll_seconds=60\nmax_items=10\nmax_value_bytes=20\nop_path='/fixture/op'\n", false}} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(p, []byte(tc.text), 0600); err != nil {
				t.Fatal(err)
			}
			c, _, err := LoadChecked(p)
			if (err != nil) != tc.fail {
				t.Fatal(err)
			}
			if err == nil && tc.name == "defaults" && (c.OnePassword.PollSeconds != 300 || c.OnePassword.MaxItems != 200 || c.OnePassword.MaxValueBytes != 65536) {
				t.Fatal("defaults")
			}
		})
	}
}
