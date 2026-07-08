package keepass

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tobischo/gokeepasslib/v3"
	w "github.com/tobischo/gokeepasslib/v3/wrappers"
)

const testKeyMaterial = "test-key-material-0123456789abcdef"

type testEntry struct {
	title, password, tags string
}

// writeTestVault encodes a KDBX4 vault at test time (no committed secret
// fixture) unlocked by a key file, and returns both paths.
func writeTestVault(t *testing.T, dir, password string, entries []testEntry) (vaultPath, keyPath string) {
	t.Helper()
	keyPath = filepath.Join(dir, "vault.key")
	if err := os.WriteFile(keyPath, []byte(testKeyMaterial), 0o600); err != nil {
		t.Fatal(err)
	}
	var creds *gokeepasslib.DBCredentials
	var err error
	if password == "" {
		creds, err = gokeepasslib.NewKeyDataCredentials([]byte(testKeyMaterial))
	} else {
		creds, err = gokeepasslib.NewPasswordAndKeyDataCredentials(password, []byte(testKeyMaterial))
	}
	if err != nil {
		t.Fatal(err)
	}
	sub := gokeepasslib.NewGroup()
	sub.Name = "Secrets"
	for _, te := range entries {
		e := gokeepasslib.NewEntry()
		e.Values = append(e.Values,
			gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: te.title}},
			gokeepasslib.ValueData{Key: "Password", Value: gokeepasslib.V{Content: te.password, Protected: w.NewBoolWrapper(true)}},
		)
		e.Tags = te.tags
		sub.Entries = append(sub.Entries, e)
	}
	root := gokeepasslib.NewGroup()
	root.Name = "Root"
	root.Groups = append(root.Groups, sub)

	db := gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion4())
	db.Credentials = creds
	db.Content.Root = &gokeepasslib.RootData{Groups: []gokeepasslib.Group{root}}
	if err := db.LockProtectedEntries(); err != nil {
		t.Fatal(err)
	}
	vaultPath = filepath.Join(dir, "vault.kdbx")
	f, err := os.Create(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := gokeepasslib.NewEncoder(f).Encode(db); err != nil {
		t.Fatal(err)
	}
	return vaultPath, keyPath
}

func TestReadSecretsTaggedExactOnly(t *testing.T) {
	vault, key := writeTestVault(t, t.TempDir(), "", []testEntry{
		{"API_KEY", "sk-1", "vault-builder;agentpantry"},
		{"COMMA_TAGGED", "v2", "misc,agentpantry"},
		{"UNTAGGED", "nope", ""},
		{"SUBSTRING", "nope", "agentpantryx"},
	})
	r := &Reader{Path: vault, Keyfile: key, Tag: "agentpantry"}
	got, err := r.ReadSecrets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]string{}
	for _, s := range got {
		byName[s.Name] = s.Value
	}
	if len(got) != 2 || byName["API_KEY"] != "sk-1" || byName["COMMA_TAGGED"] != "v2" {
		t.Fatalf("want exactly API_KEY+COMMA_TAGGED, got %v", byName)
	}
}

func TestReadSecretsSkipsEmptyTitle(t *testing.T) {
	vault, key := writeTestVault(t, t.TempDir(), "", []testEntry{
		{"", "orphan", "agentpantry"},
		{"OK", "v", "agentpantry"},
	})
	r := &Reader{Path: vault, Keyfile: key, Tag: "agentpantry"}
	got, err := r.ReadSecrets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "OK" {
		t.Fatalf("empty-title entry must be skipped, got %v", got)
	}
}

func TestReadSecretsDuplicateTitleFailsClosed(t *testing.T) {
	vault, key := writeTestVault(t, t.TempDir(), "", []testEntry{
		{"DUP", "one", "agentpantry"},
		{"DUP", "two", "agentpantry"},
	})
	r := &Reader{Path: vault, Keyfile: key, Tag: "agentpantry"}
	if _, err := r.ReadSecrets(context.Background()); err == nil || !strings.Contains(err.Error(), "DUP") {
		t.Fatalf("duplicate titles must error naming the collision, got %v", err)
	}
	if r.cached != nil {
		t.Fatal("nothing may be cached on error")
	}
}

func TestReadSecretsCachesOnUnchangedMtime(t *testing.T) {
	vault, key := writeTestVault(t, t.TempDir(), "", []testEntry{
		{"API_KEY", "sk-1", "agentpantry"},
	})
	r := &Reader{Path: vault, Keyfile: key, Tag: "agentpantry"}
	for i := 0; i < 2; i++ {
		if _, err := r.ReadSecrets(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if r.decodes != 1 {
		t.Fatalf("unchanged mtime must serve the cache, got %d decodes", r.decodes)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(vault, future, future); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadSecrets(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.decodes != 2 {
		t.Fatalf("bumped mtime must re-decode, got %d decodes", r.decodes)
	}
}

func TestReadSecretsWrongKeyErrors(t *testing.T) {
	dir := t.TempDir()
	vault, _ := writeTestVault(t, dir, "", []testEntry{{"A", "v", "agentpantry"}})
	wrong := filepath.Join(dir, "wrong.key")
	if err := os.WriteFile(wrong, []byte("not-the-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &Reader{Path: vault, Keyfile: wrong, Tag: "agentpantry"}
	if _, err := r.ReadSecrets(context.Background()); err == nil || !strings.Contains(err.Error(), vault) {
		t.Fatalf("wrong key must error naming the vault, got %v", err)
	}
}

func TestReadSecretsPasswordAndKeyfile(t *testing.T) {
	dir := t.TempDir()
	vault, key := writeTestVault(t, dir, "hunter2", []testEntry{{"A", "v", "agentpantry"}})
	passFile := filepath.Join(dir, "vault.pass")
	if err := os.WriteFile(passFile, []byte("hunter2\n"), 0o600); err != nil { // trailing newline must be trimmed
		t.Fatal(err)
	}
	r := &Reader{Path: vault, Keyfile: key, PassFile: passFile, Tag: "agentpantry"}
	got, err := r.ReadSecrets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Value != "v" {
		t.Fatalf("password+keyfile vault must open, got %v", got)
	}
}

func TestReadSecretsKeyfileRequired(t *testing.T) {
	vault, _ := writeTestVault(t, t.TempDir(), "", []testEntry{{"A", "v", "agentpantry"}})
	r := &Reader{Path: vault, Tag: "agentpantry"}
	if _, err := r.ReadSecrets(context.Background()); err == nil || !strings.Contains(err.Error(), "keepass_keyfile") {
		t.Fatalf("missing keyfile must be a clear config error, got %v", err)
	}
}
