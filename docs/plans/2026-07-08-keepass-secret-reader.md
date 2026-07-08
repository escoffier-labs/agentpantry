# Plan: source-side KeePass secret reader

Spec: `docs/specs/2026-07-08-keepass-secret-reader.md` (approved 2026-07-08)

**Goal:** a source can read named secrets from an encrypted KeePass (.kdbx) vault instead of a
plaintext `secrets_dir`.

**Architecture:** new `internal/keepass` package with a `Reader` implementing the existing
`source.SecretReader` interface (entry Title -> secret name, Password -> value, gated by an
exact-match tag). Pure-Go KDBX via `github.com/tobischo/gokeepasslib/v3` (v3.6.2, proven against
KDBX 3.1/AES, 4.0/Argon2d, and the live vault's 4.1/AES-KDF format in a 2026-07-08 spike). Config
grows four `keepass_*` fields; `cmdSource` wires the reader next to `secretsrc.DirReader`; doctor
gains a decrypt-and-count check. Transport, diffing, and the sink are untouched.

**Execution:** work task-by-task, tick the checkboxes, commit per task with conventional commits.
Run everything from the repo root. Definition of done for the branch: `./scripts/verify` plus
`make gosec` and `make vuln` (filesystem-reading feature) all pass.

## File map

- Create `internal/keepass/credfile.go` - hardened credential-file loader (perm/type/size checks, raw bytes)
- Create `internal/keepass/credfile_test.go` - loader tests (portable)
- Create `internal/keepass/credfile_unix_test.go` - perm + FIFO tests (`//go:build !windows`)
- Create `internal/keepass/keepass.go` - `Reader` (mtime cache, tag select, dup fail-closed)
- Create `internal/keepass/keepass_test.go` - vault-generating tests + `writeTestVault` helper
- Modify `internal/config/config.go` - 4 fields, `KeepassTagOrDefault`, template comments
- Modify `internal/config/config_test.go` - round-trip + default-tag tests
- Modify `cmd/agentpantry/main.go:301-307` - append reader + watch path
- Modify `internal/doctor/doctor.go` - `keepass` check in the source branch
- Modify `internal/doctor/doctor_test.go` - missing-vault Fail + healthy count tests
- Modify `README.md` - KeePass option in the named-secrets section
- Modify `CHANGELOG.md` - Unreleased/Added entry

### Task 1: dependency

**Files:** Modify: `go.mod`, `go.sum`

- [ ] `go get github.com/tobischo/gokeepasslib/v3@v3.6.2` - expect go.mod gains the require
- [ ] `go build ./...` - expect clean
- [ ] Commit: `git add go.mod go.sum && git commit -m "chore(deps): add gokeepasslib for kdbx reading"`

### Task 2: hardened credential-file loader

**Files:** Create: `internal/keepass/credfile.go`, `internal/keepass/credfile_test.go`,
`internal/keepass/credfile_unix_test.go`

- [ ] Write the failing tests (`credfile_test.go`):

```go
package keepass

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadCredFileReadsBytes(t *testing.T) {
	p := filepath.Join(t.TempDir(), "vault.key")
	if err := os.WriteFile(p, []byte{0x00, 0x01, 0xff}, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadCredFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[2] != 0xff {
		t.Fatalf("raw bytes lost: %v", got)
	}
}

func TestLoadCredFileRejectsEmpty(t *testing.T) {
	p := filepath.Join(t.TempDir(), "empty.key")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCredFile(p); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty file must be rejected, got %v", err)
	}
}

func TestLoadCredFileRejectsOversize(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big.key")
	if err := os.WriteFile(p, make([]byte, maxCredFile+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCredFile(p); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("oversize file must be rejected, got %v", err)
	}
}

func TestLoadCredFileMissing(t *testing.T) {
	if _, err := loadCredFile(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("missing file must error")
	}
}
```

- [ ] Write the unix-only tests (`credfile_unix_test.go`):

```go
//go:build !windows

package keepass

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestLoadCredFileRejectsOpenPerms(t *testing.T) {
	p := filepath.Join(t.TempDir(), "vault.key")
	if err := os.WriteFile(p, []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCredFile(p); err == nil || !strings.Contains(err.Error(), "too open") {
		t.Fatalf("0644 must be rejected, got %v", err)
	}
}

func TestLoadCredFileRejectsFIFO(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip("mkfifo unavailable:", err)
	}
	if _, err := loadCredFile(p); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("FIFO must be rejected without blocking, got %v", err)
	}
}
```

- [ ] Run: `go test ./internal/keepass/` - expect FAIL, `undefined: loadCredFile`
- [ ] Implement `credfile.go`:

```go
// Package keepass reads named secrets from an encrypted KeePass (.kdbx)
// vault on the source side.
package keepass

import (
	"fmt"
	"io"
	"os"
	"runtime"
)

// maxCredFile bounds credential files (key file or password file). KeePass
// key files are 64 raw bytes or small XML; reject anything implausibly large
// instead of reading it into memory.
const maxCredFile = 1 << 20 // 1 MiB

// loadCredFile reads a KeePass credential file with the same hardening as
// keyfile.Load: the path must resolve to a regular file (a FIFO would block
// on open, so stat first), permissions are checked on the open descriptor
// (non-Windows) so the validated file is provably the file read, and the
// size is capped. Unlike keyfile.Load it returns raw bytes: KeePass key
// files are arbitrary binary or XML, not hex.
func loadCredFile(path string) ([]byte, error) {
	if info, err := os.Stat(path); err != nil {
		return nil, err
	} else if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("credential path %s is not a regular file", path)
	}
	f, err := os.Open(path) // #nosec G304 -- credential path is intentionally operator-selected.
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if runtime.GOOS != "windows" {
		info, err := f.Stat()
		if err != nil {
			return nil, err
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("credential file %s perms %v are too open, want 0600", path, info.Mode().Perm())
		}
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxCredFile+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxCredFile {
		return nil, fmt.Errorf("credential file %s is larger than %d bytes", path, maxCredFile)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("credential file %s is empty", path)
	}
	return raw, nil
}
```

- [ ] Run to green: `go test ./internal/keepass/` - expect PASS
- [ ] Commit: `git add internal/keepass && git commit -m "feat(keepass): hardened credential file loader"`

### Task 3: the Reader

**Files:** Create: `internal/keepass/keepass.go`, `internal/keepass/keepass_test.go`

- [ ] Write the test helper + failing tests (`keepass_test.go`):

```go
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
	// A real vault: ReadSecrets stats Path before building credentials, so a
	// missing vault would mask the keyfile error this test is about.
	vault, _ := writeTestVault(t, t.TempDir(), "", []testEntry{{"A", "v", "agentpantry"}})
	r := &Reader{Path: vault, Tag: "agentpantry"}
	if _, err := r.ReadSecrets(context.Background()); err == nil || !strings.Contains(err.Error(), "keepass_keyfile") {
		t.Fatalf("missing keyfile must be a clear config error, got %v", err)
	}
}
```

- [ ] Run: `go test ./internal/keepass/` - expect FAIL, `undefined: Reader`
- [ ] Implement `keepass.go`:

```go
package keepass

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/tobischo/gokeepasslib/v3"

	"github.com/escoffier-labs/agentpantry/internal/secret"
)

// Reader reads tagged entries from an encrypted KeePass (.kdbx) vault as
// named secrets: entry Title -> secret name, entry Password -> value. Only
// entries carrying Tag (exact element match within KeePass's ";"/"," joined
// tag string) are exported, so a vault full of web logins stays private
// unless the operator opts an entry in.
type Reader struct {
	Path     string // .kdbx vault
	Keyfile  string // key file unlocking the vault (required)
	PassFile string // optional file holding the DB password (password+keyfile vaults)
	Tag      string // only entries carrying this tag are exported

	mu      sync.Mutex
	lastMod time.Time
	cached  []secret.Secret
	decodes int // decrypt count, observed by tests
}

// ReadSecrets implements source.SecretReader. The KDBX KDF is deliberately
// slow, so results are cached until the vault file's mtime changes. The
// mtime recorded is the one from before the read: if the vault is replaced
// mid-read, the next call re-reads rather than serving a stale cache.
func (r *Reader) ReadSecrets(ctx context.Context) ([]secret.Secret, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	info, err := os.Stat(r.Path)
	if err != nil {
		return nil, fmt.Errorf("keepass vault %s: %w", r.Path, err)
	}
	mod := info.ModTime()
	if r.cached != nil && mod.Equal(r.lastMod) {
		return r.cached, nil
	}
	secrets, err := r.read()
	if err != nil {
		return nil, err
	}
	r.cached = secrets
	r.lastMod = mod
	return secrets, nil
}

func (r *Reader) read() ([]secret.Secret, error) {
	creds, err := r.credentials()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(r.Path) // #nosec G304 -- vault path is intentionally operator-selected.
	if err != nil {
		return nil, fmt.Errorf("keepass vault %s: %w", r.Path, err)
	}
	defer func() { _ = f.Close() }()
	db := gokeepasslib.NewDatabase()
	db.Credentials = creds
	if err := gokeepasslib.NewDecoder(f).Decode(db); err != nil {
		return nil, fmt.Errorf("keepass vault %s: decode failed (wrong credentials or corrupt vault): %w", r.Path, err)
	}
	r.decodes++
	if err := db.UnlockProtectedEntries(); err != nil {
		return nil, fmt.Errorf("keepass vault %s: %w", r.Path, err)
	}
	var out []secret.Secret
	seen := map[string]bool{}
	for _, g := range db.Content.Root.Groups {
		if err := collect(g, r.Tag, seen, &out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (r *Reader) credentials() (*gokeepasslib.DBCredentials, error) {
	if r.Keyfile == "" {
		return nil, fmt.Errorf("keepass vault %s: keepass_keyfile is required", r.Path)
	}
	keyData, err := loadCredFile(r.Keyfile)
	if err != nil {
		return nil, fmt.Errorf("keepass key file: %w", err)
	}
	if r.PassFile == "" {
		return gokeepasslib.NewKeyDataCredentials(keyData)
	}
	passRaw, err := loadCredFile(r.PassFile)
	if err != nil {
		return nil, fmt.Errorf("keepass password file: %w", err)
	}
	return gokeepasslib.NewPasswordAndKeyDataCredentials(strings.TrimRight(string(passRaw), "\r\n"), keyData)
}

func collect(g gokeepasslib.Group, tag string, seen map[string]bool, out *[]secret.Secret) error {
	for _, e := range g.Entries {
		if !hasTag(e.Tags, tag) {
			continue
		}
		title := e.GetTitle()
		if title == "" {
			continue
		}
		// Fail closed: a silent last-writer-wins between two same-titled
		// entries would ship an arbitrary one of the two values.
		if seen[title] {
			return fmt.Errorf("keepass: two entries tagged %q share the title %q; retitle one", tag, title)
		}
		seen[title] = true
		*out = append(*out, secret.Secret{Name: title, Value: e.GetPassword()})
	}
	for _, sub := range g.Groups {
		if err := collect(sub, tag, seen, out); err != nil {
			return err
		}
	}
	return nil
}

// hasTag reports whether the KeePass tag string (";" or "," separated)
// contains tag as an exact element; a substring test would let tag "api"
// match an entry tagged "rapidapi".
func hasTag(tags, tag string) bool {
	for _, t := range strings.FieldsFunc(tags, func(r rune) bool { return r == ';' || r == ',' }) {
		if strings.TrimSpace(t) == tag {
			return true
		}
	}
	return false
}
```

- [ ] Run to green: `go test ./internal/keepass/` - expect PASS (Argon2 KDF makes this suite take a few seconds; that is expected)
- [ ] Commit: `git add internal/keepass && git commit -m "feat(keepass): tag-scoped kdbx secret reader"`

### Task 4: config fields + template

**Files:** Modify: `internal/config/config.go`, `internal/config/config_test.go`

- [ ] Write the failing tests (append to `config_test.go`):

```go
func TestKeepassRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	in := Default("source")
	in.KeepassPath = "/home/u/vault.kdbx"
	in.KeepassKeyfile = "/home/u/.config/agentpantry/vault.key"
	in.KeepassPassFile = "/home/u/.config/agentpantry/vault.pass"
	in.KeepassTag = "prod"
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	out, unknown, err := LoadChecked(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(unknown) != 0 {
		t.Fatalf("keepass_* must be known keys, got unknown %v", unknown)
	}
	if out.KeepassPath != in.KeepassPath || out.KeepassKeyfile != in.KeepassKeyfile ||
		out.KeepassPassFile != in.KeepassPassFile || out.KeepassTag != in.KeepassTag {
		t.Fatalf("keepass fields lost: %+v", out)
	}
}

func TestKeepassTagOrDefault(t *testing.T) {
	var c Config
	if got := c.KeepassTagOrDefault(); got != "agentpantry" {
		t.Fatalf("empty tag must default to agentpantry, got %q", got)
	}
	c.KeepassTag = "prod"
	if got := c.KeepassTagOrDefault(); got != "prod" {
		t.Fatalf("explicit tag must win, got %q", got)
	}
}
```

- [ ] Run: `go test ./internal/config/` - expect FAIL, `c.KeepassPath undefined`
- [ ] Add the fields to `Config` directly after `SecretsDir` (config.go:39):

```go
	KeepassPath     string        `toml:"keepass_path"`      // source: read tagged KeePass entries as named secrets
	KeepassKeyfile  string        `toml:"keepass_keyfile"`   // key file unlocking the vault (0600)
	KeepassPassFile string        `toml:"keepass_pass_file"` // optional: file holding the DB password (0600)
	KeepassTag      string        `toml:"keepass_tag"`       // export only entries with this tag (default "agentpantry")
```

- [ ] Add the method after `LoadChecked`:

```go
// KeepassTagOrDefault returns the tag gating which vault entries sync,
// defaulting to "agentpantry" so an operator opts entries in explicitly.
func (c Config) KeepassTagOrDefault() string {
	if c.KeepassTag != "" {
		return c.KeepassTag
	}
	return "agentpantry"
}
```

- [ ] In `WriteTemplate`'s source body, directly after the `#secrets_dir` block, add:

```
# Optional: read named secrets from an encrypted KeePass vault instead of (or
# alongside) secrets_dir. Only entries tagged keepass_tag are exported
# (entry Title -> secret name, Password -> value); untagging an entry
# propagates as a delete on the sink. keepass_keyfile must be 0600.
# keepass_pass_file is only needed when the vault also has a master password.
#keepass_path = "/home/you/vault.kdbx"
#keepass_keyfile = "/home/you/.config/agentpantry/vault.key"
#keepass_pass_file = "/home/you/.config/agentpantry/vault.pass"
#keepass_tag = "agentpantry"
```

- [ ] Run to green: `go test ./internal/config/` - expect PASS
- [ ] Commit: `git add internal/config && git commit -m "feat(config): keepass vault source options"`

### Task 5: source wiring

**Files:** Modify: `cmd/agentpantry/main.go` (imports + the `secretReaders` block at ~301-307)

- [ ] Add `"github.com/escoffier-labs/agentpantry/internal/keepass"` to main.go's imports
- [ ] Directly after the existing `if c.SecretsDir != ""` block in `cmdSource`, add:

```go
	if c.KeepassPath != "" {
		secretReaders = append(secretReaders, &keepass.Reader{
			Path:     c.KeepassPath,
			Keyfile:  c.KeepassKeyfile,
			PassFile: c.KeepassPassFile,
			Tag:      c.KeepassTagOrDefault(),
		})
		if _, statErr := os.Stat(c.KeepassPath); statErr == nil {
			paths = append(paths, c.KeepassPath) // a vault save triggers a resync
		}
	}
```

- [ ] Build: `go build ./...` - expect clean
- [ ] Commit: `git add cmd/agentpantry/main.go && git commit -m "feat(source): read named secrets from a keepass vault"`

### Task 6: doctor check

**Files:** Modify: `internal/doctor/doctor.go`, `internal/doctor/doctor_test.go`

- [ ] Write the failing tests (append to `doctor_test.go`; the vault builder mirrors
  `internal/keepass`'s test helper because that helper is unexported by design):

```go
func writeDoctorVault(t *testing.T, dir string) (vaultPath, keyPath string) {
	t.Helper()
	keyPath = filepath.Join(dir, "vault.key")
	if err := os.WriteFile(keyPath, []byte("doctor-key-material"), 0o600); err != nil {
		t.Fatal(err)
	}
	creds, err := gokeepasslib.NewKeyDataCredentials([]byte("doctor-key-material"))
	if err != nil {
		t.Fatal(err)
	}
	e := gokeepasslib.NewEntry()
	e.Values = append(e.Values,
		gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: "API_KEY"}},
		gokeepasslib.ValueData{Key: "Password", Value: gokeepasslib.V{Content: "v", Protected: w.NewBoolWrapper(true)}},
	)
	e.Tags = "agentpantry"
	root := gokeepasslib.NewGroup()
	root.Name = "Root"
	root.Entries = append(root.Entries, e)
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

func TestKeepassVaultMissingFails(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	c := config.Config{Role: "source", KeyPath: key, KeepassPath: filepath.Join(dir, "nope.kdbx")}
	ck := find(Run(c), "keepass")
	if ck.Status != Fail {
		t.Fatalf("missing vault must Fail, got %+v", ck)
	}
}

func TestKeepassHealthyReportsCount(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	vault, vaultKey := writeDoctorVault(t, dir)
	c := config.Config{Role: "source", KeyPath: key, KeepassPath: vault, KeepassKeyfile: vaultKey}
	ck := find(Run(c), "keepass")
	if ck.Status != OK || !strings.Contains(ck.Detail, "1 secret") {
		t.Fatalf("healthy vault must report the tagged count, got %+v", ck)
	}
}
```

  Imports to add in `doctor_test.go`: `github.com/tobischo/gokeepasslib/v3` and
  `w "github.com/tobischo/gokeepasslib/v3/wrappers"`.

- [ ] Run: `go test ./internal/doctor/` - expect FAIL, `find(...) "keepass"` returns status -1
- [ ] Implement in `doctor.go`, source branch of `Run`, directly after the `c.SecretsDir` block
  (imports to add: `context`, `github.com/escoffier-labs/agentpantry/internal/keepass`):

```go
		if c.KeepassPath != "" {
			if _, err := os.Stat(c.KeepassPath); err != nil {
				checks = append(checks, Check{"keepass", Fail, "vault unreadable: " + c.KeepassPath})
			} else {
				r := &keepass.Reader{
					Path:     c.KeepassPath,
					Keyfile:  c.KeepassKeyfile,
					PassFile: c.KeepassPassFile,
					Tag:      c.KeepassTagOrDefault(),
				}
				if ss, err := r.ReadSecrets(context.Background()); err != nil {
					checks = append(checks, Check{"keepass", Fail, err.Error()})
				} else {
					checks = append(checks, Check{"keepass", OK, fmt.Sprintf("%d secret(s) from %s (tag: %s)", len(ss), c.KeepassPath, c.KeepassTagOrDefault())})
				}
			}
		}
```

- [ ] Run to green: `go test ./internal/doctor/` - expect PASS
- [ ] Commit: `git add internal/doctor && git commit -m "feat(doctor): validate keepass vault unlock and tagged count"`

### Task 7: docs

**Files:** Modify: `README.md` (named-secrets section, after the `secrets_dir` source paragraph
around line 325), `CHANGELOG.md` (Unreleased/Added)

- [ ] README, after the source-side `secrets_dir` paragraph, add:

```markdown
Instead of (or alongside) a plaintext directory, the source can read named
secrets straight from an encrypted KeePass vault:

    keepass_path = "/home/you/vault.kdbx"
    keepass_keyfile = "/home/you/.config/agentpantry/vault.key"
    # keepass_pass_file = "..."   # only for password+keyfile vaults
    # keepass_tag = "agentpantry" # the default

Only entries carrying the `keepass_tag` tag are exported (entry Title becomes
the secret name, Password the value), so tagging is the opt-in: the rest of
the vault never leaves the machine. `[secret_names]` still applies on top.
Untagging an entry propagates as a delete on the sink. Unlock is
non-interactive via a 0600 key file (add one in KeePassXC under Database
Security), so the source runs headless. If the same name comes from both
`secrets_dir` and the vault, pick one source per name; the merge order is
otherwise unspecified. A vault that is temporarily unreadable leaves
already-synced secrets on the sink untouched for that cycle.
```

- [ ] CHANGELOG, under `## Unreleased` / `### Added`:

```markdown
- Source-side KeePass secret reader: `keepass_path`/`keepass_keyfile`/`keepass_pass_file`/`keepass_tag`
  read tagged vault entries as named secrets, replacing the need for a plaintext `secrets_dir`.
  `agentpantry doctor` validates the unlock and reports the tagged entry count.
```

- [ ] Commit: `git add README.md CHANGELOG.md && git commit -m "docs: keepass secret source"`

### Task 8: full verification (through Brigade)

- [ ] `brigade work verify run --target . --command "./scripts/verify"` - expect exit 0 (build, vet, full test suite)
- [ ] `brigade outcome capture recipe --run-id latest --kind skill`
- [ ] `make gosec` - expect 0 issues (the two `#nosec G304` carry justifications)
- [ ] `make vuln` - expect no findings
- [ ] `go test -race ./internal/keepass/ ./internal/doctor/` - expect PASS (CI runs race; catch it locally first)
