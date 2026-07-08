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
