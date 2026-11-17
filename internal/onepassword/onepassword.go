// Package onepassword reads tagged secrets through a pinned, isolated op CLI.
package onepassword

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/secret"
)

const totalLimit = 4 << 20

var errMalformed = errors.New("onepassword: malformed data")
var errLimit = errors.New("onepassword: limit exceeded")

// Config selects one dedicated service-account vault. Tags are selection only.
type Config struct {
	Vault         string `toml:"vault"`
	Tag           string `toml:"tag"`
	TokenFile     string `toml:"token_file"`
	Field         string `toml:"field"`
	OpPath        string `toml:"op_path"`
	PollSeconds   int    `toml:"poll_seconds"`
	MaxItems      int    `toml:"max_items"`
	MaxValueBytes int    `toml:"max_value_bytes"`
}

func (c *Config) Validate() error {
	if strings.TrimSpace(c.Vault) == "" || strings.TrimSpace(c.Tag) == "" || strings.TrimSpace(c.TokenFile) == "" || strings.TrimSpace(c.Field) == "" {
		return errors.New("onepassword: vault, tag, token_file and field are required")
	}
	if c.PollSeconds == 0 {
		c.PollSeconds = 300
	}
	if c.MaxItems == 0 {
		c.MaxItems = 200
	}
	if c.MaxValueBytes == 0 {
		c.MaxValueBytes = 65536
	}
	if c.PollSeconds < 60 || c.PollSeconds > 86400 || c.MaxItems < 1 || c.MaxItems > 10000 || c.MaxValueBytes < 1 || c.MaxValueBytes > totalLimit {
		return errLimit
	}
	if strings.HasPrefix(c.TokenFile, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return errors.New("onepassword: home unavailable")
		}
		c.TokenFile = filepath.Join(home, c.TokenFile[2:])
	}
	return nil
}

type item struct {
	ID      string          `json:"id"`
	Title   string          `json:"title"`
	Tags    []string        `json:"tags"`
	Version json.RawMessage `json:"version"`
	Updated string          `json:"updated_at"`
}

func validID(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
func validName(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\\\x00\r\n") && len(s) <= 255
}
func parseList(raw []byte, max int) ([]item, error) {
	raw = bytes.TrimSpace(raw)
	var items []item
	if len(raw) > totalLimit {
		return nil, errLimit
	}
	if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &items) != nil {
		return nil, errMalformed
	}
	if len(items) > max {
		return nil, errLimit
	}
	seen := map[string]bool{}
	for _, i := range items {
		if !validID(i.ID) || !validName(i.Title) || seen[i.ID] {
			return nil, errMalformed
		}
		seen[i.ID] = true
		if len(i.Version) > 0 {
			var n int64
			if json.Unmarshal(i.Version, &n) != nil || n < 1 {
				return nil, errMalformed
			}
		} else if _, err := time.Parse(time.RFC3339, i.Updated); err != nil {
			return nil, errMalformed
		}
	}
	return items, nil
}
func parseValue(raw []byte, field string, max int) (string, error) {
	raw = bytes.TrimSpace(raw)
	// op's --fields JSON is a field object for one match and an array for multiple matches.
	type value struct {
		Label string  `json:"label"`
		Value *string `json:"value"`
	}
	var fields []value
	if len(raw) > totalLimit {
		return "", errLimit
	}
	if len(raw) > 0 && raw[0] == '{' {
		var f value
		if json.Unmarshal(raw, &f) != nil {
			return "", errMalformed
		}
		fields = []value{f}
	} else if json.Unmarshal(raw, &fields) != nil {
		return "", errMalformed
	}
	if len(fields) != 1 || fields[0].Label != field || fields[0].Value == nil {
		return "", errMalformed
	}
	if len(*fields[0].Value) > max {
		return "", errLimit
	}
	return *fields[0].Value, nil
}

type entry struct{ version, title, value string }
type invoke func(context.Context, string, string, []string) ([]byte, error)

// Reader serializes polls and commits inventory only after a successful complete read.
type Reader struct {
	Config    Config
	mu        sync.Mutex
	binary    *binary
	run       invoke
	vault     string
	cache     map[string]entry
	inventory map[string]string
	absent    map[string]bool
	next      time.Time
	lastErr   error
	now       func() time.Time
}

func (*Reader) Kind() string { return "onepassword" }
func (r *Reader) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}
func snapshot(m map[string]string) []secret.Secret {
	out := make([]secret.Secret, 0, len(m))
	for n, v := range m {
		out = append(out, secret.Secret{Name: n, Value: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
func (r *Reader) session(ctx context.Context) (context.Context, context.CancelFunc, string, string, error) {
	if err := r.Config.Validate(); err != nil {
		return nil, nil, "", "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	if r.run == nil {
		if r.binary == nil {
			b, err := pinBinary(r.Config.OpPath)
			if err != nil {
				cancel()
				return nil, nil, "", "", err
			}
			r.binary = b
		}
		r.run = r.binary.invoke
	}
	f, err := openToken(r.Config.TokenFile)
	if err != nil {
		cancel()
		return nil, nil, "", "", errors.New("onepassword: token file rejected")
	}
	token, err := readToken(f)
	_ = f.Close()
	if err != nil {
		cancel()
		return nil, nil, "", "", err
	}
	dir, err := os.MkdirTemp("", "agentpantry-op-")
	if err != nil {
		cancel()
		return nil, nil, "", "", errors.New("onepassword: private directory unavailable")
	}
	if err = secureDir(dir); err != nil {
		_ = os.RemoveAll(dir)
		cancel()
		return nil, nil, "", "", err
	}
	cleanup := func() { cancel(); _ = os.RemoveAll(dir) }
	if r.vault == "" {
		raw, err := r.run(ctx, token, dir, []string{"--version"})
		if err != nil {
			cleanup()
			return nil, nil, "", "", err
		}
		if !supportedVersion(strings.TrimSpace(string(raw))) {
			cleanup()
			return nil, nil, "", "", errors.New("onepassword: CLI version must be >= 2.18.0")
		}
		raw, err = r.run(ctx, token, dir, []string{"vault", "get", r.Config.Vault, "--format", "json"})
		if err != nil {
			cleanup()
			return nil, nil, "", "", err
		}
		var v struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(raw, &v) != nil || !validID(v.ID) {
			cleanup()
			return nil, nil, "", "", errMalformed
		}
		r.vault = v.ID
	}
	return ctx, cleanup, token, dir, nil
}
func supportedVersion(s string) bool {
	p := strings.Split(s, ".")
	if len(p) != 3 {
		return false
	}
	major, e := strconv.Atoi(p[0])
	minor, e2 := strconv.Atoi(p[1])
	patch, e3 := strconv.Atoi(p[2])
	return e == nil && e2 == nil && e3 == nil && patch >= 0 && (major > 2 || major == 2 && minor >= 18)
}
func (r *Reader) list(ctx context.Context, token, dir string) ([]item, error) {
	raw, err := r.run(ctx, token, dir, []string{"item", "list", "--vault", r.vault, "--format", "json"})
	if err != nil {
		return nil, err
	}
	return parseList(raw, r.Config.MaxItems)
}
func (r *Reader) ReadSecrets(ctx context.Context) ([]secret.Secret, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.clock().Before(r.next) {
		if r.lastErr != nil {
			return nil, r.lastErr
		}
		return snapshot(r.inventory), nil
	}
	ctx, cleanup, token, dir, err := r.session(ctx)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	fail := func(err error) ([]secret.Secret, error) {
		if err.Error() == "onepassword: rate limited" {
			r.next = r.clock().Add(time.Duration(r.Config.PollSeconds) * time.Second)
			r.lastErr = err
		}
		return nil, err
	}
	items, err := r.list(ctx, token, dir)
	if err != nil {
		return fail(err)
	}
	cache := map[string]entry{}
	current := map[string]string{}
	absent := map[string]bool{}
	titles := map[string]bool{}
	for _, i := range items {
		selected := false
		for _, tag := range i.Tags {
			if tag == r.Config.Tag {
				selected = true
			}
		}
		if !selected {
			continue
		}
		if titles[i.Title] {
			return fail(errMalformed)
		}
		titles[i.Title] = true
		version := string(i.Version) + i.Updated
		e, ok := r.cache[i.ID]
		if !ok || e.version != version {
			raw, err := r.run(ctx, token, dir, []string{"item", "get", i.ID, "--vault", r.vault, "--fields", "label=" + r.Config.Field, "--reveal", "--format", "json"})
			if err != nil {
				return fail(err)
			}
			value, err := parseValue(raw, r.Config.Field, r.Config.MaxValueBytes)
			if err != nil {
				return fail(err)
			}
			e = entry{version: version, value: value}
		}
		e.title = i.Title
		cache[i.ID] = e
		current[i.Title] = e.value
	}
	for name, value := range r.inventory {
		if _, ok := current[name]; !ok && !r.absent[name] {
			current[name] = value
			absent[name] = true
		}
	}
	total := 0
	for n, v := range current {
		total += len(n) + len(v)
		if total >= totalLimit {
			return fail(errLimit)
		}
	}
	if ctx.Err() != nil {
		return fail(errors.New("onepassword: timeout"))
	}
	encoded, err := json.Marshal(snapshot(current))
	if err != nil || len(encoded) >= totalLimit {
		return fail(errLimit)
	}
	r.cache = cache
	r.inventory = current
	r.absent = absent
	r.next = r.clock().Add(time.Duration(r.Config.PollSeconds) * time.Second)
	r.lastErr = nil
	return snapshot(current), nil
}

// Inspect checks the binary, token and live inventory without fetching item values.
func (r *Reader) Inspect(ctx context.Context) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx, cleanup, token, dir, err := r.session(ctx)
	if err != nil {
		return 0, err
	}
	defer cleanup()
	items, err := r.list(ctx, token, dir)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, i := range items {
		for _, t := range i.Tags {
			if t == r.Config.Tag {
				n++
				break
			}
		}
	}
	return n, nil
}
func fixed(category string) error { return fmt.Errorf("onepassword: %s", category) }
