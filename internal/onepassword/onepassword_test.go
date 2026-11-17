package onepassword

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fake struct {
	list   string
	values map[string]string
	fail   string
	calls  int
	gets   int
	tokens []string
	args   [][]string
}

func (f *fake) invoke(ctx context.Context, token, dir string, args []string) ([]byte, error) {
	f.calls++
	f.tokens = append(f.tokens, token)
	f.args = append(f.args, append([]string{}, args...))
	if ctx.Err() != nil {
		return nil, fixed("timeout")
	}
	if args[0] == "--version" {
		return []byte("2.18.0"), nil
	}
	if args[0] == "vault" {
		return []byte(`{"id":"vaultID"}`), nil
	}
	if args[2] == "--vault" && args[3] != "vaultID" {
		return nil, errors.New("vault not pinned")
	}
	if args[1] == "list" {
		if f.fail == "list" {
			return nil, fixed("rate limited")
		}
		return []byte(f.list), nil
	}
	f.gets++
	if f.fail == args[2] {
		return nil, fixed("not found")
	}
	return []byte(f.values[args[2]]), nil
}
func fixture(t *testing.T) (*Reader, *fake, *time.Time) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte("fake-token"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := secureTokenForTest(p); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f := &fake{list: `[{"id":"a","title":"API","tags":["agentpantry"],"version":1}]`, values: map[string]string{"a": `{"label":"password","value":"secret"}`}}
	r := &Reader{Config: Config{Vault: "Dedicated", Tag: "agentpantry", Field: "password", TokenFile: p}, run: f.invoke, now: func() time.Time { return now }}
	return r, f, &now
}
func poll(t *testing.T, r *Reader, now *time.Time) map[string]string {
	t.Helper()
	*now = now.Add(301 * time.Second)
	ss, err := r.ReadSecrets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, s := range ss {
		out[s.Name] = s.Value
	}
	return out
}
func TestCacheRenameAndTwoPollDeletion(t *testing.T) {
	r, f, now := fixture(t)
	poll(t, r, now)
	poll(t, r, now)
	if f.gets != 1 {
		t.Fatal("unchanged item fetched")
	}
	f.list = strings.Replace(f.list, "API", "RENAMED", 1)
	got := poll(t, r, now)
	if got["API"] != "secret" || got["RENAMED"] != "secret" || f.gets != 1 {
		t.Fatalf("rename: %v", got)
	}
	got = poll(t, r, now)
	if _, ok := got["API"]; ok {
		t.Fatal("old title retained")
	}
	f.list = "[]"
	if len(poll(t, r, now)) != 1 {
		t.Fatal("first empty poll deleted")
	}
	calls := f.calls
	if ss, err := r.ReadSecrets(context.Background()); err != nil || len(ss) != 1 || f.calls != calls {
		t.Fatal("cache read counted as independent poll")
	}
	if len(poll(t, r, now)) != 0 {
		t.Fatal("second poll did not confirm delete")
	}
}
func TestTransactionalFailures(t *testing.T) {
	cases := map[string]func(*fake){
		"partial list": func(f *fake) { f.list = `[{"id":"a"}` },
		"missing field": func(f *fake) {
			f.values["a"] = `{"label":"other","value":"x"}`
			f.list = strings.Replace(f.list, `"version":1`, `"version":2`, 1)
		},
		"ambiguous field": func(f *fake) {
			f.values["a"] = `[{"label":"password","value":"x"},{"label":"password","value":"y"}]`
			f.list = strings.Replace(f.list, `"version":1`, `"version":2`, 1)
		},
		"mid fetch deletion": func(f *fake) { f.list = strings.Replace(f.list, `"version":1`, `"version":2`, 1); f.fail = "a" },
		"duplicate title": func(f *fake) {
			f.list = `[{"id":"a","title":"API","version":2,"tags":["agentpantry"]},{"id":"b","title":"API","version":1,"tags":["agentpantry"]}]`
		},
		"unsafe name":     func(f *fake) { f.list = strings.Replace(f.list, "API", "../bad", 1) },
		"invalid version": func(f *fake) { f.list = strings.Replace(f.list, `"version":1`, `"version":0`, 1) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			r, f, now := fixture(t)
			poll(t, r, now)
			before := r.cache["a"]
			change(f)
			*now = now.Add(301 * time.Second)
			if ss, err := r.ReadSecrets(context.Background()); err == nil || ss != nil {
				t.Fatal("partial result accepted")
			}
			if r.cache["a"] != before || r.inventory["API"] != "secret" {
				t.Fatal("failed read committed")
			}
		})
	}
}
func TestRateLimitAndTokenRotation(t *testing.T) {
	r, f, now := fixture(t)
	poll(t, r, now)
	f.fail = "list"
	*now = now.Add(301 * time.Second)
	if _, err := r.ReadSecrets(context.Background()); err == nil {
		t.Fatal("rate limit accepted")
	}
	calls := f.calls
	if _, err := r.ReadSecrets(context.Background()); err == nil || f.calls != calls {
		t.Fatal("rate-limit backoff not applied")
	}
	if r.inventory["API"] != "secret" {
		t.Fatal("lost inventory")
	}
	f.fail = ""
	if err := os.WriteFile(r.Config.TokenFile, []byte("rotated-token"), 0600); err != nil {
		t.Fatal(err)
	}
	poll(t, r, now)
	if f.tokens[len(f.tokens)-1] != "rotated-token" {
		t.Fatal("token not refreshed")
	}
	for _, args := range f.args {
		for _, a := range args {
			if strings.Contains(a, "token") {
				t.Fatal("token in argv")
			}
		}
	}
}
func TestExactTagAndInspect(t *testing.T) {
	r, f, _ := fixture(t)
	f.list = strings.Replace(f.list, "agentpantry", "agentpantry/nested", 1)
	n, err := r.Inspect(context.Background())
	if err != nil || n != 0 || f.gets != 0 {
		t.Fatal(n, err)
	}
	f.list = strings.Replace(f.list, "agentpantry/nested", "agentpantry", 1)
	n, err = r.Inspect(context.Background())
	if err != nil || n != 1 || f.gets != 0 {
		t.Fatal(n, err)
	}
}
func TestLimitsAndTimeout(t *testing.T) {
	for _, name := range []string{"items", "value", "total", "timeout"} {
		t.Run(name, func(t *testing.T) {
			r, f, _ := fixture(t)
			ctx := context.Background()
			switch name {
			case "items":
				r.Config.MaxItems = 1
				f.list = `[{"id":"a","title":"a","version":1},{"id":"b","title":"b","version":1}]`
			case "value":
				r.Config.MaxValueBytes = 2
			case "total":
				r.Config.MaxValueBytes = totalLimit
				f.values["a"] = fmt.Sprintf(`{"label":"password","value":%q}`, strings.Repeat("x", totalLimit))
			case "timeout":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := r.ReadSecrets(ctx); err == nil {
				t.Fatal("limit accepted")
			}
			if r.cache != nil {
				t.Fatal("failure committed")
			}
		})
	}
}
func TestParsers(t *testing.T) {
	for _, raw := range []string{"null", "{}", "[] garbage", `[{"id":"-flag","title":"x","version":1}]`, `[{"id":"a","title":"x"}]`} {
		if _, err := parseList([]byte(raw), 10); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	for _, raw := range []string{"null", "[]", `{"label":"password"}`, `{"label":"password","value":12}`} {
		if _, err := parseValue([]byte(raw), "password", 10); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}
func TestVersion(t *testing.T) {
	for s, want := range map[string]bool{"2.17.9": false, "2.18.0": true, "2.30.1": true, "3.0.0": true, "2.18.0-dev": false} {
		if supportedVersion(s) != want {
			t.Fatal(s)
		}
	}
}
func TestChildEnvironment(t *testing.T) {
	t.Setenv("UNTRUSTED", "parent-secret")
	env := childEnv("test-token", "private")
	for _, s := range env {
		if strings.Contains(s, "parent-secret") {
			t.Fatal("inherited parent environment")
		}
	}
	if !reflect.DeepEqual(os.Getenv("UNTRUSTED"), "parent-secret") {
		t.Fatal("parent changed")
	}
}
func FuzzParsers(f *testing.F) {
	f.Add([]byte(`[{"id":"a","title":"API","version":1}]`))
	f.Add([]byte(`{"label":"password","value":"fixture"}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = parseList(b, 200); _, _ = parseValue(b, "password", 65536) })
}

func TestCycleDeadlineAndNoFailedCacheCommit(t *testing.T) {
	r, f, now := fixture(t)
	poll(t, r, now)
	base := f.invoke
	r.run = func(ctx context.Context, token, dir string, args []string) ([]byte, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 120*time.Second {
			t.Fatal("unbounded cycle")
		}
		if args[0] == "item" && args[1] == "get" {
			return nil, fixed("timeout")
		}
		return base(ctx, token, dir, args)
	}
	f.list = strings.Replace(f.list, `"version":1`, `"version":2`, 1)
	*now = now.Add(301 * time.Second)
	if _, err := r.ReadSecrets(context.Background()); err == nil {
		t.Fatal("timeout accepted")
	}
	if r.cache["a"].version != "1" || r.inventory["API"] != "secret" {
		t.Fatal("timeout committed cache")
	}
}

func TestCacheCommitsOnlyAfterEveryGetSucceeds(t *testing.T) {
	r, f, now := fixture(t)
	poll(t, r, now)
	f.list = `[{"id":"a","title":"API","tags":["agentpantry"],"version":2},{"id":"b","title":"SECOND","tags":["agentpantry"],"version":1}]`
	f.values["a"] = `{"label":"password","value":"changed"}`
	f.fail = "b"
	*now = now.Add(301 * time.Second)
	if ss, err := r.ReadSecrets(context.Background()); err == nil || ss != nil {
		t.Fatal("partial result accepted")
	}
	if r.cache["a"].value != "secret" || r.cache["a"].version != "1" || len(r.cache) != 1 {
		t.Fatal("partial cache committed")
	}
	f.fail = ""
	f.values["b"] = `{"label":"password","value":"second"}`
	if got := poll(t, r, now); got["API"] != "changed" || got["SECOND"] != "second" {
		t.Fatal("retry did not fetch full inventory")
	}
}
