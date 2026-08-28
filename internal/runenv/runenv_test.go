package runenv

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/policy"
	"github.com/escoffier-labs/agentpantry/internal/secret"
)

func TestPlanDenyWins(t *testing.T) {
	secrets := []secret.Secret{
		{Name: "gh_token", Value: "tok"},
		{Name: "aws_key", Value: "aws"},
	}
	pol := policy.Names{Deny: []string{"aws_key"}}
	got, err := Plan(secrets, pol, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "gh_token" || got[0].EnvVar != "GH_TOKEN" || got[0].Value != "tok" {
		t.Fatalf("unexpected bindings: %+v", got)
	}
}

func TestPlanEmptyAllowPermitsAll(t *testing.T) {
	secrets := []secret.Secret{{Name: "a", Value: "1"}, {Name: "b", Value: "2"}}
	got, err := Plan(secrets, policy.Names{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("empty allow must inject all, got %+v", got)
	}
}

func TestPlanAllowList(t *testing.T) {
	secrets := []secret.Secret{{Name: "keep", Value: "1"}, {Name: "drop", Value: "2"}}
	got, err := Plan(secrets, policy.Names{Allow: []string{"keep"}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "keep" {
		t.Fatalf("allow list: %+v", got)
	}
}

func TestPlanOnlyFurtherNarrows(t *testing.T) {
	secrets := []secret.Secret{{Name: "keep", Value: "1"}, {Name: "other", Value: "2"}}
	got, err := Plan(secrets, policy.Names{}, []string{"keep"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "keep" {
		t.Fatalf("only list: %+v", got)
	}
}

func TestPlanOnlyDeniedFailsClosed(t *testing.T) {
	secrets := []secret.Secret{{Name: "aws_key", Value: "aws"}}
	_, err := Plan(secrets, policy.Names{Deny: []string{"aws_key"}}, []string{"aws_key"}, nil)
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("denied -secret must fail closed, got %v", err)
	}
}

func TestPlanOnlyMissingFailsClosed(t *testing.T) {
	_, err := Plan(nil, policy.Names{}, []string{"missing"}, nil)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing -secret must fail closed, got %v", err)
	}
}

func TestPlanDenyOverridesAllow(t *testing.T) {
	secrets := []secret.Secret{{Name: "gh_token", Value: "tok"}}
	_, err := Plan(secrets, policy.Names{Allow: []string{"gh_token"}, Deny: []string{"gh_token"}}, []string{"gh_token"}, nil)
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("deny must win over allow and -secret, got %v", err)
	}
}

func TestPlanEnvMapping(t *testing.T) {
	secrets := []secret.Secret{{Name: "gh_token", Value: "tok"}}
	got, err := Plan(secrets, policy.Names{}, nil, map[string]string{"gh_token": "MY_TOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].EnvVar != "MY_TOKEN" {
		t.Fatalf("mapping: %+v", got)
	}
}

func TestPlanEnvMappingNotSelectedFails(t *testing.T) {
	secrets := []secret.Secret{{Name: "gh_token", Value: "tok"}, {Name: "other", Value: "x"}}
	_, err := Plan(secrets, policy.Names{}, []string{"gh_token"}, map[string]string{"other": "OTHER"})
	if err == nil || !strings.Contains(err.Error(), "not selected") {
		t.Fatalf("mapping for unselected secret must fail, got %v", err)
	}
}

func TestPlanEnvMappingDeniedFails(t *testing.T) {
	secrets := []secret.Secret{{Name: "aws_key", Value: "aws"}}
	_, err := Plan(secrets, policy.Names{Deny: []string{"aws_key"}}, nil, map[string]string{"aws_key": "AWS_KEY"})
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("mapping for denied secret must fail, got %v", err)
	}
}

func TestPlanCollisionFailsClosed(t *testing.T) {
	secrets := []secret.Secret{
		{Name: "gh-token", Value: "a"},
		{Name: "gh_token", Value: "b"},
	}
	_, err := Plan(secrets, policy.Names{}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "collision") {
		t.Fatalf("sanitized collision must fail closed, got %v", err)
	}
}

func TestPlanNULValueFailsClosed(t *testing.T) {
	secrets := []secret.Secret{{Name: "gh_token", Value: "tok\x00more"}}
	_, err := Plan(secrets, policy.Names{}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("NUL value must fail closed, got %v", err)
	}
}

func TestPlanDeniedNULIsIgnored(t *testing.T) {
	secrets := []secret.Secret{
		{Name: "good", Value: "ok"},
		{Name: "bad", Value: "x\x00y"},
	}
	got, err := Plan(secrets, policy.Names{Deny: []string{"bad"}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "good" {
		t.Fatalf("denied NUL secret must not fail the plan: %+v", got)
	}
}

func TestSanitizeEnvName(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"gh_token", "GH_TOKEN"},
		{"my-api-key", "MY_API_KEY"},
		{"123secret", "_123SECRET"},
		{"already_OK", "ALREADY_OK"},
		{"a.b", "A_B"},
	}
	for _, tc := range cases {
		got, err := SanitizeEnvName(tc.in)
		if err != nil {
			t.Fatalf("SanitizeEnvName(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("SanitizeEnvName(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if !ValidEnvName(got) {
			t.Fatalf("sanitized %q is not a valid env name", got)
		}
	}
	if _, err := SanitizeEnvName(""); err == nil {
		t.Fatal("empty name must fail")
	}
}

func TestValidEnvName(t *testing.T) {
	ok := []string{"A", "_", "GH_TOKEN", "a1", "_1"}
	for _, s := range ok {
		if !ValidEnvName(s) {
			t.Fatalf("ValidEnvName(%q) = false", s)
		}
	}
	bad := []string{"", "1A", "A-B", "A=B", "A B", "Ä", "="}
	for _, s := range bad {
		if ValidEnvName(s) {
			t.Fatalf("ValidEnvName(%q) = true", s)
		}
	}
}

func TestParseEnvMapping(t *testing.T) {
	name, envVar, err := ParseEnvMapping("gh_token=MY_TOKEN")
	if err != nil || name != "gh_token" || envVar != "MY_TOKEN" {
		t.Fatalf("got %q %q %v", name, envVar, err)
	}
	for _, raw := range []string{"", "nocolon", "=ENV", "name=", "name=1BAD", "name=A-B"} {
		if _, _, err := ParseEnvMapping(raw); err == nil {
			t.Fatalf("ParseEnvMapping(%q) must fail", raw)
		}
	}
}

func TestMergeEnvironParentPlusBindings(t *testing.T) {
	parent := []string{"KEEP=from-parent", "GH_TOKEN=stale"}
	out := MergeEnviron(parent, []Binding{{Name: "gh_token", EnvVar: "GH_TOKEN", Value: "fresh"}})
	m := envMap(out)
	if m["KEEP"] != "from-parent" {
		t.Fatalf("parent var lost: %v", m)
	}
	if m["GH_TOKEN"] != "fresh" {
		t.Fatalf("binding must replace parent: %v", m)
	}
	if _, ok := m["AGENTPANTRY_RUN"]; ok {
		t.Fatal("must not inject extra helper vars")
	}
}

func TestMergeEnvironAddsMissing(t *testing.T) {
	out := MergeEnviron([]string{"PATH=/bin"}, []Binding{{Name: "k", EnvVar: "K", Value: "v"}})
	m := envMap(out)
	if m["PATH"] != "/bin" || m["K"] != "v" {
		t.Fatalf("merge: %v", m)
	}
}

func TestLoadSecretsReadsDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "gh_token"), []byte("tok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".hidden"), []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSecrets(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "gh_token" || got[0].Value != "tok" {
		t.Fatalf("LoadSecrets: %+v", got)
	}
}

func TestInvokePropagatesExitAndEnv(t *testing.T) {
	helper := buildHelper(t)
	code, err := Invoke([]string{helper, "-exit", "0"}, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	code, err = Invoke([]string{helper, "-exit", "7"}, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	if code != 7 {
		t.Fatalf("want exit 7, got %d", code)
	}
}

func TestInvokeRequiresCommand(t *testing.T) {
	if _, err := Invoke(nil, nil); err == nil {
		t.Fatal("empty argv must fail")
	}
}

func envMap(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if ok {
			m[k] = v
		}
	}
	return m
}

func buildHelper(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	body := `package main
import ("fmt"; "os"; "strconv")
func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	switch os.Args[1] {
	case "-print":
		if len(os.Args) < 3 {
			os.Exit(2)
		}
		fmt.Print(os.Getenv(os.Args[2]))
	case "-exit":
		n, err := strconv.Atoi(os.Args[2])
		if err != nil {
			os.Exit(2)
		}
		os.Exit(n)
	default:
		os.Exit(2)
	}
}
`
	if err := os.WriteFile(src, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "helper")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helper build: %v\n%s", err, out)
	}
	return bin
}
