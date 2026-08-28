// Package runenv builds a child process environment from already-synced
// secrets. Values stay in memory; this package never writes them to a file.
package runenv

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/escoffier-labs/agentpantry/internal/policy"
	"github.com/escoffier-labs/agentpantry/internal/secret"
	"github.com/escoffier-labs/agentpantry/internal/secretsrc"
)

// Binding is one secret that will be injected as an environment variable.
type Binding struct {
	Name   string
	EnvVar string
	Value  string
}

// Plan selects secrets that pass deny-wins policy (and an optional extra
// name list), maps each to an environment variable, and fails closed on
// collisions, missing names, or invalid mappings. Denied or unselected
// secrets are omitted; their values are not inspected.
func Plan(secrets []secret.Secret, pol policy.Names, only []string, envMap map[string]string) ([]Binding, error) {
	byName := make(map[string]secret.Secret, len(secrets))
	for _, s := range secrets {
		if s.Name == "" {
			return nil, errors.New("empty secret name")
		}
		byName[s.Name] = s
	}

	var names []string
	if len(only) > 0 {
		seen := make(map[string]struct{}, len(only))
		for _, name := range only {
			if name == "" {
				return nil, errors.New("empty -secret name")
			}
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
			if !pol.Permit(name) {
				return nil, fmt.Errorf("secret %q denied by [secret_names]", name)
			}
			if _, ok := byName[name]; !ok {
				return nil, fmt.Errorf("secret %q not found", name)
			}
			names = append(names, name)
		}
	} else {
		for name := range byName {
			if pol.Permit(name) {
				names = append(names, name)
			}
		}
		sort.Strings(names)
	}

	selected := make(map[string]struct{}, len(names))
	for _, name := range names {
		selected[name] = struct{}{}
	}
	for name := range envMap {
		if _, ok := selected[name]; !ok {
			if !pol.Permit(name) {
				return nil, fmt.Errorf("secret %q denied by [secret_names]", name)
			}
			return nil, fmt.Errorf("secret %q not selected for injection", name)
		}
	}

	used := make(map[string]string, len(names)) // env var -> secret name
	out := make([]Binding, 0, len(names))
	for _, name := range names {
		sec := byName[name]
		if strings.IndexByte(sec.Value, 0) >= 0 {
			return nil, fmt.Errorf("secret %q contains a NUL byte", name)
		}
		envVar, err := envVarFor(name, envMap)
		if err != nil {
			return nil, err
		}
		if ReservedEnvName(envVar) {
			return nil, fmt.Errorf("secret %q maps to reserved environment variable %s", name, envVar)
		}
		if prev, ok := used[envVar]; ok {
			return nil, fmt.Errorf("env var collision: %s from %q and %q", envVar, prev, name)
		}
		used[envVar] = name
		out = append(out, Binding{Name: name, EnvVar: envVar, Value: sec.Value})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EnvVar < out[j].EnvVar })
	return out, nil
}

func envVarFor(name string, envMap map[string]string) (string, error) {
	if mapped, ok := envMap[name]; ok {
		if !ValidEnvName(mapped) {
			return "", fmt.Errorf("invalid env var name %q for secret %q", mapped, name)
		}
		return mapped, nil
	}
	return SanitizeEnvName(name)
}

// ParseEnvMapping parses a NAME=ENVVAR flag value. ENVVAR must already be a
// portable environment variable name; it is not sanitized.
func ParseEnvMapping(raw string) (name, envVar string, err error) {
	name, envVar, ok := strings.Cut(raw, "=")
	if !ok {
		return "", "", fmt.Errorf("invalid -env %q (want NAME=ENVVAR)", raw)
	}
	if name == "" || envVar == "" {
		return "", "", fmt.Errorf("invalid -env %q (want NAME=ENVVAR)", raw)
	}
	if !ValidEnvName(envVar) {
		return "", "", fmt.Errorf("invalid env var name %q", envVar)
	}
	return name, envVar, nil
}

// ValidEnvName reports whether s is a portable environment variable name:
// [A-Za-z_][A-Za-z0-9_]*.
func ValidEnvName(s string) bool {
	if s == "" || !utf8.ValidString(s) {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

// SanitizeEnvName maps a secret name to a portable environment variable.
// Non-alphanumeric runes become '_', letters are uppercased, and a leading
// digit is prefixed with '_'.
func SanitizeEnvName(name string) (string, error) {
	if name == "" {
		return "", errors.New("empty secret name")
	}
	var b strings.Builder
	b.Grow(len(name) + 1)
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 'a' + 'A')
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	s := b.String()
	if s == "" {
		return "", fmt.Errorf("secret %q sanitizes to an empty env var name", name)
	}
	if s[0] >= '0' && s[0] <= '9' {
		s = "_" + s
	}
	return s, nil
}

// reservedEnvNames are loader and interpreter variables that must not be
// injected. A synced secret named path or ld_preload would otherwise become
// PATH / LD_PRELOAD in every wrapped child.
var reservedEnvNames = []string{
	"PATH",
	"PATHEXT",
	"LD_PRELOAD",
	"LD_LIBRARY_PATH",
	"LD_AUDIT",
	"DYLD_INSERT_LIBRARIES",
	"DYLD_LIBRARY_PATH",
	"DYLD_FRAMEWORK_PATH",
	"DYLD_FALLBACK_LIBRARY_PATH",
	"NODE_OPTIONS",
	"PYTHONPATH",
	"PYTHONHOME",
	"PYTHONSTARTUP",
	"PERL5LIB",
	"PERL5OPT",
	"RUBYLIB",
	"RUBYOPT",
	"CLASSPATH",
	"JAVA_TOOL_OPTIONS",
	"_JAVA_OPTIONS",
	"JDK_JAVA_OPTIONS",
	"BASH_ENV",
	"ENV",
	"SHELLOPTS",
	"GCONV_PATH",
	"IFS",
	"GIT_SSH_COMMAND",
	"GIT_EXEC_PATH",
}

// ReservedEnvName reports whether envVar is a loader or interpreter variable
// that run refuses to inject, compared case-insensitively.
func ReservedEnvName(envVar string) bool {
	for _, r := range reservedEnvNames {
		if strings.EqualFold(envVar, r) {
			return true
		}
	}
	return false
}

// LoadSecrets reads already-synced secret files from dir. It does not write.
func LoadSecrets(dir string) ([]secret.Secret, error) {
	r := &secretsrc.DirReader{Dir: dir}
	return r.ReadSecrets(context.Background())
}

// MergeEnviron returns parent with bindings overlaid. The child inherits the
// parent environment plus the allowed secret set, and nothing else. A binding
// replaces a parent variable of the same name (case-insensitive on Windows).
func MergeEnviron(parent []string, bindings []Binding) []string {
	overlay := make(map[string]string, len(bindings))
	canon := make(map[string]string, len(bindings))
	for _, b := range bindings {
		overlay[environKey(b.EnvVar)] = b.Value
		canon[environKey(b.EnvVar)] = b.EnvVar
	}
	out := make([]string, 0, len(parent)+len(bindings))
	seen := make(map[string]struct{}, len(parent)+len(bindings))
	for _, kv := range parent {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		key := environKey(k)
		if _, dup := seen[key]; dup {
			continue
		}
		if val, inject := overlay[key]; inject {
			out = append(out, canon[key]+"="+val)
			seen[key] = struct{}{}
			continue
		}
		seen[key] = struct{}{}
		out = append(out, k+"="+v)
	}
	var extra []string
	for _, b := range bindings {
		if _, ok := seen[environKey(b.EnvVar)]; ok {
			continue
		}
		extra = append(extra, b.EnvVar+"="+b.Value)
	}
	sort.Strings(extra)
	return append(out, extra...)
}

func environKey(k string) string {
	if runtime.GOOS == "windows" {
		return strings.ToUpper(k)
	}
	return k
}

// Invoke starts argv with env and waits. It returns the child's exit code.
// env must already be the complete child environment (see MergeEnviron).
func Invoke(argv []string, env []string) (int, error) {
	if len(argv) == 0 {
		return 1, errors.New("run requires a command after --")
	}
	// #nosec G204 -- argv is the operator-supplied command after --; env is
	// parent plus policy-filtered secrets and is never written to a file.
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env
	if err := cmd.Start(); err != nil {
		return 1, err
	}
	return waitCmd(cmd)
}

func childStatus(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return 1, err
	}
	return signaledExit(ee)
}
