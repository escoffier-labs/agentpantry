package source

import (
	"bytes"
	"context"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/policy"
	"github.com/escoffier-labs/agentpantry/internal/secret"
	"github.com/escoffier-labs/agentpantry/internal/transport"
	"github.com/escoffier-labs/agentpantry/internal/wire"
)

// kindedSecrets is a fake reader that names itself, like secrets_dir/keepass.
type kindedSecrets struct {
	kind string
	ss   []secret.Secret
}

func (k kindedSecrets) Kind() string { return k.kind }
func (k kindedSecrets) ReadSecrets(context.Context) ([]secret.Secret, error) {
	return k.ss, nil
}

// captureStderr runs fn with os.Stderr redirected and returns what was written.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	func() {
		defer func() {
			os.Stderr = orig
			_ = w.Close()
		}()
		fn()
	}()
	return <-done
}

// runCollisionCycle syncs once with prior synced secrets and the given
// readers, returning the payload, stderr output, and the syncer.
func runCollisionCycle(t *testing.T, prior []secret.Secret, readers ...SecretReader) (wire.Payload, string, *Syncer) {
	t.Helper()
	sealer, _ := transport.NewSealer(make([]byte, 32), make([]byte, 16))
	var buf bytes.Buffer
	syncer := &Syncer{
		Vaults: []CookieReader{fakeVault{cs: []cookie.Cookie{
			{Host: "github.com", Name: "sid", Path: "/", Value: "keep"},
		}}},
		Secrets: readers,
		Policy:  policy.Domain{Allow: []string{"github.com"}},
		Sealer:  sealer,
		Out:     &buf,
	}
	syncer.prevSecrets = secret.NewSnapshot(prior)
	var err error
	stderr := captureStderr(t, func() { err = syncer.SyncOnce(context.Background()) })
	if err != nil {
		t.Fatalf("collision must not fail the cycle: %v", err)
	}
	return decodePayload(t, &buf), stderr, syncer
}

func assertSecretsUntouched(t *testing.T, p wire.Payload, syncer *Syncer, prior []secret.Secret) {
	t.Helper()
	if len(p.Secrets.Upserts) != 0 || len(p.Secrets.Deletes) != 0 {
		t.Fatalf("no secret diff expected on collision: %+v", p.Secrets)
	}
	if !reflect.DeepEqual(syncer.prevSecrets, secret.NewSnapshot(prior)) {
		t.Fatalf("prevSecrets must be unchanged: %+v", syncer.prevSecrets)
	}
	if len(p.Cookies.Upserts) != 1 {
		t.Fatalf("cookies should still sync: %+v", p.Cookies.Upserts)
	}
}

func TestSyncOnceSecretNameCollisionAcrossReaders(t *testing.T) {
	prior := []secret.Secret{{Name: "gh", Value: "synced"}, {Name: "other", Value: "o"}}
	p, stderr, syncer := runCollisionCycle(t, prior,
		kindedSecrets{kind: "secrets_dir", ss: []secret.Secret{{Name: "gh", Value: "dir-value-XYZ"}}},
		kindedSecrets{kind: "keepass", ss: []secret.Secret{{Name: "gh", Value: "kp-value-ABC"}}},
	)
	assertSecretsUntouched(t, p, syncer, prior)
	if !strings.Contains(stderr, `"gh"`) || !strings.Contains(stderr, "secrets_dir") || !strings.Contains(stderr, "keepass") {
		t.Fatalf("stderr must name the secret and both readers: %q", stderr)
	}
	if strings.Count(strings.TrimSpace(stderr), "\n") != 0 {
		t.Fatalf("expected one stderr line: %q", stderr)
	}
	if strings.Contains(stderr, "dir-value-XYZ") || strings.Contains(stderr, "kp-value-ABC") {
		t.Fatalf("stderr leaked a secret value: %q", stderr)
	}
}

func TestSyncOnceSecretNameCollisionWithinOneReader(t *testing.T) {
	prior := []secret.Secret{{Name: "gh", Value: "synced"}}
	p, stderr, syncer := runCollisionCycle(t, prior,
		kindedSecrets{kind: "keepass", ss: []secret.Secret{
			{Name: "gh", Value: "one"}, {Name: "gh", Value: "two"}, {Name: "ok", Value: "fine"},
		}},
	)
	assertSecretsUntouched(t, p, syncer, prior)
	if !strings.Contains(stderr, `"gh"`) || !strings.Contains(stderr, "keepass, keepass") {
		t.Fatalf("stderr must name the secret and the reader twice: %q", stderr)
	}
	if strings.Contains(stderr, `"ok"`) {
		t.Fatalf("non-colliding name must not be reported: %q", stderr)
	}
}

func TestSyncOnceSecretNameCollisionReportsEveryName(t *testing.T) {
	_, stderr, _ := runCollisionCycle(t, nil,
		kindedSecrets{kind: "secrets_dir", ss: []secret.Secret{{Name: "b", Value: "1"}, {Name: "a", Value: "1"}}},
		kindedSecrets{kind: "keepass", ss: []secret.Secret{{Name: "a", Value: "2"}, {Name: "b", Value: "2"}}},
	)
	ia, ib := strings.Index(stderr, `"a"`), strings.Index(stderr, `"b"`)
	if ia < 0 || ib < 0 || ia > ib {
		t.Fatalf("both colliding names expected, sorted: %q", stderr)
	}
}

// The check runs before the [secret_names] filter, so a collision is reported
// even when the policy would drop the name.
func TestSyncOnceSecretNameCollisionDetectedBeforePolicyFilter(t *testing.T) {
	sealer, _ := transport.NewSealer(make([]byte, 32), make([]byte, 16))
	var buf bytes.Buffer
	syncer := &Syncer{
		Secrets: []SecretReader{
			kindedSecrets{kind: "secrets_dir", ss: []secret.Secret{{Name: "denied", Value: "1"}}},
			kindedSecrets{kind: "keepass", ss: []secret.Secret{{Name: "denied", Value: "2"}}},
		},
		SecretPolicy: policy.Names{Deny: []string{"denied"}},
		Sealer:       sealer,
		Out:          &buf,
	}
	stderr := captureStderr(t, func() {
		if err := syncer.SyncOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(stderr, `"denied"`) {
		t.Fatalf("collision on a policy-denied name must still be reported: %q", stderr)
	}
}

func TestSyncOnceNoCollisionUnchanged(t *testing.T) {
	p, stderr, syncer := runCollisionCycle(t, nil,
		kindedSecrets{kind: "secrets_dir", ss: []secret.Secret{{Name: "gh", Value: "tok"}}},
		kindedSecrets{kind: "keepass", ss: []secret.Secret{{Name: "npm", Value: "n"}}},
	)
	if stderr != "" {
		t.Fatalf("no stderr expected without a collision: %q", stderr)
	}
	if len(p.Secrets.Upserts) != 2 || len(p.Secrets.Deletes) != 0 {
		t.Fatalf("both secrets should sync: %+v", p.Secrets)
	}
	if len(syncer.prevSecrets.Secrets) != 2 {
		t.Fatalf("prevSecrets should advance: %+v", syncer.prevSecrets)
	}
}

func TestSyncOnceCollisionFallbackKindForUnnamedReader(t *testing.T) {
	_, stderr, _ := runCollisionCycle(t, nil,
		fakeSecrets{ss: []secret.Secret{{Name: "gh", Value: "1"}}},
		fakeSecrets{ss: []secret.Secret{{Name: "gh", Value: "2"}}},
	)
	if !strings.Contains(stderr, "reader#0") || !strings.Contains(stderr, "reader#1") {
		t.Fatalf("unnamed readers should fall back to reader#N: %q", stderr)
	}
}

func TestOnePasswordCollision(t *testing.T) {
	prior := []secret.Secret{{Name: "API", Value: "retained"}}
	p, stderr, s := runCollisionCycle(t, prior, kindedSecrets{kind: "onepassword", ss: []secret.Secret{{Name: "API", Value: "op-value"}}}, kindedSecrets{kind: "secrets_dir", ss: []secret.Secret{{Name: "API", Value: "dir-value"}}})
	assertSecretsUntouched(t, p, s, prior)
	if !strings.Contains(stderr, "onepassword") || strings.Contains(stderr, "op-value") {
		t.Fatal("collision diagnostic")
	}
}
