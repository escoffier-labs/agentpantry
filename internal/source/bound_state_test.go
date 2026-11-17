package source

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/secret"
	"github.com/escoffier-labs/agentpantry/internal/state"
	"github.com/escoffier-labs/agentpantry/internal/transport"
)

func TestCopiedStateBindingMismatchNeverDeletes(t *testing.T) {
	for _, field := range []string{"host", "identity", "config", "peer", "key"} {
		t.Run(field, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fixture.toml.state.json")
			old := testBinding(t, path)
			binding := old
			switch field {
			case "host":
				binding.Hostname += "-other"
			case "identity":
				binding.Identity += "-other"
			case "config":
				binding.ConfigPath += ".other"
			case "peer":
				binding.Peer = "other:8787"
			case "key":
				binding.KeyFingerprint = strings.Repeat("a", 64)
			}
			if err := state.Save(path, state.State{Binding: &old, ExportedSecrets: []string{"API_A"}, Tombstones: []state.Tombstone{{Name: "TOMB_A", ExpiresUnix: time.Now().Add(state.TombstoneTTL).Unix()}}}); err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			sealer, _ := transport.NewSealer(make([]byte, 32), make([]byte, 16))
			s := &Syncer{StatePath: path, Binding: binding, Secrets: []SecretReader{fakeSecrets{ss: []secret.Secret{{Name: "API_B", Value: "fixture-value"}}}}, Sealer: sealer, Out: &buf}
			defer s.Close()
			message := captureStderr(t, func() {
				for range 2 {
					if err := s.SyncOnce(context.Background()); err != nil {
						t.Fatal(err)
					}
				}
			})
			if strings.Count(message, "identity binding mismatch") != 1 {
				t.Fatal("binding warning not emitted once")
			}
			p := decodePayload(t, &buf)
			if len(p.Secrets.Deletes) != 0 || len(p.Secrets.Upserts) != 1 {
				t.Fatal("foreign baseline emitted deletes", p.Secrets)
			}
			st, err := state.Load(path)
			if err != nil || st.Binding == nil || *st.Binding != binding || !reflect.DeepEqual(st.ExportedSecrets, []string{"API_B"}) || len(st.Tombstones) != 0 {
				t.Fatal("binding not replaced on success", err)
			}
		})
	}
}
func TestBindingMismatchUnavailableDoesNotRewrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.state.json")
	binding := testBinding(t, path)
	old := binding
	old.Hostname += "-old"
	if err := state.Save(path, state.State{Binding: &old, ExportedSecrets: []string{"OLD"}}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := &Syncer{StatePath: path, Binding: binding, Secrets: []SecretReader{errSecrets{}}}
	defer s.Close()
	if err = s.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("unavailable reader rewrote foreign state", err)
	}
}

type tombClock struct{ now time.Time }

func (c *tombClock) Now() time.Time { return c.now }
func TestTombstoneReplayExpiryAndReappearance(t *testing.T) {
	for _, reappear := range []bool{false, true} {
		t.Run(map[bool]string{false: "expiry", true: "reappearance"}[reappear], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fixture.state.json")
			clock := &tombClock{now: time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)}
			var buf bytes.Buffer
			sealer, _ := transport.NewSealer(make([]byte, 32), make([]byte, 16))
			s := &Syncer{StatePath: path, Binding: testBinding(t, path), Clock: clock, Secrets: []SecretReader{fakeSecrets{ss: []secret.Secret{{Name: "API", Value: "fixture-value"}}}}, Sealer: sealer, Out: &buf}
			defer s.Close()
			if err := s.SyncOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			buf.Reset()
			s.Secrets = nil
			if err := s.SyncOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			// Drop this frame: the sink crashed before applying the delete.
			st, err := state.Load(path)
			if err != nil || len(st.Tombstones) != 1 {
				t.Fatal("delete not retained", err)
			}
			expiry := st.Tombstones[0].ExpiresUnix
			if expiry != clock.now.Add(state.TombstoneTTL).Unix() {
				t.Fatal("wrong tombstone window")
			}
			buf.Reset()
			s.Reset()
			if err = s.SyncOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			p := decodePayload(t, &buf)
			if !reflect.DeepEqual(p.Secrets.Deletes, []string{"API"}) {
				t.Fatal("delete not replayed after sink crash")
			}
			st, err = state.Load(path)
			if err != nil || st.Tombstones[0].ExpiresUnix != expiry {
				t.Fatal("replay extended tombstone lifetime")
			}
			buf.Reset()
			s.Reset()
			if reappear {
				s.Secrets = []SecretReader{fakeSecrets{ss: []secret.Secret{{Name: "API", Value: "new-value"}}}}
			} else {
				clock.now = time.Unix(expiry, 0)
			}
			if err = s.SyncOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			if reappear {
				p = decodePayload(t, &buf)
				if len(p.Secrets.Deletes) != 0 || len(p.Secrets.Upserts) != 1 {
					t.Fatal("reappearing name was deleted")
				}
			} else if buf.Len() != 0 {
				t.Fatal("expired tombstone was sent")
			}
			st, err = state.Load(path)
			if err != nil || len(st.Tombstones) != 0 {
				t.Fatal("tombstone not cleared", err)
			}
		})
	}
}
func TestTombstoneNotReplayedOnUnavailableRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.state.json")
	binding := testBinding(t, path)
	if err := state.Save(path, state.State{Binding: &binding, Tombstones: []state.Tombstone{{Name: "API", ExpiresUnix: time.Now().Add(state.TombstoneTTL).Unix()}}}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	s := &Syncer{StatePath: path, Binding: binding, Secrets: []SecretReader{errSecrets{}}, Out: &buf}
	defer s.Close()
	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatal("unavailable read replayed tombstone")
	}
}
func TestConcurrentSyncerRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.state.json")
	a := &Syncer{StatePath: path, Binding: testBinding(t, path)}
	b := &Syncer{StatePath: path, Binding: a.Binding}
	defer a.Close()
	defer b.Close()
	if err := a.OpenState(); err != nil {
		t.Fatal(err)
	}
	if err := b.SyncOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "already locked") {
		t.Fatal("second source did not fail fast", err)
	}
	a.Reset()
	if err := b.OpenState(); err == nil {
		t.Fatal("reconnect released writer lease")
	}
}

func TestSourceIdentityCannotChangeUnderLock(t *testing.T) {
	for _, field := range []string{"peer", "path"} {
		t.Run(field, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fixture.state.json")
			s := &Syncer{StatePath: path, Binding: testBinding(t, path)}
			defer s.Close()
			if err := s.OpenState(); err != nil {
				t.Fatal(err)
			}
			if field == "peer" {
				s.Binding.Peer = "other:8787"
			} else {
				s.StatePath = ""
			}
			if err := s.SyncOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "identity changed") {
				t.Fatal("identity changed under live writer lease", err)
			}
		})
	}
}

func TestBindingWarningOnceAcrossReconnects(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.state.json")
	binding := testBinding(t, path)
	old := binding
	old.Hostname += "-other"
	if err := state.Save(path, state.State{Binding: &old, ExportedSecrets: []string{"OLD"}}); err != nil {
		t.Fatal(err)
	}
	s := &Syncer{StatePath: path, Binding: binding, Secrets: []SecretReader{errSecrets{}}}
	defer s.Close()
	message := captureStderr(t, func() {
		for range 2 {
			s.Reset()
			if err := s.SyncOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
	})
	if strings.Count(message, "identity binding mismatch") != 1 {
		t.Fatal("binding warning repeated across reconnects")
	}
}

func TestNextWriterLoadsLatestCommittedNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.state.json")
	binding := testBinding(t, path)
	var first, second bytes.Buffer
	sealerA, _ := transport.NewSealer(make([]byte, 32), make([]byte, 16))
	sealerB, _ := transport.NewSealer(make([]byte, 32), make([]byte, 16))
	a := &Syncer{StatePath: path, Binding: binding, Secrets: []SecretReader{fakeSecrets{ss: []secret.Secret{{Name: "LATEST", Value: "a-value"}}}}, Sealer: sealerA, Out: &first}
	defer a.Close()
	b := &Syncer{StatePath: path, Binding: binding, Secrets: []SecretReader{fakeSecrets{ss: []secret.Secret{{Name: "NEW", Value: "b-value"}}}}, Sealer: sealerB, Out: &second}
	defer b.Close()
	if err := a.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := b.SyncOnce(context.Background()); err == nil {
		t.Fatal("concurrent source accepted")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	p := decodePayload(t, &second)
	if !reflect.DeepEqual(p.Secrets.Deletes, []string{"LATEST"}) {
		t.Fatal("next writer failed to read latest committed baseline", p.Secrets.Deletes)
	}
}

type advancingTombClock struct{ now time.Time }

func (c *advancingTombClock) Now() time.Time {
	now := c.now
	c.now = c.now.Add(time.Second)
	return now
}
func TestTombstoneReplayDoesNotRenewAcrossExpiryBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.state.json")
	binding := testBinding(t, path)
	clock := &advancingTombClock{now: time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)}
	if err := state.Save(path, state.State{Binding: &binding, Tombstones: []state.Tombstone{{Name: "API", ExpiresUnix: clock.now.Add(time.Second).Unix()}}}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	sealer, _ := transport.NewSealer(make([]byte, 32), make([]byte, 16))
	s := &Syncer{StatePath: path, Binding: binding, Clock: clock, Out: &buf, Sealer: sealer}
	defer s.Close()
	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p := decodePayload(t, &buf); len(p.Secrets.Deletes) != 1 {
		t.Fatal("expected replay selected before expiry")
	}
	st, err := state.Load(path)
	if err != nil || len(st.Tombstones) != 0 {
		t.Fatal("replay renewed expired tombstone", err)
	}
	s.Reset()
	buf.Reset()
	if err = s.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatal("expired replay created a new tombstone window")
	}
}
