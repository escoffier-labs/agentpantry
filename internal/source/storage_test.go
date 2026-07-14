package source

import (
	"bytes"
	"context"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/policy"
	"github.com/escoffier-labs/agentpantry/internal/transport"
	"github.com/escoffier-labs/agentpantry/internal/webstorage"
)

type staticStorage struct {
	items []webstorage.Item
	err   error
}

func (s *staticStorage) ReadStorage(context.Context) ([]webstorage.Item, error) {
	return s.items, s.err
}

func newStorageSyncer(t *testing.T, r StorageReader, sentStorage *[]int) *Syncer {
	t.Helper()
	sealer, err := transport.NewSealer(make([]byte, 32), make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	return &Syncer{
		Storage: []StorageReader{r},
		Policy:  policy.Domain{Allow: []string{"github.com"}},
		Sealer:  sealer,
		Out:     &bytes.Buffer{},
		AfterSync: func(sent bool, _, _, storage int) {
			if sent {
				*sentStorage = append(*sentStorage, storage)
			}
		},
	}
}

// Only permitted origins sync, and an unchanged snapshot does not resend.
func TestSyncStorageDomainFilterAndNoResend(t *testing.T) {
	var sent []int
	r := &staticStorage{items: []webstorage.Item{
		{Origin: "https://github.com", Key: "tok", Value: "1"},
		{Origin: "https://sub.github.com", Key: "dev", Value: "2"},
		{Origin: "https://evil.com", Key: "x", Value: "3"}, // off-policy, dropped
	}}
	s := newStorageSyncer(t, r, &sent)

	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatalf("second sync: %v", err)
	}
	if len(sent) != 1 || sent[0] != 2 {
		t.Fatalf("sent storage upserts = %v, want one frame with 2 (github.com origins only)", sent)
	}
}

// A transient capture failure must not wipe already-synced localStorage: the
// previous snapshot survives, so a later identical read does not re-send.
func TestSyncStorageTransientFailureLeavesPrevUntouched(t *testing.T) {
	var sent []int
	r := &staticStorage{items: []webstorage.Item{{Origin: "https://github.com", Key: "tok", Value: "1"}}}
	s := newStorageSyncer(t, r, &sent)

	if err := s.SyncOnce(context.Background()); err != nil { // sends 1
		t.Fatalf("first sync: %v", err)
	}
	r.err = context.DeadlineExceeded // capture fails this cycle
	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatalf("second sync (failing read) must not error the cycle: %v", err)
	}
	r.err = nil // recovered, same item as before
	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatalf("third sync: %v", err)
	}
	if len(sent) != 1 || sent[0] != 1 {
		t.Fatalf("sent frames = %v; a transient failure must not wipe prev state (want only the first cycle to send)", sent)
	}
}
