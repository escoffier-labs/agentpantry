package source

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/policy"
	"github.com/escoffier-labs/agentpantry/internal/secret"
	"github.com/escoffier-labs/agentpantry/internal/state"
	"github.com/escoffier-labs/agentpantry/internal/transport"
	"github.com/escoffier-labs/agentpantry/internal/webstorage"
	"github.com/escoffier-labs/agentpantry/internal/wire"
	"github.com/fsnotify/fsnotify"
)

// CookieReader is the slice of BrowserVault that Syncer needs.
type CookieReader interface {
	ReadCookies(ctx context.Context) ([]cookie.Cookie, error)
}

// SecretReader yields the current secrets from one source.
type SecretReader interface {
	ReadSecrets(ctx context.Context) ([]secret.Secret, error)
}

// KindedSecretReader is an optional extension of SecretReader. A reader that
// implements it names itself (for example "secrets_dir" or "keepass") so a
// secret name collision can say which sources produced the name.
type KindedSecretReader interface {
	SecretReader
	Kind() string
}

// StorageReader yields the current localStorage items from one source.
type StorageReader interface {
	ReadStorage(ctx context.Context) ([]webstorage.Item, error)
}

// Syncer turns successive vault, secret, and localStorage reads into sealed
// payload frames.
type Syncer struct {
	Vaults       []CookieReader
	Secrets      []SecretReader
	Storage      []StorageReader
	Policy       policy.Domain
	SecretPolicy policy.Names
	Sealer       *transport.Sealer
	Out          io.Writer

	// StatePath is config-specific status and deletion metadata. Secret values are never persisted.
	StatePath             string
	Binding               state.Binding
	stateLock             *state.Lock
	lockedPath            string
	lockedBinding         state.Binding
	bindingMismatchWarned bool
	fullResend            bool
	Clock                 state.Clock

	// AfterSync, if set, is called at the end of each successful SyncOnce.
	// sent reports whether a frame was written; cookies/secrets/storage are the
	// upsert counts in that frame (0 when nothing was sent).
	AfterSync func(sent bool, cookies, secrets, storage int)

	// AfterPayload, if set, is called after a non-empty frame is written.
	AfterPayload func(p wire.Payload)

	baselineLoaded bool
	baselineNames  []string
	diskState      state.State
	stateUsable    bool

	prev        cookie.Snapshot
	prevSecrets secret.Snapshot
	prevStorage webstorage.Snapshot
}

// Reset clears the previous snapshots so the next SyncOnce resends full state.
// Used after a (re)connect, since the peer starts a fresh session.
func (s *Syncer) Reset() {
	s.prev = cookie.Snapshot{}
	s.prevSecrets = secret.Snapshot{}
	s.prevStorage = webstorage.Snapshot{}
	s.baselineLoaded = false
	s.baselineNames = nil
	s.fullResend = true
}

// OpenState acquires the writer lease before any source read or network write.
// Call Close at process exit. Reset preserves the lock across reconnects.
func (s *Syncer) OpenState() error {
	if s.stateLock != nil {
		if s.lockedPath != s.StatePath || s.lockedBinding != s.Binding {
			return fmt.Errorf("source state path or identity changed while writer lock is held")
		}
		return nil
	}
	if s.StatePath == "" {
		return nil
	}
	if !s.Binding.Valid() {
		return fmt.Errorf("source state requires a valid identity binding")
	}
	lock, err := state.Acquire(s.StatePath)
	if err != nil {
		return err
	}
	s.stateLock = lock
	s.lockedPath = s.StatePath
	s.lockedBinding = s.Binding
	return nil
}
func (s *Syncer) Close() error {
	if s.stateLock == nil {
		return nil
	}
	err := s.stateLock.Close()
	s.stateLock = nil
	s.Reset()
	return err
}

// loadBaseline keeps names separate from snapshots. Empty snapshots force every
// current secret to be upserted after startup or reconnect, even an empty value.
func (s *Syncer) loadBaseline() {
	if s.baselineLoaded {
		return
	}
	s.baselineLoaded = true
	s.fullResend = true
	if s.StatePath == "" {
		return
	}
	st, err := state.Load(s.StatePath)
	s.stateUsable = err == nil
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentpantry: warning: source state %q could not be loaded; no secret deletion baseline\n", s.StatePath)
		s.diskState = state.State{}
		return
	}
	if st.Binding == nil || *st.Binding != s.Binding {
		if _, statErr := os.Stat(s.StatePath); !os.IsNotExist(statErr) {
			s.stateUsable = false
			if !s.bindingMismatchWarned {
				fmt.Fprintf(os.Stderr, "agentpantry: warning: source state %q identity binding mismatch; no secret deletion baseline\n", s.StatePath)
				s.bindingMismatchWarned = true
			}
		}

		s.diskState = state.State{}
		return
	}
	s.diskState = st
	s.baselineNames = append([]string(nil), st.ExportedSecrets...)
}

// Backoff returns a capped exponential delay for reconnect attempt n (0-based):
// 1s, 2s, 4s, 8s, 16s, then 30s.
func Backoff(attempt int) time.Duration {
	const base = time.Second
	const maxDelay = 30 * time.Second
	if attempt >= 5 {
		return maxDelay
	}
	d := base << attempt
	if d <= 0 || d > maxDelay {
		return maxDelay
	}
	return d
}

// filterSecrets keeps only secrets whose name the policy permits.
func filterSecrets(in []secret.Secret, p policy.Names) []secret.Secret {
	out := in[:0]
	for _, s := range in {
		if p.Permit(s.Name) {
			out = append(out, s)
		}
	}
	return out
}

// readerKind labels reader i for collision reports.
func readerKind(r SecretReader, i int) string {
	if k, ok := r.(KindedSecretReader); ok {
		return k.Kind()
	}
	return fmt.Sprintf("reader#%d", i)
}

// secretCollisions reports every secret name produced more than once, either
// by different readers or repeatedly by one. perReader[i] holds what reader i
// returned and kinds[i] labels it. The result is one human-readable string per
// colliding name, sorted by name, listing the producing reader kinds once per
// occurrence. It carries names and kinds only, never values.
func secretCollisions(perReader [][]secret.Secret, kinds []string) []string {
	owners := make(map[string][]string)
	for i, ss := range perReader {
		for _, s := range ss {
			owners[s.Name] = append(owners[s.Name], kinds[i])
		}
	}
	var names []string
	for name, o := range owners {
		if len(o) > 1 {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	out := make([]string, 0, len(names))
	for _, name := range names {
		// %q keeps a hostile file name or entry title from forging log lines.
		out = append(out, fmt.Sprintf("%q (%s)", name, strings.Join(owners[name], ", ")))
	}
	return out
}

// SyncOnce performs a single read-diff-send cycle.
func (s *Syncer) SyncOnce(ctx context.Context) error {
	if err := s.OpenState(); err != nil {
		return err
	}
	s.loadBaseline()
	var allCookies []cookie.Cookie
	for _, v := range s.Vaults {
		cs, err := v.ReadCookies(ctx)
		if err != nil {
			return err
		}
		for _, c := range cs {
			if s.Policy.Permit(c.Host) {
				allCookies = append(allCookies, c)
			}
		}
	}
	curCookies := cookie.NewSnapshot(allCookies)
	cookieDiff := curCookies.DiffFrom(s.prev)

	var allSecrets []secret.Secret
	perReader := make([][]secret.Secret, 0, len(s.Secrets))
	kinds := make([]string, 0, len(s.Secrets))
	secretsUnavailable := false
	for i, r := range s.Secrets {
		ss, err := r.ReadSecrets(ctx)
		if err != nil {
			secretsUnavailable = true
			break
		}
		perReader = append(perReader, ss)
		kinds = append(kinds, readerKind(r, i))
		allSecrets = append(allSecrets, ss...)
	}

	// Check for duplicate names BEFORE the [secret_names] policy filter, so a
	// collision is reported even when one copy would be filtered out: the
	// ambiguity is in the source configuration and would resurface the moment
	// the policy changes, and last-writer-wins would otherwise pick a value by
	// reader order.
	var collisions []string
	if !secretsUnavailable {
		collisions = secretCollisions(perReader, kinds)
	}

	var secretDiff secret.Diff
	var newDeletes []string
	secretsCommitted := false
	var curSecrets secret.Snapshot
	if len(collisions) > 0 {
		// Same unavailable semantics as a failed read: no secret diff, so the
		// sink keeps what it has and no deletes are sent. Cookies still proceed.
		fmt.Fprintf(os.Stderr, "agentpantry: secret name collision across sources, leaving synced secrets untouched this cycle: %s\n", strings.Join(collisions, "; "))
	} else if secretsUnavailable {
		// A source secrets read failed (e.g. a vanished/unmounted dir). Leave the
		// already-synced secrets on the sink untouched this cycle instead of
		// emitting deletes for everything. Cookies still proceed.
		fmt.Fprintln(os.Stderr, "agentpantry: secrets source unavailable this cycle, leaving synced secrets untouched")
	} else {
		curSecrets = secret.NewSnapshot(filterSecrets(allSecrets, s.SecretPolicy))
		secretDiff = curSecrets.DiffFrom(s.prevSecrets)
		for _, name := range s.baselineNames {
			if _, present := curSecrets.Secrets[name]; !present {
				secretDiff.Deletes = append(secretDiff.Deletes, name)
			}
		}
		newDeletes = append([]string(nil), secretDiff.Deletes...)
		if s.fullResend {
			deleted := map[string]bool{}
			for _, name := range secretDiff.Deletes {
				deleted[name] = true
			}
			for _, tomb := range s.diskState.Tombstones {
				if _, present := curSecrets.Secrets[tomb.Name]; !present && tomb.ExpiresUnix > s.now().Unix() && !deleted[tomb.Name] {
					secretDiff.Deletes = append(secretDiff.Deletes, tomb.Name)
					deleted[tomb.Name] = true
				}
			}
		}
		sort.Strings(secretDiff.Deletes)
		secretsCommitted = true
	}

	var storageDiff webstorage.Diff
	storageCommitted := false
	var curStorage webstorage.Snapshot
	if len(s.Storage) > 0 {
		var allItems []webstorage.Item
		storageUnavailable := false
		for _, r := range s.Storage {
			items, err := r.ReadStorage(ctx)
			if err != nil {
				storageUnavailable = true
				break
			}
			allItems = append(allItems, items...)
		}
		if storageUnavailable {
			// Mirror the secrets policy: a transient capture failure leaves the
			// already-synced localStorage on the sink untouched this cycle
			// instead of emitting deletes for everything.
			fmt.Fprintln(os.Stderr, "agentpantry: localStorage source unavailable this cycle, leaving synced storage untouched")
		} else {
			permitted := allItems[:0]
			for _, it := range allItems {
				if host, ok := webstorage.OriginHost(it.Origin); ok && s.Policy.Permit(host) {
					permitted = append(permitted, it)
				}
			}
			curStorage = webstorage.NewSnapshot(permitted)
			storageDiff = curStorage.DiffFrom(s.prevStorage)
			storageCommitted = true
		}
	}

	commitPrev := func(sent bool) error {
		st := s.diskState
		droppedTombstones := 0
		now := s.now().Unix()
		st.LastSyncUnix = now
		if sent {
			st.LastSentUnix = now
			st.Cookies = len(cookieDiff.Upserts)
			st.Secrets = len(secretDiff.Upserts)
			st.Storage = len(storageDiff.Upserts)
		}
		if secretsCommitted {
			binding := s.Binding
			st.Binding = &binding
			tombs := map[string]state.Tombstone{}
			for _, tomb := range st.Tombstones {
				if _, present := curSecrets.Secrets[tomb.Name]; !present && tomb.ExpiresUnix > now {
					tombs[tomb.Name] = tomb
				}
			}
			for _, name := range newDeletes {
				if _, exists := tombs[name]; !exists {
					tombs[name] = state.Tombstone{Name: name, ExpiresUnix: now + int64(state.TombstoneTTL/time.Second)}
				}
			}
			st.Tombstones = nil
			for _, tomb := range tombs {
				st.Tombstones = append(st.Tombstones, tomb)
			}
			st.Tombstones, droppedTombstones = state.CapTombstones(st.Tombstones)
			st.ExportedSecrets = make([]string, 0, len(curSecrets.Secrets))
			for name := range curSecrets.Secrets {
				st.ExportedSecrets = append(st.ExportedSecrets, name)
			}
			sort.Strings(st.ExportedSecrets)
		}
		// An invalid state file is replaced only after a fully successful secret
		// read. A non-empty payload must already have been written successfully.
		if s.StatePath != "" && (s.stateUsable || secretsCommitted) {
			if err := state.Save(s.StatePath, st); err != nil {
				return fmt.Errorf("persist source state: %w", err)
			}
			s.diskState = st
			s.stateUsable = true
		}
		state.WarnDroppedTombstones(droppedTombstones)
		s.prev = curCookies
		if secretsCommitted {
			s.prevSecrets = curSecrets
			s.baselineNames = nil
			s.fullResend = false
		}
		if storageCommitted {
			s.prevStorage = curStorage
		}
		return nil
	}

	p := wire.Payload{Cookies: cookieDiff, Secrets: secretDiff, Storage: storageDiff}
	if p.IsEmpty() {
		if err := commitPrev(false); err != nil {
			return err
		}
		s.afterSync(false, 0, 0, 0)
		return nil
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	frame, err := s.Sealer.Seal(raw)
	if err != nil {
		return err
	}
	if err := transport.WriteFrame(s.Out, frame); err != nil {
		return err
	}
	if err := commitPrev(true); err != nil {
		return err
	}
	s.afterSync(true, len(cookieDiff.Upserts), len(secretDiff.Upserts), len(storageDiff.Upserts))
	if s.AfterPayload != nil {
		s.AfterPayload(p)
	}
	return nil
}

func (s *Syncer) now() time.Time {
	if s.Clock != nil {
		return s.Clock.Now()
	}
	return time.Now()
}

func (s *Syncer) afterSync(sent bool, cookies, secrets, storage int) {
	if s.AfterSync != nil {
		s.AfterSync(sent, cookies, secrets, storage)
	}
}

// Watch runs an initial sync, then re-syncs on debounced events for paths and,
// if resync > 0, on a periodic ticker (covers missed events and file-less cdp
// sources).
func (s *Syncer) Watch(ctx context.Context, paths []string, debounce, resync time.Duration) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer w.Close()
	for _, p := range paths {
		if err := w.Add(p); err != nil {
			return err
		}
	}

	if err := s.SyncOnce(ctx); err != nil {
		return err
	}

	var resyncC <-chan time.Time
	if resync > 0 {
		tk := time.NewTicker(resync)
		defer tk.Stop()
		resyncC = tk.C
	}

	var timer *time.Timer
	var timerC <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case _, ok := <-w.Events:
			if !ok {
				return nil
			}
			if timer == nil {
				timer = time.NewTimer(debounce)
				timerC = timer.C
			} else {
				timer.Reset(debounce)
			}
		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			return err
		case <-timerC:
			if err := s.SyncOnce(ctx); err != nil {
				return err
			}
		case <-resyncC:
			if err := s.SyncOnce(ctx); err != nil {
				return err
			}
		}
	}
}
