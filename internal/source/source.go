package source

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/policy"
	"github.com/escoffier-labs/agentpantry/internal/secret"
	"github.com/escoffier-labs/agentpantry/internal/transport"
	"github.com/escoffier-labs/agentpantry/internal/wire"
)

// CookieReader is the slice of BrowserVault that Syncer needs.
type CookieReader interface {
	ReadCookies(ctx context.Context) ([]cookie.Cookie, error)
}

// SecretReader yields the current secrets from one source.
type SecretReader interface {
	ReadSecrets(ctx context.Context) ([]secret.Secret, error)
}

// Syncer turns successive vault and secret reads into sealed payload frames.
type Syncer struct {
	Vaults  []CookieReader
	Secrets []SecretReader
	Policy  policy.Domain
	Sealer  *transport.Sealer
	Out     io.Writer

	prev        cookie.Snapshot
	prevSecrets secret.Snapshot
}

// SyncOnce performs a single read-diff-send cycle.
func (s *Syncer) SyncOnce(ctx context.Context) error {
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
	secretsUnavailable := false
	for _, r := range s.Secrets {
		ss, err := r.ReadSecrets(ctx)
		if err != nil {
			secretsUnavailable = true
			break
		}
		allSecrets = append(allSecrets, ss...)
	}

	var secretDiff secret.Diff
	if secretsUnavailable {
		// A source secrets read failed (e.g. a vanished/unmounted dir). Leave the
		// already-synced secrets on the sink untouched this cycle instead of
		// emitting deletes for everything. Cookies still proceed.
		fmt.Fprintln(os.Stderr, "agentpantry: secrets source unavailable this cycle, leaving synced secrets untouched")
	} else {
		curSecrets := secret.NewSnapshot(allSecrets)
		secretDiff = curSecrets.DiffFrom(s.prevSecrets)
		s.prevSecrets = curSecrets
	}

	s.prev = curCookies

	p := wire.Payload{Cookies: cookieDiff, Secrets: secretDiff}
	if p.IsEmpty() {
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
	return transport.WriteFrame(s.Out, frame)
}

// Watch runs an initial sync, then re-syncs on debounced events for paths.
func (s *Syncer) Watch(ctx context.Context, paths []string, debounce time.Duration) error {
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
		}
	}
}
