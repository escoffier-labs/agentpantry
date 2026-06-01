package source

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/solomonneas/agentpantry/internal/cookie"
	"github.com/solomonneas/agentpantry/internal/policy"
	"github.com/solomonneas/agentpantry/internal/transport"
)

// CookieReader is the slice of BrowserVault that Syncer needs.
type CookieReader interface {
	ReadCookies(ctx context.Context) ([]cookie.Cookie, error)
}

// Syncer turns successive vault reads into sealed diff frames.
type Syncer struct {
	Vaults []CookieReader
	Policy policy.Domain
	Sealer *transport.Sealer
	Out    io.Writer

	prev cookie.Snapshot
}

// SyncOnce performs a single read-diff-send cycle.
func (s *Syncer) SyncOnce(ctx context.Context) error {
	var all []cookie.Cookie
	for _, v := range s.Vaults {
		cs, err := v.ReadCookies(ctx)
		if err != nil {
			return err
		}
		for _, c := range cs {
			if s.Policy.Permit(c.Host) {
				all = append(all, c)
			}
		}
	}
	cur := cookie.NewSnapshot(all)
	d := cur.DiffFrom(s.prev)
	s.prev = cur
	if d.IsEmpty() {
		return nil
	}
	payload, err := json.Marshal(d)
	if err != nil {
		return err
	}
	frame, err := s.Sealer.Seal(payload)
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
