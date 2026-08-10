package main

import (
	"context"
	"errors"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
)

var (
	errFirstCookieWrite  = errors.New("first cookie write failed")
	errSecondCookieWrite = errors.New("second cookie write failed")
	errHydration         = errors.New("hydration failed")
)

type cookieReplayEvent string

const (
	eventCookieWrite cookieReplayEvent = "write"
	eventHydrate     cookieReplayEvent = "hydrate"
)

// fakeCookieWriter records WriteCookies invocations for writeBrowserCookies tests.
type fakeCookieWriter struct {
	calls   [][]cookie.Cookie
	skipped []int
	errs    []error
	onWrite func()
}

func (f *fakeCookieWriter) WriteCookies(_ context.Context, cookies []cookie.Cookie) (int, error) {
	n := len(f.calls)
	cp := append([]cookie.Cookie(nil), cookies...)
	f.calls = append(f.calls, cp)

	if f.onWrite != nil {
		f.onWrite()
	}

	skipped := 0
	if n < len(f.skipped) {
		skipped = f.skipped[n]
	}
	var err error
	if n < len(f.errs) {
		err = f.errs[n]
	}
	return skipped, err
}

func fixtureBrowserCookies() []cookie.Cookie {
	return []cookie.Cookie{
		{
			Host:       "example.com",
			Name:       "sid",
			Value:      "fixture-session",
			Path:       "/",
			ExpiresUTC: cookie.ExpiresFromUnix(1893456000),
			IsSecure:   true,
			IsHTTPOnly: true,
			SameSite:   2,
		},
		{
			Host:     "api.example.com",
			Name:     "prefs",
			Value:    "fixture-prefs",
			Path:     "/app",
			SameSite: 1,
		},
	}
}

func cookiesEqual(a, b []cookie.Cookie) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func hydrateRecorder(seq *[]cookieReplayEvent, err error) func() error {
	return func() error {
		*seq = append(*seq, eventHydrate)
		return err
	}
}

func eventsEqual(got, want []cookieReplayEvent) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestWriteBrowserCookiesEmptySkipsWritesRunsHydration(t *testing.T) {
	var seq []cookieReplayEvent
	fw := &fakeCookieWriter{}

	skipped, err := writeBrowserCookies(context.Background(), fw, nil, hydrateRecorder(&seq, nil))
	if err != nil {
		t.Fatalf("writeBrowserCookies(nil): %v", err)
	}
	if skipped != 0 {
		t.Fatalf("skipped = %d, want 0", skipped)
	}
	if len(fw.calls) != 0 {
		t.Fatalf("writer calls = %d, want 0 for nil input", len(fw.calls))
	}
	if !eventsEqual(seq, []cookieReplayEvent{eventHydrate}) {
		t.Fatalf("events = %v, want [%s]", seq, eventHydrate)
	}

	skipped, err = writeBrowserCookies(context.Background(), fw, []cookie.Cookie{}, hydrateRecorder(&seq, nil))
	if err != nil {
		t.Fatalf("writeBrowserCookies(empty slice): %v", err)
	}
	if skipped != 0 {
		t.Fatalf("skipped = %d, want 0", skipped)
	}
	if len(fw.calls) != 0 {
		t.Fatalf("writer calls = %d, want 0 for empty slice", len(fw.calls))
	}
	if !eventsEqual(seq, []cookieReplayEvent{eventHydrate, eventHydrate}) {
		t.Fatalf("events = %v, want two %s steps", seq, eventHydrate)
	}
}

func TestWriteBrowserCookiesWritesTwiceIdempotently(t *testing.T) {
	cookies := fixtureBrowserCookies()
	var seq []cookieReplayEvent
	fw := &fakeCookieWriter{
		skipped: []int{2, 5},
		onWrite: func() { seq = append(seq, eventCookieWrite) },
	}

	skipped, err := writeBrowserCookies(context.Background(), fw, cookies, hydrateRecorder(&seq, nil))
	if err != nil {
		t.Fatalf("writeBrowserCookies: %v", err)
	}
	if skipped != 2 {
		t.Fatalf("skipped = %d, want first call's count 2", skipped)
	}
	if len(fw.calls) != 2 {
		t.Fatalf("writer calls = %d, want 2", len(fw.calls))
	}
	if !cookiesEqual(fw.calls[0], cookies) {
		t.Fatalf("first call cookies = %+v, want %+v", fw.calls[0], cookies)
	}
	if !cookiesEqual(fw.calls[1], cookies) {
		t.Fatalf("second call cookies = %+v, want %+v", fw.calls[1], cookies)
	}
	if !cookiesEqual(fw.calls[0], fw.calls[1]) {
		t.Fatalf("calls must pass the same cookies: first %+v, second %+v", fw.calls[0], fw.calls[1])
	}
	if !eventsEqual(seq, []cookieReplayEvent{eventCookieWrite, eventHydrate, eventCookieWrite}) {
		t.Fatalf("events = %v, want [write hydrate write]", seq)
	}
}

func TestWriteBrowserCookiesFirstCallErrorStops(t *testing.T) {
	var seq []cookieReplayEvent
	fw := &fakeCookieWriter{
		errs: []error{errFirstCookieWrite},
		onWrite: func() {
			seq = append(seq, eventCookieWrite)
		},
	}

	skipped, err := writeBrowserCookies(context.Background(), fw, fixtureBrowserCookies(), hydrateRecorder(&seq, nil))
	if !errors.Is(err, errFirstCookieWrite) {
		t.Fatalf("err = %v, want %v", err, errFirstCookieWrite)
	}
	if skipped != 0 {
		t.Fatalf("skipped = %d, want 0 when first call errors", skipped)
	}
	if len(fw.calls) != 1 {
		t.Fatalf("writer calls = %d, want 1 after first-call error", len(fw.calls))
	}
	if !eventsEqual(seq, []cookieReplayEvent{eventCookieWrite}) {
		t.Fatalf("events = %v, want [%s] only (no hydration or replay)", seq, eventCookieWrite)
	}
}

func TestWriteBrowserCookiesHydrationErrorStops(t *testing.T) {
	var seq []cookieReplayEvent
	fw := &fakeCookieWriter{
		onWrite: func() { seq = append(seq, eventCookieWrite) },
	}

	skipped, err := writeBrowserCookies(context.Background(), fw, fixtureBrowserCookies(), hydrateRecorder(&seq, errHydration))
	if !errors.Is(err, errHydration) {
		t.Fatalf("err = %v, want %v", err, errHydration)
	}
	if skipped != 0 {
		t.Fatalf("skipped = %d, want 0 when hydration errors", skipped)
	}
	if len(fw.calls) != 1 {
		t.Fatalf("writer calls = %d, want 1 after hydration error", len(fw.calls))
	}
	if !eventsEqual(seq, []cookieReplayEvent{eventCookieWrite, eventHydrate}) {
		t.Fatalf("events = %v, want [write hydrate] (no replay)", seq)
	}
}

func TestWriteBrowserCookiesSecondCallErrorPreserved(t *testing.T) {
	var seq []cookieReplayEvent
	fw := &fakeCookieWriter{
		skipped: []int{1, 3},
		errs:    []error{nil, errSecondCookieWrite},
		onWrite: func() { seq = append(seq, eventCookieWrite) },
	}

	skipped, err := writeBrowserCookies(context.Background(), fw, fixtureBrowserCookies(), hydrateRecorder(&seq, nil))
	if !errors.Is(err, errSecondCookieWrite) {
		t.Fatalf("err = %v, want %v", err, errSecondCookieWrite)
	}
	if skipped != 1 {
		t.Fatalf("skipped = %d, want first call's count 1", skipped)
	}
	if len(fw.calls) != 2 {
		t.Fatalf("writer calls = %d, want 2 before returning second-call error", len(fw.calls))
	}
	if !eventsEqual(seq, []cookieReplayEvent{eventCookieWrite, eventHydrate, eventCookieWrite}) {
		t.Fatalf("events = %v, want [write hydrate write]", seq)
	}
}
