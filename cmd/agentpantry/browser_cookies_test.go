package main

import (
	"context"
	"errors"
	"testing"
	"time"

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
	eventCookieRead  cookieReplayEvent = "read"
	eventHydrate     cookieReplayEvent = "hydrate"
)

// fakeCookieWriter records WriteCookies invocations for writeBrowserCookies tests.
type fakeCookieWriter struct {
	calls                   [][]cookie.Cookie
	contexts                []context.Context
	contextErrs             []error
	contextDeadlines        []time.Time
	contextHasDeadlines     []bool
	readContexts            []context.Context
	readContextErrs         []error
	readContextDeadlines    []time.Time
	readContextHasDeadlines []bool
	readCalls               int
	readCookies             []cookie.Cookie
	readErr                 error
	skipped                 []int
	errs                    []error
	onWrite                 func()
	onRead                  func()
}

type blockingCookieReader struct {
	started chan struct{}
	ctx     context.Context
}

func (r *blockingCookieReader) ReadCookies(ctx context.Context) ([]cookie.Cookie, error) {
	r.ctx = ctx
	close(r.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

func (f *fakeCookieWriter) ReadCookies(ctx context.Context) ([]cookie.Cookie, error) {
	f.readCalls++
	f.readContexts = append(f.readContexts, ctx)
	f.readContextErrs = append(f.readContextErrs, ctx.Err())
	deadline, hasDeadline := ctx.Deadline()
	f.readContextDeadlines = append(f.readContextDeadlines, deadline)
	f.readContextHasDeadlines = append(f.readContextHasDeadlines, hasDeadline)
	if f.onRead != nil {
		f.onRead()
	}
	if f.readErr != nil {
		return nil, f.readErr
	}
	return append([]cookie.Cookie(nil), f.readCookies...), nil
}

func (f *fakeCookieWriter) WriteCookies(ctx context.Context, cookies []cookie.Cookie) (int, error) {
	n := len(f.calls)
	cp := append([]cookie.Cookie(nil), cookies...)
	f.calls = append(f.calls, cp)
	f.contexts = append(f.contexts, ctx)
	f.contextErrs = append(f.contextErrs, ctx.Err())
	deadline, hasDeadline := ctx.Deadline()
	f.contextDeadlines = append(f.contextDeadlines, deadline)
	f.contextHasDeadlines = append(f.contextHasDeadlines, hasDeadline)

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

	skipped, err := writeBrowserCookies(context.Background(), context.Background(), fw, nil, hydrateRecorder(&seq, nil))
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

	skipped, err = writeBrowserCookies(context.Background(), context.Background(), fw, []cookie.Cookie{}, hydrateRecorder(&seq, nil))
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

func TestWriteBrowserCookiesAllPresentSkipsSecondWrite(t *testing.T) {
	cookies := fixtureBrowserCookies()
	var seq []cookieReplayEvent
	fw := &fakeCookieWriter{
		skipped:     []int{2},
		readCookies: cookies,
		onWrite:     func() { seq = append(seq, eventCookieWrite) },
		onRead:      func() { seq = append(seq, eventCookieRead) },
	}

	skipped, err := writeBrowserCookies(context.Background(), context.Background(), fw, cookies, hydrateRecorder(&seq, nil))
	if err != nil {
		t.Fatalf("writeBrowserCookies: %v", err)
	}
	if skipped != 2 {
		t.Fatalf("skipped = %d, want first call's count 2", skipped)
	}
	if len(fw.calls) != 1 {
		t.Fatalf("writer calls = %d, want 1", len(fw.calls))
	}
	if !cookiesEqual(fw.calls[0], cookies) {
		t.Fatalf("first call cookies = %+v, want %+v", fw.calls[0], cookies)
	}
	if fw.readCalls != 1 {
		t.Fatalf("read calls = %d, want 1", fw.readCalls)
	}
	if fw.contexts[0] == fw.readContexts[0] {
		t.Fatal("readback must use a fresh context")
	}
	if _, ok := fw.readContexts[0].Deadline(); !ok {
		t.Fatal("readback context must have a bounded deadline")
	}
	if !eventsEqual(seq, []cookieReplayEvent{eventCookieWrite, eventHydrate, eventCookieRead}) {
		t.Fatalf("events = %v, want [write hydrate read]", seq)
	}
}

func TestWriteBrowserCookiesReplaysOnlyMissingSlots(t *testing.T) {
	cookies := fixtureBrowserCookies()
	fw := &fakeCookieWriter{readCookies: []cookie.Cookie{cookies[0]}}

	_, err := writeBrowserCookies(context.Background(), context.Background(), fw, cookies, func() error { return nil })
	if err != nil {
		t.Fatalf("writeBrowserCookies: %v", err)
	}
	if len(fw.calls) != 2 {
		t.Fatalf("writer calls = %d, want 2", len(fw.calls))
	}
	if !cookiesEqual(fw.calls[1], []cookie.Cookie{cookies[1]}) {
		t.Fatalf("replay cookies = %+v, want only missing cookie %+v", fw.calls[1], cookies[1])
	}
}

func TestWriteBrowserCookiesPreservesRotatedPresentSlot(t *testing.T) {
	cookies := fixtureBrowserCookies()
	rotated := cookies[0]
	rotated.Value = "rotated-session"
	fw := &fakeCookieWriter{readCookies: []cookie.Cookie{rotated}}

	_, err := writeBrowserCookies(context.Background(), context.Background(), fw, cookies, func() error { return nil })
	if err != nil {
		t.Fatalf("writeBrowserCookies: %v", err)
	}
	if len(fw.calls) != 2 {
		t.Fatalf("writer calls = %d, want 2", len(fw.calls))
	}
	if len(fw.calls[1]) != 1 || cookie.Key(fw.calls[1][0]) != cookie.Key(cookies[1]) {
		t.Fatalf("replay cookies = %+v, want only missing non-rotated slot", fw.calls[1])
	}
}

func TestWriteBrowserCookiesLeadingDotReadbackKeepsBackupSlotPresent(t *testing.T) {
	backup := cookie.Cookie{Host: "example.com", Name: "sid", Path: "/", Value: "backup-session"}
	readback := backup
	readback.Host = ".example.com"
	fw := &fakeCookieWriter{readCookies: []cookie.Cookie{readback}}

	_, err := writeBrowserCookies(context.Background(), context.Background(), fw, []cookie.Cookie{backup}, func() error { return nil })
	if err != nil {
		t.Fatalf("writeBrowserCookies: %v", err)
	}
	if len(fw.calls) != 1 {
		t.Fatalf("writer calls = %d, want 1 when leading-dot readback is present", len(fw.calls))
	}
}

func TestWriteBrowserCookiesLeadingDotRotatedReadbackReplaysOnlyMissingSlot(t *testing.T) {
	cookies := fixtureBrowserCookies()
	rotated := cookies[0]
	rotated.Host = ".example.com"
	rotated.Value = "rotated-session"
	fw := &fakeCookieWriter{readCookies: []cookie.Cookie{rotated}}

	_, err := writeBrowserCookies(context.Background(), context.Background(), fw, cookies, func() error { return nil })
	if err != nil {
		t.Fatalf("writeBrowserCookies: %v", err)
	}
	if len(fw.calls) != 2 {
		t.Fatalf("writer calls = %d, want 2", len(fw.calls))
	}
	if !cookiesEqual(fw.calls[1], []cookie.Cookie{cookies[1]}) {
		t.Fatalf("replay cookies = %+v, want only genuinely missing slot %+v", fw.calls[1], cookies[1])
	}
}

func TestWriteBrowserCookiesLeadingDotReadbackKeepsSubdomainsDistinct(t *testing.T) {
	backup := cookie.Cookie{Host: "api.example.com", Name: "sid", Path: "/", Value: "backup-session"}
	unrelated := backup
	unrelated.Host = ".www.example.com"
	fw := &fakeCookieWriter{readCookies: []cookie.Cookie{unrelated}}

	_, err := writeBrowserCookies(context.Background(), context.Background(), fw, []cookie.Cookie{backup}, func() error { return nil })
	if err != nil {
		t.Fatalf("writeBrowserCookies: %v", err)
	}
	if len(fw.calls) != 2 {
		t.Fatalf("writer calls = %d, want 2 for unrelated subdomain", len(fw.calls))
	}
	if !cookiesEqual(fw.calls[1], []cookie.Cookie{backup}) {
		t.Fatalf("replay cookies = %+v, want missing backup slot %+v", fw.calls[1], backup)
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

	skipped, err := writeBrowserCookies(context.Background(), context.Background(), fw, fixtureBrowserCookies(), hydrateRecorder(&seq, nil))
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

	skipped, err := writeBrowserCookies(context.Background(), context.Background(), fw, fixtureBrowserCookies(), hydrateRecorder(&seq, errHydration))
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

func TestWriteBrowserCookiesReplayFailureIsWarningOnly(t *testing.T) {
	var seq []cookieReplayEvent
	fw := &fakeCookieWriter{
		skipped: []int{1, 3},
		errs:    []error{nil, errSecondCookieWrite},
		onWrite: func() { seq = append(seq, eventCookieWrite) },
	}

	skipped, err := writeBrowserCookies(context.Background(), context.Background(), fw, fixtureBrowserCookies(), hydrateRecorder(&seq, nil))
	var warning *cookieReplayWarning
	if !errors.As(err, &warning) {
		t.Fatalf("err = %v, want replay warning", err)
	}
	if warning.Error() != "cookie replay after storage hydration failed" {
		t.Fatalf("warning = %q, want generic replay warning", warning)
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

func TestWriteBrowserCookiesReadbackFailureIsWarningOnly(t *testing.T) {
	fw := &fakeCookieWriter{readErr: errors.New("readback failed")}

	skipped, err := writeBrowserCookies(context.Background(), context.Background(), fw, fixtureBrowserCookies(), func() error { return nil })
	var warning *cookieReplayWarning
	if !errors.As(err, &warning) {
		t.Fatalf("err = %v, want replay warning", err)
	}
	if skipped != 0 {
		t.Fatalf("skipped = %d, want first write's count 0", skipped)
	}
	if len(fw.calls) != 1 {
		t.Fatalf("writer calls = %d, want no replay after readback failure", len(fw.calls))
	}
}

func TestWriteBrowserCookiesReplayUsesFreshSignalBoundedContext(t *testing.T) {
	restoreCtx, cancelRestore := context.WithCancel(context.Background())
	defer cancelRestore()
	fw := &fakeCookieWriter{}

	_, err := writeBrowserCookies(restoreCtx, context.Background(), fw, fixtureBrowserCookies(), func() error {
		cancelRestore()
		return nil
	})
	if err != nil {
		t.Fatalf("writeBrowserCookies: %v", err)
	}
	if len(fw.contexts) != 2 || len(fw.readContexts) != 1 {
		t.Fatalf("writer/read contexts = %d/%d, want 2/1", len(fw.contexts), len(fw.readContexts))
	}
	if fw.contextErrs[0] != nil {
		t.Fatalf("initial write context = %v, want active", fw.contextErrs[0])
	}
	if fw.contextErrs[1] != nil {
		t.Fatalf("replay context at write = %v, want active", fw.contextErrs[1])
	}
	if fw.readContextErrs[0] != nil {
		t.Fatalf("readback context = %v, want active", fw.readContextErrs[0])
	}
	if fw.readContexts[0] != fw.contexts[1] {
		t.Fatal("readback and missing-slot replay must share the fresh context")
	}
	deadline := fw.contextDeadlines[1]
	if !fw.contextHasDeadlines[1] || time.Until(deadline) <= 0 || time.Until(deadline) > time.Minute {
		t.Fatalf("replay deadline = %v, bounded=%v, want fresh deadline under one minute", deadline, fw.contextHasDeadlines[1])
	}
}

func TestWriteBrowserCookiesReplayCallerCancellationIsFatal(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	fw := &fakeCookieWriter{errs: []error{nil, context.Canceled}}

	_, err := writeBrowserCookies(context.Background(), parent, fw, fixtureBrowserCookies(), func() error {
		cancelParent()
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context canceled", err)
	}
}

func TestReadBrowserVerifyCookiesUsesFreshSignalBoundedContext(t *testing.T) {
	restoreCtx, cancelRestore := context.WithCancel(context.Background())
	cancelRestore()
	if err := restoreCtx.Err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("restore context = %v, want canceled", err)
	}

	signalParent, cancelSignal := context.WithCancel(context.Background())
	defer cancelSignal()
	reader := &blockingCookieReader{started: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		_, err := readBrowserVerifyCookies(signalParent, reader)
		done <- err
	}()

	<-reader.started
	if reader.ctx == restoreCtx {
		t.Fatal("verify read must not reuse the canceled restore context")
	}
	if err := reader.ctx.Err(); err != nil {
		t.Fatalf("verify read context = %v, want active", err)
	}
	deadline, hasDeadline := reader.ctx.Deadline()
	if !hasDeadline || time.Until(deadline) <= 0 || time.Until(deadline) > 30*time.Second {
		t.Fatalf("verify read deadline = %v, bounded=%v, want fresh 30-second deadline", deadline, hasDeadline)
	}

	cancelSignal()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("verify read error = %v, want signal cancellation", err)
	}
}
