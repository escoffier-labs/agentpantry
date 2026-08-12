package cdpvault

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/webstorage"
	"github.com/gorilla/websocket"
)

// fakeCDPWriteStorageServer models DOMStorage: an origin in framedOrigins accepts
// setDOMStorageItem; any other origin is rejected (Chrome rejects an origin with
// no live frame), so the test can assert best-effort skipping.
func fakeCDPWriteStorageServer(t *testing.T, framedOrigins map[string]bool) *httptest.Server {
	t.Helper()
	up := websocket.Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		ws := "ws://" + r.Host + "/devtools/page/ABC"
		_ = json.NewEncoder(w).Encode([]map[string]any{{"type": "page", "webSocketDebuggerUrl": ws}})
	})
	mux.HandleFunc("/devtools/page/ABC", func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			var cmd struct {
				ID     int    `json:"id"`
				Method string `json:"method"`
				Params struct {
					StorageID struct {
						SecurityOrigin string `json:"securityOrigin"`
					} `json:"storageId"`
				} `json:"params"`
			}
			if err := c.ReadJSON(&cmd); err != nil {
				return
			}
			switch cmd.Method {
			case "DOMStorage.enable":
				_ = c.WriteJSON(map[string]any{"id": cmd.ID, "result": map[string]any{}})
			case "DOMStorage.setDOMStorageItem":
				if framedOrigins[cmd.Params.StorageID.SecurityOrigin] {
					_ = c.WriteJSON(map[string]any{"id": cmd.ID, "result": map[string]any{}})
				} else {
					_ = c.WriteJSON(map[string]any{"id": cmd.ID, "error": map[string]any{"code": -32000}})
				}
			default:
				_ = c.WriteJSON(map[string]any{"id": cmd.ID, "error": map[string]any{"code": -32601}})
			}
		}
	})
	return httptest.NewServer(mux)
}

func TestWriteStorageBestEffortSkipsUnframedOrigins(t *testing.T) {
	srv := fakeCDPWriteStorageServer(t, map[string]bool{"https://github.com": true})
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	items := []webstorage.Item{
		{Origin: "https://github.com", Key: "tok", Value: "1"}, // framed -> written
		{Origin: "https://github.com", Key: "dev", Value: "2"}, // framed -> written
		{Origin: "https://noframe.com", Key: "x", Value: "3"},  // no frame -> skipped
	}
	written, err := (&CDP{BaseURL: srv.URL}).WriteStorage(ctx, items)
	if err != nil {
		t.Fatalf("WriteStorage: %v", err)
	}
	if written != 2 {
		t.Fatalf("written = %d, want 2 (unframed origin skipped best-effort)", written)
	}
}

func TestWriteStorageEmptyIsNoop(t *testing.T) {
	// No server: an empty item list must return without dialing.
	written, err := (&CDP{BaseURL: "http://127.0.0.1:0"}).WriteStorage(context.Background(), nil)
	if err != nil || written != 0 {
		t.Fatalf("WriteStorage(nil) = (%d, %v), want (0, nil)", written, err)
	}
}

// fakeCDPFrameServer models a tab loaded on origin: /json lists it with its URL,
// and Runtime.evaluate answers the readiness probe as complete-on-origin and the
// setItem loop with setResult.
func fakeCDPFrameServer(t *testing.T, origin, setResult string) *httptest.Server {
	t.Helper()
	up := websocket.Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		ws := "ws://" + r.Host + "/devtools/page/ABC"
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"type": "page", "url": origin + "/", "webSocketDebuggerUrl": ws},
		})
	})
	mux.HandleFunc("/devtools/page/ABC", func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			var cmd struct {
				ID     int `json:"id"`
				Params struct {
					Expression string `json:"expression"`
				} `json:"params"`
			}
			if err := c.ReadJSON(&cmd); err != nil {
				return
			}
			value := setResult
			if strings.Contains(cmd.Params.Expression, "document.readyState") {
				value = `{"o":"` + origin + `","r":"complete"}`
			}
			_ = c.WriteJSON(map[string]any{
				"id":     cmd.ID,
				"result": map[string]any{"result": map[string]any{"type": "string", "value": value}},
			})
		}
	})
	return httptest.NewServer(mux)
}

func TestSeedFrameReadinessDeadlineBoundsStalledEvaluate(t *testing.T) {
	const origin = "https://ready.example"

	firstEvaluate := make(chan struct{})
	mutation := make(chan struct{}, 1)
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		for calls := 0; ; calls++ {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
			if calls == 0 {
				close(firstEvaluate)
				continue // Stall the readiness evaluation without replying.
			}
			select {
			case mutation <- struct{}{}:
			default:
			}
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	started := time.Now()
	written, err := (&CDP{}).seedFrameUntil(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/devtools/page/ABC", origin, [][2]string{{"private-key", "private-value"}}, time.Now().Add(150*time.Millisecond))
	if err != nil {
		t.Fatalf("seedFrameUntil: %v", err)
	}
	if written != 0 {
		t.Fatalf("written = %d, want 0 for a document that never becomes ready", written)
	}
	if elapsed := time.Since(started); elapsed >= 750*time.Millisecond {
		t.Fatalf("stalled readiness evaluation took %v, want local deadline", elapsed)
	}
	select {
	case <-firstEvaluate:
	default:
		t.Fatal("readiness evaluation was not sent")
	}
	select {
	case <-mutation:
		t.Fatal("stalled readiness evaluation reached localStorage mutation")
	default:
	}
}

func TestSeedFrameReadinessDeadlineBoundsStalledHandshake(t *testing.T) {
	handshakeStarted := make(chan struct{})
	handshakeCanceled := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(handshakeStarted)
		<-r.Context().Done() // Accept HTTP, but never complete the WebSocket upgrade.
		close(handshakeCanceled)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	started := time.Now()
	written, err := (&CDP{}).seedFrameUntil(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/devtools/page/ABC", "https://ready.example", [][2]string{{"private-key", "private-value"}}, time.Now().Add(150*time.Millisecond))
	if err != nil {
		t.Fatalf("seedFrameUntil: %v", err)
	}
	if written != 0 {
		t.Fatalf("written = %d, want 0 when the WebSocket handshake misses the readiness deadline", written)
	}
	if elapsed := time.Since(started); elapsed >= 500*time.Millisecond {
		t.Fatalf("stalled WebSocket handshake took %v, want local readiness deadline", elapsed)
	}
	select {
	case <-handshakeStarted:
	default:
		t.Fatal("WebSocket handshake did not start")
	}
	select {
	case <-handshakeCanceled:
	case <-time.After(time.Second):
		t.Fatal("readiness deadline did not cancel the WebSocket handshake")
	}
}

func TestSeedFrameCallerDeadlineWinsStalledHandshake(t *testing.T) {
	handshakeStarted := make(chan struct{})
	handshakeCanceled := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(handshakeStarted)
		<-r.Context().Done()
		close(handshakeCanceled)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 125*time.Millisecond)
	defer cancel()
	started := time.Now()
	written, err := (&CDP{}).seedFrameUntil(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/devtools/page/ABC", "https://ready.example", [][2]string{{"private-key", "private-value"}}, time.Now().Add(700*time.Millisecond))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("seedFrameUntil error = %v, want caller deadline exceeded", err)
	}
	if written != 0 {
		t.Fatalf("written = %d, want 0 when caller deadline ends the handshake", written)
	}
	if elapsed := time.Since(started); elapsed >= 500*time.Millisecond {
		t.Fatalf("stalled WebSocket handshake took %v, want caller deadline", elapsed)
	}
	select {
	case <-handshakeStarted:
	default:
		t.Fatal("WebSocket handshake did not start")
	}
	select {
	case <-handshakeCanceled:
	case <-time.After(time.Second):
		t.Fatal("caller deadline did not cancel the WebSocket handshake")
	}
}

func TestSeedFrameCallerDeadlineWinsStalledReadinessEvaluate(t *testing.T) {
	readinessStarted := make(chan struct{})
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
		close(readinessStarted)
		_, _, _ = conn.ReadMessage()
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 125*time.Millisecond)
	defer cancel()
	written, err := (&CDP{}).seedFrameUntil(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/devtools/page/ABC", "https://ready.example", [][2]string{{"private-key", "private-value"}}, time.Now().Add(700*time.Millisecond))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("seedFrameUntil error = %v, want caller deadline exceeded", err)
	}
	if written != 0 {
		t.Fatalf("written = %d, want 0 when caller deadline ends readiness", written)
	}
	select {
	case <-readinessStarted:
	default:
		t.Fatal("readiness evaluation did not start")
	}
}

func TestSeedFrameImmediateDialFailureRemainsAnError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	ws := "ws" + strings.TrimPrefix(srv.URL, "http") + "/devtools/page/ABC"
	srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	written, err := (&CDP{}).seedFrameUntil(ctx, ws, "https://ready.example", [][2]string{{"private-key", "private-value"}}, time.Now().Add(700*time.Millisecond))
	if err == nil {
		t.Fatal("immediate non-timeout dial failure must remain an error")
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Fatalf("immediate dial failure = %v, want its original error", err)
	}
	if written != 0 {
		t.Fatalf("written = %d, want 0 after dial failure", written)
	}
}

func TestSeedFrameRestoresOuterDeadlineForMutation(t *testing.T) {
	const origin = "https://ready.example"

	mutationStarted := make(chan struct{})
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		for calls := 0; ; calls++ {
			var command struct {
				ID int `json:"id"`
			}
			if err := conn.ReadJSON(&command); err != nil {
				return
			}
			if calls == 0 {
				_ = conn.WriteJSON(map[string]any{
					"id":     command.ID,
					"result": map[string]any{"result": map[string]any{"type": "string", "value": `{"o":"https://ready.example","r":"complete"}`}},
				})
				continue
			}
			close(mutationStarted)
			time.Sleep(250 * time.Millisecond)
			_ = conn.WriteJSON(map[string]any{
				"id":     command.ID,
				"result": map[string]any{"result": map[string]any{"type": "string", "value": "1"}},
			})
			return
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	written, err := (&CDP{}).seedFrameUntil(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/devtools/page/ABC", origin, [][2]string{{"private-key", "private-value"}}, time.Now().Add(150*time.Millisecond))
	if err != nil {
		t.Fatalf("seedFrameUntil: %v", err)
	}
	if written != 1 {
		t.Fatalf("written = %d, want 1 after mutation response beyond readiness deadline", written)
	}
	select {
	case <-mutationStarted:
	default:
		t.Fatal("localStorage mutation was not sent")
	}
}

func TestSeedFrameMutationReadStopsOnCallerCancellation(t *testing.T) {
	const origin = "https://ready.example"

	mutationStarted := make(chan struct{})
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		for calls := 0; ; calls++ {
			var command struct {
				ID int `json:"id"`
			}
			if err := conn.ReadJSON(&command); err != nil {
				return
			}
			if calls == 0 {
				_ = conn.WriteJSON(map[string]any{
					"id":     command.ID,
					"result": map[string]any{"result": map[string]any{"type": "string", "value": `{"o":"https://ready.example","r":"complete"}`}},
				})
				continue
			}
			close(mutationStarted)
			_, _, _ = conn.ReadMessage() // Wait for the canceled caller to close the socket.
			return
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type result struct {
		written int
		err     error
	}
	done := make(chan result, 1)
	go func() {
		written, err := (&CDP{}).seedFrameUntil(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/devtools/page/ABC", origin, [][2]string{{"private-key", "private-value"}}, time.Now().Add(time.Second))
		done <- result{written: written, err: err}
	}()

	select {
	case <-mutationStarted:
	case <-time.After(time.Second):
		t.Fatal("localStorage mutation was not sent")
	}
	cancel()
	select {
	case got := <-done:
		if !errors.Is(got.err, context.Canceled) {
			t.Fatalf("seedFrameUntil error = %v, want context canceled", got.err)
		}
		if got.written != 0 {
			t.Fatalf("written = %d, want 0 after caller cancellation", got.written)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("caller cancellation did not interrupt the stalled mutation read")
	}
}

func TestWriteStorageViaFramesSeedsLoadedOrigin(t *testing.T) {
	origin := "https://github.com"
	srv := fakeCDPFrameServer(t, origin, "2")
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	written, err := (&CDP{BaseURL: srv.URL}).WriteStorageViaFrames(ctx, []webstorage.Item{
		{Origin: origin, Key: "a", Value: "1"},
		{Origin: origin, Key: "b", Value: "2"},
	})
	if err != nil {
		t.Fatalf("WriteStorageViaFrames: %v", err)
	}
	if written != 2 {
		t.Fatalf("written = %d, want 2 (both items seeded into the loaded frame)", written)
	}
}

func TestWriteStorageViaFramesEmptyIsNoop(t *testing.T) {
	written, err := (&CDP{BaseURL: "http://127.0.0.1:0"}).WriteStorageViaFrames(context.Background(), nil)
	if err != nil || written != 0 {
		t.Fatalf("WriteStorageViaFrames(nil) = (%d, %v), want (0, nil)", written, err)
	}
}

// frameWSJSONResponse builds a /json target-list body of exactly size bytes.
// size must be large enough to hold the fixed JSON envelope around pad.
func frameWSJSONResponse(t *testing.T, origin, ws, pad string, size int) string {
	t.Helper()
	prefix := `[{"type":"page","id":"TARGET-ID-SECRET","url":"` + origin + `/","webSocketDebuggerUrl":"` + ws + `","pad":"`
	suffix := `"}]`
	need := size - len(prefix) - len(suffix)
	if need < 0 {
		t.Fatalf("size %d too small for envelope", size)
	}
	if pad == "" {
		pad = "x"
	}
	body := prefix + strings.Repeat(pad, (need+len(pad)-1)/len(pad))
	body = body[:size-len(suffix)] + suffix
	if len(body) != size {
		t.Fatalf("built body len %d, want %d", len(body), size)
	}
	return body
}

func TestFrameWSForOriginAcceptsResponseAtCap(t *testing.T) {
	origin := "https://example.com"
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ws := "ws://" + strings.TrimPrefix(srv.URL, "http://") + "/devtools/page/ABC"
	body := frameWSJSONResponse(t, origin, ws, "a", maxCDPJSONResponseBytes)
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := (&CDP{BaseURL: srv.URL}).frameWSForOrigin(ctx, origin)
	if err != nil {
		t.Fatalf("frameWSForOrigin at cap: %v", err)
	}
	if got != ws {
		t.Fatalf("websocket = %q, want %q", got, ws)
	}
}

func TestFrameWSForOriginReadinessDeadlineCancelsInFlightRequest(t *testing.T) {
	const origin = "https://example.com"

	requestStarted := make(chan struct{})
	requestCanceled := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		<-r.Context().Done()
		close(requestCanceled)
	}))
	defer srv.Close()

	started := time.Now()
	got, err := (&CDP{BaseURL: srv.URL}).frameWSForOriginUntil(context.Background(), origin, time.Now().Add(500*time.Millisecond))
	if err != nil {
		t.Fatalf("frameWSForOriginUntil: %v", err)
	}
	if got != "" {
		t.Fatalf("websocket = %q, want empty after readiness expiry", got)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("readiness expiry took %v, want well below the 30s HTTP client timeout", elapsed)
	}
	select {
	case <-requestStarted:
	default:
		t.Fatal("/json request did not start")
	}
	select {
	case <-requestCanceled:
	case <-time.After(time.Second):
		t.Fatal("readiness deadline did not cancel in-flight /json request")
	}
}

func TestFrameWSForOriginRejectsOversizedResponse(t *testing.T) {
	origin := "https://secret-origin.example"
	const marker = "oversized-private-value"
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := "ws://" + strings.TrimPrefix(srv.URL, "http://") + "/devtools/page/LEAK-TARGET"
	body := frameWSJSONResponse(t, origin, wsURL, marker, maxCDPJSONResponseBytes+1)
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := (&CDP{BaseURL: srv.URL}).frameWSForOrigin(ctx, origin)
	if err == nil {
		t.Fatal("oversized /json response must fail")
	}
	if got != "" {
		t.Fatalf("websocket = %q, want empty on oversized failure", got)
	}
	if !errors.Is(err, errCDPJSONResponseTooLarge) {
		t.Fatalf("error = %v, want %v", err, errCDPJSONResponseTooLarge)
	}
	msg := err.Error()
	for _, leak := range []string{marker, "TARGET-ID-SECRET", "LEAK-TARGET", origin, "secret-origin.example", wsURL, srv.URL} {
		if strings.Contains(msg, leak) {
			t.Fatalf("oversized error leaked %q: %q", leak, msg)
		}
	}
}

func TestFrameWSForOriginRetriesOrdinaryDecodeFailure(t *testing.T) {
	origin := "https://example.com"
	const marker = "malformed-poll-private-value"
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ws := "ws://" + strings.TrimPrefix(srv.URL, "http://") + "/devtools/page/ABC"
	var polls atomic.Int32
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if polls.Add(1) == 1 {
			_, _ = w.Write([]byte(`{"not-a-target-list":"` + marker))
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"type": "page", "url": origin + "/", "webSocketDebuggerUrl": ws},
		})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := (&CDP{BaseURL: srv.URL}).frameWSForOrigin(ctx, origin)
	if err != nil {
		msg := err.Error()
		for _, leak := range []string{marker, "not-a-target-list", origin, ws, srv.URL} {
			if strings.Contains(msg, leak) {
				t.Fatalf("decode-retry error leaked %q: %q", leak, msg)
			}
		}
		t.Fatalf("frameWSForOrigin after ordinary decode failure: %v", err)
	}
	if got != ws {
		t.Fatalf("websocket = %q, want %q", got, ws)
	}
	if got != "" {
		for _, leak := range []string{marker, "not-a-target-list"} {
			if strings.Contains(got, leak) {
				t.Fatalf("websocket leaked poll body %q: %q", leak, got)
			}
		}
	}
	if polls.Load() < 2 {
		t.Fatalf("polls = %d, want at least 2 (retry after ordinary decode failure)", polls.Load())
	}
}
