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
