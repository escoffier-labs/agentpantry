package cdpvault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
