package cdpvault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fakeStoragePage is one page target: an origin and its localStorage entries.
type fakeStoragePage struct {
	id      string
	origin  string
	entries [][2]string
	fail    bool // respond with a Runtime.evaluate error
}

// fakeCDPStorageServer serves a DevTools /json listing every page and a
// Runtime.evaluate handler per page that returns that page's localStorage.
func fakeCDPStorageServer(t *testing.T, pages []fakeStoragePage) *httptest.Server {
	t.Helper()
	up := websocket.Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		var targets []map[string]any
		for _, p := range pages {
			targets = append(targets, map[string]any{
				"type":                 "page",
				"webSocketDebuggerUrl": "ws://" + r.Host + "/devtools/page/" + p.id,
			})
		}
		_ = json.NewEncoder(w).Encode(targets)
	})
	for _, p := range pages {
		p := p
		mux.HandleFunc("/devtools/page/"+p.id, func(w http.ResponseWriter, r *http.Request) {
			c, err := up.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer c.Close()
			var cmd struct {
				ID     int    `json:"id"`
				Method string `json:"method"`
			}
			if err := c.ReadJSON(&cmd); err != nil {
				return
			}
			if cmd.Method != "Runtime.evaluate" {
				_ = c.WriteJSON(map[string]any{"id": cmd.ID, "error": map[string]any{"code": -32601}})
				return
			}
			if p.fail {
				_ = c.WriteJSON(map[string]any{"id": cmd.ID, "error": map[string]any{"code": -32000}})
				return
			}
			value, _ := json.Marshal(map[string]any{"o": p.origin, "e": p.entries})
			_ = c.WriteJSON(map[string]any{
				"id":     cmd.ID,
				"result": map[string]any{"result": map[string]any{"type": "string", "value": string(value)}},
			})
		})
	}
	return httptest.NewServer(mux)
}

func TestReadStorageReturnsItemsPerOrigin(t *testing.T) {
	srv := fakeCDPStorageServer(t, []fakeStoragePage{
		{id: "A", origin: "https://github.com", entries: [][2]string{{"tok", "gh-token"}, {"dev", "on"}}},
		{id: "B", origin: "https://app.example.com", entries: [][2]string{{"sess", "abc"}}},
	})
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	items, err := (&CDP{BaseURL: srv.URL}).ReadStorage(ctx)
	if err != nil {
		t.Fatalf("ReadStorage: %v", err)
	}
	got := map[string]string{}
	for _, it := range items {
		got[it.Origin+"|"+it.Key] = it.Value
	}
	want := map[string]string{
		"https://github.com|tok":       "gh-token",
		"https://github.com|dev":       "on",
		"https://app.example.com|sess": "abc",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d items, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("item %q = %q, want %q", k, got[k], v)
		}
	}
}

func TestReadStorageDropsOversizeValue(t *testing.T) {
	big := strings.Repeat("x", maxItemValueBytes+1)
	srv := fakeCDPStorageServer(t, []fakeStoragePage{
		{id: "A", origin: "https://github.com", entries: [][2]string{{"small", "ok"}, {"huge", big}}},
	})
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	items, err := (&CDP{BaseURL: srv.URL}).ReadStorage(ctx)
	if err != nil {
		t.Fatalf("ReadStorage: %v", err)
	}
	if len(items) != 1 || items[0].Key != "small" {
		t.Fatalf("oversize value not dropped: %+v", items)
	}
}

func TestReadStorageSkipsFailingPage(t *testing.T) {
	srv := fakeCDPStorageServer(t, []fakeStoragePage{
		{id: "A", origin: "https://github.com", entries: [][2]string{{"tok", "1"}}},
		{id: "B", origin: "https://x.com", fail: true},
	})
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	items, err := (&CDP{BaseURL: srv.URL}).ReadStorage(ctx)
	if err != nil {
		t.Fatalf("ReadStorage should not fail on one bad page: %v", err)
	}
	if len(items) != 1 || items[0].Origin != "https://github.com" {
		t.Fatalf("a failing page must be skipped, not fatal: %+v", items)
	}
}
