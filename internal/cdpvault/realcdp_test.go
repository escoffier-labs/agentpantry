package cdpvault

import (
	"context"
	"os"
	"testing"

	"github.com/gorilla/websocket"
)

// TestRealCDP exercises the reader against a real Chrome DevTools endpoint when
// AGENTPANTRY_CDP_URL is set (e.g. a Chrome launched with --remote-debugging-port).
func TestRealCDP(t *testing.T) {
	url := os.Getenv("AGENTPANTRY_CDP_URL")
	if url == "" {
		t.Skip("set AGENTPANTRY_CDP_URL to a live Chrome DevTools base URL to run")
	}
	c := &CDP{BaseURL: url}
	cs, err := c.ReadCookies(context.Background())
	if err != nil {
		t.Fatalf("ReadCookies against real Chrome: %v", err)
	}
	t.Logf("real CDP export returned %d cookie(s)", len(cs))
}

// TestRealCDPSetAndRead sets a cookie via CDP on a live Chrome, then confirms the
// reader exports it. Runs only when AGENTPANTRY_CDP_URL points at a live endpoint.
func TestRealCDPSetAndRead(t *testing.T) {
	url := os.Getenv("AGENTPANTRY_CDP_URL")
	if url == "" {
		t.Skip("set AGENTPANTRY_CDP_URL to a live Chrome DevTools base URL to run")
	}
	c := &CDP{BaseURL: url}
	ws, err := c.wsURL(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	conn, _, err := websocket.DefaultDialer.Dial(ws, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteJSON(map[string]any{
		"id":     1,
		"method": "Network.setCookie",
		"params": map[string]any{"name": "ap_probe", "value": "ok123", "domain": "example.com", "path": "/"},
	}); err != nil {
		t.Fatal(err)
	}
	var resp map[string]any
	conn.ReadJSON(&resp)
	conn.Close()

	cs, err := c.ReadCookies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ck := range cs {
		if ck.Name == "ap_probe" && ck.Value == "ok123" {
			found = true
		}
	}
	if !found {
		t.Fatalf("reader did not export the set cookie; got %d cookies: %+v", len(cs), cs)
	}
	t.Logf("real CDP set+read returned the cookie among %d total", len(cs))
}
