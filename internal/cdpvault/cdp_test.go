package cdpvault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/gorilla/websocket"
)

func fakeCDPServer(t *testing.T) *httptest.Server {
	t.Helper()
	up := websocket.Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		ws := "ws://" + r.Host + "/devtools/page/ABC"
		json.NewEncoder(w).Encode([]map[string]any{
			{"type": "page", "webSocketDebuggerUrl": ws},
		})
	})
	mux.HandleFunc("/devtools/page/ABC", func(w http.ResponseWriter, r *http.Request) {
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
		// The reader must call Storage.getCookies (not Network.getAllCookies),
		// because only Storage.getCookies returns partitioned (CHIPS) cookies.
		if cmd.Method != "Storage.getCookies" {
			c.WriteJSON(map[string]any{
				"id":    cmd.ID,
				"error": map[string]any{"message": "unexpected method " + cmd.Method},
			})
			return
		}
		resp := map[string]any{
			"id": cmd.ID,
			"result": map[string]any{
				"cookies": []map[string]any{
					{"name": "sid", "value": "v20-session", "domain": ".github.com", "path": "/",
						"expires": 1637000000.0, "secure": true, "httpOnly": true, "sameSite": "Lax"},
					{"name": "s", "value": "sess", "domain": "x.com", "path": "/",
						"expires": -1.0, "secure": false, "httpOnly": false, "sameSite": "None"},
					// Partitioned (CHIPS) httpOnly cookie: Network.getAllCookies
					// drops these; Storage.getCookies returns them with a
					// partitionKey field.
					{"name": "sessionKey", "value": "chips-token", "domain": ".claude.ai", "path": "/",
						"expires": 1637000000.0, "secure": true, "httpOnly": true, "sameSite": "None",
						"partitionKey": map[string]any{"topLevelSite": "https://claude.ai", "hasCrossSiteAncestor": false}},
				},
			},
		}
		c.WriteJSON(resp)
	})
	return httptest.NewServer(mux)
}

func TestCDPReadCookies(t *testing.T) {
	srv := fakeCDPServer(t)
	defer srv.Close()

	c := &CDP{BaseURL: srv.URL}
	cs, err := c.ReadCookies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 3 {
		t.Fatalf("want 3 cookies, got %d", len(cs))
	}
	var sid cookie.Cookie
	for _, ck := range cs {
		if ck.Name == "sid" {
			sid = ck
		}
	}
	if sid.Host != ".github.com" || sid.Value != "v20-session" || !sid.IsSecure || !sid.IsHTTPOnly || sid.SameSite != 1 {
		t.Fatalf("unexpected sid cookie: %+v", sid)
	}
	if sid.ExpiresUTC != cookie.ExpiresFromUnix(1637000000) {
		t.Fatalf("expiry not converted: %d", sid.ExpiresUTC)
	}
	for _, ck := range cs {
		if ck.Name == "s" && ck.ExpiresUTC != 0 {
			t.Fatalf("session cookie expiry should be 0, got %d", ck.ExpiresUTC)
		}
	}
}

// TestCDPReadCookiesIncludesPartitioned guards the CHIPS regression: the reader
// must surface partitioned, httpOnly cookies (e.g. a claude.ai sessionKey) that
// Network.getAllCookies silently drops but Storage.getCookies returns.
func TestCDPReadCookiesIncludesPartitioned(t *testing.T) {
	srv := fakeCDPServer(t)
	defer srv.Close()

	c := &CDP{BaseURL: srv.URL}
	cs, err := c.ReadCookies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var session cookie.Cookie
	found := false
	for _, ck := range cs {
		if ck.Name == "sessionKey" {
			session = ck
			found = true
		}
	}
	if !found {
		t.Fatalf("partitioned cookie was dropped; got %+v", cs)
	}
	if session.Host != ".claude.ai" || session.Value != "chips-token" || !session.IsSecure || !session.IsHTTPOnly {
		t.Fatalf("unexpected partitioned cookie: %+v", session)
	}
}

func TestCDPNoEndpointErrors(t *testing.T) {
	c := &CDP{BaseURL: "http://127.0.0.1:1"}
	if _, err := c.ReadCookies(context.Background()); err == nil {
		t.Fatal("unreachable endpoint must error")
	}
}

func TestCDPRejectsNonLoopbackBaseURL(t *testing.T) {
	c := &CDP{BaseURL: "http://198.51.100.10:9222"}
	if _, err := c.ReadCookies(context.Background()); err == nil {
		t.Fatal("non-loopback CDP base URL must error")
	}
}

func TestCDPRejectsNonLoopbackWebSocketURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]any{
			{"type": "page", "webSocketDebuggerUrl": "ws://198.51.100.10/devtools/page/ABC"},
		})
	}))
	defer srv.Close()
	c := &CDP{BaseURL: srv.URL}
	if _, err := c.ReadCookies(context.Background()); err == nil {
		t.Fatal("non-loopback CDP websocket URL must error")
	}
}

func TestCDPRejectsNonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := &CDP{BaseURL: srv.URL}
	if _, err := c.ReadCookies(context.Background()); err == nil {
		t.Fatal("non-200 /json must error")
	}
}
