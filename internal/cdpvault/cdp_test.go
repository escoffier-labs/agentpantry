package cdpvault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
					{"name": "sid", "value": "v20-session", "domain": ".example.com", "path": "/",
						"expires": 1637000000.0, "secure": true, "httpOnly": true, "sameSite": "Lax"},
					{"name": "s", "value": "sess", "domain": "api.example.com", "path": "/",
						"expires": -1.0, "secure": false, "httpOnly": false, "sameSite": "None"},
					// Partitioned (CHIPS) httpOnly cookie: Network.getAllCookies
					// drops these; Storage.getCookies returns them with a
					// partitionKey field.
					{"name": "sessionKey", "value": "chips-token", "domain": ".example.net", "path": "/",
						"expires": 1637000000.0, "secure": true, "httpOnly": true, "sameSite": "None",
						"partitionKey": map[string]any{"topLevelSite": "https://example.net", "hasCrossSiteAncestor": false}},
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
	if sid.Host != ".example.com" || sid.Value != "v20-session" || !sid.IsSecure || !sid.IsHTTPOnly || sid.SameSite != 1 {
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
// must surface partitioned, httpOnly cookies (e.g. a sessionKey) that
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
	if session.Host != ".example.net" || session.Value != "chips-token" || !session.IsSecure || !session.IsHTTPOnly {
		t.Fatalf("unexpected partitioned cookie: %+v", session)
	}
}

func TestSameSiteString(t *testing.T) {
	cases := []struct {
		code int
		want string
		ok   bool
	}{
		{code: 0, want: "None", ok: true},
		{code: 1, want: "Lax", ok: true},
		{code: 2, want: "Strict", ok: true},
		{code: 99, want: "", ok: false},
	}
	for _, tc := range cases {
		got, ok := sameSiteString(tc.code)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("sameSiteString(%d) = %q, %v; want %q, %v", tc.code, got, ok, tc.want, tc.ok)
		}
	}
}

func TestCDPWriteCookiesUsesStorageSetCookiesAndSkipsExpired(t *testing.T) {
	up := websocket.Upgrader{}
	seen := make(chan map[string]any, 1)
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
		var cmd map[string]any
		if err := c.ReadJSON(&cmd); err != nil {
			return
		}
		seen <- cmd
		c.WriteJSON(map[string]any{"id": cmd["id"], "result": map[string]any{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &CDP{BaseURL: srv.URL}
	skipped, err := c.WriteCookies(context.Background(), []cookie.Cookie{
		{Host: "example.com", Name: "sid", Value: "keep", Path: "/", IsSecure: true, IsHTTPOnly: true, SameSite: 2, ExpiresUTC: cookie.ExpiresFromUnix(1893456000)},
		{Host: "api.example.com", Name: "session", Value: "keep-session", Path: "/", SameSite: 1},
		{Host: "expired.example.com", Name: "old", Value: "drop", Path: "/", SameSite: 1, ExpiresUTC: cookie.ExpiresFromUnix(946684800)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1", skipped)
	}

	cmd := <-seen
	if cmd["method"] != "Storage.setCookies" {
		t.Fatalf("method = %v, want Storage.setCookies", cmd["method"])
	}
	params, ok := cmd["params"].(map[string]any)
	if !ok {
		t.Fatalf("params missing or wrong type: %#v", cmd["params"])
	}
	cookies, ok := params["cookies"].([]any)
	if !ok {
		t.Fatalf("params.cookies missing or wrong type: %#v", params["cookies"])
	}
	if len(cookies) != 2 {
		t.Fatalf("Storage.setCookies got %d cookies, want 2: %#v", len(cookies), cookies)
	}
	first := cookies[0].(map[string]any)
	if first["name"] != "sid" || first["value"] != "keep" || first["domain"] != "example.com" ||
		first["path"] != "/" || first["sameSite"] != "Strict" || first["secure"] != true || first["httpOnly"] != true {
		t.Fatalf("unexpected first cookie params: %#v", first)
	}
	if first["expires"] != 1893456000.0 {
		t.Fatalf("expires = %#v, want 1893456000", first["expires"])
	}
	second := cookies[1].(map[string]any)
	if second["name"] != "session" || second["sameSite"] != "Lax" {
		t.Fatalf("unexpected second cookie params: %#v", second)
	}
	if _, ok := second["expires"]; ok {
		t.Fatalf("session cookie should omit expires: %#v", second)
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

func TestCDPWriteCookiesErrorDoesNotLeakValues(t *testing.T) {
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
		var cmd map[string]any
		if err := c.ReadJSON(&cmd); err != nil {
			return
		}
		// Hostile/buggy browser that echoes the offending cookie value back.
		c.WriteJSON(map[string]any{
			"id": cmd["id"],
			"error": map[string]any{
				"code":    -32000,
				"message": "Sanitizing cookie failed for value super-secret-token-value",
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &CDP{BaseURL: srv.URL}
	_, err := c.WriteCookies(context.Background(), []cookie.Cookie{
		{Host: "example.com", Name: "sid", Value: "super-secret-token-value", Path: "/", SameSite: 1},
	})
	if err == nil {
		t.Fatal("expected error when CDP rejects setCookies")
	}
	if strings.Contains(err.Error(), "super-secret-token-value") {
		t.Fatalf("CDP error leaked a cookie value: %q", err)
	}
}
