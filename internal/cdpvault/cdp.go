package cdpvault

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/gorilla/websocket"
)

// CDP reads cookies from a running Chromium via the DevTools Protocol. Chrome
// decrypts its own cookies, so this works for app-bound (v20) profiles.
type CDP struct {
	BaseURL string // e.g. http://127.0.0.1:9222
}

func (c *CDP) Name() string { return "cdp:" + c.BaseURL }

// ValidateLoopbackURL requires CDP HTTP/WebSocket endpoints to stay on loopback.
// A DevTools port grants full browser control, so remote CDP is intentionally
// not supported.
func ValidateLoopbackURL(raw string, allowedSchemes ...string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Host == "" {
		return fmt.Errorf("missing host")
	}
	schemeOK := false
	for _, s := range allowedSchemes {
		if u.Scheme == s {
			schemeOK = true
			break
		}
	}
	if !schemeOK {
		return fmt.Errorf("scheme %q is not allowed", u.Scheme)
	}
	host := u.Hostname()
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("host %q is not loopback", host)
	}
	return nil
}

type cdpTarget struct {
	Type                 string `json:"type"`
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

func (c *CDP) wsURL(ctx context.Context) (string, error) {
	if err := ValidateLoopbackURL(c.BaseURL, "http", "https"); err != nil {
		return "", fmt.Errorf("invalid CDP base URL: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/json", nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("CDP /json returned %d", resp.StatusCode)
	}
	var targets []cdpTarget
	if err := json.NewDecoder(resp.Body).Decode(&targets); err != nil {
		return "", err
	}
	for _, t := range targets {
		if t.WebSocketDebuggerURL != "" && (t.Type == "page" || t.Type == "") {
			if err := ValidateLoopbackURL(t.WebSocketDebuggerURL, "ws", "wss"); err != nil {
				return "", fmt.Errorf("invalid CDP websocket URL: %w", err)
			}
			return t.WebSocketDebuggerURL, nil
		}
	}
	for _, t := range targets {
		if t.WebSocketDebuggerURL != "" {
			if err := ValidateLoopbackURL(t.WebSocketDebuggerURL, "ws", "wss"); err != nil {
				return "", fmt.Errorf("invalid CDP websocket URL: %w", err)
			}
			return t.WebSocketDebuggerURL, nil
		}
	}
	return "", fmt.Errorf("no DevTools target with a websocket URL at %s", c.BaseURL)
}

type cdpCookie struct {
	Name     string  `json:"name"`
	Value    string  `json:"value"`
	Domain   string  `json:"domain"`
	Path     string  `json:"path"`
	Expires  float64 `json:"expires"`
	Secure   bool    `json:"secure"`
	HTTPOnly bool    `json:"httpOnly"`
	SameSite string  `json:"sameSite"`
	// PartitionKey is present on partitioned (CHIPS) cookies. We do not
	// propagate it into the cookie model, but decoding it keeps the field
	// from being lost and documents that Storage.getCookies returns it.
	PartitionKey json.RawMessage `json:"partitionKey"`
}

func sameSiteCode(s string) int {
	switch s {
	case "Strict":
		return 2
	case "Lax":
		return 1
	default:
		return 0
	}
}

func sameSiteString(code int) (string, bool) {
	switch code {
	case 2:
		return "Strict", true
	case 1:
		return "Lax", true
	case 0:
		return "None", true
	default:
		return "", false
	}
}

type cdpSetCookieParam struct {
	Name     string   `json:"name"`
	Value    string   `json:"value"`
	Domain   string   `json:"domain"`
	Path     string   `json:"path,omitempty"`
	Expires  *float64 `json:"expires,omitempty"`
	Secure   bool     `json:"secure"`
	HTTPOnly bool     `json:"httpOnly"`
	SameSite string   `json:"sameSite,omitempty"`
}

// WriteCookies materializes cookies into a running Chromium through CDP. It
// skips already-expired persistent cookies because setting them would delete or
// immediately discard the slot in Chromium. The returned count is safe to log.
func (c *CDP) WriteCookies(ctx context.Context, cookies []cookie.Cookie) (int, error) {
	now := time.Now().Unix()
	params := make([]cdpSetCookieParam, 0, len(cookies))
	skippedExpired := 0
	for _, ck := range cookies {
		if ck.ExpiresUTC > 0 && cookie.ExpiresUnix(ck.ExpiresUTC) <= now {
			skippedExpired++
			continue
		}
		sameSite, ok := sameSiteString(ck.SameSite)
		if !ok {
			return skippedExpired, fmt.Errorf("cookie %s@%s has unsupported SameSite code %d", ck.Name, ck.Host, ck.SameSite)
		}
		path := ck.Path
		if path == "" {
			path = "/"
		}
		param := cdpSetCookieParam{
			Name: ck.Name, Value: ck.Value, Domain: ck.Host, Path: path,
			Secure: ck.IsSecure, HTTPOnly: ck.IsHTTPOnly, SameSite: sameSite,
		}
		if ck.ExpiresUTC > 0 {
			exp := float64(cookie.ExpiresUnix(ck.ExpiresUTC))
			param.Expires = &exp
		}
		params = append(params, param)
	}
	if len(params) == 0 {
		return skippedExpired, nil
	}

	ws, err := c.wsURL(ctx)
	if err != nil {
		return skippedExpired, err
	}
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, ws, nil)
	if err != nil {
		return skippedExpired, fmt.Errorf("dial devtools websocket: %w", err)
	}
	defer conn.Close()

	if err := conn.WriteJSON(map[string]any{
		"id":     1,
		"method": "Storage.setCookies",
		"params": map[string]any{"cookies": params},
	}); err != nil {
		return skippedExpired, err
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return skippedExpired, fmt.Errorf("set read deadline: %w", err)
	}
	for {
		var msg struct {
			ID    int `json:"id"`
			Error *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := conn.ReadJSON(&msg); err != nil {
			return skippedExpired, err
		}
		if msg.ID != 1 {
			continue
		}
		if msg.Error != nil {
			// The setCookies payload carries cookie values, and a browser may
			// echo the offending value in its error message. Report the numeric
			// code only, never the message, so values cannot leak into logs.
			return skippedExpired, fmt.Errorf("CDP rejected Storage.setCookies (code %d); message withheld to avoid logging cookie values", msg.Error.Code)
		}
		return skippedExpired, nil
	}
}

func (c *CDP) ReadCookies(ctx context.Context) ([]cookie.Cookie, error) {
	ws, err := c.wsURL(ctx)
	if err != nil {
		return nil, err
	}
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, ws, nil)
	if err != nil {
		return nil, fmt.Errorf("dial devtools websocket: %w", err)
	}
	defer conn.Close()

	// Storage.getCookies (not Network.getAllCookies) is the only method that
	// returns partitioned (CHIPS) cookies. With no browserContextId param it
	// targets the default context. Network.getAllCookies silently dropped a
	// real claude.ai sessionKey during dogfooding.
	if err := conn.WriteJSON(map[string]any{"id": 1, "method": "Storage.getCookies"}); err != nil {
		return nil, err
	}

	// Bound the read loop so a hung or crashed DevTools target fails the sync
	// cycle instead of wedging it forever. Honor the caller's deadline if set,
	// otherwise fall back to a conservative default.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}

	for {
		var msg struct {
			ID     int `json:"id"`
			Result struct {
				Cookies []cdpCookie `json:"cookies"`
			} `json:"result"`
			Error *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := conn.ReadJSON(&msg); err != nil {
			return nil, err
		}
		if msg.ID != 1 {
			continue // skip CDP events
		}
		if msg.Error != nil {
			// Withhold the browser's message to keep cookie material out of logs.
			return nil, fmt.Errorf("CDP rejected the cookie read (code %d); message withheld to avoid logging cookie values", msg.Error.Code)
		}
		out := make([]cookie.Cookie, 0, len(msg.Result.Cookies))
		for _, cc := range msg.Result.Cookies {
			var exp int64
			if cc.Expires > 0 {
				exp = cookie.ExpiresFromUnix(int64(cc.Expires))
			}
			out = append(out, cookie.Cookie{
				Host: cc.Domain, Name: cc.Name, Value: cc.Value, Path: cc.Path,
				ExpiresUTC: exp, IsSecure: cc.Secure, IsHTTPOnly: cc.HTTPOnly,
				SameSite: sameSiteCode(cc.SameSite),
			})
		}
		return out, nil
	}
}
