package cdpvault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/webstorage"
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
	ID                   string `json:"id"`
	Type                 string `json:"type"`
	URL                  string `json:"url"`
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

// maxCDPJSONResponseBytes caps GET /json bodies read by frameWSForOrigin so a
// hostile or buggy debugger port cannot force unbounded allocation during
// target polling and target creation. Other CDP JSON readers are unchanged.
const maxCDPJSONResponseBytes = 1024 * 1024

var errCDPJSONResponseTooLarge = errors.New("CDP JSON response too large")

func decodeLimitedJSON(body io.Reader, dst any) error {
	data, err := io.ReadAll(io.LimitReader(body, maxCDPJSONResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read CDP JSON response: %w", err)
	}
	if len(data) > maxCDPJSONResponseBytes {
		return errCDPJSONResponseTooLarge
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return err
	}
	return nil
}

// ValidateStorageOrigin is a compatibility wrapper around
// webstorage.ValidateOrigin. Only an exact canonical HTTP(S) origin is
// accepted; unsafe input is never normalized. Errors are generic and never
// echo the raw origin. CDP HTTP/WebSocket endpoints remain loopback-only via
// ValidateLoopbackURL.
func ValidateStorageOrigin(raw string) error {
	return webstorage.ValidateOrigin(raw)
}

func validateTargetID(id string) error {
	if id == "" {
		return fmt.Errorf("empty target ID")
	}
	if id[0] == '.' {
		return fmt.Errorf("invalid target ID")
	}
	for i := 0; i < len(id); i++ {
		b := id[i]
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '-' || b == '_' || b == '.' {
			continue
		}
		return fmt.Errorf("invalid target ID")
	}
	return nil
}

func dedupePreserveOrder(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// canonicalSortedStorageOrigins returns a new slice of unique origins in
// lexicographic order. The caller's slice is never mutated. OpenStorageOrigins
// and WriteStorageViaTargets share this contract so target IDs and item-origin
// groups always pair in the same order.
func canonicalSortedStorageOrigins(origins []string) []string {
	out := dedupePreserveOrder(origins)
	sort.Strings(out)
	return out
}

func (c *CDP) cdpHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *CDP) listTargets(ctx context.Context, client *http.Client) ([]cdpTarget, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/json/list", nil)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("list CDP targets request failed")
	}
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("list CDP targets failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list CDP targets returned status %d", resp.StatusCode)
	}
	var targets []cdpTarget
	if err := decodeLimitedJSON(resp.Body, &targets); err != nil {
		return nil, fmt.Errorf("decode CDP target list response: %w", err)
	}
	return targets, nil
}

// OpenStorageOrigins opens one page target per distinct storage origin via the
// DevTools /json/new endpoint so localStorage can be seeded in that frame.
// Distinct origins are created and returned in shared canonical sorted order
// (deduplicated, lexicographic), matching WriteStorageViaTargets pairing.
// Arbitrary caller input such as [B,A] yields target IDs in A,B order.
// On non-nil error, returned IDs were created only by this call and may still
// be open; the caller must pass them to CloseTargets. An empty slice means no
// caller cleanup retry is needed.
func (c *CDP) OpenStorageOrigins(ctx context.Context, origins []string) (ids []string, retErr error) {
	if len(origins) == 0 {
		return nil, nil
	}
	if err := ValidateLoopbackURL(c.BaseURL, "http", "https"); err != nil {
		return nil, fmt.Errorf("invalid CDP base URL: %w", err)
	}
	origins = canonicalSortedStorageOrigins(origins)
	for _, origin := range origins {
		if err := ValidateStorageOrigin(origin); err != nil {
			return nil, err
		}
	}

	client := c.cdpHTTPClient()
	existingTargets, err := c.listTargets(ctx, client)
	if err != nil {
		return nil, err
	}
	knownIDs := make(map[string]struct{}, len(existingTargets)+len(origins))
	for _, target := range existingTargets {
		if target.ID != "" {
			knownIDs[target.ID] = struct{}{}
		}
	}

	// ownedForCleanup: IDs we created and must close on failure (never baseline/duplicates).
	// verified: IDs that passed type, origin, and websocket checks.
	var ownedForCleanup []string
	var verified []string
	defer func() {
		if retErr == nil || len(ownedForCleanup) == 0 {
			return
		}
		// Caller ctx may already be canceled; still attempt bounded cleanup.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Close one owned ID at a time so successful closes drop out of the
		// retry set. Never close or return baseline/duplicate/unsafe IDs.
		var failed []string
		var cleanupErrs []error
		for _, id := range ownedForCleanup {
			if err := c.CloseTargets(cleanupCtx, []string{id}); err != nil {
				cleanupErrs = append(cleanupErrs, err)
				failed = append(failed, id)
			}
		}
		if len(cleanupErrs) > 0 {
			retErr = errors.Join(retErr, fmt.Errorf("cleanup CDP targets: %w", errors.Join(cleanupErrs...)))
			// Reconcile against a fresh list: Chrome may have accepted /json/close
			// even when the HTTP/transport response failed. Keep only failed owned
			// IDs still present as type "page"; omit already-closed ones.
			retry := append([]string(nil), failed...)
			if cleanupCtx.Err() == nil {
				if targets, listErr := c.listTargets(cleanupCtx, c.cdpHTTPClient()); listErr == nil {
					presentPage := make(map[string]struct{}, len(targets))
					for _, t := range targets {
						if t.ID != "" && t.Type == "page" {
							presentPage[t.ID] = struct{}{}
						}
					}
					retry = retry[:0]
					for _, id := range failed {
						if _, ok := presentPage[id]; ok {
							retry = append(retry, id)
						}
					}
				}
			}
			ids = append([]string(nil), retry...)
			return
		}
		// Cleanup succeeded: all owned targets are already closed; return zero IDs.
		ids = nil
	}()

	for _, origin := range origins {
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.BaseURL+"/json/new?"+origin, nil)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("create CDP target request failed")
		}
		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("create CDP target failed")
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("create CDP target returned status %d", resp.StatusCode)
		}
		var tgt cdpTarget
		decErr := decodeLimitedJSON(resp.Body, &tgt)
		_ = resp.Body.Close()
		if decErr != nil {
			return nil, fmt.Errorf("decode CDP target response: %w", decErr)
		}
		if tgt.ID == "" {
			return nil, fmt.Errorf("create CDP target returned empty ID")
		}
		if err := validateTargetID(tgt.ID); err != nil {
			return nil, err
		}
		if _, exists := knownIDs[tgt.ID]; exists {
			return nil, fmt.Errorf("create CDP target returned non-new ID")
		}
		// Own the candidate for cleanup before type/origin/websocket verification.
		ownedForCleanup = append(ownedForCleanup, tgt.ID)
		knownIDs[tgt.ID] = struct{}{}
		if tgt.Type != "page" {
			return nil, fmt.Errorf("create CDP target returned non-page target")
		}
		returnedOrigin, ok := originOf(tgt.URL)
		if !ok || returnedOrigin != origin {
			return nil, fmt.Errorf("create CDP target returned mismatched origin")
		}
		if tgt.WebSocketDebuggerURL != "" {
			if err := ValidateLoopbackURL(tgt.WebSocketDebuggerURL, "ws", "wss"); err != nil {
				return nil, fmt.Errorf("invalid CDP websocket URL")
			}
		}
		verified = append(verified, tgt.ID)
	}
	return append([]string(nil), verified...), nil
}

// CloseTargets closes the given DevTools page targets via /json/close.
func (c *CDP) CloseTargets(ctx context.Context, targetIDs []string) error {
	if len(targetIDs) == 0 {
		return nil
	}
	if err := ValidateLoopbackURL(c.BaseURL, "http", "https"); err != nil {
		return fmt.Errorf("invalid CDP base URL: %w", err)
	}
	targetIDs = dedupePreserveOrder(targetIDs)
	for _, id := range targetIDs {
		if err := validateTargetID(id); err != nil {
			return err
		}
	}

	client := c.cdpHTTPClient()
	var errs []error
	for _, id := range targetIDs {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/json/close/"+id, nil)
		if err != nil {
			if ctx.Err() != nil {
				errs = append(errs, ctx.Err())
			} else {
				errs = append(errs, fmt.Errorf("close CDP target request failed"))
			}
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				errs = append(errs, ctx.Err())
			} else {
				errs = append(errs, fmt.Errorf("close CDP target failed"))
			}
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			errs = append(errs, fmt.Errorf("close CDP target returned status %d", resp.StatusCode))
		}
	}
	return errors.Join(errs...)
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

// localStorage capture caps. localStorage is attacker-influenceable and can be
// large, so a pathological store is bounded rather than streamed into a frame.
// Anything skipped is counted and reported (count only), never silently dropped.
const (
	maxItemValueBytes = 256 * 1024
	maxItemsPerOrigin = 512
	maxStorageBytes   = 8 * 1024 * 1024
)

// pageWSURLs returns every loopback page-target websocket URL, so localStorage
// can be read from each open tab. Cookie reads only need one target (cookies are
// browser-wide), but localStorage is per-origin, one execution context per page.
func (c *CDP) pageWSURLs(ctx context.Context) ([]string, error) {
	if err := ValidateLoopbackURL(c.BaseURL, "http", "https"); err != nil {
		return nil, fmt.Errorf("invalid CDP base URL: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CDP /json returned %d", resp.StatusCode)
	}
	var targets []cdpTarget
	if err := json.NewDecoder(resp.Body).Decode(&targets); err != nil {
		return nil, err
	}
	var out []string
	for _, t := range targets {
		if t.WebSocketDebuggerURL == "" || (t.Type != "page" && t.Type != "") {
			continue
		}
		if err := ValidateLoopbackURL(t.WebSocketDebuggerURL, "ws", "wss"); err != nil {
			return nil, fmt.Errorf("invalid CDP websocket URL: %w", err)
		}
		out = append(out, t.WebSocketDebuggerURL)
	}
	return out, nil
}

// lsCapture is the shape returned by the in-page evaluation: the tab's origin
// and its localStorage entries as [key, value] pairs.
type lsCapture struct {
	Origin  string      `json:"o"`
	Entries [][2]string `json:"e"`
}

// readOnePageStorage evaluates localStorage in one page's top document. The
// try/catch keeps an opaque or storage-denied origin from failing the capture.
const lsExpr = `(function(){try{return JSON.stringify({o:location.origin,e:Object.entries(window.localStorage)})}catch(e){return JSON.stringify({o:location.origin,e:[]})}})()`

func (c *CDP) readOnePageStorage(ctx context.Context, ws string) (lsCapture, error) {
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, ws, nil)
	if err != nil {
		return lsCapture{}, fmt.Errorf("dial devtools websocket: %w", err)
	}
	defer conn.Close()
	if err := conn.WriteJSON(map[string]any{
		"id":     1,
		"method": "Runtime.evaluate",
		"params": map[string]any{"expression": lsExpr, "returnByValue": true},
	}); err != nil {
		return lsCapture{}, err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return lsCapture{}, fmt.Errorf("set read deadline: %w", err)
	}
	for {
		var msg struct {
			ID     int `json:"id"`
			Result struct {
				Result struct {
					Value string `json:"value"`
				} `json:"result"`
				ExceptionDetails json.RawMessage `json:"exceptionDetails"`
			} `json:"result"`
			Error *struct {
				Code int `json:"code"`
			} `json:"error"`
		}
		if err := conn.ReadJSON(&msg); err != nil {
			return lsCapture{}, err
		}
		if msg.ID != 1 {
			continue // skip CDP events
		}
		if msg.Error != nil {
			// Withhold the browser message: it can echo localStorage values.
			return lsCapture{}, fmt.Errorf("CDP Runtime.evaluate failed (code %d); message withheld", msg.Error.Code)
		}
		if len(msg.Result.ExceptionDetails) > 0 {
			// A page threw (e.g. storage disabled); treat as empty, not fatal.
			return lsCapture{Origin: ""}, nil
		}
		var cap lsCapture
		if err := json.Unmarshal([]byte(msg.Result.Result.Value), &cap); err != nil {
			return lsCapture{}, err
		}
		return cap, nil
	}
}

// wsRoundtrip sends one CDP command over conn and waits for the response with
// the matching id. It returns the CDP error code (0 on success) so a caller can
// treat a per-item rejection as best-effort. err covers only transport failures.
// The browser's error message is withheld so it cannot leak stored values.
func wsRoundtrip(conn *websocket.Conn, id int, method string, params any) (int, error) {
	msg := map[string]any{"id": id, "method": method}
	if params != nil {
		msg["params"] = params
	}
	if err := conn.WriteJSON(msg); err != nil {
		return 0, err
	}
	for {
		var resp struct {
			ID    int `json:"id"`
			Error *struct {
				Code int `json:"code"`
			} `json:"error"`
		}
		if err := conn.ReadJSON(&resp); err != nil {
			return 0, err
		}
		if resp.ID != id {
			continue // skip events and other ids
		}
		if resp.Error != nil {
			return resp.Error.Code, nil
		}
		return 0, nil
	}
}

// WriteStorage writes localStorage into a running Chromium via DOMStorage,
// without navigating: it targets a browser the operator launched, so a page load
// would be intrusive and an anti-bot fingerprint signal. Because localStorage is
// renderer-owned, an origin with no live frame in the target browser is rejected
// by Chrome; that item is skipped and counted (best-effort). Full seeding of an
// arbitrary origin belongs to the launch helper, which owns its browser and may
// navigate. Values are never logged. Returns the number of items written.
func (c *CDP) WriteStorage(ctx context.Context, items []webstorage.Item) (int, error) {
	if len(items) == 0 {
		return 0, nil
	}
	ws, err := c.wsURL(ctx)
	if err != nil {
		return 0, err
	}
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, ws, nil)
	if err != nil {
		return 0, fmt.Errorf("dial devtools websocket: %w", err)
	}
	defer conn.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return 0, fmt.Errorf("set read deadline: %w", err)
	}

	if code, err := wsRoundtrip(conn, 1, "DOMStorage.enable", nil); err != nil {
		return 0, err
	} else if code != 0 {
		return 0, fmt.Errorf("CDP rejected DOMStorage.enable (code %d)", code)
	}

	written, skipped := 0, 0
	for i, it := range items {
		params := map[string]any{
			"storageId": map[string]any{"securityOrigin": it.Origin, "isLocalStorage": true},
			"key":       it.Key,
			"value":     it.Value,
		}
		code, err := wsRoundtrip(conn, i+2, "DOMStorage.setDOMStorageItem", params)
		if err != nil {
			return written, err
		}
		if code != 0 {
			skipped++ // origin without a live frame; best-effort skip
			continue
		}
		written++
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "agentpantry: skipped %d localStorage item(s) whose origin has no live frame in the target browser; use `agentpantry browser` to seed by navigation\n", skipped)
	}
	return written, nil
}

// evalValue runs a Runtime.evaluate whose expression returns a string, and
// returns that string. An in-page exception yields ("", nil) so callers can treat
// it as "not ready / not set" rather than fatal. Values are never logged.
func (c *CDP) evalValue(conn *websocket.Conn, id int, expr string) (string, error) {
	if err := conn.WriteJSON(map[string]any{
		"id":     id,
		"method": "Runtime.evaluate",
		"params": map[string]any{"expression": expr, "returnByValue": true},
	}); err != nil {
		return "", err
	}
	for {
		var msg struct {
			ID     int `json:"id"`
			Result struct {
				Result struct {
					Value string `json:"value"`
				} `json:"result"`
				ExceptionDetails json.RawMessage `json:"exceptionDetails"`
			} `json:"result"`
			Error *struct {
				Code int `json:"code"`
			} `json:"error"`
		}
		if err := conn.ReadJSON(&msg); err != nil {
			return "", err
		}
		if msg.ID != id {
			continue
		}
		if msg.Error != nil {
			return "", fmt.Errorf("CDP Runtime.evaluate failed (code %d); message withheld", msg.Error.Code)
		}
		if len(msg.Result.ExceptionDetails) > 0 {
			return "", nil
		}
		return msg.Result.Result.Value, nil
	}
}

// originOf returns the scheme://host[:port] origin of an http(s) URL.
func originOf(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", false
	}
	return u.Scheme + "://" + u.Host, true
}

// WriteStorageViaFrames seeds localStorage by evaluating localStorage.setItem in
// the tab already open on each item's origin. Unlike WriteStorage this is the
// reliable path, but it requires a tab on the origin, so it is for a browser the
// caller launched with those origins open (the `agentpantry browser` helper),
// not an operator's arbitrary browser. Values are never logged. It returns the
// number of items set.
func (c *CDP) WriteStorageViaFrames(ctx context.Context, items []webstorage.Item) (int, error) {
	if len(items) == 0 {
		return 0, nil
	}
	byOrigin := map[string][][2]string{}
	var order []string
	for _, it := range items {
		if _, ok := byOrigin[it.Origin]; !ok {
			order = append(order, it.Origin)
		}
		byOrigin[it.Origin] = append(byOrigin[it.Origin], [2]string{it.Key, it.Value})
	}

	if err := ValidateLoopbackURL(c.BaseURL, "http", "https"); err != nil {
		return 0, fmt.Errorf("invalid CDP base URL: %w", err)
	}

	written := 0
	for _, origin := range order {
		ws, err := c.frameWSForOrigin(ctx, origin)
		if err != nil {
			return written, err
		}
		if ws == "" {
			continue // no tab on this origin; skip
		}
		n, err := c.seedFrame(ctx, ws, origin, byOrigin[origin])
		if err != nil {
			return written, err
		}
		written += n
	}
	return written, nil
}

// WriteStorageViaTargets seeds localStorage into exact DevTools page targets.
// Items are grouped by distinct origin in the shared canonical sorted order
// (deduplicated, lexicographic; same contract as OpenStorageOrigins) and paired
// with targetIDs in that same order. Per-origin item order is preserved. Every
// origin/target pair is preflighted before any seedFrame call so a mismatch
// writes nothing. Errors are generic and never echo origins, URLs, target IDs,
// keys, or values.
func (c *CDP) WriteStorageViaTargets(ctx context.Context, items []webstorage.Item, targetIDs []string) (int, error) {
	if len(items) == 0 && len(targetIDs) == 0 {
		return 0, nil
	}
	if err := ValidateLoopbackURL(c.BaseURL, "http", "https"); err != nil {
		return 0, fmt.Errorf("invalid CDP base URL")
	}

	byOrigin := map[string][][2]string{}
	var itemOrigins []string
	for _, it := range items {
		if err := ValidateStorageOrigin(it.Origin); err != nil {
			return 0, err
		}
		itemOrigins = append(itemOrigins, it.Origin)
		byOrigin[it.Origin] = append(byOrigin[it.Origin], [2]string{it.Key, it.Value})
	}
	order := canonicalSortedStorageOrigins(itemOrigins)

	seenIDs := make(map[string]struct{}, len(targetIDs))
	for _, id := range targetIDs {
		if err := validateTargetID(id); err != nil {
			return 0, fmt.Errorf("invalid target ID")
		}
		if _, dup := seenIDs[id]; dup {
			return 0, fmt.Errorf("duplicate target ID")
		}
		seenIDs[id] = struct{}{}
	}
	if len(targetIDs) != len(order) {
		return 0, fmt.Errorf("target ID count mismatch")
	}

	type seededOrigin struct {
		ws     string
		origin string
		pairs  [][2]string
	}
	ready := make([]seededOrigin, 0, len(order))
	for i, origin := range order {
		ws, err := c.frameWSForTargetID(ctx, targetIDs[i], origin)
		if err != nil {
			return 0, err
		}
		ready = append(ready, seededOrigin{ws: ws, origin: origin, pairs: byOrigin[origin]})
	}

	written := 0
	for _, entry := range ready {
		n, err := c.seedFrame(ctx, entry.ws, entry.origin, entry.pairs)
		if err != nil {
			return written, err
		}
		written += n
	}
	return written, nil
}

// frameWSForTargetID resolves the websocket for one exact DevTools target ID,
// retrying target-list readiness for up to 10s. It never selects a different
// same-origin target. Missing targets and not-yet-ready about:blank / empty
// websocket entries may retry; a present target whose type is not exactly
// "page" (including empty), unsafe ID, non-loopback websocket, or a different
// canonical HTTP(S) origin fails generically before any seed.
func (c *CDP) frameWSForTargetID(ctx context.Context, targetID, origin string) (string, error) {
	deadline := time.Now().Add(10 * time.Second)
	client := c.cdpHTTPClient()
	for {
		targets, err := c.listTargets(ctx, client)
		if err == nil {
			var found *cdpTarget
			for i := range targets {
				if targets[i].ID == targetID {
					found = &targets[i]
					break
				}
			}
			if found != nil {
				if err := validateTargetID(found.ID); err != nil {
					return "", fmt.Errorf("invalid storage target")
				}
				if found.Type != "page" {
					return "", fmt.Errorf("invalid storage target")
				}
				urlReady := found.URL != "" && found.URL != "about:blank"
				wsReady := found.WebSocketDebuggerURL != ""
				if urlReady && wsReady {
					o, ok := originOf(found.URL)
					if !ok || o != origin {
						return "", fmt.Errorf("storage target ownership mismatch")
					}
					if err := ValidateLoopbackURL(found.WebSocketDebuggerURL, "ws", "wss"); err != nil {
						return "", fmt.Errorf("invalid CDP websocket URL")
					}
					return found.WebSocketDebuggerURL, nil
				}
				// Missing URL / about:blank / empty websocket: not ready yet.
			}
			// Missing target: retry until deadline.
		} else if ctx.Err() != nil {
			return "", ctx.Err()
		}

		if time.Now().After(deadline) {
			return "", fmt.Errorf("storage target not ready")
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// frameWSForOrigin finds the websocket of a page target whose URL origin matches,
// retrying briefly because a freshly launched tab may not have its URL set yet.
func (c *CDP) frameWSForOrigin(ctx context.Context, origin string) (string, error) {
	deadline := time.Now().Add(10 * time.Second)
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/json", nil)
		if err != nil {
			return "", err
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			var targets []cdpTarget
			derr := decodeLimitedJSON(resp.Body, &targets)
			_ = resp.Body.Close()
			if errors.Is(derr, errCDPJSONResponseTooLarge) {
				return "", derr
			}
			if derr == nil {
				for _, t := range targets {
					if t.WebSocketDebuggerURL == "" || (t.Type != "page" && t.Type != "") {
						continue
					}
					if o, ok := originOf(t.URL); ok && o == origin {
						if err := ValidateLoopbackURL(t.WebSocketDebuggerURL, "ws", "wss"); err != nil {
							return "", fmt.Errorf("invalid CDP websocket URL: %w", err)
						}
						return t.WebSocketDebuggerURL, nil
					}
				}
			}
		}
		if time.Now().After(deadline) {
			return "", nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// seedFrame waits for the origin's document to be ready, then sets its
// localStorage entries in one evaluate. Returns the number set.
func (c *CDP) seedFrame(ctx context.Context, ws, origin string, pairs [][2]string) (int, error) {
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, ws, nil)
	if err != nil {
		return 0, fmt.Errorf("dial devtools websocket: %w", err)
	}
	defer conn.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return 0, fmt.Errorf("set read deadline: %w", err)
	}

	id := 1
	ready := false
	readyBy := time.Now().Add(10 * time.Second)
	for {
		val, err := c.evalValue(conn, id, `JSON.stringify({o:location.origin,r:document.readyState})`)
		id++
		if err != nil {
			return 0, err
		}
		var st struct {
			O string `json:"o"`
			R string `json:"r"`
		}
		if val != "" && json.Unmarshal([]byte(val), &st) == nil && st.O == origin && st.R != "loading" {
			ready = true
			break
		}
		if time.Now().After(readyBy) {
			break
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	if !ready {
		return 0, nil // the tab never became the origin document; skip
	}

	originLit, err := json.Marshal(origin)
	if err != nil {
		return 0, err
	}
	payload, err := json.Marshal(pairs)
	if err != nil {
		return 0, err
	}
	// Embed expected origin and pairs as JSON literals (valid JS). The mutation
	// expression is the authoritative race-safe guard: refuse setItem if
	// location.origin drifted after the readiness loop. Never log keys/values/origin.
	expr := `(function(){if(location.origin!==` + string(originLit) + `)return '0';var it=` + string(payload) + `;var n=0;for(var i=0;i<it.length;i++){try{localStorage.setItem(it[i][0],it[i][1]);n++}catch(e){}}return ''+n;})()`
	val, err := c.evalValue(conn, id, expr)
	if err != nil {
		return 0, err
	}
	n, _ := strconv.Atoi(val)
	return n, nil
}

// ReadStorage mirrors localStorage from every open tab's top document. It is
// non-intrusive: it never navigates or reloads a page. A single hung or closed
// page is skipped rather than failing the whole capture. Values are never
// logged. Size caps bound a pathological store; skipped items are counted.
func (c *CDP) ReadStorage(ctx context.Context) ([]webstorage.Item, error) {
	urls, err := c.pageWSURLs(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]webstorage.Item{}
	var order []string
	perOrigin := map[string]int{}
	total := 0
	dropped := 0
	for _, ws := range urls {
		capd, err := c.readOnePageStorage(ctx, ws)
		if err != nil {
			continue // one bad page does not sink the cycle
		}
		for _, kv := range capd.Entries {
			k, v := kv[0], kv[1]
			if len(v) > maxItemValueBytes || perOrigin[capd.Origin] >= maxItemsPerOrigin || total+len(k)+len(v) > maxStorageBytes {
				dropped++
				continue
			}
			it := webstorage.Item{Origin: capd.Origin, Key: k, Value: v}
			key := webstorage.Key(it)
			if _, ok := seen[key]; !ok {
				order = append(order, key)
			}
			seen[key] = it
			perOrigin[capd.Origin]++
			total += len(k) + len(v)
		}
	}
	if dropped > 0 {
		fmt.Fprintf(os.Stderr, "agentpantry: skipped %d localStorage item(s) over size/count caps\n", dropped)
	}
	out := make([]webstorage.Item, 0, len(order))
	for _, k := range order {
		out = append(out, seen[k])
	}
	return out, nil
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
