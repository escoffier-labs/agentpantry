// Package lane checks whether an already-running Chromium still holds a working
// session for a host.
//
// A captured session cannot be moved: clearance cookies are bound to the TLS
// fingerprint and header order of the browser that earned them, so replaying
// them from another client is refused even when the values are fresh and the
// User-Agent matches. The only reliable question is whether the browser itself
// still gets real content, which is what this package answers by loading one
// page and inspecting what came back.
package lane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/cdpvault"
	"github.com/gorilla/websocket"
)

// Verdicts classify what a probe actually received.
const (
	// VerdictOK means the page returned usable content.
	VerdictOK = "ok"
	// VerdictChallenge means a bot challenge or block page answered instead of
	// the page.
	VerdictChallenge = "challenge"
	// VerdictEmpty means the page loaded but carried almost no text.
	VerdictEmpty = "empty"
)

// minTextLen is the floor for "usable content". Pages below it are treated as
// empty (a shell with no body) or, when a marker matches, as a challenge.
const minTextLen = 200

// textSampleLimit bounds how much rendered text is inspected. Only the head of
// the document is needed to recognise an interstitial.
const textSampleLimit = 4000

// titleMarkers appear in the <title> of a challenge or block page.
var titleMarkers = []string{
	"just a moment",
	"attention required",
	"security check",
	"security |",
	"verify you are human",
	"prove you are human",
	"prove your humanity",
	"checking your browser",
	"access denied",
	"are you a robot",
	"blocked",
}

// bodyMarkers appear in the rendered text of a challenge or block page.
var bodyMarkers = []string{
	"enable javascript and cookies to continue",
	"verify you are human",
	"prove you are human",
	"prove your humanity",
	"checking your browser",
	"just a moment",
	"attention required",
	"unusual traffic",
	"are you a robot",
	"are you a human",
	"access denied",
	"request blocked",
	"security check",
	"captcha",
	"cf-turnstile",
}

// Probe is the read-only result of loading one URL in a lane browser. It never
// carries cookie values, headers, or page text.
type Probe struct {
	URL      string `json:"url"`
	FinalURL string `json:"final_url"`
	Title    string `json:"title"`
	TextLen  int    `json:"text_len"`
	Verdict  string `json:"verdict"`
	Marker   string `json:"marker,omitempty"`
}

// OK reports whether the probe got usable content.
func (p Probe) OK() bool { return p.Verdict == VerdictOK }

// Classify decides what a loaded page is, from its title, rendered text and
// final URL. A challenge is only claimed for a page that also came back short,
// so a long documentation page that merely mentions a security check is not
// misreported.
func Classify(title, text, finalURL string) (verdict, marker string) {
	trimmed := strings.TrimSpace(text)
	n := len([]rune(trimmed))

	if strings.Contains(finalURL, "/cdn-cgi/challenge-platform") {
		return VerdictChallenge, "challenge platform URL"
	}

	if n < textSampleLimit {
		lowerTitle := strings.ToLower(title)
		for _, m := range titleMarkers {
			if strings.Contains(lowerTitle, m) {
				return VerdictChallenge, m
			}
		}
		lowerText := strings.ToLower(trimmed)
		for _, m := range bodyMarkers {
			if strings.Contains(lowerText, m) {
				return VerdictChallenge, m
			}
		}
	}

	if n < minTextLen {
		return VerdictEmpty, "short page"
	}
	return VerdictOK, ""
}

// hostMatches reports whether got is want or a subdomain of it.
func hostMatches(got, want string) bool {
	got = strings.ToLower(strings.TrimSuffix(got, "."))
	want = strings.ToLower(strings.Trim(strings.TrimSuffix(want, "."), "."))
	if want == "" {
		return false
	}
	return got == want || strings.HasSuffix(got, "."+want)
}

type target struct {
	ID                   string `json:"id"`
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

// openTarget asks the lane browser for a new tab at rawURL.
func openTarget(ctx context.Context, baseURL, rawURL string) (target, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		strings.TrimSuffix(baseURL, "/")+"/json/new?"+url.QueryEscape(rawURL), nil)
	if err != nil {
		return target{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return target{}, fmt.Errorf("open tab in lane browser: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return target{}, fmt.Errorf("lane browser refused a new tab (HTTP %d)", resp.StatusCode)
	}
	var t target
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return target{}, fmt.Errorf("decode lane tab: %w", err)
	}
	if t.WebSocketDebuggerURL == "" {
		return target{}, fmt.Errorf("lane browser returned a tab with no debugger URL")
	}
	if err := cdpvault.ValidateLoopbackURL(t.WebSocketDebuggerURL, "ws", "wss"); err != nil {
		return target{}, fmt.Errorf("lane browser returned a non-loopback debugger URL: %w", err)
	}
	return t, nil
}

// closeTarget closes the tab the probe opened, so a check never leaves a tab
// behind in the operator's browser.
func closeTarget(baseURL, id string) {
	if id == "" {
		return
	}
	req, err := http.NewRequest(http.MethodGet,
		strings.TrimSuffix(baseURL, "/")+"/json/close/"+url.PathEscape(id), nil)
	if err != nil {
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

// evalString runs a Runtime.evaluate whose expression returns a string. A
// document that is not ready yet yields an empty value rather than an error so
// the caller can retry.
func evalString(conn *websocket.Conn, id int, expr string) (string, error) {
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
			continue // skip events and unrelated responses
		}
		if msg.Error != nil {
			return "", fmt.Errorf("CDP rejected Runtime.evaluate (code %d)", msg.Error.Code)
		}
		if msg.Result.ExceptionDetails != nil {
			return "", nil // page not ready; caller retries
		}
		return msg.Result.Result.Value, nil
	}
}

const readyExpr = `(document.readyState === 'complete') ? 'complete' : String(document.readyState)`

// probeExpr returns the title, final URL and a bounded sample of rendered text.
// It is built once so the sample limit and the classifier agree.
var probeExpr = fmt.Sprintf(`(function () {
  var body = document.body;
  var text = body ? (body.innerText || '') : '';
  return JSON.stringify({
    title: document.title || '',
    text: text.slice(0, %d),
    len: text.length,
    url: location.href
  });
})()`, textSampleLimit)

// Verify loads rawURL in the lane browser at baseURL and reports whether the
// session still produces real content. host, when set, must match the URL's
// host: a check is scoped to one domain so this cannot be used to drive the
// operator's authenticated browser anywhere else.
func Verify(ctx context.Context, baseURL, rawURL, host string, timeout time.Duration) (Probe, error) {
	if err := cdpvault.ValidateLoopbackURL(baseURL, "http", "https"); err != nil {
		return Probe{}, fmt.Errorf("lane URL must be loopback: %w", err)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return Probe{}, fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return Probe{}, fmt.Errorf("only http and https URLs can be verified")
	}
	if host == "" {
		return Probe{}, fmt.Errorf("-domain is required so a check cannot drive the browser anywhere else")
	}
	if !hostMatches(u.Hostname(), host) {
		return Probe{}, fmt.Errorf("URL host %q does not match -domain %q", u.Hostname(), host)
	}
	if timeout <= 0 {
		timeout = 25 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	t, err := openTarget(ctx, baseURL, rawURL)
	if err != nil {
		return Probe{}, err
	}
	defer closeTarget(baseURL, t.ID)

	conn, _, err := websocket.DefaultDialer.DialContext(ctx, t.WebSocketDebuggerURL, nil)
	if err != nil {
		return Probe{}, fmt.Errorf("dial lane tab: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetReadDeadline(deadline); err != nil {
			return Probe{}, fmt.Errorf("set read deadline: %w", err)
		}
	}

	// Wait for the document to finish loading. A challenge interstitial also
	// reaches 'complete', so this only bounds the wait; Classify decides.
	id := 1
	for {
		state, err := evalString(conn, id, readyExpr)
		id++
		if err != nil {
			return Probe{}, err
		}
		if state == "complete" {
			break
		}
		select {
		case <-ctx.Done():
			return Probe{}, fmt.Errorf("lane page did not finish loading before the timeout")
		case <-time.After(250 * time.Millisecond):
		}
	}

	// One short settle allows late client-side redirects to land before the
	// page is read.
	select {
	case <-ctx.Done():
		return Probe{}, fmt.Errorf("lane page did not settle before the timeout")
	case <-time.After(400 * time.Millisecond):
	}

	raw, err := evalString(conn, id, probeExpr)
	if err != nil {
		return Probe{}, err
	}
	var page struct {
		Title string `json:"title"`
		Text  string `json:"text"`
		Len   int    `json:"len"`
		URL   string `json:"url"`
	}
	if err := json.Unmarshal([]byte(raw), &page); err != nil {
		return Probe{}, fmt.Errorf("lane page returned an unreadable probe result")
	}

	verdict, marker := Classify(page.Title, page.Text, page.URL)
	return Probe{
		URL:      rawURL,
		FinalURL: page.URL,
		Title:    page.Title,
		TextLen:  page.Len,
		Verdict:  verdict,
		Marker:   marker,
	}, nil
}
