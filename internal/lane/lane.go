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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
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
	// VerdictOffDomain means the browser ended up on a host outside the checked
	// domain, typically an expired session bounced to an external sign-in. The
	// off-domain page is never read or reported.
	VerdictOffDomain = "off_domain"
)

// minTextLen is the floor for "usable content". Pages below it are treated as
// empty (a shell with no body) or, when a marker matches, as a challenge.
const minTextLen = 200

// textSampleLimit bounds how much rendered text is inspected. Only the head of
// the document is needed to recognise an interstitial.
const textSampleLimit = 4000

// titleMarkers appear in the <title> of a challenge or block page. A title is
// short by nature, so these are checked regardless of how much text the page
// carries: an interstitial can ship long explanatory copy.
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
}

// titleWordMarkers are title markers that must match as a whole word, because
// the bare word appears inside ordinary titles ("How to get unblocked").
var titleWordMarkers = map[string]*regexp.Regexp{
	"blocked": regexp.MustCompile(`\bblocked\b`),
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
// carries cookie values or headers, and URLs are stripped of query and fragment.
// Title is set only for a page on the checked domain; page text is never kept.
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

// Classify decides what a loaded page is, from its title, a bounded sample of
// its rendered text, the full length of that text, and the final URL. A title
// marker is decisive on its own. A body marker only counts when the whole page
// is short, so a long documentation page that merely mentions a security check
// is not misreported.
func Classify(title, textSample string, fullLen int, finalURL string) (verdict, marker string) {
	trimmed := strings.TrimSpace(textSample)
	n := fullLen
	if sampleLen := len([]rune(trimmed)); sampleLen > n {
		n = sampleLen
	}

	if strings.Contains(finalURL, "/cdn-cgi/challenge-platform") {
		return VerdictChallenge, "challenge platform URL"
	}

	lowerTitle := strings.ToLower(title)
	for _, m := range titleMarkers {
		if strings.Contains(lowerTitle, m) {
			return VerdictChallenge, m
		}
	}
	for m, re := range titleWordMarkers {
		if re.MatchString(lowerTitle) {
			return VerdictChallenge, m
		}
	}

	if n < textSampleLimit {
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

// RedactURL drops userinfo, query and fragment from raw, which can carry
// tokens, so a URL is safe to print. An unparseable value is replaced rather
// than echoed.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(unparseable URL)"
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	return u.String()
}

type target struct {
	ID                   string `json:"id"`
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

// httpTimeout bounds every DevTools HTTP call. The tab open runs inside the
// verify context; the close runs on its own because that one has usually
// expired by the time the tab is closed.
const httpTimeout = 10 * time.Second

// closeTimeout bounds closing the tab, independent of the verify context.
const closeTimeout = 3 * time.Second

// targetIDPattern is the charset of Chrome target IDs (hex or alphanumeric). An
// ID outside it is never spliced into a request path.
var targetIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// openTarget asks the lane browser for a new tab at rawURL. A tab that was
// created but then rejected is closed again before returning.
func openTarget(ctx context.Context, baseURL, rawURL string) (target, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		strings.TrimSuffix(baseURL, "/")+"/json/new?"+url.QueryEscape(rawURL), nil)
	if err != nil {
		return target{}, err
	}
	resp, err := cdpvault.NewHTTPClient(httpTimeout).Do(req)
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
	fail := func(err error) (target, error) {
		_ = closeTarget(baseURL, t.ID)
		return target{}, err
	}
	if !targetIDPattern.MatchString(t.ID) {
		return target{}, fmt.Errorf("lane browser returned a tab with an unusable id")
	}
	if t.WebSocketDebuggerURL == "" {
		return fail(fmt.Errorf("lane browser returned a tab with no debugger URL"))
	}
	if err := cdpvault.ValidateLoopbackURL(t.WebSocketDebuggerURL, "ws", "wss"); err != nil {
		return fail(fmt.Errorf("lane browser returned a non-loopback debugger URL: %w", err))
	}
	return t, nil
}

// closeTarget closes the tab the probe opened, so a check never leaves a tab
// behind in the operator's browser. It runs on its own bounded context because
// the verify context has often already expired.
func closeTarget(baseURL, id string) error {
	if id == "" {
		return nil
	}
	if !targetIDPattern.MatchString(id) {
		return fmt.Errorf("refusing to close tab with unusable id")
	}
	ctx, cancel := context.WithTimeout(context.Background(), closeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimSuffix(baseURL, "/")+"/json/close/"+id, nil)
	if err != nil {
		return err
	}
	resp, err := cdpvault.NewHTTPClient(closeTimeout).Do(req)
	if err != nil {
		return fmt.Errorf("close lane tab: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("close lane tab: HTTP %d", resp.StatusCode)
	}
	return nil
}

// writeTimeout bounds one CDP write so a stalled peer cannot pin the run.
const writeTimeout = 5 * time.Second

// readMargin is added to the content-poll deadline when bounding a single read.
const readMargin = 2 * time.Second

// transientCDPErrors are CDP error messages that mean the page is mid
// navigation, so the evaluate is retried rather than failing the check.
var transientCDPErrors = []string{
	"cannot find context with specified id",
	"execution context was destroyed",
	"inspected target navigated or closed",
	"cannot find default execution context",
}

// evalString runs a Runtime.evaluate whose expression returns a string. ready
// is false (with a nil error) when the document is not ready yet: the page
// threw, or navigation destroyed the execution context. The caller retries.
// readDeadline bounds waiting for the reply.
func evalString(conn *websocket.Conn, id int, expr string, readDeadline time.Time) (value string, ready bool, err error) {
	if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return "", false, err
	}
	if err := conn.WriteJSON(map[string]any{
		"id":     id,
		"method": "Runtime.evaluate",
		"params": map[string]any{"expression": expr, "returnByValue": true},
	}); err != nil {
		return "", false, err
	}
	if err := conn.SetReadDeadline(readDeadline); err != nil {
		return "", false, err
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
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := conn.ReadJSON(&msg); err != nil {
			return "", false, err
		}
		if msg.ID != id {
			continue // skip events and unrelated responses
		}
		if msg.Error != nil {
			lower := strings.ToLower(msg.Error.Message)
			for _, m := range transientCDPErrors {
				if strings.Contains(lower, m) {
					return "", false, nil
				}
			}
			return "", false, fmt.Errorf("CDP rejected Runtime.evaluate (code %d)", msg.Error.Code)
		}
		// json.RawMessage holds the literal null, so presence alone is not an
		// exception: require a real object.
		if ex := bytes.TrimSpace(msg.Result.ExceptionDetails); len(ex) > 0 && ex[0] == '{' {
			return "", false, nil
		}
		return msg.Result.Result.Value, true, nil
	}
}

// pollInterval is how often the page is re-read while it loads.
var pollInterval = 300 * time.Millisecond

// contentPollLimit bounds the wait for text. A challenged or empty page never
// gains any, so a check must not run to the full timeout.
var contentPollLimit = 8 * time.Second

// pageProbe is one read of the loaded document.
type pageProbe struct {
	Title string `json:"title"`
	Text  string `json:"text"`
	Len   int    `json:"len"`
	URL   string `json:"url"`
}

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

// offDomainMarker names only the host a page ended up on, never its content.
func offDomainMarker(u *url.URL) string {
	if h := u.Hostname(); h != "" {
		return h
	}
	return u.Scheme + ":"
}

// Verify loads rawURL in the lane browser at baseURL and reports whether the
// session still produces real content. host, when set, must match the URL's
// host: a check is scoped to one domain so this cannot be used to drive the
// operator's authenticated browser anywhere else. The final URL is held to the
// same scope: a page that ends up elsewhere is reported as off_domain.
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
	if u.User != nil {
		return Probe{}, fmt.Errorf("URLs with embedded credentials are not accepted")
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
	defer func() { _ = closeTarget(baseURL, t.ID) }()

	conn, _, err := websocket.DefaultDialer.DialContext(ctx, t.WebSocketDebuggerURL, nil)
	if err != nil {
		return Probe{}, fmt.Errorf("dial lane tab: %w", err)
	}
	defer conn.Close()

	// Poll the page instead of trusting one readyState read. A tab created with
	// a URL starts on about:blank and can report 'complete' for that document
	// before the navigation begins, and a body exists before it has rendered
	// text. Reading once raced both cases and reported an empty page for pages
	// that were still loading. A challenge or a genuinely empty shell never
	// gains text, so the wait is capped rather than run to the deadline. A
	// not-ready read (script exception, or the execution context destroyed by
	// the navigation itself) is retried until that same deadline.
	id := 1
	var page pageProbe
	contentDeadline := time.Now().Add(contentPollLimit)
	readDeadline := contentDeadline.Add(readMargin)
	if d, ok := ctx.Deadline(); ok && d.Before(readDeadline) {
		readDeadline = d
	}
	for {
		raw, ready, err := evalString(conn, id, probeExpr, readDeadline)
		id++
		if err != nil {
			return Probe{}, err
		}
		if ready {
			var next pageProbe
			if err := json.Unmarshal([]byte(raw), &next); err != nil {
				return Probe{}, fmt.Errorf("lane page returned an unreadable probe result")
			}
			if next.URL != "" && next.URL != "about:blank" {
				page = next
				fu, perr := url.Parse(page.URL)
				switch {
				case perr != nil:
					return Probe{}, fmt.Errorf("lane page reported an unreadable URL")
				case fu.Scheme == "chrome-error":
					return Probe{}, fmt.Errorf("lane browser could not load %s (network error page)", u.Hostname())
				case !hostMatches(fu.Hostname(), host):
					// Stop at once: the authenticated browser should not keep
					// rendering a page outside the scoped domain.
					return Probe{
						URL:      RedactURL(rawURL),
						FinalURL: RedactURL(page.URL),
						Verdict:  VerdictOffDomain,
						Marker:   offDomainMarker(fu),
					}, nil
				}
				if page.Len >= minTextLen {
					break
				}
			}
		}
		if !time.Now().Before(contentDeadline) {
			break
		}
		select {
		case <-ctx.Done():
			return Probe{}, fmt.Errorf("lane page did not settle before the timeout")
		case <-time.After(pollInterval):
		}
	}

	// A tab that never left about:blank (or never became readable) is a failure
	// to run the check, not a finding about the site.
	if page.URL == "" || page.URL == "about:blank" {
		return Probe{}, fmt.Errorf("lane tab never navigated to the URL; check that the lane accepts %s", u.Hostname())
	}

	verdict, marker := Classify(page.Title, page.Text, page.Len, page.URL)
	return Probe{
		URL:      RedactURL(rawURL),
		FinalURL: RedactURL(page.URL),
		Title:    page.Title,
		TextLen:  page.Len,
		Verdict:  verdict,
		Marker:   marker,
	}, nil
}
