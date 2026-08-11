package cdpvault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/webstorage"
	"github.com/gorilla/websocket"
)

type targetFixture struct {
	id         string
	targetType string
	url        string
	wsPath     string
	closed     bool
	origin     string
	keys       []string
	// emitEmptyType forces /json/list to serialize type as "" (not coerced to "page").
	emitEmptyType bool
	// driftOriginAfterReady, when set, replaces the document origin immediately
	// after a ready-state/location-origin evaluate returns and before the next
	// evaluate (the localStorage mutation).
	driftOriginAfterReady string
}

type fakeCDPTargetServer struct {
	srv *httptest.Server

	mu          sync.Mutex
	targets     map[string]*targetFixture
	nextSeq     int
	newOrigins  []string
	closedIDs   []string
	failNewOn   int
	newAttempts int
	badWSHost   string

	newResponses          []cdpTarget
	oversizedNewResponse  bool
	oversizedListResponse bool
	failCloseCount        int
	// failCloseAfterAcceptCount marks the target closed (Chrome accepted the
	// close) then returns an HTTP error, simulating a lost/failed response.
	failCloseAfterAcceptCount int
	// failListOn fails the Nth /json/list request (1-based). Use 2 so the
	// baseline list in OpenStorageOrigins succeeds and the cleanup
	// reconciliation list fails.
	failListOn   int
	listAttempts int
}

func newFakeCDPTargetServer(t *testing.T) *fakeCDPTargetServer {
	t.Helper()
	f := &fakeCDPTargetServer{targets: make(map[string]*targetFixture)}
	up := websocket.Upgrader{}
	mux := http.NewServeMux()

	mux.HandleFunc("/json/new", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		originURL := r.URL.RawQuery
		if originURL == "" {
			http.Error(w, "missing origin", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.newAttempts++
		attempt := f.newAttempts
		if f.failNewOn > 0 && attempt == f.failNewOn {
			f.mu.Unlock()
			http.Error(w, "injected new failure", http.StatusInternalServerError)
			return
		}
		if f.oversizedNewResponse {
			f.mu.Unlock()
			_, _ = fmt.Fprintf(w, `{"id":"%s`, strings.Repeat("oversized-private-value", 100000))
			return
		}

		var response cdpTarget
		if attempt <= len(f.newResponses) {
			response = f.newResponses[attempt-1]
			if response.ID != "" {
				if _, exists := f.targets[response.ID]; !exists {
					origin, ok := originOf(response.URL)
					if !ok {
						origin = response.URL
					}
					f.targets[response.ID] = &targetFixture{
						id:         response.ID,
						targetType: response.Type,
						url:        response.URL,
						wsPath:     "/devtools/page/" + response.ID,
						origin:     origin,
					}
				}
			}
		} else {
			f.nextSeq++
			id := fmt.Sprintf("target-%d", f.nextSeq)
			origin, ok := originOf(originURL)
			if !ok {
				origin = originURL
			}
			tg := &targetFixture{
				id:         id,
				targetType: "page",
				url:        originURL,
				wsPath:     "/devtools/page/" + id,
				origin:     origin,
			}
			f.targets[id] = tg
			ws := "ws://" + r.Host + tg.wsPath
			if f.badWSHost != "" {
				ws = "ws://" + f.badWSHost + tg.wsPath
			}
			response = cdpTarget{
				ID:                   id,
				Type:                 "page",
				URL:                  originURL,
				WebSocketDebuggerURL: ws,
			}
		}
		f.newOrigins = append(f.newOrigins, originURL)
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(response)
	})

	listTargets := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		f.mu.Lock()
		f.listAttempts++
		if f.failListOn > 0 && f.listAttempts == f.failListOn {
			f.mu.Unlock()
			http.Error(w, "injected list failure", http.StatusInternalServerError)
			return
		}
		if f.oversizedListResponse {
			f.mu.Unlock()
			_, _ = fmt.Fprintf(w, `[{"id":"%s`, strings.Repeat("oversized-private-value", 100000))
			return
		}
		var list []map[string]any
		for _, tg := range f.targets {
			if tg.closed {
				continue
			}
			targetType := tg.targetType
			if tg.emitEmptyType {
				targetType = ""
			} else if targetType == "" {
				targetType = "page"
			}
			ws := "ws://" + r.Host + tg.wsPath
			if f.badWSHost != "" {
				ws = "ws://" + f.badWSHost + tg.wsPath
			}
			list = append(list, map[string]any{
				"id":                   tg.id,
				"type":                 targetType,
				"url":                  tg.url,
				"webSocketDebuggerUrl": ws,
			})
		}
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(list)
	}
	mux.HandleFunc("/json", listTargets)
	mux.HandleFunc("/json/list", listTargets)

	mux.HandleFunc("/json/close/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/json/close/")
		f.mu.Lock()
		if f.failCloseAfterAcceptCount > 0 {
			f.failCloseAfterAcceptCount--
			if tg, ok := f.targets[id]; ok {
				tg.closed = true
				f.closedIDs = append(f.closedIDs, id)
			}
			f.mu.Unlock()
			http.Error(w, "injected close loss after accept", http.StatusInternalServerError)
			return
		}
		if f.failCloseCount > 0 {
			f.failCloseCount--
			f.mu.Unlock()
			http.Error(w, "injected close failure", http.StatusInternalServerError)
			return
		}
		if tg, ok := f.targets[id]; ok {
			tg.closed = true
			f.closedIDs = append(f.closedIDs, id)
		}
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/devtools/page/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/devtools/page/")
		f.mu.Lock()
		tg := f.targets[id]
		f.mu.Unlock()
		if tg == nil {
			http.NotFound(w, r)
			return
		}
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
			value := "0"
			expr := cmd.Params.Expression
			if strings.Contains(expr, "document.readyState") {
				f.mu.Lock()
				readyOrigin := tg.origin
				driftTo := tg.driftOriginAfterReady
				f.mu.Unlock()
				value = `{"o":"` + readyOrigin + `","r":"complete"}`
				// Navigation race: document origin changes after the ready
				// response is produced and before the mutation evaluate.
				if driftTo != "" {
					f.mu.Lock()
					if tg.driftOriginAfterReady != "" {
						tg.origin = tg.driftOriginAfterReady
						tg.url = tg.driftOriginAfterReady + "/"
						tg.driftOriginAfterReady = ""
					}
					f.mu.Unlock()
				}
			} else if strings.Contains(expr, "localStorage.setItem") {
				keys := extractSetItemKeys(expr)
				want, hasGuard := mutationOriginGuard(expr)
				f.mu.Lock()
				curOrigin := tg.origin
				if hasGuard && want != curOrigin {
					// Inline location.origin guard refused the write.
					f.mu.Unlock()
					value = "0"
				} else if len(keys) > 0 {
					tg.keys = append(tg.keys, keys...)
					f.mu.Unlock()
					value = fmt.Sprintf("%d", len(keys))
				} else {
					f.mu.Unlock()
				}
			}
			_ = c.WriteJSON(map[string]any{
				"id":     cmd.ID,
				"result": map[string]any{"result": map[string]any{"type": "string", "value": value}},
			})
		}
	})

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func extractSetItemKeys(expr string) []string {
	start := strings.Index(expr, `var it=`)
	if start < 0 {
		return nil
	}
	rest := expr[start+len(`var it=`):]
	end := strings.Index(rest, `;var n=0`)
	if end < 0 {
		return nil
	}
	var pairs [][2]string
	if err := json.Unmarshal([]byte(rest[:end]), &pairs); err != nil {
		return nil
	}
	keys := make([]string, 0, len(pairs))
	for _, p := range pairs {
		keys = append(keys, p[0])
	}
	return keys
}

// mutationOriginGuard reports whether expr has a pre-setItem mismatch guard
// matching seedFrame semantics:
//
//	if(location.origin!=="<origin>")return ...
//
// or the braced form if(...){return ...} before localStorage.setItem.
// The protective return statement must complete before the first
// localStorage.setItem; a mismatch branch of return localStorage.setItem(...)
// is not protective. Equality checks, empty mismatch bodies, unrelated later
// returns, comparisons without an early return, and guards after setItem are
// not protective.
func mutationOriginGuard(expr string) (want string, ok bool) {
	setIdx := strings.Index(expr, "localStorage.setItem")
	if setIdx < 0 {
		return "", false
	}
	head := expr[:setIdx]
	const prefix = "if(location.origin!=="
	guardIdx := strings.Index(head, prefix)
	if guardIdx < 0 {
		return "", false
	}
	after := head[guardIdx+len(prefix):]
	// Canonical production shape: JSON origin literal immediately after !==.
	if len(after) == 0 || after[0] != '"' {
		return "", false
	}
	origin, litEnd, ok := firstJSONStringLiteralSpan(after)
	if !ok || litEnd == 0 {
		return "", false
	}
	rest := after[litEnd:]
	if !strings.HasPrefix(rest, ")") {
		return "", false
	}
	body := strings.TrimLeft(rest[1:], " \t\n\r")
	if strings.HasPrefix(body, "{") {
		body = strings.TrimLeft(body[1:], " \t\n\r")
	}
	// Body itself must begin with return; a later return elsewhere does not count.
	if !strings.HasPrefix(body, "return") {
		return "", false
	}
	if len(body) > len("return") {
		c := body[len("return")]
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			return "", false
		}
	}
	// The protective return must complete (';' or closing '}') before the first
	// localStorage mutation. A mismatch branch like
	// return localStorage.setItem(...) mutates while evaluating the return
	// expression and is not protective (setItem is already at setIdx, so head
	// ends before that call and the return never completes in head).
	retTail := body[len("return"):]
	completed := false
	for i := 0; i < len(retTail); i++ {
		switch retTail[i] {
		case ';', '}':
			completed = true
		}
		if completed {
			break
		}
	}
	if !completed {
		return "", false
	}
	if err := ValidateStorageOrigin(origin); err != nil {
		return "", false
	}
	return origin, true
}

func firstJSONStringLiteralSpan(s string) (string, int, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] != '"' {
			continue
		}
		for end := i + 1; end < len(s); end++ {
			var out string
			if err := json.Unmarshal([]byte(s[i:end+1]), &out); err == nil {
				return out, end + 1, true
			}
		}
	}
	return "", 0, false
}

func (f *fakeCDPTargetServer) addUnrelatedPage(origin string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextSeq++
	id := fmt.Sprintf("unrelated-%d", f.nextSeq)
	f.targets[id] = &targetFixture{
		id:         id,
		targetType: "page",
		url:        origin + "/",
		wsPath:     "/devtools/page/" + id,
		origin:     origin,
	}
	return id
}

func (f *fakeCDPTargetServer) openTargets() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var ids []string
	for id, tg := range f.targets {
		if !tg.closed {
			ids = append(ids, id)
		}
	}
	return ids
}

func (f *fakeCDPTargetServer) originForTarget(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	tg := f.targets[id]
	if tg == nil {
		return ""
	}
	return tg.origin
}

func (f *fakeCDPTargetServer) keysForTarget(id string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	tg := f.targets[id]
	if tg == nil {
		return nil
	}
	out := make([]string, len(tg.keys))
	copy(out, tg.keys)
	return out
}

// setTargetURL rebinds a target's listed URL/origin after bootstrap, so ownership
// revalidation can be tested without starting a real browser.
func (f *fakeCDPTargetServer) setTargetURL(id, url string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	tg := f.targets[id]
	if tg == nil {
		return
	}
	tg.url = url
	if o, ok := originOf(url); ok {
		tg.origin = o
	} else {
		tg.origin = url
	}
}

// setDriftOriginAfterReady schedules a document-origin change immediately after
// the next ready-state evaluate for this target.
func (f *fakeCDPTargetServer) setDriftOriginAfterReady(id, origin string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	tg := f.targets[id]
	if tg == nil {
		return
	}
	tg.driftOriginAfterReady = origin
}

// setEmitEmptyType forces /json/list to report an explicit empty type for id.
func (f *fakeCDPTargetServer) setEmitEmptyType(id string, empty bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	tg := f.targets[id]
	if tg == nil {
		return
	}
	tg.emitEmptyType = empty
}

func TestOpenStorageOriginsRejectsNonLoopbackBase(t *testing.T) {
	_, err := (&CDP{BaseURL: "http://198.51.100.10:9222"}).OpenStorageOrigins(context.Background(), []string{"https://example.com"})
	if err == nil {
		t.Fatal("non-loopback CDP base must error")
	}
}

func TestOpenStorageOriginsEmptyInputIsNoop(t *testing.T) {
	ids, err := (&CDP{}).OpenStorageOrigins(context.Background(), nil)
	if err != nil {
		t.Fatalf("empty input: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("empty input returned %d IDs, want none", len(ids))
	}
}

func TestValidateTargetIDRejectsLeadingDotIDs(t *testing.T) {
	invalid := []string{".", "..", ".hidden"}
	for _, id := range invalid {
		if err := validateTargetID(id); err == nil {
			t.Fatalf("target ID %q must be rejected", id)
		}
	}
	if err := validateTargetID("target-1"); err != nil {
		t.Fatalf("normal Chrome-style target ID must be accepted: %v", err)
	}
	if err := validateTargetID("A1B2C3D4E5F6"); err != nil {
		t.Fatalf("alphanumeric Chrome-style target ID must be accepted: %v", err)
	}
}

func canonicalStorageOriginAccepted() []string {
	return []string{
		"https://example.com",
		"http://example.com",
		"https://example.com:8443",
		"https://127.0.0.1",
		"https://[::1]",
		"http://example.com:8080",
		// Canonical non-loopback IP literals are valid storage origins.
		// CDP base/WebSocket endpoints remain loopback-only.
		"https://192.0.2.1",
		"https://[2001:db8::1]",
	}
}

func canonicalStorageOriginRejected() []string {
	return []string{
		// credentials
		"https://user:secret@example.com",
		// non-empty path, query, fragment
		"https://example.com/path",
		"https://example.com?x=1",
		"https://example.com#frag",
		"https://example.com/",
		// uppercase scheme and uppercase host
		"HTTPS://example.com",
		"https://EXAMPLE.com",
		// explicit default ports
		"https://example.com:443",
		"http://example.com:80",
		// leading-zero ports
		"https://example.com:0443",
		"http://example.com:080",
		"https://example.com:08443",
		// port 0 and port 65536
		"https://example.com:0",
		"http://example.com:65536",
		// Unicode hostname
		"https://éxample.com",
		// trailing-dot DNS and empty DNS labels
		"https://example.com.",
		"https://example..com",
		"https://.example.com",
		// ambiguous IPv4
		"https://127.0.0.01",
		"https://127.1",
		"https://2130706433",
		"https://0x7f000001",
		"https://256.0.0.1",
		// mixed-label hosts: numeric final label routes WHATWG parsing through IPv4
		"https://foo.123",
		"https://a.0x1",
		// expanded / non-canonical IPv6
		"https://[0:0:0:0:0:0:0:1]",
		// IPv4-mapped IPv6: dotted form can pass netip string equality while
		// Chrome rewrites it; hex form is Chrome-canonical. Reject both to keep
		// the validator exact and conservative.
		"https://[::ffff:127.0.0.1]",
		"https://[::ffff:7f00:1]",
		// IPv6 zone identifiers
		"https://[::1%25eth0]",
		// opaque and non-HTTP(S) origins
		"blob:opaque",
		"file:///etc/passwd",
		"data:text/plain,hello",
		"about:blank",
		"ftp://example.com",
		"not-a-url",
	}
}

func TestValidateStorageOriginExactCanonicalContract(t *testing.T) {
	for _, origin := range canonicalStorageOriginAccepted() {
		if err := ValidateStorageOrigin(origin); err != nil {
			t.Errorf("accepted origin %q rejected: %v", origin, err)
		}
	}
	for _, origin := range canonicalStorageOriginRejected() {
		err := ValidateStorageOrigin(origin)
		if err == nil {
			t.Errorf("rejected origin %q must be rejected", origin)
			continue
		}
		msg := err.Error()
		if strings.Contains(msg, "secret") || strings.Contains(msg, "user") {
			t.Errorf("ValidateStorageOrigin error leaked credential material: %v", err)
		}
		if strings.Contains(msg, origin) {
			t.Errorf("ValidateStorageOrigin error echoed storage origin: %v", err)
		}
	}
}

func TestOpenStorageOriginsRejectsInvalidOrigins(t *testing.T) {
	srv := newFakeCDPTargetServer(t)
	invalid := canonicalStorageOriginRejected()
	for _, origin := range invalid {
		srv.mu.Lock()
		beforeAttempts := srv.newAttempts
		beforeOrigins := len(srv.newOrigins)
		srv.mu.Unlock()

		_, err := (&CDP{BaseURL: srv.srv.URL}).OpenStorageOrigins(context.Background(), []string{origin})
		if err == nil {
			t.Fatalf("origin %q must be rejected", origin)
		}
		msg := err.Error()
		if strings.Contains(msg, "secret") || strings.Contains(msg, "user") {
			t.Fatalf("error leaked credential from origin: %v", err)
		}
		if strings.Contains(msg, origin) {
			t.Fatalf("error leaked storage origin: %v", err)
		}

		srv.mu.Lock()
		afterAttempts := srv.newAttempts
		afterOrigins := len(srv.newOrigins)
		srv.mu.Unlock()
		if afterAttempts != beforeAttempts || afterOrigins != beforeOrigins {
			t.Fatalf("rejected origin %q reached /json/new (attempts %d->%d, origins %d->%d)",
				origin, beforeAttempts, afterAttempts, beforeOrigins, afterOrigins)
		}
	}
}

func TestOpenStorageOriginsAcceptsCanonicalOrigins(t *testing.T) {
	srv := newFakeCDPTargetServer(t)
	accepted := canonicalStorageOriginAccepted()
	// OpenStorageOrigins returns/creates targets in shared canonical sorted
	// order (deduplicated, lexicographic), not fixture declaration order.
	want := []string{
		"http://example.com",
		"http://example.com:8080",
		"https://127.0.0.1",
		"https://192.0.2.1",
		"https://[2001:db8::1]",
		"https://[::1]",
		"https://example.com",
		"https://example.com:8443",
	}
	ids, err := (&CDP{BaseURL: srv.srv.URL}).OpenStorageOrigins(context.Background(), accepted)
	if err != nil {
		t.Fatalf("OpenStorageOrigins accepted set: %v", err)
	}
	if len(ids) != len(want) {
		t.Fatalf("created target count = %d, want %d", len(ids), len(want))
	}
	if len(accepted) != len(want) {
		t.Fatalf("accepted fixture count = %d, want unique sorted count %d", len(accepted), len(want))
	}
	srv.mu.Lock()
	got := append([]string(nil), srv.newOrigins...)
	srv.mu.Unlock()
	if len(got) != len(want) {
		t.Fatalf("new origins = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("new origins[%d] = %q, want %q (full %v)", i, got[i], want[i], got)
		}
	}
}

func TestValidateStorageOriginRejectsUppercaseCompressedIPv6(t *testing.T) {
	if err := ValidateStorageOrigin("https://[2001:DB8::1]"); err == nil {
		t.Fatal("uppercase compressed IPv6 origin must be rejected")
	}
}

func TestFrameWSForTargetIDRetriesAboutBlankUntilCanonicalOrigin(t *testing.T) {
	const (
		targetID = "bootstrap-target"
		origin   = "https://example.com"
	)

	var polls atomic.Int32
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ws := "ws://" + strings.TrimPrefix(srv.URL, "http://") + "/devtools/page/" + targetID
	mux.HandleFunc("/json/list", func(w http.ResponseWriter, r *http.Request) {
		url := "about:blank"
		if polls.Add(1) > 1 {
			url = origin + "/"
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"id":                   targetID,
			"type":                 "page",
			"url":                  url,
			"webSocketDebuggerUrl": ws,
		}})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := (&CDP{BaseURL: srv.URL}).frameWSForTargetID(ctx, targetID, origin)
	if err != nil {
		t.Fatalf("frameWSForTargetID: %v", err)
	}
	if got != ws {
		t.Fatalf("websocket = %q, want loopback websocket %q", got, ws)
	}
	if polls.Load() < 2 {
		t.Fatalf("polls = %d, want retry after about:blank", polls.Load())
	}
}

func TestValidateStorageOriginCanonicalPorts(t *testing.T) {
	for _, origin := range []string{
		"https://example.com:443",
		"http://example.com:80",
		"https://example.com:0443",
		"http://example.com:080",
		"https://example.com:08443",
	} {
		if err := ValidateStorageOrigin(origin); err == nil {
			t.Errorf("noncanonical port in %q must be rejected", origin)
		}
	}
	for _, origin := range []string{"https://example.com:8443", "http://example.com:8080"} {
		if err := ValidateStorageOrigin(origin); err != nil {
			t.Errorf("nondefault port in %q must be accepted: %v", origin, err)
		}
	}
}

// TestOpenStorageOriginsDeduplicatesAndCanonicalSorts proves OpenStorageOrigins
// deduplicates and creates targets in shared canonical lexicographic order
// (matching WriteStorageViaTargets), not caller/first-seen order.
func TestOpenStorageOriginsDeduplicatesAndCanonicalSorts(t *testing.T) {
	srv := newFakeCDPTargetServer(t)
	origins := []string{
		"https://b.example",
		"https://a.example",
		"https://b.example",
		"http://127.0.0.1:9",
	}
	ids, err := (&CDP{BaseURL: srv.srv.URL}).OpenStorageOrigins(context.Background(), origins)
	if err != nil {
		t.Fatalf("OpenStorageOrigins: %v", err)
	}
	if len(ids) != 3 {
		t.Fatalf("created target count = %d, want 3", len(ids))
	}
	srv.mu.Lock()
	got := append([]string(nil), srv.newOrigins...)
	srv.mu.Unlock()
	want := []string{"http://127.0.0.1:9", "https://a.example", "https://b.example"}
	if len(got) != len(want) {
		t.Fatalf("new origins = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("new origins[%d] = %q, want %q (full %v)", i, got[i], want[i], got)
		}
	}
}

func TestOpenStorageOriginsReturnsOnlyCreatedTargetIDs(t *testing.T) {
	srv := newFakeCDPTargetServer(t)
	unrelated := srv.addUnrelatedPage("https://keep.example")
	ids, err := (&CDP{BaseURL: srv.srv.URL}).OpenStorageOrigins(context.Background(), []string{"https://one.example", "https://two.example"})
	if err != nil {
		t.Fatalf("OpenStorageOrigins: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("returned IDs = %v, want 2 created targets", ids)
	}
	for _, id := range ids {
		if id == unrelated {
			t.Fatalf("returned pre-existing unrelated target ID %q", id)
		}
	}
}

func TestOpenStorageOriginsVerifiesTargetOwnership(t *testing.T) {
	const requestedOrigin = "https://requested.example"

	t.Run("pre-existing ID", func(t *testing.T) {
		srv := newFakeCDPTargetServer(t)
		preExisting := srv.addUnrelatedPage(requestedOrigin)
		srv.newResponses = []cdpTarget{{ID: preExisting, Type: "page", URL: requestedOrigin + "/"}}

		ids, err := (&CDP{BaseURL: srv.srv.URL}).OpenStorageOrigins(context.Background(), []string{requestedOrigin})
		if err == nil {
			t.Fatalf("pre-existing target ID was accepted: %v", ids)
		}
		if len(ids) != 0 {
			t.Fatalf("pre-existing target returned as owned: %v", ids)
		}
		srv.mu.Lock()
		closed := append([]string(nil), srv.closedIDs...)
		srv.mu.Unlock()
		if len(closed) != 0 {
			t.Fatalf("pre-existing target was closed: %v", closed)
		}
		if strings.Contains(err.Error(), preExisting) || strings.Contains(err.Error(), requestedOrigin) {
			t.Fatalf("ownership error leaked target or origin: %v", err)
		}
	})

	t.Run("wrong type", func(t *testing.T) {
		srv := newFakeCDPTargetServer(t)
		const targetID = "worker-target"
		srv.newResponses = []cdpTarget{{ID: targetID, Type: "service_worker", URL: requestedOrigin + "/"}}

		ids, err := (&CDP{BaseURL: srv.srv.URL}).OpenStorageOrigins(context.Background(), []string{requestedOrigin})
		if err == nil {
			t.Fatalf("non-page target was accepted: %v", ids)
		}
		if len(ids) != 0 {
			t.Fatalf("invalid candidate returned as verified ID after ownership failure: %v", ids)
		}
		srv.mu.Lock()
		closed := append([]string(nil), srv.closedIDs...)
		srv.mu.Unlock()
		if len(closed) != 1 || closed[0] != targetID {
			t.Fatalf("wrong-type newly created target cleanup = %v, want [%s]", closed, targetID)
		}
		if open := srv.openTargets(); len(open) != 0 {
			t.Fatalf("open targets after wrong-type cleanup = %v, want none", open)
		}
		if strings.Contains(err.Error(), targetID) || strings.Contains(err.Error(), requestedOrigin) {
			t.Fatalf("type error leaked target or origin: %v", err)
		}
	})

	t.Run("wrong origin", func(t *testing.T) {
		srv := newFakeCDPTargetServer(t)
		const targetID = "wrong-origin-target"
		const wrongOrigin = "https://other.example"
		srv.newResponses = []cdpTarget{{ID: targetID, Type: "page", URL: wrongOrigin + "/"}}

		ids, err := (&CDP{BaseURL: srv.srv.URL}).OpenStorageOrigins(context.Background(), []string{requestedOrigin})
		if err == nil {
			t.Fatalf("wrong-origin target was accepted: %v", ids)
		}
		if len(ids) != 0 {
			t.Fatalf("invalid candidate returned as verified ID after ownership failure: %v", ids)
		}
		srv.mu.Lock()
		closed := append([]string(nil), srv.closedIDs...)
		srv.mu.Unlock()
		if len(closed) != 1 || closed[0] != targetID {
			t.Fatalf("wrong-origin newly created target cleanup = %v, want [%s]", closed, targetID)
		}
		if open := srv.openTargets(); len(open) != 0 {
			t.Fatalf("open targets after wrong-origin cleanup = %v, want none", open)
		}
		if strings.Contains(err.Error(), targetID) || strings.Contains(err.Error(), wrongOrigin) || strings.Contains(err.Error(), requestedOrigin) {
			t.Fatalf("origin error leaked target or origin: %v", err)
		}
	})

	t.Run("duplicate ID", func(t *testing.T) {
		srv := newFakeCDPTargetServer(t)
		const targetID = "duplicate-target"
		const secondOrigin = "https://second.example"
		srv.newResponses = []cdpTarget{
			{ID: targetID, Type: "page", URL: requestedOrigin + "/"},
			{ID: targetID, Type: "page", URL: secondOrigin + "/"},
		}

		ids, err := (&CDP{BaseURL: srv.srv.URL}).OpenStorageOrigins(context.Background(), []string{requestedOrigin, secondOrigin})
		if err == nil {
			t.Fatalf("duplicate target ID was accepted: %v", ids)
		}
		if len(ids) != 0 {
			t.Fatalf("successful cleanup must return zero IDs on duplicate error, got %v", ids)
		}
		srv.mu.Lock()
		closed := append([]string(nil), srv.closedIDs...)
		srv.mu.Unlock()
		if len(closed) != 1 || closed[0] != targetID {
			t.Fatalf("first owned target cleanup = %v, want [%s]", closed, targetID)
		}
		if open := srv.openTargets(); len(open) != 0 {
			t.Fatalf("open targets after duplicate cleanup = %v, want none", open)
		}
		if strings.Contains(err.Error(), targetID) || strings.Contains(err.Error(), secondOrigin) {
			t.Fatalf("duplicate error leaked target or origin: %v", err)
		}
	})

	t.Run("valid new page", func(t *testing.T) {
		srv := newFakeCDPTargetServer(t)
		const targetID = "valid-new-target"
		srv.newResponses = []cdpTarget{{ID: targetID, Type: "page", URL: requestedOrigin + "/"}}

		ids, err := (&CDP{BaseURL: srv.srv.URL}).OpenStorageOrigins(context.Background(), []string{requestedOrigin})
		if err != nil {
			t.Fatalf("valid new target rejected: %v", err)
		}
		if len(ids) != 1 || ids[0] != targetID {
			t.Fatalf("valid new target IDs = %v, want [%s]", ids, targetID)
		}
	})
}

func TestOpenStorageOriginsRejectsNonLoopbackWebSocket(t *testing.T) {
	srv := newFakeCDPTargetServer(t)
	srv.badWSHost = "198.51.100.10"
	_, err := (&CDP{BaseURL: srv.srv.URL}).OpenStorageOrigins(context.Background(), []string{"https://example.com"})
	if err == nil {
		t.Fatal("non-loopback websocket from /json/new must error")
	}
	if strings.Contains(err.Error(), "198.51.100.10") {
		t.Fatalf("error leaked private websocket host: %v", err)
	}
	srv.mu.Lock()
	closed := append([]string(nil), srv.closedIDs...)
	srv.mu.Unlock()
	if len(closed) != 1 {
		t.Fatalf("closed %d targets after bad websocket, want cleanup of 1 created target: %v", len(closed), closed)
	}
	if open := srv.openTargets(); len(open) != 0 {
		t.Fatalf("open targets after bad websocket = %v, want none left from bootstrap", open)
	}
}

func TestOpenStorageOriginsRequestFailureOmitsOriginAndHostname(t *testing.T) {
	srv := newFakeCDPTargetServer(t)
	baseURL := srv.srv.URL
	origin := "https://example.com"
	srv.srv.Close()
	_, err := (&CDP{BaseURL: baseURL}).OpenStorageOrigins(context.Background(), []string{origin})
	if err == nil {
		t.Fatal("request to stopped CDP server must error")
	}
	msg := err.Error()
	if strings.Contains(msg, origin) {
		t.Fatalf("error leaked storage origin: %q", msg)
	}
	if strings.Contains(msg, "example.com") {
		t.Fatalf("error leaked origin hostname: %q", msg)
	}
}

func TestOpenStorageOriginsHonorsContext(t *testing.T) {
	srv := newFakeCDPTargetServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (&CDP{BaseURL: srv.srv.URL}).OpenStorageOrigins(ctx, []string{"https://example.com"})
	if err == nil {
		t.Fatal("cancelled context must error")
	}
}

func TestOpenStorageOriginsCleansUpOnPartialFailure(t *testing.T) {
	srv := newFakeCDPTargetServer(t)
	srv.failNewOn = 3
	ids, err := (&CDP{BaseURL: srv.srv.URL}).OpenStorageOrigins(context.Background(), []string{
		"https://one.example",
		"https://two.example",
		"https://three.example",
	})
	if err == nil {
		t.Fatal("partial /json/new failure must error")
	}
	if len(ids) != 0 {
		t.Fatalf("successful cleanup must return zero IDs for caller, got %v", ids)
	}
	srv.mu.Lock()
	closed := append([]string(nil), srv.closedIDs...)
	srv.mu.Unlock()
	if len(closed) != 2 {
		t.Fatalf("closed %d targets after partial failure, want cleanup of 2 created targets: %v", len(closed), closed)
	}
	open := srv.openTargets()
	if len(open) != 0 {
		t.Fatalf("open targets after failed open = %v, want none left from bootstrap", open)
	}
}

func TestOpenStorageOriginsReturnsIDsAndCleanupErrorOnPartialFailure(t *testing.T) {
	srv := newFakeCDPTargetServer(t)
	srv.failNewOn = 2
	srv.failCloseCount = 1
	cdp := &CDP{BaseURL: srv.srv.URL}

	ids, err := cdp.OpenStorageOrigins(context.Background(), []string{
		"https://one.example",
		"https://two.example",
	})
	if err == nil {
		t.Fatal("partial create with failed cleanup must error")
	}
	if len(ids) != 1 {
		t.Fatalf("returned IDs after failed cleanup = %v, want the one verified target", ids)
	}
	msg := err.Error()
	if !strings.Contains(msg, "create CDP target returned status 500") {
		t.Fatalf("error omitted create failure: %v", err)
	}
	if !strings.Contains(msg, "close CDP target returned status 500") {
		t.Fatalf("error omitted cleanup failure: %v", err)
	}
	for _, private := range []string{ids[0], "one.example", "two.example"} {
		if strings.Contains(msg, private) {
			t.Fatalf("partial-create error leaked target or origin %q: %v", private, err)
		}
	}

	if err := cdp.CloseTargets(context.Background(), ids); err != nil {
		t.Fatalf("caller retry of returned IDs: %v", err)
	}
	if open := srv.openTargets(); len(open) != 0 {
		t.Fatalf("open targets after caller retry = %v, want none", open)
	}
}

// TestOpenStorageOriginsPartialCleanupReturnsOnlyUnclosedIDs owns two safe
// targets, then fails create on a third. Deferred cleanup closes one owned ID
// and fails the other; retry IDs must be only the still-open target.
func TestOpenStorageOriginsPartialCleanupReturnsOnlyUnclosedIDs(t *testing.T) {
	srv := newFakeCDPTargetServer(t)
	srv.failNewOn = 3
	srv.failCloseCount = 1
	cdp := &CDP{BaseURL: srv.srv.URL}

	const (
		originOne   = "https://one.example"
		originTwo   = "https://two.example"
		originThree = "https://three.example"
	)
	ids, err := cdp.OpenStorageOrigins(context.Background(), []string{
		originOne,
		originTwo,
		originThree,
	})
	if err == nil {
		t.Fatal("partial create with partial cleanup failure must error")
	}

	srv.mu.Lock()
	closedAfterCleanup := append([]string(nil), srv.closedIDs...)
	ownedAttempts := srv.newAttempts
	srv.mu.Unlock()
	if ownedAttempts < 3 {
		t.Fatalf("newAttempts = %d, want at least 3 (two owned + one failed create)", ownedAttempts)
	}
	if len(closedAfterCleanup) != 1 {
		t.Fatalf("successful cleanup closes = %v, want exactly one owned ID closed", closedAfterCleanup)
	}
	closedID := closedAfterCleanup[0]
	open := srv.openTargets()
	if len(open) != 1 {
		t.Fatalf("open targets after partial cleanup = %v, want exactly one still-unclosed owned ID", open)
	}
	unclosedID := open[0]
	if unclosedID == closedID {
		t.Fatalf("unclosed ID %q equals closed ID", unclosedID)
	}

	if len(ids) != 1 || ids[0] != unclosedID {
		t.Fatalf("retry IDs = %v, want only still-unclosed %q (never already-closed %q)", ids, unclosedID, closedID)
	}
	for _, id := range ids {
		if id == closedID {
			t.Fatalf("retry IDs included already-closed %q: %v", closedID, ids)
		}
	}

	msg := err.Error()
	if !strings.Contains(msg, "cleanup CDP targets") {
		t.Fatalf("error omitted cleanup failure wrapper: %v", err)
	}
	if !strings.Contains(msg, "close CDP target returned status 500") {
		t.Fatalf("error omitted close failure: %v", err)
	}
	for _, private := range []string{
		unclosedID, closedID,
		originOne, originTwo, originThree,
		"one.example", "two.example", "three.example",
	} {
		if strings.Contains(msg, private) {
			t.Fatalf("cleanup error leaked %q: %v", private, err)
		}
	}

	if err := cdp.CloseTargets(context.Background(), ids); err != nil {
		t.Fatalf("caller retry of returned IDs: %v", err)
	}
	srv.mu.Lock()
	closedAfterRetry := append([]string(nil), srv.closedIDs...)
	srv.mu.Unlock()
	closedCount := map[string]int{}
	for _, id := range closedAfterRetry {
		closedCount[id]++
	}
	if closedCount[closedID] != 1 {
		t.Fatalf("already-closed ID %q close count = %d, want 1 (no double-close); closedIDs=%v",
			closedID, closedCount[closedID], closedAfterRetry)
	}
	if closedCount[unclosedID] != 1 {
		t.Fatalf("unclosed ID %q close count = %d, want 1 after retry; closedIDs=%v",
			unclosedID, closedCount[unclosedID], closedAfterRetry)
	}
	if open := srv.openTargets(); len(open) != 0 {
		t.Fatalf("open targets after caller retry = %v, want none", open)
	}
}

func TestOpenStorageOriginsBoundsJSONResponses(t *testing.T) {
	t.Run("target list", func(t *testing.T) {
		srv := newFakeCDPTargetServer(t)
		srv.oversizedListResponse = true

		_, err := (&CDP{BaseURL: srv.srv.URL}).OpenStorageOrigins(context.Background(), []string{"https://example.com"})
		if err == nil || !strings.Contains(err.Error(), "response too large") {
			t.Fatalf("oversized target list error = %v, want explicit response-too-large error", err)
		}
		if strings.Contains(err.Error(), "oversized-private-value") {
			t.Fatalf("oversized target list error leaked response content: %v", err)
		}
	})

	t.Run("new target", func(t *testing.T) {
		srv := newFakeCDPTargetServer(t)
		srv.oversizedNewResponse = true

		_, err := (&CDP{BaseURL: srv.srv.URL}).OpenStorageOrigins(context.Background(), []string{"https://example.com"})
		if err == nil || !strings.Contains(err.Error(), "response too large") {
			t.Fatalf("oversized new-target error = %v, want explicit response-too-large error", err)
		}
		if strings.Contains(err.Error(), "oversized-private-value") {
			t.Fatalf("oversized new-target error leaked response content: %v", err)
		}
	})
}

func TestOpenStorageOriginsErrorsOmitSecretsAndPrivateURLs(t *testing.T) {
	srv := newFakeCDPTargetServer(t)
	_, err := (&CDP{BaseURL: srv.srv.URL}).OpenStorageOrigins(context.Background(), []string{"https://alice:topsecret@example.com"})
	if err == nil {
		t.Fatal("credentialed origin must be rejected")
	}
	msg := err.Error()
	if strings.Contains(msg, "topsecret") || strings.Contains(msg, "alice") {
		t.Fatalf("error leaked origin credentials: %q", msg)
	}
}

func TestCloseTargetsRejectsNonLoopbackBase(t *testing.T) {
	err := (&CDP{BaseURL: "http://198.51.100.10:9222"}).CloseTargets(context.Background(), []string{"target-1"})
	if err == nil {
		t.Fatal("non-loopback CDP base must error")
	}
}

func TestCloseTargetsRejectsUnsafeTargetIDs(t *testing.T) {
	srv := newFakeCDPTargetServer(t)
	unsafe := []string{
		"",
		"../json",
		"target/extra",
		"ws://127.0.0.1:1/devtools",
		"target%2Fextra", // percent-encoded slash
		"target extra",   // ASCII whitespace
		"target\\extra",  // backslash
	}
	for _, id := range unsafe {
		if err := (&CDP{BaseURL: srv.srv.URL}).CloseTargets(context.Background(), []string{id}); err == nil {
			t.Fatalf("unsafe target ID %q must be rejected", id)
		}
	}
}

func TestCloseTargetsDeduplicatesIDs(t *testing.T) {
	srv := newFakeCDPTargetServer(t)
	id := srv.addUnrelatedPage("https://dedupe.example")
	if err := (&CDP{BaseURL: srv.srv.URL}).CloseTargets(context.Background(), []string{id, id, id}); err != nil {
		t.Fatalf("CloseTargets: %v", err)
	}
	srv.mu.Lock()
	n := len(srv.closedIDs)
	srv.mu.Unlock()
	if n != 1 {
		t.Fatalf("close called %d times, want 1 after dedupe", n)
	}
}

func TestCloseTargetsClosesOnlySuppliedIDs(t *testing.T) {
	srv := newFakeCDPTargetServer(t)
	keep := srv.addUnrelatedPage("https://keep.example")
	closeMe := srv.addUnrelatedPage("https://drop.example")
	if err := (&CDP{BaseURL: srv.srv.URL}).CloseTargets(context.Background(), []string{closeMe}); err != nil {
		t.Fatalf("CloseTargets: %v", err)
	}
	open := srv.openTargets()
	if len(open) != 1 || open[0] != keep {
		t.Fatalf("open targets = %v, want only %q", open, keep)
	}
}

func TestCloseTargetsEmptyIsNoop(t *testing.T) {
	srv := newFakeCDPTargetServer(t)
	_ = srv.addUnrelatedPage("https://stay.example")
	if err := (&CDP{BaseURL: srv.srv.URL}).CloseTargets(context.Background(), nil); err != nil {
		t.Fatalf("CloseTargets(nil): %v", err)
	}
	if n := len(srv.openTargets()); n != 1 {
		t.Fatalf("open targets after empty close = %d, want 1 untouched page", n)
	}
}

func TestCloseTargetsHonorsContext(t *testing.T) {
	srv := newFakeCDPTargetServer(t)
	id := srv.addUnrelatedPage("https://ctx.example")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (&CDP{BaseURL: srv.srv.URL}).CloseTargets(ctx, []string{id}); err == nil {
		t.Fatal("cancelled context must error")
	}
}

func TestCloseTargetsTransportErrorOmitsBaseAndTargetID(t *testing.T) {
	srv := newFakeCDPTargetServer(t)
	baseURL := srv.srv.URL
	id := srv.addUnrelatedPage("https://example.com")
	srv.srv.Close()
	err := (&CDP{BaseURL: baseURL}).CloseTargets(context.Background(), []string{id})
	if err == nil {
		t.Fatal("request to stopped CDP server must error")
	}
	msg := err.Error()
	if strings.Contains(msg, baseURL) {
		t.Fatalf("error leaked CDP base URL: %q", msg)
	}
	if strings.Contains(msg, id) {
		t.Fatalf("error leaked target ID: %q", msg)
	}

	t.Run("cancelled context", func(t *testing.T) {
		srv := newFakeCDPTargetServer(t)
		baseURL := srv.srv.URL
		id := srv.addUnrelatedPage("https://ctx.example")
		srv.srv.Close()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := (&CDP{BaseURL: baseURL}).CloseTargets(ctx, []string{id})
		if err == nil {
			t.Fatal("cancelled context with stopped server must error")
		}
		msg := err.Error()
		if strings.Contains(msg, baseURL) {
			t.Fatalf("error leaked CDP base URL: %q", msg)
		}
		if strings.Contains(msg, id) {
			t.Fatalf("error leaked target ID: %q", msg)
		}
	})
}

func TestMultiOriginWriteStorageViaFramesAfterOpenStorageOrigins(t *testing.T) {
	srv := newFakeCDPTargetServer(t)
	originA := "https://a.example"
	originB := "https://b.example"
	cdp := &CDP{BaseURL: srv.srv.URL}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ids, err := cdp.OpenStorageOrigins(ctx, []string{originA, originB})
	if err != nil {
		t.Fatalf("OpenStorageOrigins: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("created %d bootstrap targets, want 2", len(ids))
	}

	written, err := cdp.WriteStorageViaFrames(ctx, []webstorage.Item{
		{Origin: originA, Key: "only-a", Value: "va"},
		{Origin: originB, Key: "only-b", Value: "vb"},
		{Origin: originA, Key: "also-a", Value: "va2"},
	})
	if err != nil {
		t.Fatalf("WriteStorageViaFrames: %v", err)
	}
	if written != 3 {
		t.Fatalf("written = %d, want 3 items across both origins", written)
	}

	keysByTarget := map[string][]string{}
	for _, id := range ids {
		keysByTarget[id] = srv.keysForTarget(id)
	}
	assertKeys := func(targetID, origin string, wantKeys []string) {
		t.Helper()
		got := keysByTarget[targetID]
		if len(got) != len(wantKeys) {
			t.Fatalf("target %q (%s) keys = %v, want %v", targetID, origin, got, wantKeys)
		}
		for i, want := range wantKeys {
			if got[i] != want {
				t.Fatalf("target %q (%s) keys[%d] = %q, want %q (full %v)", targetID, origin, i, got[i], want, got)
			}
		}
	}
	for _, id := range ids {
		switch srv.originForTarget(id) {
		case originA:
			assertKeys(id, originA, []string{"only-a", "also-a"})
		case originB:
			assertKeys(id, originB, []string{"only-b"})
		default:
			t.Fatalf("unexpected bootstrap origin on target %q", id)
		}
	}
}

// TestWriteStorageViaTargetsBindsHydrationToOpenStorageOriginsIDs pins the
// wished-for WriteStorageViaTargets(ctx, items, targetIDs) contract used by
// headless restore. Pairing uses canonical sorted item-origin order with
// targetIDs in OpenStorageOrigins return order. Before seedFrame, the method must validate
// count and each safe target ID, retry target-list readiness like
// frameWSForOrigin, and require exact target ID, page type, exact origin, and a
// loopback websocket URL. Same-origin unrelated pages must receive no keys.
func TestWriteStorageViaTargetsBindsHydrationToOpenStorageOriginsIDs(t *testing.T) {
	srv := newFakeCDPTargetServer(t)
	const (
		originA = "https://a.example"
		originB = "https://b.example"
	)
	unrelated := srv.addUnrelatedPage(originA)
	cdp := &CDP{BaseURL: srv.srv.URL}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ids, err := cdp.OpenStorageOrigins(ctx, []string{originA, originB})
	if err != nil {
		t.Fatalf("OpenStorageOrigins: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("created %d bootstrap targets, want 2", len(ids))
	}
	for _, id := range ids {
		if id == unrelated {
			t.Fatalf("OpenStorageOrigins returned pre-existing unrelated target %q", id)
		}
	}

	// Distinct item-origin order is originA then originB; pair with OpenStorageOrigins IDs.
	items := []webstorage.Item{
		{Origin: originA, Key: "only-a", Value: "va"},
		{Origin: originB, Key: "only-b", Value: "vb"},
		{Origin: originA, Key: "also-a", Value: "va2"},
	}
	written, err := cdp.WriteStorageViaTargets(ctx, items, ids)
	if err != nil {
		t.Fatalf("WriteStorageViaTargets: %v", err)
	}
	if written != 3 {
		t.Fatalf("written = %d, want 3", written)
	}

	assertKeys := func(targetID string, wantKeys []string) {
		t.Helper()
		got := srv.keysForTarget(targetID)
		if len(got) != len(wantKeys) {
			t.Fatalf("target keys = %v, want %v", got, wantKeys)
		}
		for i, want := range wantKeys {
			if got[i] != want {
				t.Fatalf("target keys[%d] = %q, want %q (full %v)", i, got[i], want, got)
			}
		}
	}
	for _, id := range ids {
		switch srv.originForTarget(id) {
		case originA:
			assertKeys(id, []string{"only-a", "also-a"})
		case originB:
			assertKeys(id, []string{"only-b"})
		default:
			t.Fatalf("unexpected bootstrap origin on target")
		}
	}
	if got := srv.keysForTarget(unrelated); len(got) != 0 {
		t.Fatalf("unrelated same-origin target received keys %v, want none", got)
	}
}

// TestWriteStorageViaTargetsRevalidatesTargetOriginOwnership proves mismatched
// target/origin pairing errors before any wrong-target seed, and that errors omit
// origin URLs and target IDs.
func TestWriteStorageViaTargetsRevalidatesTargetOriginOwnership(t *testing.T) {
	const (
		originA = "https://a.example"
		originB = "https://b.example"
	)
	items := []webstorage.Item{
		{Origin: originA, Key: "only-a", Value: "va"},
		{Origin: originB, Key: "only-b", Value: "vb"},
	}

	t.Run("swapped target IDs", func(t *testing.T) {
		srv := newFakeCDPTargetServer(t)
		cdp := &CDP{BaseURL: srv.srv.URL}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		ids, err := cdp.OpenStorageOrigins(ctx, []string{originA, originB})
		if err != nil {
			t.Fatalf("OpenStorageOrigins: %v", err)
		}
		if len(ids) != 2 {
			t.Fatalf("created %d bootstrap targets, want 2", len(ids))
		}
		swapped := []string{ids[1], ids[0]}
		written, err := cdp.WriteStorageViaTargets(ctx, items, swapped)
		if err == nil {
			t.Fatalf("swapped target IDs must error, wrote %d", written)
		}
		if written != 0 {
			t.Fatalf("wrote %d before ownership error, want 0", written)
		}
		msg := err.Error()
		for _, private := range []string{ids[0], ids[1], originA, originB, "a.example", "b.example"} {
			if strings.Contains(msg, private) {
				t.Fatalf("ownership error leaked %q: %v", private, err)
			}
		}
		for _, id := range ids {
			if got := srv.keysForTarget(id); len(got) != 0 {
				t.Fatalf("target received keys %v after mismatch, want none", got)
			}
		}
	})

	t.Run("target current origin differs", func(t *testing.T) {
		srv := newFakeCDPTargetServer(t)
		cdp := &CDP{BaseURL: srv.srv.URL}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		ids, err := cdp.OpenStorageOrigins(ctx, []string{originA, originB})
		if err != nil {
			t.Fatalf("OpenStorageOrigins: %v", err)
		}
		if len(ids) != 2 {
			t.Fatalf("created %d bootstrap targets, want 2", len(ids))
		}
		const drifted = "https://other.example"
		srv.setTargetURL(ids[0], drifted+"/")
		written, err := cdp.WriteStorageViaTargets(ctx, items, ids)
		if err == nil {
			t.Fatalf("drifted target origin must error, wrote %d", written)
		}
		if written != 0 {
			t.Fatalf("wrote %d before ownership error, want 0", written)
		}
		msg := err.Error()
		for _, private := range []string{ids[0], ids[1], originA, originB, drifted, "a.example", "b.example", "other.example"} {
			if strings.Contains(msg, private) {
				t.Fatalf("ownership error leaked %q: %v", private, err)
			}
		}
		for _, id := range ids {
			if got := srv.keysForTarget(id); len(got) != 0 {
				t.Fatalf("target received keys %v after mismatch, want none", got)
			}
		}
	})
}

// TestMutationOriginGuardRequiresMismatchEarlyReturnBeforeSetItem pins the
// fake harness parser to seedFrame's intended guard shape only.
func TestMutationOriginGuardRequiresMismatchEarlyReturnBeforeSetItem(t *testing.T) {
	const origin = "https://a.example"
	accept := `(function(){if(location.origin!=="` + origin + `")return '0';var it=[["k","v"]];var n=0;for(var i=0;i<it.length;i++){try{localStorage.setItem(it[i][0],it[i][1]);n++}catch(e){}}return ''+n;})()`
	want, ok := mutationOriginGuard(accept)
	if !ok || want != origin {
		t.Fatalf("protective mismatch early-return guard: got (%q, %v), want (%q, true)", want, ok, origin)
	}

	rejects := []struct {
		name string
		expr string
	}{
		{
			name: "dead equality comparison",
			expr: `(function(){if(location.origin==="` + origin + `")return '0';localStorage.setItem("k","v");return '1';})()`,
		},
		{
			name: "comparison with no early return",
			expr: `(function(){if(location.origin!=="` + origin + `"){}localStorage.setItem("k","v");return '1';})()`,
		},
		{
			name: "empty mismatch body with unrelated later return",
			expr: `(function(){if(location.origin!=="` + origin + `"){}if(other)return '0';localStorage.setItem("k","v");return '1';})()`,
		},
		{
			name: "guard after setItem",
			expr: `(function(){localStorage.setItem("k","v");if(location.origin!=="` + origin + `")return '0';return '1';})()`,
		},
		{
			name: "loose inequality without strict mismatch",
			expr: `(function(){if(location.origin!="` + origin + `")return '0';localStorage.setItem("k","v");return '1';})()`,
		},
		{
			name: "origin mention without comparison",
			expr: `(function(){var o=location.origin;localStorage.setItem("k","v");return '1';})()`,
		},
		{
			name: "return expression mutates via setItem",
			expr: `(function(){if(location.origin!=="` + origin + `")return localStorage.setItem("k","v");var it=[["k","v"]];var n=0;for(var i=0;i<it.length;i++){try{localStorage.setItem(it[i][0],it[i][1]);n++}catch(e){}}return ''+n;})()`,
		},
	}
	for _, tc := range rejects {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := mutationOriginGuard(tc.expr); ok {
				t.Fatalf("mutationOriginGuard accepted non-protective form, got want=%q", got)
			}
		})
	}
}

// TestWriteStorageViaTargetsMutationOriginGuardBlocksNavigationRace proves that
// after ready-state succeeds, a document-origin drift before the localStorage
// mutation must write zero keys. seedFrame must embed an inline location.origin
// guard in the mutation expression; the fake evaluates that guard semantically.
func TestWriteStorageViaTargetsMutationOriginGuardBlocksNavigationRace(t *testing.T) {
	srv := newFakeCDPTargetServer(t)
	const (
		originA = "https://a.example"
		drifted = "https://drifted.example"
		itemKey = "race-key"
		itemVal = "race-value"
	)
	cdp := &CDP{BaseURL: srv.srv.URL}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ids, err := cdp.OpenStorageOrigins(ctx, []string{originA})
	if err != nil {
		t.Fatalf("OpenStorageOrigins: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("created %d bootstrap targets, want 1", len(ids))
	}
	srv.setDriftOriginAfterReady(ids[0], drifted)

	written, err := cdp.WriteStorageViaTargets(ctx, []webstorage.Item{
		{Origin: originA, Key: itemKey, Value: itemVal},
	}, ids)
	if err != nil {
		msg := err.Error()
		for _, private := range []string{ids[0], originA, drifted, itemKey, itemVal, "a.example", "drifted.example"} {
			if strings.Contains(msg, private) {
				t.Fatalf("mutation race error leaked %q: %v", private, err)
			}
		}
	}
	if written != 0 {
		t.Fatalf("written = %d after origin drift race, want 0", written)
	}
	if got := srv.keysForTarget(ids[0]); len(got) != 0 {
		t.Fatalf("drifted origin received keys %v, want none", got)
	}
	if got := srv.originForTarget(ids[0]); got != drifted {
		t.Fatalf("document origin after race = %q, want drifted origin", got)
	}
}

// TestWriteStorageViaTargetsUsesCanonicalSortedOriginOrder pins pairing to the
// same sorted unique origin order as distinctStorageOrigins/OpenStorageOrigins,
// not item first-seen order. Open receives sorted A,B; items arrive as B,A,B.
func TestWriteStorageViaTargetsUsesCanonicalSortedOriginOrder(t *testing.T) {
	srv := newFakeCDPTargetServer(t)
	const (
		originA = "https://a.example"
		originB = "https://b.example"
	)
	cdp := &CDP{BaseURL: srv.srv.URL}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Canonical sorted origins A,B (a.example < b.example).
	ids, err := cdp.OpenStorageOrigins(ctx, []string{originA, originB})
	if err != nil {
		t.Fatalf("OpenStorageOrigins: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("created %d bootstrap targets, want 2", len(ids))
	}
	if srv.originForTarget(ids[0]) != originA || srv.originForTarget(ids[1]) != originB {
		t.Fatalf("OpenStorageOrigins ID order not sorted A then B")
	}

	// First-seen item order is B,A,B (reversed/interleaved vs sorted A,B).
	items := []webstorage.Item{
		{Origin: originB, Key: "only-b", Value: "vb"},
		{Origin: originA, Key: "only-a", Value: "va"},
		{Origin: originB, Key: "also-b", Value: "vb2"},
	}
	written, err := cdp.WriteStorageViaTargets(ctx, items, ids)
	if err != nil {
		t.Fatalf("WriteStorageViaTargets with interleaved items: %v", err)
	}
	if written != 3 {
		t.Fatalf("written = %d, want 3", written)
	}
	assertKeys := func(targetID string, wantKeys []string) {
		t.Helper()
		got := srv.keysForTarget(targetID)
		if len(got) != len(wantKeys) {
			t.Fatalf("target keys = %v, want %v", got, wantKeys)
		}
		for i, want := range wantKeys {
			if got[i] != want {
				t.Fatalf("target keys[%d] = %q, want %q (full %v)", i, got[i], want, got)
			}
		}
	}
	assertKeys(ids[0], []string{"only-a"})
	assertKeys(ids[1], []string{"only-b", "also-b"})
}

// TestWriteStorageViaTargetsAdjacentUnsortedOpenAndItemsShareCanonicalOrder
// proves OpenStorageOrigins([B,A]) and WriteStorageViaTargets(items B,A,B)
// share one canonical sorted unique origin order so hydration succeeds and
// keys land on the exact A/B target IDs (not first-seen Open order).
func TestWriteStorageViaTargetsAdjacentUnsortedOpenAndItemsShareCanonicalOrder(t *testing.T) {
	srv := newFakeCDPTargetServer(t)
	const (
		originA = "https://a.example"
		originB = "https://b.example"
	)
	cdp := &CDP{BaseURL: srv.srv.URL}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Unsorted Open input: B then A. Return order must still be sorted A,B.
	ids, err := cdp.OpenStorageOrigins(ctx, []string{originB, originA})
	if err != nil {
		t.Fatalf("OpenStorageOrigins: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("created %d bootstrap targets, want 2", len(ids))
	}
	if srv.originForTarget(ids[0]) != originA || srv.originForTarget(ids[1]) != originB {
		t.Fatalf("OpenStorageOrigins IDs must be sorted A then B, got %q then %q",
			srv.originForTarget(ids[0]), srv.originForTarget(ids[1]))
	}

	// Unsorted/interleaved items: B, A, B. Same first-seen mismatch as the
	// sorted-Open sibling test; pairing must still use sorted A,B.
	items := []webstorage.Item{
		{Origin: originB, Key: "only-b", Value: "vb"},
		{Origin: originA, Key: "only-a", Value: "va"},
		{Origin: originB, Key: "also-b", Value: "vb2"},
	}
	written, err := cdp.WriteStorageViaTargets(ctx, items, ids)
	if err != nil {
		t.Fatalf("WriteStorageViaTargets with unsorted Open IDs + interleaved items: %v", err)
	}
	if written != 3 {
		t.Fatalf("written = %d, want 3", written)
	}
	assertKeys := func(targetID string, wantKeys []string) {
		t.Helper()
		got := srv.keysForTarget(targetID)
		if len(got) != len(wantKeys) {
			t.Fatalf("target keys = %v, want %v", got, wantKeys)
		}
		for i, want := range wantKeys {
			if got[i] != want {
				t.Fatalf("target keys[%d] = %q, want %q (full %v)", i, got[i], want, got)
			}
		}
	}
	assertKeys(ids[0], []string{"only-a"})
	assertKeys(ids[1], []string{"only-b", "also-b"})
	// Wrong-target cross-check: A's ID must never hold B keys and vice versa.
	for _, key := range srv.keysForTarget(ids[0]) {
		if key == "only-b" || key == "also-b" {
			t.Fatalf("origin A target received B key %q", key)
		}
	}
	for _, key := range srv.keysForTarget(ids[1]) {
		if key == "only-a" {
			t.Fatalf("origin B target received A key %q", key)
		}
	}
}

// TestOpenStorageOriginsReconciliationListFailureReturnsPossiblyClosedRetryIDs
// proves that when accepted closes lose their HTTP responses and the cleanup
// reconciliation /json/list also fails, OpenStorageOrigins must conservatively
// return the failed owned IDs even though they may already be closed. Retry IDs
// stay scoped to this call's owned targets (never baseline), and errors stay
// generic.
func TestOpenStorageOriginsReconciliationListFailureReturnsPossiblyClosedRetryIDs(t *testing.T) {
	srv := newFakeCDPTargetServer(t)
	unrelated := srv.addUnrelatedPage("https://keep.example")
	srv.failNewOn = 3
	srv.failCloseAfterAcceptCount = 2
	srv.failListOn = 2 // baseline list OK; reconciliation list fails
	cdp := &CDP{BaseURL: srv.srv.URL}

	const (
		originOne   = "https://one.example"
		originTwo   = "https://two.example"
		originThree = "https://three.example"
	)
	ids, err := cdp.OpenStorageOrigins(context.Background(), []string{
		originOne,
		originTwo,
		originThree,
	})
	if err == nil {
		t.Fatal("partial create with lost closes and failed reconciliation must error")
	}
	if len(ids) != 2 {
		t.Fatalf("retry IDs = %v, want the two owned targets (possibly closed)", ids)
	}
	for _, id := range ids {
		if id == unrelated {
			t.Fatalf("retry IDs included baseline/unrelated target %q: %v", unrelated, ids)
		}
	}

	srv.mu.Lock()
	closed := append([]string(nil), srv.closedIDs...)
	listAttempts := srv.listAttempts
	srv.mu.Unlock()
	if listAttempts < 2 {
		t.Fatalf("listAttempts = %d, want at least 2 (baseline + failed reconciliation)", listAttempts)
	}
	if len(closed) != 2 {
		t.Fatalf("accepted-close count = %d, want 2 owned targets closed before HTTP error", len(closed))
	}
	closedSet := map[string]struct{}{}
	for _, id := range closed {
		closedSet[id] = struct{}{}
	}
	for _, id := range ids {
		if _, ok := closedSet[id]; !ok {
			t.Fatalf("returned ID %q was not among accepted-close targets %v (fake knows closed state)", id, closed)
		}
	}
	// Fake-side proof: returned IDs are possibly closed, not certainly open.
	open := srv.openTargets()
	openSet := map[string]struct{}{}
	for _, id := range open {
		openSet[id] = struct{}{}
	}
	if _, ok := openSet[unrelated]; !ok {
		t.Fatalf("baseline unrelated target %q must remain open; open=%v", unrelated, open)
	}
	for _, id := range ids {
		if _, stillOpen := openSet[id]; stillOpen {
			t.Fatalf("accepted-close target %q still open in fake; returned IDs must be possibly-closed", id)
		}
	}

	msg := err.Error()
	if !strings.Contains(msg, "cleanup CDP targets") {
		t.Fatalf("error omitted cleanup failure wrapper: %v", err)
	}
	if !strings.Contains(msg, "close CDP target returned status 500") {
		t.Fatalf("error omitted close failure: %v", err)
	}
	for _, private := range []string{
		unrelated, ids[0], ids[1],
		originOne, originTwo, originThree,
		"one.example", "two.example", "three.example", "keep.example",
		"injected list failure", "injected close loss after accept",
	} {
		if strings.Contains(msg, private) {
			t.Fatalf("cleanup error leaked %q: %v", private, err)
		}
	}
	for _, id := range closed {
		if strings.Contains(msg, id) {
			t.Fatalf("cleanup error leaked closed target ID: %v", err)
		}
	}
}

// TestOpenStorageOriginsCleanupReconcilesAcceptedCloseHTTPError simulates Chrome
// accepting /json/close then losing the HTTP response. Rollback must reconcile
// against a fresh target list so already-closed owned IDs are omitted from the
// retry set and no outer retry/double-close is required.
func TestOpenStorageOriginsCleanupReconcilesAcceptedCloseHTTPError(t *testing.T) {
	srv := newFakeCDPTargetServer(t)
	srv.failNewOn = 3
	srv.failCloseAfterAcceptCount = 2
	cdp := &CDP{BaseURL: srv.srv.URL}

	const (
		originOne   = "https://one.example"
		originTwo   = "https://two.example"
		originThree = "https://three.example"
	)
	ids, err := cdp.OpenStorageOrigins(context.Background(), []string{
		originOne,
		originTwo,
		originThree,
	})
	if err == nil {
		t.Fatal("partial create with lost close responses must error")
	}

	srv.mu.Lock()
	closed := append([]string(nil), srv.closedIDs...)
	srv.mu.Unlock()
	if len(closed) != 2 {
		t.Fatalf("accepted-close count = %d, want 2 owned targets closed before HTTP error", len(closed))
	}
	closedSet := map[string]struct{}{}
	for _, id := range closed {
		closedSet[id] = struct{}{}
	}
	for _, id := range ids {
		if _, wasClosed := closedSet[id]; wasClosed {
			t.Fatalf("retry IDs included already-closed target after reconciliation: %v (closed %v)", ids, closed)
		}
	}
	if len(ids) != 0 {
		t.Fatalf("retry IDs = %v, want none after fresh-list reconciliation of accepted closes", ids)
	}
	if open := srv.openTargets(); len(open) != 0 {
		t.Fatalf("open targets after reconciled cleanup = %v, want none (no outer retry needed)", open)
	}

	msg := err.Error()
	if !strings.Contains(msg, "cleanup CDP targets") {
		t.Fatalf("error omitted cleanup failure wrapper: %v", err)
	}
	for _, private := range []string{
		originOne, originTwo, originThree,
		"one.example", "two.example", "three.example",
	} {
		if strings.Contains(msg, private) {
			t.Fatalf("cleanup error leaked %q: %v", private, err)
		}
	}
	for _, id := range closed {
		if strings.Contains(msg, id) {
			t.Fatalf("cleanup error leaked closed target ID: %v", err)
		}
	}

	// No outer retry: a second CloseTargets pass must not be required and must
	// not double-close already-reconciled IDs.
	srv.mu.Lock()
	closedBefore := len(srv.closedIDs)
	srv.mu.Unlock()
	if err := cdp.CloseTargets(context.Background(), ids); err != nil {
		t.Fatalf("CloseTargets(nil retry set): %v", err)
	}
	srv.mu.Lock()
	closedAfter := append([]string(nil), srv.closedIDs...)
	srv.mu.Unlock()
	if len(closedAfter) != closedBefore {
		t.Fatalf("outer CloseTargets changed closedIDs %d -> %d; double-close or extra close", closedBefore, len(closedAfter))
	}
	counts := map[string]int{}
	for _, id := range closedAfter {
		counts[id]++
	}
	for _, n := range counts {
		if n != 1 {
			t.Fatalf("target close count = %d, want 1 (no double-close)", n)
		}
	}
}

// TestWriteStorageViaTargetsRejectsEmptyTargetType requires exact-ID hydration
// to demand type "page". An owned bootstrap ID re-listed with an explicit empty
// type must error before any seed, write zero, and omit ID/origin from errors.
func TestWriteStorageViaTargetsRejectsEmptyTargetType(t *testing.T) {
	srv := newFakeCDPTargetServer(t)
	const originA = "https://a.example"
	cdp := &CDP{BaseURL: srv.srv.URL}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ids, err := cdp.OpenStorageOrigins(ctx, []string{originA})
	if err != nil {
		t.Fatalf("OpenStorageOrigins: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("created %d bootstrap targets, want 1", len(ids))
	}
	srv.setEmitEmptyType(ids[0], true)

	written, err := cdp.WriteStorageViaTargets(ctx, []webstorage.Item{
		{Origin: originA, Key: "k", Value: "v"},
	}, ids)
	if err == nil {
		t.Fatalf("empty target type must error, wrote %d", written)
	}
	if written != 0 {
		t.Fatalf("wrote %d before empty-type rejection, want 0", written)
	}
	if got := srv.keysForTarget(ids[0]); len(got) != 0 {
		t.Fatalf("empty-type target received keys %v, want none", got)
	}
	msg := err.Error()
	for _, private := range []string{ids[0], originA, "a.example"} {
		if strings.Contains(msg, private) {
			t.Fatalf("empty-type error leaked %q: %v", private, err)
		}
	}
}

func TestCloseTargetsLeavesUnrelatedPagesOpen(t *testing.T) {
	srv := newFakeCDPTargetServer(t)
	unrelated := srv.addUnrelatedPage("https://unrelated.example")
	cdp := &CDP{BaseURL: srv.srv.URL}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	bootstrap, err := cdp.OpenStorageOrigins(ctx, []string{"https://boot.example"})
	if err != nil {
		t.Fatalf("OpenStorageOrigins: %v", err)
	}
	if len(bootstrap) != 1 {
		t.Fatalf("bootstrap targets = %v, want 1", bootstrap)
	}
	if err := cdp.CloseTargets(ctx, bootstrap); err != nil {
		t.Fatalf("CloseTargets: %v", err)
	}
	open := srv.openTargets()
	if len(open) != 1 || open[0] != unrelated {
		t.Fatalf("open targets after bootstrap cleanup = %v, want unrelated page %q", open, unrelated)
	}
}
