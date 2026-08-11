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
			if targetType == "" {
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
				value = `{"o":"` + tg.origin + `","r":"complete"}`
			} else if strings.Contains(expr, "localStorage.setItem") {
				keys := extractSetItemKeys(expr)
				if len(keys) > 0 {
					f.mu.Lock()
					tg.keys = append(tg.keys, keys...)
					f.mu.Unlock()
					value = fmt.Sprintf("%d", len(keys))
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

func TestOpenStorageOriginsRejectsInvalidOrigins(t *testing.T) {
	srv := newFakeCDPTargetServer(t)
	invalid := []string{
		"https://user:secret@example.com",
		"https://example.com/path",
		"https://example.com?x=1",
		"https://example.com#frag",
		"https://EXAMPLE.com",
		"blob:opaque",
		"file:///etc/passwd",
		"data:text/plain,hello",
		"about:blank",
		"not-a-url",
	}
	for _, origin := range invalid {
		_, err := (&CDP{BaseURL: srv.srv.URL}).OpenStorageOrigins(context.Background(), []string{origin})
		if err == nil {
			t.Fatalf("origin %q must be rejected", origin)
		}
		if strings.Contains(err.Error(), "secret") {
			t.Fatalf("error leaked credential from origin: %v", err)
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
		if err := validateStorageOrigin(origin); err == nil {
			t.Errorf("noncanonical port in %q must be rejected", origin)
		}
	}
	for _, origin := range []string{"https://example.com:8443", "http://example.com:8080"} {
		if err := validateStorageOrigin(origin); err != nil {
			t.Errorf("nondefault port in %q must be accepted: %v", origin, err)
		}
	}
}

func TestOpenStorageOriginsDeduplicatesPreservesOrder(t *testing.T) {
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
	want := []string{"https://b.example", "https://a.example", "http://127.0.0.1:9"}
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
			t.Fatalf("non-page target returned as owned: %v", ids)
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
			t.Fatalf("wrong-origin target returned as owned: %v", ids)
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
		if len(ids) != 1 || ids[0] != targetID {
			t.Fatalf("verified IDs on duplicate error = %v, want [%s]", ids, targetID)
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
	srv.failNewOn = 2
	_, err := (&CDP{BaseURL: srv.srv.URL}).OpenStorageOrigins(context.Background(), []string{
		"https://one.example",
		"https://two.example",
		"https://three.example",
	})
	if err == nil {
		t.Fatal("partial /json/new failure must error")
	}
	srv.mu.Lock()
	closed := append([]string(nil), srv.closedIDs...)
	srv.mu.Unlock()
	if len(closed) != 1 {
		t.Fatalf("closed %d targets after partial failure, want cleanup of 1 created target: %v", len(closed), closed)
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
