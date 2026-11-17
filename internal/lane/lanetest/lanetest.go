// Package lanetest is a fake Chrome DevTools endpoint for tests of the lane
// verifier. It speaks just enough HTTP and websocket to open a tab, answer
// Runtime.evaluate from a script, and record tab closes. It binds to loopback
// and never touches a real browser.
package lanetest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gorilla/websocket"
)

// TabID is the id of the single tab the fake hands out.
const TabID = "ABCDEF0123456789"

// Reply is the body of one Runtime.evaluate response, minus the id. Nil means
// the fake stays silent, simulating a stalled renderer.
type Reply map[string]any

// Eval answers the nth (1-based) Runtime.evaluate call.
type Eval func(n int) Reply

// Server is a fake DevTools endpoint.
type Server struct {
	// URL is the CDP base URL, e.g. http://127.0.0.1:41234.
	URL string

	evals  atomic.Int32
	closes atomic.Int32
	opens  atomic.Int32
	srv    *httptest.Server
}

// Evals is how many Runtime.evaluate calls were received.
func (s *Server) Evals() int { return int(s.evals.Load()) }

// Closes is how many times the tab was closed.
func (s *Server) Closes() int { return int(s.closes.Load()) }

// Opens is how many tabs were opened.
func (s *Server) Opens() int { return int(s.opens.Load()) }

// New starts a fake lane browser that answers Runtime.evaluate through eval.
func New(t *testing.T, eval Eval) *Server {
	t.Helper()
	s := &Server{}
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc("/json/new", func(w http.ResponseWriter, r *http.Request) {
		s.opens.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id":                   TabID,
			"webSocketDebuggerUrl": "ws://" + r.Host + "/devtools/page/" + TabID,
		})
	})
	mux.HandleFunc("/json/close/", func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimPrefix(r.URL.Path, "/json/close/") == TabID {
			s.closes.Add(1)
		}
		_, _ = w.Write([]byte("Target is closing"))
	})
	mux.HandleFunc("/devtools/page/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			var req struct {
				ID int `json:"id"`
			}
			if err := conn.ReadJSON(&req); err != nil {
				return
			}
			reply := eval(int(s.evals.Add(1)))
			if reply == nil {
				continue
			}
			out := map[string]any{"id": req.ID}
			for k, v := range reply {
				out[k] = v
			}
			if err := conn.WriteJSON(out); err != nil {
				return
			}
		}
	})
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	s.URL = s.srv.URL
	return s
}

// Page is a successful Runtime.evaluate reply carrying one page probe.
func Page(title, text string, length int, pageURL string) Reply {
	b, _ := json.Marshal(map[string]any{
		"title": title, "text": text, "len": length, "url": pageURL,
	})
	return Reply{"result": map[string]any{"result": map[string]any{"type": "string", "value": string(b)}}}
}

// Exception is a Runtime.evaluate reply whose script threw.
func Exception() Reply {
	return Reply{"result": map[string]any{
		"result":           map[string]any{"type": "object"},
		"exceptionDetails": map[string]any{"exceptionId": 1, "text": "Uncaught"},
	}}
}

// ContextGone is the CDP error returned while a navigation tears down the
// execution context.
func ContextGone() Reply {
	return Reply{"error": map[string]any{"code": -32000, "message": "Cannot find context with specified id"}}
}

// WithNullException wraps a Page reply with "exceptionDetails": null, which a
// real browser can send alongside a good result.
func WithNullException(r Reply) Reply {
	res := r["result"].(map[string]any)
	res["exceptionDetails"] = nil
	return r
}
