package tailnet

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type replyTransport struct {
	body   string
	status int
}

func (r replyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: r.status, Body: io.NopCloser(strings.NewReader(r.body)), Header: make(http.Header)}, nil
}
func TestLocalClientMalformedWhoIs(t *testing.T) {
	for _, body := range []string{"null", "{}", `{"Node":null}`, `{"Node":{"StableID":5}}`, `{"Node":{"Addresses":["garbage"]}}`, "not json"} {
		t.Run(body, func(t *testing.T) {
			c := &LocalClient{}
			c.Client.Transport = replyTransport{body, 200}
			c.Client.OmitAuth = true
			if _, e := c.WhoIs(context.Background(), "100.100.1.2:1234"); e == nil {
				t.Fatal("malformed response accepted")
			}
		})
	}
}
func TestLocalClientMapping(t *testing.T) {
	c := &LocalClient{}
	c.Client.Transport = replyTransport{`{"Node":{"StableID":"node","Addresses":["100.100.1.2/32"],"Tags":["tag:source"]},"UserProfile":{"ID":123}}`, 200}
	c.Client.OmitAuth = true
	id, e := c.WhoIs(context.Background(), "100.100.1.2:1234")
	if e != nil || id.StableID != "node" || id.UserID != "123" || len(id.Tags) != 1 || len(id.Addresses) != 1 {
		t.Fatal(id, e)
	}
}
func TestLocalClientStatus(t *testing.T) {
	for _, tc := range []struct {
		body string
		code int
		ok   bool
	}{{`{"BackendState":"Running","Self":{"TailscaleIPs":["100.100.1.1"]}}`, 200, true}, {`null`, 200, false}, {`{}`, 200, false}, {`not json`, 200, false}, {`denied`, 403, false}} {
		c := &LocalClient{}
		c.Client.Transport = replyTransport{tc.body, tc.code}
		c.Client.OmitAuth = true
		s, e := c.Status(context.Background())
		if (e == nil) != tc.ok {
			t.Fatal(tc.body, e)
		}
		if tc.ok && (!s.Running || len(s.SelfIPs) != 1) {
			t.Fatal(s)
		}
	}
}
