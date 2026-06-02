package cdpvault

import (
	"context"
	"os"
	"testing"
)

// TestRealCDP exercises the reader against a real Chrome DevTools endpoint when
// AGENTPANTRY_CDP_URL is set (e.g. a Chrome launched with --remote-debugging-port).
func TestRealCDP(t *testing.T) {
	url := os.Getenv("AGENTPANTRY_CDP_URL")
	if url == "" {
		t.Skip("set AGENTPANTRY_CDP_URL to a live Chrome DevTools base URL to run")
	}
	c := &CDP{BaseURL: url}
	cs, err := c.ReadCookies(context.Background())
	if err != nil {
		t.Fatalf("ReadCookies against real Chrome: %v", err)
	}
	t.Logf("real CDP export returned %d cookie(s)", len(cs))
}
