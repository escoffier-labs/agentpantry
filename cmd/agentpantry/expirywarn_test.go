package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
)

func TestWarnNearExpiryNamesEachCookie(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	within := 7 * 24 * time.Hour
	cutoff := now.Add(within).Unix()

	cookies := []cookie.Cookie{
		{Host: "claude.ai", Name: "sessionKey", ExpiresUTC: cookie.ExpiresFromUnix(cutoff - 3600)},
		{Host: "github.com", Name: "user_session", ExpiresUTC: cookie.ExpiresFromUnix(cutoff + 3600)}, // outside window
		{Host: "x.com", Name: "auth_token", ExpiresUTC: 0},                                            // session cookie
	}

	var buf bytes.Buffer
	n := warnNearExpiry(&buf, cookies, within, now)
	if n != 1 {
		t.Fatalf("want 1 near-expiry warning, got %d", n)
	}
	out := buf.String()
	if !strings.Contains(out, "sessionKey") || !strings.Contains(out, "claude.ai") {
		t.Fatalf("warning must name the host and cookie: %q", out)
	}
	if !strings.Contains(out, "within 7d") {
		t.Fatalf("warning must state the window: %q", out)
	}
	if strings.Contains(out, "user_session") || strings.Contains(out, "auth_token") {
		t.Fatalf("warning must not name out-of-window or session cookies: %q", out)
	}
	if !strings.Contains(out, "re-auth") {
		t.Fatalf("warning should advise re-auth: %q", out)
	}
}

func TestWarnNearExpirySilentWhenNothingDue(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	within := 24 * time.Hour
	far := cookie.ExpiresFromUnix(now.Add(30 * 24 * time.Hour).Unix())
	var buf bytes.Buffer
	n := warnNearExpiry(&buf, []cookie.Cookie{{Host: "h", Name: "n", ExpiresUTC: far}}, within, now)
	if n != 0 {
		t.Fatalf("want 0 warnings, got %d", n)
	}
	if buf.Len() != 0 {
		t.Fatalf("no cookies due means no output, got %q", buf.String())
	}
}
