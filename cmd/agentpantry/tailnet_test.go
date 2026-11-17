package main

import (
	"context"
	"testing"
)

func TestPrepareTailnetRequiresPolicy(t *testing.T) {
	for _, bind := range []string{"tailnet:8787", "tailnet6:8787"} {
		if _, _, e := prepareTailnet(context.Background(), bind, nil); e == nil {
			t.Fatal("resolved bind without policy")
		}
	}
	bind, gate, e := prepareTailnet(context.Background(), "127.0.0.1:8787", nil)
	if e != nil || gate != nil || bind != "127.0.0.1:8787" {
		t.Fatal(bind, e)
	}
}
