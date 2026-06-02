package wire

import (
	"encoding/json"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/secret"
)

func TestPayloadRoundTripAndEmpty(t *testing.T) {
	p := Payload{
		Cookies: cookie.Diff{Upserts: []cookie.Cookie{{Host: "a.com", Name: "x", Path: "/", Value: "v"}}},
		Secrets: secret.Diff{Upserts: []secret.Secret{{Name: "gh", Value: "tok"}}},
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var got Payload
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Cookies.Upserts[0].Value != "v" || got.Secrets.Upserts[0].Value != "tok" {
		t.Fatalf("round trip lost data: %+v", got)
	}
	if (Payload{}).IsEmpty() != true {
		t.Fatal("zero payload must be empty")
	}
	if p.IsEmpty() {
		t.Fatal("populated payload must not be empty")
	}
}
