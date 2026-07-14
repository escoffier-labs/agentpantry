package wire

import (
	"encoding/json"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/secret"
	"github.com/escoffier-labs/agentpantry/internal/webstorage"
)

func TestPayloadRoundTripAndEmpty(t *testing.T) {
	p := Payload{
		Cookies: cookie.Diff{Upserts: []cookie.Cookie{{Host: "a.com", Name: "x", Path: "/", Value: "v"}}},
		Secrets: secret.Diff{Upserts: []secret.Secret{{Name: "gh", Value: "tok"}}},
		Storage: webstorage.Diff{Upserts: []webstorage.Item{{Origin: "https://a.com", Key: "sess", Value: "ls"}}},
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var got Payload
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Cookies.Upserts[0].Value != "v" || got.Secrets.Upserts[0].Value != "tok" || got.Storage.Upserts[0].Value != "ls" {
		t.Fatalf("round trip lost data: %+v", got)
	}
	if (Payload{}).IsEmpty() != true {
		t.Fatal("zero payload must be empty")
	}
	if p.IsEmpty() {
		t.Fatal("populated payload must not be empty")
	}
}

// A payload carrying only localStorage must not be reported empty.
func TestPayloadStorageOnlyNotEmpty(t *testing.T) {
	p := Payload{Storage: webstorage.Diff{Deletes: []string{"https://a.com\x00k"}}}
	if p.IsEmpty() {
		t.Fatal("storage-only payload must not be empty")
	}
}

// An older source's frame has no "storage" field; a new sink must read it as an
// empty localStorage diff rather than fail.
func TestPayloadBackwardCompatNoStorageField(t *testing.T) {
	oldFrame := []byte(`{"cookies":{"upserts":[{"host":"a.com","name":"x","path":"/","value":"v"}]},"secrets":{}}`)
	var got Payload
	if err := json.Unmarshal(oldFrame, &got); err != nil {
		t.Fatalf("new sink rejected an old frame: %v", err)
	}
	if !got.Storage.IsEmpty() {
		t.Fatalf("missing storage field must decode to empty, got %+v", got.Storage)
	}
	if got.Cookies.Upserts[0].Value != "v" {
		t.Fatal("cookies lost decoding an old frame")
	}
}
