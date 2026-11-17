package doctor

import (
	"context"
	"errors"
	"github.com/escoffier-labs/agentpantry/internal/onepassword"
	"strings"
	"testing"
)

func TestOnePasswordInventoryDiagnostics(t *testing.T) {
	checks := onePasswordChecks(func(context.Context) (onepassword.Inspection, error) {
		return onepassword.Inspection{VaultItems: 12, TaggedItems: 0, MaxItems: 200, VaultID: "vaultID", Tag: "tag"}, nil
	})
	if len(checks) != 2 || checks[1].Status != Warn || !strings.Contains(checks[0].Detail, "vault item count 12 / max_items 200") || !strings.Contains(checks[1].Detail, "vaultID") {
		t.Fatal(checks)
	}
}
func TestOnePasswordTokenFixDiagnostic(t *testing.T) {
	message := "onepassword: token file rejected: icacls.exe 'fixture' /reset"
	checks := onePasswordChecks(func(context.Context) (onepassword.Inspection, error) {
		return onepassword.Inspection{}, errors.New(message)
	})
	if len(checks) != 1 || checks[0].Status != Fail || checks[0].Detail != message {
		t.Fatal(checks)
	}
}
