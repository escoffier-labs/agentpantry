package vault

import "testing"

func TestPeanutsFallback(t *testing.T) {
	p := &SecretServiceKey{Label: "Chrome Safe Storage", fetch: func(string) (string, error) {
		return "", errNoSecret
	}}
	got, err := p.Passphrase()
	if err != nil {
		t.Fatal(err)
	}
	if got != "peanuts" {
		t.Fatalf("want peanuts fallback, got %q", got)
	}
}

func TestSecretServiceReturnsFoundSecret(t *testing.T) {
	p := &SecretServiceKey{Label: "Chrome Safe Storage", fetch: func(string) (string, error) {
		return "real-keyring-secret", nil
	}}
	got, err := p.Passphrase()
	if err != nil {
		t.Fatal(err)
	}
	if got != "real-keyring-secret" {
		t.Fatalf("got %q", got)
	}
}
