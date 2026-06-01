package vault

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/godbus/dbus/v5"
)

var errNoSecret = errors.New("secret not found")

// fallbackWarnOnce ensures the "basic" backend fallback notice is printed at
// most once per process.
var fallbackWarnOnce sync.Once

func warnPeanutsFallback() {
	fallbackWarnOnce.Do(func() {
		fmt.Fprintln(os.Stderr, "agentpantry: browser keyring secret not found via Secret Service; falling back to the 'basic' backend passphrase. If your browser uses gnome-keyring/kwallet, ensure it is running and unlocked.")
	})
}

// SecretServiceKey fetches the browser keyring passphrase via the freedesktop
// Secret Service, falling back to "peanuts" when unavailable.
type SecretServiceKey struct {
	Label string
	// fetch is injectable for testing; nil means use the real D-Bus lookup.
	fetch func(label string) (string, error)
}

func (k *SecretServiceKey) Passphrase() (string, error) {
	f := k.fetch
	if f == nil {
		f = dbusFetch
	}
	secret, err := f(k.Label)
	if err != nil {
		if errors.Is(err, errNoSecret) {
			warnPeanutsFallback()
			return "peanuts", nil
		}
		return "", err
	}
	if secret == "" {
		warnPeanutsFallback()
		return "peanuts", nil
	}
	return secret, nil
}

// dbusFetch searches the Secret Service for a stored item whose label matches.
func dbusFetch(label string) (string, error) {
	conn, err := dbus.SessionBus()
	if err != nil {
		return "", errNoSecret
	}
	svc := conn.Object("org.freedesktop.secrets", "/org/freedesktop/secrets")

	var unlocked, locked []dbus.ObjectPath
	call := svc.Call("org.freedesktop.Secret.Service.SearchItems", 0,
		map[string]string{"application": "chrome", "xdg:schema": "chrome_libsecret_os_crypt_password_v2"})
	if call.Err != nil {
		return "", errNoSecret
	}
	if err := call.Store(&unlocked, &locked); err != nil {
		return "", errNoSecret
	}
	if len(unlocked) == 0 {
		return "", errNoSecret
	}

	// Open a session for plain (unencrypted) secret transfer.
	var output dbus.Variant
	var session dbus.ObjectPath
	if err := svc.Call("org.freedesktop.Secret.Service.OpenSession", 0,
		"plain", dbus.MakeVariant("")).Store(&output, &session); err != nil {
		return "", errNoSecret
	}

	item := conn.Object("org.freedesktop.secrets", unlocked[0])
	var secret struct {
		Session     dbus.ObjectPath
		Parameters  []byte
		Value       []byte
		ContentType string
	}
	if err := item.Call("org.freedesktop.Secret.Item.GetSecret", 0, session).Store(&secret); err != nil {
		return "", errNoSecret
	}
	return string(secret.Value), nil
}
