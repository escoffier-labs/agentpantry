//go:build !windows

package main

import (
	"github.com/escoffier-labs/agentpantry/internal/config"
	"github.com/escoffier-labs/agentpantry/internal/source"
	"github.com/escoffier-labs/agentpantry/internal/vault"
)

func newChromiumReader(b config.BrowserRef) source.CookieReader {
	return &vault.LinuxChromium{
		Profile:     b.Profile,
		CookiePath:  b.CookiePath,
		KeyProvider: &vault.SecretServiceKey{Label: "Chrome Safe Storage"},
	}
}
