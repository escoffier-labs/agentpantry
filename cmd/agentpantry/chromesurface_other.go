//go:build !windows

package main

import (
	"github.com/escoffier-labs/agentpantry/internal/sink"
	"github.com/escoffier-labs/agentpantry/internal/surface"
	"github.com/escoffier-labs/agentpantry/internal/vault"
)

func newChromeSurface(cookiePath string) (sink.CookieSurface, func() error, error) {
	cs, err := surface.NewChromeStore(cookiePath, &vault.SecretServiceKey{Label: "Chrome Safe Storage"})
	if err != nil {
		return nil, nil, err
	}
	return cs, cs.Close, nil
}
