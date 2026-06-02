//go:build windows

package main

import (
	"github.com/escoffier-labs/agentpantry/internal/sink"
	"github.com/escoffier-labs/agentpantry/internal/surface"
	"github.com/escoffier-labs/agentpantry/internal/vault"
	"github.com/escoffier-labs/agentpantry/internal/wincrypto"
)

func newChromeSurface(cookiePath string) (sink.CookieSurface, func() error, error) {
	key, err := vault.WindowsChromeKey(cookiePath)
	if err != nil {
		return nil, nil, err
	}
	cs, err := surface.NewChromeStoreEnc(cookiePath, func(v string) ([]byte, error) {
		return wincrypto.EncryptV10GCM(v, key)
	})
	if err != nil {
		return nil, nil, err
	}
	return cs, cs.Close, nil
}
