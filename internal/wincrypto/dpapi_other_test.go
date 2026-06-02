//go:build !windows

package wincrypto

import "testing"

func TestUnwrapDPAPIUnsupportedOffWindows(t *testing.T) {
	if _, err := UnwrapDPAPI([]byte("x")); err == nil {
		t.Fatal("DPAPI must be unsupported off Windows")
	}
}
