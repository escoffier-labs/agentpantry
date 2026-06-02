//go:build !windows

package wincrypto

import "errors"

// UnwrapDPAPI is unsupported off Windows.
func UnwrapDPAPI(wrapped []byte) ([]byte, error) {
	return nil, errors.New("DPAPI is only available on Windows")
}
