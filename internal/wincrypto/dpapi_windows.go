//go:build windows

package wincrypto

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// UnwrapDPAPI turns a DPAPI-wrapped key into the raw AES key via CryptUnprotectData.
func UnwrapDPAPI(wrapped []byte) ([]byte, error) {
	if len(wrapped) == 0 {
		return nil, windows.ERROR_INVALID_PARAMETER
	}
	in := windows.DataBlob{Size: uint32(len(wrapped)), Data: &wrapped[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, 0, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	key := make([]byte, out.Size)
	copy(key, unsafe.Slice(out.Data, out.Size))
	return key, nil
}
