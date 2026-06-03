// Package dbcopy copies a (possibly locked) SQLite file to a private temp copy.
package dbcopy

import (
	"io"
	"os"
)

// ToTemp copies src to a fresh 0600 temp file and returns its path plus a
// cleanup closure that removes it. Used to read browser cookie stores without
// contending with a running browser's lock.
func ToTemp(src string) (string, func(), error) {
	in, err := os.Open(src) // #nosec G304 -- browser cookie store path is intentionally operator-selected.
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = in.Close() }()
	tmp, err := os.CreateTemp("", "agentpantry-db-*.sqlite")
	if err != nil {
		return "", nil, err
	}
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", nil, err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return "", nil, err
	}
	return tmp.Name(), func() { _ = os.Remove(tmp.Name()) }, nil
}
