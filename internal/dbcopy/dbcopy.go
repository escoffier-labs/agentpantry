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
	in, err := os.Open(src)
	if err != nil {
		return "", nil, err
	}
	defer in.Close()
	tmp, err := os.CreateTemp("", "agentpantry-db-*.sqlite")
	if err != nil {
		return "", nil, err
	}
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", nil, err
	}
	tmp.Close()
	return tmp.Name(), func() { os.Remove(tmp.Name()) }, nil
}
