// Package keepass reads named secrets from an encrypted KeePass (.kdbx)
// vault on the source side.
package keepass

import (
	"fmt"
	"io"
	"os"
	"runtime"
)

// maxCredFile bounds credential files (key file or password file). KeePass
// key files are 64 raw bytes or small XML; reject anything implausibly large
// instead of reading it into memory.
const maxCredFile = 1 << 20 // 1 MiB

// loadCredFile reads a KeePass credential file with the same hardening as
// keyfile.Load: the path must resolve to a regular file (a FIFO would block
// on open, so stat first), permissions are checked on the open descriptor
// (non-Windows) so the validated file is provably the file read, and the
// size is capped. Unlike keyfile.Load it returns raw bytes: KeePass key
// files are arbitrary binary or XML, not hex.
func loadCredFile(path string) ([]byte, error) {
	if info, err := os.Stat(path); err != nil {
		return nil, err
	} else if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("credential path %s is not a regular file", path)
	}
	f, err := os.Open(path) // #nosec G304 -- credential path is intentionally operator-selected.
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if runtime.GOOS != "windows" {
		info, err := f.Stat()
		if err != nil {
			return nil, err
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("credential file %s perms %v are too open, want 0600", path, info.Mode().Perm())
		}
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxCredFile+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxCredFile {
		return nil, fmt.Errorf("credential file %s is larger than %d bytes", path, maxCredFile)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("credential file %s is empty", path)
	}
	return raw, nil
}
