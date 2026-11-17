package state

import (
	"fmt"
	"os"
	"path/filepath"
)

// Lock holds one config's writer lease. The sibling file is never unlinked:
// unlinking it could let a new inode bypass another process's advisory lock.
type Lock struct{ file *os.File }

func Acquire(path string) (*Lock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := openLock(path + ".lock")
	if err != nil {
		return nil, fmt.Errorf("open source state lock: %w", err)
	}
	if err = lockFile(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("source state %q is already locked or unavailable; another source may be running for this config: %w", path, err)
	}
	return &Lock{f}, nil
}
func (l *Lock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := unlockFile(l.file)
	err := l.file.Close()
	l.file = nil
	if unlockErr != nil {
		return unlockErr
	}
	return err
}
