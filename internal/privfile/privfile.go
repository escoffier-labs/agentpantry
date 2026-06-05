// Package privfile writes private (0600) files atomically.
package privfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrSymlink reports that the destination is a symlink; callers can use
// errors.Is to treat a planted symlink as a skip rather than an I/O failure.
var ErrSymlink = errors.New("refusing to write through symlink")

// Write atomically replaces path with data, mode 0600. It refuses to write
// through a symlink, and stages the data in a same-directory temp file that is
// fsynced and renamed into place, so a crash mid-write can never leave path
// truncated or partially written.
func Write(path string, data []byte) error {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrSymlink, path)
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*") // 0600 from birth
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	renamed = true
	return nil
}
