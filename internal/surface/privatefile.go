package surface

import (
	"fmt"
	"os"
	"runtime"
)

func ensureDirNotSymlink(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing directory symlink %s", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	return nil
}

func ensurePrivateDir(path string) error {
	if err := ensureDirNotSymlink(path); err != nil {
		return err
	}
	return os.Chmod(path, 0o700) // #nosec G302 -- directories need execute permission; 0700 is private.
}

func ensureSafeOutputDir(path string) error {
	if err := ensureDirNotSymlink(path); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		// Go synthesizes 0777 for any writable directory on Windows, so the
		// Unix group/world-writable check below would reject every output dir.
		// Access control is ACL-based there; skip the mode check.
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("refusing group/world-writable output directory %s", path)
	}
	return nil
}
