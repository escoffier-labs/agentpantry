package surface

import (
	"fmt"
	"os"
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
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("refusing group/world-writable output directory %s", path)
	}
	return nil
}

func writePrivateFile(path string, data []byte) error {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to write symlink %s", path)
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}
