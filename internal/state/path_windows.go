package state

import (
	"golang.org/x/sys/windows"
	"path/filepath"
	"strings"
)

func finalConfigPath(path string) (string, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 512)
	for {
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), 0) // FILE_NAME_NORMALIZED | VOLUME_NAME_DOS
		if err != nil {
			return "", err
		}
		if n < uint32(len(buf)) {
			real := windows.UTF16ToString(buf[:n])
			if strings.HasPrefix(real, `\\?\UNC\`) {
				real = `\\` + strings.TrimPrefix(real, `\\?\UNC\`)
			} else {
				real = strings.TrimPrefix(real, `\\?\`)
			}
			return filepath.Clean(real), nil
		}
		buf = make([]uint16, int(n)+1)
	}
}
