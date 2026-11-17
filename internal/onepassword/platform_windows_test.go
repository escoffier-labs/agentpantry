package onepassword

import (
	"context"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func secureTokenForTest(path string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
func TestTokenACL(t *testing.T) {
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := secureTokenForTest(p); err != nil {
		t.Fatal(err)
	}
	f, err := openToken(p)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if f, err = openToken(p); err == nil {
		_ = f.Close()
		t.Fatal("world ACL accepted")
	}
}
func TestJobTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"), "/c", "ping -n 30 127.0.0.1 >nul")
	cleanup, err := startProcess(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	start := time.Now()
	if err = cmd.Wait(); err == nil {
		t.Fatal("timeout succeeded")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("job did not terminate")
	}
}
