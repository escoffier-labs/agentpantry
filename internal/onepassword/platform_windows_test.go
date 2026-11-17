package onepassword

import (
	"context"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func secureTokenForTest(path string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")")
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

func checkPrivateDirForTest(path string) error {
	f, err := openChecked(path, true)
	if err != nil {
		return err
	}
	defer f.Close()
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fixed("directory DACL not protected")
	}
	return nil
}
func TestDirectoryAppendACL(t *testing.T) {
	trusted := func(s *windows.SID) bool {
		sys, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
		return s.Equals(sys)
	}
	for _, tc := range []struct {
		right              string
		directory, allowed bool
	}{{"0x4", true, true}, {"0x4", false, false}, {"0x2", true, false}, {"0x40", true, false}, {"0x10000", true, false}, {"0x40000", true, false}, {"0x80000", true, false}, {"0x40000000", true, false}, {"0x10000000", true, false}} {
		sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;" + tc.right + ";;;AU)")
		if err != nil {
			t.Fatal(err)
		}
		acl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err = checkACL(acl, false, tc.directory, trusted); (err == nil) != tc.allowed {
			t.Fatalf("right %s directory %v: %v", tc.right, tc.directory, err)
		}
	}
}
func TestTokenReparsePoint(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "token")
	if err := os.WriteFile(target, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := secureTokenForTest(target); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	p, err := windows.UTF16PtrFromString(link)
	if err != nil {
		t.Fatal(err)
	}
	targetP, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.CreateSymbolicLink(p, targetP, 0x2 /* SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE */); err != nil {
		t.Fatal(err)
	}
	if f, err := openChecked(link, true); err == nil {
		f.Close()
		t.Fatal("token reparse point accepted")
	}
}
func TestTokenRemediation(t *testing.T) {
	err := tokenFileError(`C:\fixture's dir\token`)
	if !strings.Contains(err.Error(), `icacls.exe 'C:\fixture''s dir\token' /reset`) || !strings.Contains(err.Error(), "/inheritance:r /grant:r '*S-1-") || !strings.Contains(err.Error(), "/setowner '*S-1-") {
		t.Fatal(err)
	}
}

func TestDefaultWindowsBinaryParents(t *testing.T) {
	for _, dir := range []string{filepath.VolumeName(os.Getenv("SystemRoot")) + `\`, os.Getenv("ProgramFiles")} {
		if dir == "" {
			t.Fatal("standard Windows directory unavailable")
		}
		if err := checkBinaryPath(dir); err != nil {
			t.Fatalf("default binary parent %s: %v", dir, err)
		}
	}
}

func TestInheritanceOnlyACL(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICIIO;FA;;;CO)(A;;FA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	trusted := func(s *windows.SID) bool {
		system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
		return s.Equals(system)
	}
	if err := checkACL(acl, false, true, trusted); err != nil {
		t.Fatal("inheritance-only grant rejected", err)
	}
}
