package onepassword

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// FILE_DELETE_CHILD grants deletion of entries in a directory.
const fileDeleteChild = 0x0040

func trustedACL(h windows.Handle, private bool) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fixed("ACL rejected")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fixed("ACL rejected")
	}
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	admins, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	// TrustedInstaller owns system-managed binary directories on standard Windows installs.
	var installer *windows.SID
	if !private {
		installer, _, _, _ = windows.LookupSID("", "NT SERVICE\\TrustedInstaller")
	}
	trusted := func(s *windows.SID) bool {
		return s.Equals(user.User.Sid) || s.Equals(system) || s.Equals(admins) || (!private && installer != nil && s.Equals(installer))
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !trusted(owner) {
		return fixed("ACL owner rejected")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return fixed("ACL rejected")
	}
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &info) != nil {
		return fixed("file rejected")
	}
	return checkACL(acl, private, info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0, trusted)
}

func checkACL(acl *windows.ACL, private, directory bool, trusted func(*windows.SID) bool) error {
	unsafeMask := windows.ACCESS_MASK(fileDeleteChild | windows.FILE_WRITE_DATA | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL)
	if !directory {
		unsafeMask |= windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil {
			return fixed("ACL rejected")
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fixed("ACL rejected")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !trusted(sid) && (private || ace.Mask&unsafeMask != 0) {
			return fixed("ACL rejected")
		}
	}
	return nil
}
func openChecked(path string, private bool) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fixed("path rejected")
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, fixed("file rejected")
	}
	f := os.NewFile(uintptr(h), path)
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = f.Close()
		return nil, fixed("reparse point rejected")
	}
	if err = trustedACL(h, private); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
func openToken(path string) (*os.File, error) {
	f, err := openChecked(path, true)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fixed("token rejected")
	}
	return f, nil
}
func checkBinaryPath(path string) error {
	for {
		f, err := openChecked(path, false)
		if err != nil {
			return err
		}
		_ = f.Close()
		parent := filepath.Dir(path)
		if parent == path {
			break
		}
		path = parent
	}
	return nil
}
func privateDir() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", fixed("ACL rejected")
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return "", fixed("ACL rejected")
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	for range 10 {
		var nonce [16]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return "", fixed("private directory unavailable")
		}
		dir := filepath.Join(os.TempDir(), "agentpantry-op-"+hex.EncodeToString(nonce[:]))
		p, err := windows.UTF16PtrFromString(dir)
		if err != nil {
			return "", err
		}
		err = windows.CreateDirectory(p, &sa)
		if err == windows.ERROR_ALREADY_EXISTS {
			continue
		}
		if err != nil {
			return "", fixed("private directory unavailable")
		}
		return dir, nil
	}
	return "", fixed("private directory unavailable")
}
func tokenFileError(path string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fixed("token file rejected: current user SID unavailable")
	}
	// PowerShell single quotes protect spaces and shell metacharacters in the path.
	p := "'" + strings.ReplaceAll(path, "'", "''") + "'"
	return fmt.Errorf("onepassword: token file rejected: restrict access to the current user in PowerShell: icacls.exe %s /setowner '*%s'; icacls.exe %s /reset; icacls.exe %s /inheritance:r /grant:r '*%s:(F)'", p, user.User.Sid.String(), p, p, user.User.Sid.String())
}
func childEnv(token, dir string) []string {
	return []string{"OP_SERVICE_ACCOUNT_TOKEN=" + token, "OP_CONFIG_DIR=" + dir, "HOME=" + dir, "APPDATA=" + dir, "LOCALAPPDATA=" + dir, "TEMP=" + dir, "TMP=" + dir, "SystemRoot=" + os.Getenv("SystemRoot")}
}
func startProcess(cmd *exec.Cmd) (func(), error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	closeJob := func() { _ = windows.CloseHandle(job) }
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		closeJob()
		return nil, err
	}
	// Suspend before assignment so no descendant can escape the job.
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED}
	cmd.Cancel = func() error { return windows.TerminateJobObject(job, 1) }
	if err = cmd.Start(); err != nil {
		closeJob()
		return nil, err
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_SUSPEND_RESUME, false, uint32(cmd.Process.Pid))
	if err == nil {
		defer windows.CloseHandle(h)
		err = windows.AssignProcessToJobObject(job, h)
		if err == nil {
			resume := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtResumeProcess")
			status, _, _ := resume.Call(uintptr(h))
			if status != 0 {
				err = fixed("process resume failed")
			}
		}
	}
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		closeJob()
		return nil, err
	}
	return closeJob, nil
}
