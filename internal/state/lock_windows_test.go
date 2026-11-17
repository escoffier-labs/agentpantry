package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestExistingLockRejectsUntrustedACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.state.json")
	lock, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = lock.Close(); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;GR;;;AU)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetNamedSecurityInfo(path+".lock", windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if lock, err = Acquire(path); err == nil {
		lock.Close()
		t.Fatal("pre-existing untrusted lock grants accepted")
	} else if !strings.Contains(err.Error(), "owner/DACL rejected") {
		t.Fatal("unclear ACL diagnostic", err)
	}
}
func TestLockDescriptorOwnerAndAllowedPrincipals(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	for _, owner := range []string{user.User.Sid.String(), "SY", "BA", "WD"} {
		sd, err := windows.SecurityDescriptorFromString("O:" + owner + "D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;SY)(A;;FA;;;BA)")
		if err != nil {
			t.Fatal(err)
		}
		if err = validateLockDescriptor(sd, user.User.Sid); (err == nil) != (owner != "WD") {
			t.Fatal("wrong owner trust result", owner, err)
		}
	}
}
func TestWindowsFinalPathResolvesConfigAlias(t *testing.T) {
	target := fixtureConfig(t)
	alias := filepath.Join(filepath.Dir(target), "alias.toml")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveConfig(alias)
	if err != nil {
		t.Fatal(err)
	}
	want, err := ResolveConfig(target)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("final config path retains alias")
	}
}
