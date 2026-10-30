//go:build windows

package client

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

// private makes a directory of the mailbox its owner's alone, as mode 0700 does
// on Unix, where Windows has no modes: a protected access list, so nothing is
// inherited from the directory above, inherited in turn by every file and
// directory made in it, that gives full control to the user running the
// client, to SYSTEM and to the local Administrators, and to no one else.
// Those three are what OpenSSH for Windows takes on a user's key file
// (contrib/win32/win32compat/w32-sshfileperm.c, read 2026-10-25), and the
// other two can take any file on the machine anyway, as root can on Unix.
//
// A directory that already has that list is left as it is, so the files in
// it are not walked again at every open. The list is read back once it is
// set: a volume that keeps no access lists, as FAT does, takes the call and
// keeps nothing, and a mailbox is never made there.
func private(dir string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("the user running the client: %w", err)
	}
	want, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	if ok, err := hasDACL(dir, want); err != nil || ok {
		return err
	}
	dacl, _, err := want.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return err
	}
	ok, err := hasDACL(dir, want)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("its volume keeps no access list, so nothing can make it its owner's alone")
	}
	return nil
}

// hasDACL is whether dir's access list is protected and allows what want's
// allows, entry for entry.
func hasDACL(dir string, want *windows.SECURITY_DESCRIPTOR) (bool, error) {
	got, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	control, _, err := got.Control()
	if err != nil {
		return false, err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return false, nil
	}
	return aces(got.String()) == aces(want.String()), nil
}

// aces is the entries of a security descriptor's text form, without the
// flags before them, which Windows adds to when it keeps a list.
func aces(sddl string) string {
	if i := strings.IndexByte(sddl, '('); i >= 0 {
		return sddl[i:]
	}
	return ""
}
