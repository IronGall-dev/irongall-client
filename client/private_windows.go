//go:build windows

package client

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// private makes the box's directory its owner's alone, as mode 0700 does on
// Unix, where Windows has no modes: a protected access list, so nothing is
// inherited from the directory above, inherited in turn by every file and
// directory made in it, that gives full control to the user running the
// client, to SYSTEM and to the local Administrators, and to no one else.
// Those three are what OpenSSH for Windows takes on a user's key file
// (contrib/win32/win32compat/w32-sshfileperm.c, read 2026-10-25), and the
// other two can take any file on the machine anyway, as root can on Unix.
func private(dir string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("the user running the client: %w", err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
