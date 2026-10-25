//go:build windows

package client_test

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ownerOnly is whether the file or directory at path is its owner's alone
// as Windows has it (private): its access list allows nothing to anyone but
// the user running the test, SYSTEM and the local Administrators.
func ownerOnly(path string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if dacl == nil {
		return fmt.Errorf("an empty access list, which allows everyone everything")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) //nolint:gosec // an ACE's SID starts at SidStart
		if !windows.EqualSid(sid, user.User.Sid) && !windows.EqualSid(sid, system) && !windows.EqualSid(sid, admins) {
			return fmt.Errorf("its access list allows %s", sid)
		}
	}
	return nil
}
