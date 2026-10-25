//go:build !unix && !windows

package client

import "os"

// private is mode 0700 where the system has neither Unix modes nor Windows'
// access lists to hold it: what the system makes of the mode is its own.
func private(dir string) error { return os.Chmod(dir, 0o700) }
