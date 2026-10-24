package client

import "os"

// syncFile flushes f to the disk, unless the build is a test's (fsync).
func syncFile(f *os.File) error {
	if !fsync {
		return nil
	}
	return f.Sync()
}
