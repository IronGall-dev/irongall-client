//go:build !unix

package revocationserver

import "os"

// flock is nothing where there is no flock: one process to a directory is
// then its operator's to keep.
func flock(*os.File) error { return nil }

// syncDir is nothing where a directory cannot be synced.
func syncDir(string) error { return nil }
