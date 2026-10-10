//go:build !unix

package client

// syncDir is a no-op where a directory cannot be opened to sync it.
func syncDir(string) error { return nil }
