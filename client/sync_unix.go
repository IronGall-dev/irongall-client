//go:build unix

package client

import "os"

// syncDir makes a rename in dir durable.
func syncDir(dir string) error {
	if !fsync {
		return nil
	}
	d, err := os.Open(dir) //nolint:gosec // a directory inside the box's own
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		d.Close() //nolint:errcheck,gosec // the sync error wins
		return err
	}
	return d.Close()
}
