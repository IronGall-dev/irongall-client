// Package agetool gives the tests that run the age command one that reads and
// makes post-quantum files (age >= 1.3): the age on PATH when it can, and
// otherwise the one go.mod names as a tool, at the version this module links,
// which go tool builds into the build cache.
package agetool

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// PQ reports whether the age on PATH makes post-quantum keys. The key goes to
// stdout and is dropped: age-keygen refuses -o on a file that exists,
// /dev/null included, which would make this false on every age.
func PQ() bool { return exec.Command("age-keygen", "-pq").Run() == nil }

// Path is PATH with an age and age-keygen that make post-quantum keys first
// in it: PATH itself when its own do, otherwise the module's tools before it.
// It runs go from the working directory, which must be inside this module.
func Path() (string, error) {
	path := os.Getenv("PATH")
	if PQ() {
		return path, nil
	}
	dirs := make([]string, 0, 3)
	for _, tool := range []string{"age", "age-keygen"} {
		out, err := exec.Command("go", "tool", "-n", tool).Output() //nolint:gosec // one of the two names above
		if err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return "", fmt.Errorf("go tool -n %s: %w: %s", tool, err, bytes.TrimSpace(ee.Stderr))
			}
			return "", fmt.Errorf("go tool -n %s: %w", tool, err)
		}
		dirs = append(dirs, filepath.Dir(strings.TrimSpace(string(out))))
	}
	return strings.Join(append(dirs, path), string(os.PathListSeparator)), nil
}
