package client

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// Dir returns the state directory of the box to use, as the stock recipe
// finds it: $CROSSBOT_HOME if set, otherwise
// ${XDG_CONFIG_HOME:-$HOME/.config}/crossbot/${CROSSBOT_BOX:-default}.
// It is never the working directory, which for a coding agent is a git
// repository.
func Dir() (string, error) {
	if d := os.Getenv("CROSSBOT_HOME"); d != "" {
		return d, nil
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	box := os.Getenv("CROSSBOT_BOX")
	if box == "" {
		box = "default"
	}
	return filepath.Join(base, "crossbot", box), nil
}

// writeFile writes a file with mode 0600 through a temporary file and a
// rename, so a reader never sees half of it.
func writeFile(name string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(name), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck // gone after the rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close() //nolint:errcheck,gosec // the write error wins
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), name)
}

// exists reports whether name exists and is not empty, as the recipe's [ -s ].
func exists(name string) bool {
	fi, err := os.Stat(name)
	return err == nil && fi.Size() > 0
}

// removeIfExists removes name; a file already gone is not an error.
func removeIfExists(name string) error {
	if err := os.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
