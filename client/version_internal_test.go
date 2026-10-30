package client

import "testing"

// A Go module's version is named as a request names one: its v and its build
// metadata taken off, a pseudo-version a pre-release, and anything else
// DevelVersion (PROTOCOL.md §11.17).
func TestAModulesVersionIsNamedAsARequestNamesOne(t *testing.T) {
	for in, want := range map[string]string{
		"v0.1.8":                               "0.1.8",
		"v0.1.9-0.20261029120000-abcdef123456": "0.1.9-0.20261029120000-abcdef123456",
		"v0.1.8+dirty":                         "0.1.8",
		"v0.1.9-0.20261029120000-abcdef123456+dirty": "0.1.9-0.20261029120000-abcdef123456",
		"(devel)": DevelVersion,
		"":        DevelVersion,
		"v0.1":    DevelVersion,
	} {
		if got := asRequestVersion(in); got != want {
			t.Errorf("%q is named %q, want %q", in, got, want)
		}
	}
}
