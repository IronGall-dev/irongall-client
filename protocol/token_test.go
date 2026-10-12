package protocol_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/IronGall-dev/irongall-client/protocol"
)

func TestIsToken(t *testing.T) {
	good := "igt1_" + base64.RawURLEncoding.EncodeToString(make([]byte, 37))
	for name, tc := range map[string]struct {
		in   string
		want bool
	}{
		"a token":                 {good, true},
		"an envelope":             {`{"v":1,"from":"a","to":"b","body":"x"}`, false},
		"empty":                   {"", false},
		"the prefix alone":        {"igt1_", false},
		"another prefix":          {"iga1_" + good[5:], false},
		"one character short":     {good[:len(good)-1], false},
		"one character long":      {good + "A", false},
		"a trailing newline":      {good + "\n", false},
		"a line break inside":     {good[:20] + "\n" + good[21:], false},
		"a line break and 50":     {good[:20] + "\n" + good[20:], false},
		"padding":                 {good + "==", false},
		"the standard alphabet":   {"igt1_" + strings.Repeat("+", 49) + "A", false},
		"bits past the last byte": {good[:len(good)-1] + "B", false},
		"36 bytes":                {"igt1_" + base64.RawURLEncoding.EncodeToString(make([]byte, 36)), false},
		"38 bytes":                {"igt1_" + base64.RawURLEncoding.EncodeToString(make([]byte, 38)), false},
	} {
		if got := protocol.IsToken([]byte(tc.in)); got != tc.want {
			t.Errorf("%s: IsToken(%q) = %v, want %v", name, tc.in, got, tc.want)
		}
	}
}
