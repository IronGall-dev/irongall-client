package protocol

import (
	"regexp"
	"testing"
)

// oldWords matches "mail" and "box" as words of their own, or as a part of a
// name between underscores or hyphens: what a mailbox holds is a message, and
// where it lands is a mailbox (inbox and outbox are its folders).
var oldWords = regexp.MustCompile(`(?i)(^|[^a-z])(mail|mails|box|boxes)([^a-z]|$)`)

// Every code the API answers, its title, every quota and every subject a
// quota names say message and mailbox, never mail or box.
func TestTheWireSaysMessageAndMailbox(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"held mail", "a box", "box_changed", "mail-headers"} {
		if !oldWords.MatchString(s) {
			t.Fatalf("the reading misses %q", s)
		}
	}
	for _, s := range []string{"mailbox_full", "inbox", "outbox", "no_such_mailbox", "message"} {
		if oldWords.MatchString(s) {
			t.Fatalf("the reading matches %q", s)
		}
	}
	var read int
	for code, c := range codes {
		read++
		for _, w := range []string{string(code), c.title} {
			if oldWords.MatchString(w) {
				t.Errorf("code %s: %q", code, w)
			}
		}
	}
	for q, s := range quotas {
		read++
		for _, w := range []string{string(q), string(s)} {
			if oldWords.MatchString(w) {
				t.Errorf("quota %s: %q", q, w)
			}
		}
	}
	if read < 20 {
		t.Fatalf("read %d codes and quotas", read)
	}
}
