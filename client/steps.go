package client

// A command writes the mailbox in steps, each on disk before the next begins
// (writeFile, a transaction of the state file): a process killed between two
// leaves the mailbox as the first left it, and the next command goes on from
// there. step marks the point just past one, by its name; steps lists them by
// what they are a step of. The crash tests kill a process at each
// (crash_test.go), and a test holds this list to the calls in the code.
var steps = map[string][]string{
	"renewal":    {"renewal begun", "working key made", "prekey made", "statement kept", "renewal taken", "renewal recorded"},
	"revocation": {"revocation published", "revocation kept"},
	"delivery":   {"delivery written", "delivery seen"},
	"refusal":    {"refusal written", "refusal kept"},
	"post":       {"outbox written", "posted", "sent kept"},
	"adoption":   {"lists adopted", "adoption recorded"},
	"heal":       {"ACL read owed", "held ACL kept", "ACL read made"},
	"partial":    {"partial kept", "partial dropped"},
}

// atStep is called at each step with its name: nil but in a test.
var atStep func(name string)

func step(name string) {
	if atStep != nil {
		atStep(name)
	}
}
