package client

import (
	"context"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
)

// Module is this client's module path: the version of it a binary was built
// with is the version every request names ([Version]).
const Module = "github.com/dromas-dev/dromas-client"

// DevelVersion is the version a build that records none names: a build of
// this module's own checkout, Go's "(devel)", or one with no build
// information. A pre-release of 0.0.0, it is below every release.
const DevelVersion = "0.0.0-devel"

// Version is the version this binary names in every request's
// Dromas-Version (PROTOCOL.md §11.17): the version of Module in its build
// information (runtime/debug), the binary's own module's where Module is the
// one built (the dromas command), or the one it depends on otherwise (a
// program that imports this library), without its "v" and without build
// metadata (Go's "+dirty", "+incompatible"). A Go pseudo-version is then a
// SemVer pre-release of the patch after the release it follows. A build that
// records none of these is DevelVersion.
func Version() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return DevelVersion
	}
	v := ""
	if bi.Main.Path == Module {
		v = bi.Main.Version
	} else {
		for _, d := range bi.Deps {
			if d.Path == Module {
				v = d.Version
				if d.Replace != nil {
					v = d.Replace.Version
				}
				break
			}
		}
	}
	return asRequestVersion(v)
}

// asRequestVersion is a Go module version as a request names it: its "v"
// and its build metadata taken off, or DevelVersion for one that is then not
// a version of the request's form, "(devel)" and "" among them.
func asRequestVersion(v string) string {
	v, _, _ = strings.Cut(strings.TrimPrefix(v, "v"), "+")
	if _, err := protocol.ParseVersion(v); err != nil {
		return DevelVersion
	}
	return v
}

// Versions is what the answers a command met said of this client's version
// (PROTOCOL.md §11.17): a deprecation of it, from the Deprecation an answer
// carried, a sunset of it, from the Sunset one carried, and an upgrade, from the latest version the server's document names, read
// at most once a day. Every Mailbox made with the same Options.Versions
// keeps what it met there, so whoever runs the command says it once at its
// end. A Mailbox made with none keeps its own ([Mailbox.Versions]). It is
// safe for concurrent use.
type Versions struct {
	mu         sync.Mutex
	own        string
	now        func() time.Time
	answered   bool // a server answered one of the command's calls
	deprecated time.Time
	sunset     time.Time
	upgrade    string
	read       bool // the command has read the server's document, or tried to
}

// Own is the version this client names in every request.
func (v *Versions) Own() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.own
}

// Sunset is the date of the earliest Sunset an answer the command met
// carried, the date its server stops taking this client's version, and false
// where none carried one of its form.
func (v *Versions) Sunset() (time.Time, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.sunset, !v.sunset.IsZero()
}

// Deprecation is the date of the earliest Deprecation an answer the command
// met carried, from which its server deems this client's version deprecated,
// and whether that date has passed at this client's clock; ok is false where
// none carried one of its form. A date to come says the version will be
// deprecated then (RFC 9745 §2.1).
func (v *Versions) Deprecation() (at time.Time, passed, ok bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.deprecated.IsZero() {
		return time.Time{}, false, false
	}
	now := v.now
	if now == nil {
		now = time.Now
	}
	return v.deprecated, !now().Before(v.deprecated), true
}

// Upgrade is the latest version the server's document names, where the
// command read it and it is an upgrade for this client
// ([protocol.PolicyVersion.Upgrade]), and false otherwise: the document is
// read at most once a day, so this is said at most once a day.
func (v *Versions) Upgrade() (string, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.upgrade, v.upgrade != ""
}

// answer records what an answer's header says of versions: that a server
// answered, its Deprecation, as a Structured Field Date, and its Sunset, as
// an HTTP-date, each where it is of that form (PROTOCOL.md §11.17); anything
// else is none, and nothing of it is kept. Of each, the earliest the command
// met is kept.
func (v *Versions) answer(h http.Header) {
	dep, dok := protocol.ParseDeprecation(h.Get(protocol.DeprecationHeader))
	sun, sok := protocol.ParseSunset(h.Get(protocol.SunsetHeader))
	v.mu.Lock()
	defer v.mu.Unlock()
	v.answered = true
	if dok && (v.deprecated.IsZero() || dep.Before(v.deprecated)) {
		v.deprecated = dep
	}
	if sok && (v.sunset.IsZero() || sun.Before(v.sunset)) {
		v.sunset = sun
	}
}

// Versions is what this mailbox's commands met of its version: Options.Versions,
// where it was given one.
func (b *Mailbox) Versions() *Versions { return b.met }

// documentEvery is how often a mailbox reads its server's document: once a
// day at most (PROTOCOL.md §11.17).
const documentEvery = 24 * time.Hour

// The mailbox's own records of versions, in its state's mailbox bucket:
//
//	deprecation     "<version> <time>": the date the last command that had an answer met in Deprecation, and this client's version then; none where its answers carried none
//	sunset          "<version> <time>": the same, of Sunset
//	document-read   when the mailbox last read its server's document, a time
//	latest          the latest_version that read found; none where it named none
const (
	keyDeprecation  = "deprecation"
	keySunset       = "sunset"
	keyDocumentRead = "document-read"
	keyLatest       = "latest"
)

// recordVersions is the end of every command that holds the mailbox's lock
// (lockedFinished): where the command's calls had an answer, it reads the
// server's document once its last read is a day old (readDocument), and
// keeps in the mailbox's state the deprecation and the sunset its answers
// carried, or none, so that status says them with no call. Nothing it meets fails the command:
// a read that fails is tried again by the next command that has an answer,
// and a fault of the mailbox's state leaves what it held.
func (b *Mailbox) recordVersions(ctx context.Context) {
	m := b.met
	m.mu.Lock()
	answered, tried := m.answered, m.read
	m.mu.Unlock()
	if !answered {
		return
	}
	if !tried && ctx.Err() == nil && b.ended == nil && b.dir != "" {
		b.readDocument(ctx)
	}
	// After the read, whose answer may carry either too.
	m.mu.Lock()
	dated := map[string]time.Time{keyDeprecation: m.deprecated, keySunset: m.sunset}
	m.mu.Unlock()
	_ = b.update(func(s store) error { //nolint:errcheck // a fault leaves what was held, which the next command writes again
		for key, at := range dated {
			value := []byte(nil)
			if !at.IsZero() {
				value = []byte(b.version + " " + at.UTC().Format(protocol.TimeLayout))
			}
			var err error
			switch {
			case string(s.get(bucketMailbox, key)) == string(value):
			case value == nil:
				err = s.del(bucketMailbox, key)
			default:
				err = s.put(bucketMailbox, key, value)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// readDocument reads the server's document, GET /v1/, where the mailbox last
// read it a day ago or more, or never, or at a time its clock has since gone
// back past, and keeps when it read it and the latest version it names. Where
// that version is an upgrade for this client, the command says so
// (Versions.Upgrade). A mailbox that holds its own revocation asks nothing
// (finished). A read that fails, or a document that breaks its form, is no
// read: the next command that has an answer tries again.
func (b *Mailbox) readDocument(ctx context.Context) {
	b.met.mu.Lock()
	b.met.read = true
	b.met.mu.Unlock()
	now := b.now().UTC()
	var last []byte
	if err := b.view(func(s store) error { last = s.get(bucketMailbox, keyDocumentRead); return nil }); err != nil {
		return
	}
	if t, err := protocol.ParseTime(string(last)); err == nil && !now.Before(t) && now.Sub(t) < documentEvery {
		return
	}
	if b.finished() != nil {
		return
	}
	var d protocol.ServerDocument
	if _, err := b.exchange(ctx, http.MethodGet, protocol.DocumentPath, nil, nil, &d); err != nil {
		return
	}
	if err := b.update(func(s store) error {
		if err := s.put(bucketMailbox, keyDocumentRead, []byte(now.Format(protocol.TimeLayout))); err != nil {
			return err
		}
		if d.LatestVersion == "" {
			return s.del(bucketMailbox, keyLatest)
		}
		return s.put(bucketMailbox, keyLatest, []byte(d.LatestVersion))
	}); err != nil {
		return
	}
	if upgrade(d.LatestVersion, b.version) {
		b.met.mu.Lock()
		b.met.upgrade = d.LatestVersion
		b.met.mu.Unlock()
	}
}

// upgrade reports whether latest, a server's latest_version, is an upgrade
// for a client of version own; a value of another form is none.
func upgrade(latest, own string) bool {
	p, err := protocol.ParsePolicyVersion(latest)
	if err != nil {
		return false
	}
	v, err := protocol.ParseVersion(own)
	return err == nil && p.Upgrade(v)
}

// versionsAttention is what status says of versions, from what the mailbox's
// last commands kept, with no call: a deprecation of this client's version
// once its date has passed at the mailbox's clock, a sunset of it, each with
// its date, and an upgrade the server's document named at its last read. A
// deprecation to come is no attention, as it changes no command's exit
// status. What was kept of another version of this client, one since
// upgraded from, is not said.
func (b *Mailbox) versionsAttention() []string {
	var deprecation, sunset, latest []byte
	if err := b.view(func(s store) error {
		deprecation, sunset, latest = s.get(bucketMailbox, keyDeprecation), s.get(bucketMailbox, keySunset), s.get(bucketMailbox, keyLatest)
		return nil
	}); err != nil {
		return nil
	}
	dated := func(kept []byte) (time.Time, bool) {
		v, at, ok := strings.Cut(string(kept), " ")
		if !ok || v != b.version {
			return time.Time{}, false
		}
		t, err := protocol.ParseTime(at)
		return t, err == nil
	}
	var said []string
	if t, ok := dated(deprecation); ok && !b.now().Before(t) {
		said = append(said, DeprecationWords(b.version, t))
	}
	if t, ok := dated(sunset); ok {
		said = append(said, SunsetWords(b.version, t))
	}
	if upgrade(string(latest), b.version) {
		said = append(said, UpgradeWords(b.version, string(latest)))
	}
	return said
}

// SunsetWords say, in this client's own words, that the mailbox's server
// stops taking this client's version, own, at a date (PROTOCOL.md §11.17).
func SunsetWords(own string, at time.Time) string {
	return "the server stops taking this client's version, " + own + ", from " + at.UTC().Format(protocol.TimeLayout) +
		", by the Sunset its last answer carried: upgrade this client, whose calls it refuses as version_retired from then on"
}

// DeprecationWords say, in this client's own words, that the server deems
// this client's version, own, deprecated from a date (RFC 9745 §2.1).
func DeprecationWords(own string, at time.Time) string {
	return "the server deems this client's version, " + own + ", deprecated from " + at.UTC().Format(protocol.TimeLayout) +
		", by the Deprecation its last answer carried: it still takes it, and an upgrade of this client is due"
}

// UpgradeWords say, in this client's own words, that the mailbox's server
// names a later version of this client than own.
func UpgradeWords(own, latest string) string {
	return "the server names " + latest + " as the latest version of this client, above this one, " + own + ": an upgrade is available"
}
