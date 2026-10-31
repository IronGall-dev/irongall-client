package protocol

import (
	"cmp"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The header fields of versions (PROTOCOL.md §11.17): every request names its
// client's version in VersionHeader, an answer to a version a deprecation
// covers carries DeprecationHeader (RFC 9745), and one to a version a sunset
// covers SunsetHeader (RFC 8594).
const (
	VersionHeader     = "Dromas-Version"
	DeprecationHeader = "Deprecation"
	SunsetHeader      = "Sunset"
)

// DocumentPath is the server's document, GET /v1/ (PROTOCOL.md §11.18).
const DocumentPath = "/v1/"

// Version is a client's version as a request names it (PROTOCOL.md §11.17):
// SemVer 2.0.0's MAJOR.MINOR.PATCH and an optional pre-release, with no "v"
// and no build metadata. Go's pseudo-versions, with the "v" taken off, are
// such versions: pre-releases of the patch after the release they follow.
type Version struct {
	Major, Minor, Patch uint64
	// Pre is the pre-release, without its hyphen: "" for a release.
	Pre string
}

// versionGrammar is SemVer 2.0.0's version core and pre-release (§2, §9; the
// grammar of semver.org's BNF): numbers with no leading zero, and each
// pre-release identifier alphanumeric with hyphens, a numeric one with no
// leading zero.
var versionGrammar = regexp.MustCompile(`\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?\z`)

// policyGrammar is a version as a policy writes one: MAJOR.MINOR or
// MAJOR.MINOR.PATCH (PROTOCOL.md §11.17).
var policyGrammar = regexp.MustCompile(`\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?\z`)

// errVersion is a value that is not a version of its form. Its words never
// quote the value, which may be a server's or a caller's.
var errVersion = errors.New("not a version of its form")

// ParseVersion reads s as a request's version: SemVer's MAJOR.MINOR.PATCH and
// an optional pre-release, exactly. Anything else, a "v" before it or build
// metadata after it included, or a number past a uint64, is an error.
func ParseVersion(s string) (Version, error) {
	m := versionGrammar.FindStringSubmatch(s)
	if m == nil {
		return Version{}, errVersion
	}
	var v Version
	var err error
	for i, n := range []*uint64{&v.Major, &v.Minor, &v.Patch} {
		if *n, err = strconv.ParseUint(m[i+1], 10, 64); err != nil {
			return Version{}, errVersion
		}
	}
	v.Pre = m[4]
	return v, nil
}

// RequestVersion is the version a server reads a request's Dromas-Version
// as: the value's, or 0.0.0 for a request without the field or with a value
// of another form (PROTOCOL.md §11.17). A value given twice is the caller's
// to join or refuse: this reads one.
func RequestVersion(s string) Version {
	v, err := ParseVersion(s)
	if err != nil {
		return Version{}
	}
	return v
}

// String writes v as a request names it.
func (v Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	return s
}

// Compare orders v and w by SemVer's precedence (§11): -1 when v is before
// w, 0 when they have the same, 1 when v is after. A pre-release is before
// its release; pre-releases compare identifier by identifier, numeric ones
// as numbers and before alphanumeric ones, which compare in ASCII order, and
// a shorter list of equal identifiers is before a longer.
func (v Version) Compare(w Version) int {
	if c := cmp.Or(cmp.Compare(v.Major, w.Major), cmp.Compare(v.Minor, w.Minor), cmp.Compare(v.Patch, w.Patch)); c != 0 {
		return c
	}
	switch {
	case v.Pre == w.Pre:
		return 0
	case v.Pre == "":
		return 1
	case w.Pre == "":
		return -1
	}
	a, b := strings.Split(v.Pre, "."), strings.Split(w.Pre, ".")
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := compareIdentifiers(a[i], b[i]); c != 0 {
			return c
		}
	}
	return cmp.Compare(len(a), len(b))
}

// compareIdentifiers orders two pre-release identifiers (SemVer §11.4).
func compareIdentifiers(a, b string) int {
	an, aerr := strconv.ParseUint(a, 10, 64)
	bn, berr := strconv.ParseUint(b, 10, 64)
	aNum, bNum := numeric(a), numeric(b)
	switch {
	case aNum && bNum:
		if aerr == nil && berr == nil {
			return cmp.Compare(an, bn)
		}
		// Past a uint64: a longer one, with no leading zero, is larger.
		return cmp.Or(cmp.Compare(len(a), len(b)), strings.Compare(a, b))
	case aNum:
		return -1
	case bNum:
		return 1
	}
	return strings.Compare(a, b)
}

// numeric reports whether a pre-release identifier is digits alone.
func numeric(s string) bool { return s != "" && strings.Trim(s, "0123456789") == "" }

// PolicyVersion is a version as a server's policy writes one: MAJOR.MINOR or
// MAJOR.MINOR.PATCH (PROTOCOL.md §11.17), in a floor, a sunset or the latest
// version a server names.
type PolicyVersion struct {
	Major, Minor, Patch uint64
	// HasPatch is set where the patch is written.
	HasPatch bool
}

// ParsePolicyVersion reads s as a policy's version, exactly.
func ParsePolicyVersion(s string) (PolicyVersion, error) {
	m := policyGrammar.FindStringSubmatch(s)
	if m == nil {
		return PolicyVersion{}, errVersion
	}
	var p PolicyVersion
	var err error
	if p.Major, err = strconv.ParseUint(m[1], 10, 64); err != nil {
		return PolicyVersion{}, errVersion
	}
	if p.Minor, err = strconv.ParseUint(m[2], 10, 64); err != nil {
		return PolicyVersion{}, errVersion
	}
	if m[3] != "" {
		if p.Patch, err = strconv.ParseUint(m[3], 10, 64); err != nil {
			return PolicyVersion{}, errVersion
		}
		p.HasPatch = true
	}
	return p, nil
}

// String writes p as the policy writes it.
func (p PolicyVersion) String() string {
	if p.HasPatch {
		return fmt.Sprintf("%d.%d.%d", p.Major, p.Minor, p.Patch)
	}
	return fmt.Sprintf("%d.%d", p.Major, p.Minor)
}

// Release is the version p stands for where versions are ordered, a floor's
// and a sunset's below: MAJOR.MINOR.0 when it writes no patch.
func (p PolicyVersion) Release() Version {
	return Version{Major: p.Major, Minor: p.Minor, Patch: p.Patch}
}

// Below reports whether SemVer orders v before p (Release), as a floor and a
// sunset's below cover a version.
func (p PolicyVersion) Below(v Version) bool { return v.Compare(p.Release()) < 0 }

// Names reports whether v's major, minor and, where p writes one, patch are
// p's own, as a sunset's version covers a version: a pre-release of them
// among them.
func (p PolicyVersion) Names(v Version) bool {
	return v.Major == p.Major && v.Minor == p.Minor && (!p.HasPatch || v.Patch == p.Patch)
}

// Upgrade reports whether p, the latest version a server names, is an upgrade
// for a client of version v (PROTOCOL.md §11.17): the two compared in the
// parts p writes, from the major on, p higher in one of them. Equal in every
// part p writes is no upgrade, whatever v writes past them: 1.5.2 against 1.5
// is none, against 1.5.3 or 1.6 one.
func (p PolicyVersion) Upgrade(v Version) bool {
	c := cmp.Or(cmp.Compare(p.Major, v.Major), cmp.Compare(p.Minor, v.Minor))
	if c == 0 && p.HasPatch {
		c = cmp.Compare(p.Patch, v.Patch)
	}
	return c > 0
}

// The most deprecations, sunsets and capabilities a server's document lists,
// and a reader reads (PROTOCOL.md §11.18): past any, a document breaks its
// form.
const (
	MaxDeprecations = 64
	MaxSunsets      = 64
	MaxCapabilities = 64
)

// capabilityGrammar is a capability's name: 1 to 64 of a–z, 0–9 and _,
// beginning with a letter (PROTOCOL.md §11.18).
var capabilityGrammar = regexp.MustCompile(`\A[a-z][a-z0-9_]{0,63}\z`)

// ServerDocument is GET /v1/, the server's version policy and the
// capabilities it serves (PROTOCOL.md §11.18). Its versions and times are
// strings, as they travel, each held to its form when the document is read
// ([Unmarshal]) or checked ([ServerDocument.Check]). A writer writes both
// lists, empty or not.
type ServerDocument struct {
	// MinVersion is the floor, "" for none.
	MinVersion string `json:"min_version,omitempty"`
	// LatestVersion is the latest version the server names, "" for none.
	LatestVersion string       `json:"latest_version,omitempty"`
	Deprecations  []Scheduled  `json:"deprecations"`
	Sunsets       []Scheduled  `json:"sunsets"`
	Capabilities  []Capability `json:"capabilities"`
	// MaxCertificateLifetime is the longest a certificate the server takes may
	// run, valid-before less valid-after, in seconds (PROTOCOL.md §11.7): from
	// 1 to MaxInteger.
	MaxCertificateLifetime uint64 `json:"max_certificate_lifetime"`
}

// Scheduled is a deprecation or a sunset of versions, and its date: a
// deprecation, a date from which the server deems them deprecated (RFC
// 9745), and a sunset, the date it stops taking them (RFC 8594). It covers
// every version SemVer orders before Below, or every version Version names
// ([PolicyVersion.Names]); exactly one of the two is set. At is its date, a
// time (PROTOCOL.md §2.2).
type Scheduled struct {
	Below   string `json:"below,omitempty"`
	Version string `json:"version,omitempty"`
	At      string `json:"at"`
}

// Capability is one capability of version 1 the server serves, by its name.
type Capability struct {
	Name string `json:"name"`
}

// Check holds d to its form: each version a policy's, each deprecation and
// sunset with exactly one of below and version and its date a time, each
// capability's name of its form, and no more than MaxDeprecations,
// MaxSunsets and MaxCapabilities of each; and to RFC 9745 §4's rule, no
// sunset earlier than a deprecation of the same versions, the same below or
// the same version, written alike (PROTOCOL.md §11.17). It names the member
// that breaks it ([Member]).
func (d *ServerDocument) Check() error {
	for name, v := range map[string]string{"min_version": d.MinVersion, "latest_version": d.LatestVersion} {
		if v != "" {
			if _, err := ParsePolicyVersion(v); err != nil {
				return &memberError{name: name, known: true}
			}
		}
	}
	if len(d.Deprecations) > MaxDeprecations {
		return &memberError{name: "deprecations", known: true}
	}
	if len(d.Sunsets) > MaxSunsets {
		return &memberError{name: "sunsets", known: true}
	}
	for _, s := range append(slices.Clone(d.Deprecations), d.Sunsets...) {
		if _, _, err := s.parse(); err != nil {
			return err
		}
	}
	for _, s := range d.Sunsets {
		_, end, _ := s.parse()
		for _, dep := range d.Deprecations {
			if _, from, _ := dep.parse(); dep.Below == s.Below && dep.Version == s.Version && end.Before(from) {
				return &memberError{name: "sunsets", known: true}
			}
		}
	}
	if len(d.Capabilities) > MaxCapabilities {
		return &memberError{name: "capabilities", known: true}
	}
	if d.MaxCertificateLifetime == 0 || d.MaxCertificateLifetime > MaxInteger {
		return &memberError{name: "max_certificate_lifetime", known: true}
	}
	for _, c := range d.Capabilities {
		if !capabilityGrammar.MatchString(c.Name) {
			return &memberError{name: "name", known: true}
		}
	}
	return nil
}

// checkType is Check, as a read of the document makes it.
func (d *ServerDocument) checkType() error { return d.Check() }

// parse is s's version, as below or as version, and its date, or the member
// that breaks its form.
func (s Scheduled) parse() (PolicyVersion, time.Time, error) {
	if (s.Below == "") == (s.Version == "") {
		return PolicyVersion{}, time.Time{}, &memberError{name: "below", known: true}
	}
	name, v := "below", s.Below
	if s.Version != "" {
		name, v = "version", s.Version
	}
	p, err := ParsePolicyVersion(v)
	if err != nil {
		return PolicyVersion{}, time.Time{}, &memberError{name: name, known: true}
	}
	at, err := ParseTime(s.At)
	if err != nil {
		return PolicyVersion{}, time.Time{}, &memberError{name: "at", known: true}
	}
	return p, at, nil
}

// Covers reports whether s covers v (PROTOCOL.md §11.17). One not of its
// form covers nothing.
func (s Scheduled) Covers(v Version) bool {
	p, _, err := s.parse()
	switch {
	case err != nil:
		return false
	case s.Below != "":
		return p.Below(v)
	}
	return p.Names(v)
}

// SunsetFor is the date an answer to a request of version v carries in
// Sunset: the earliest of the sunsets that cover it, and false where none
// does (PROTOCOL.md §11.17).
func (d *ServerDocument) SunsetFor(v Version) (time.Time, bool) { return earliest(d.Sunsets, v) }

// DeprecationFor is the date an answer to a request of version v carries in
// Deprecation: the earliest of the deprecations that cover it, and false
// where none does (PROTOCOL.md §11.17).
func (d *ServerDocument) DeprecationFor(v Version) (time.Time, bool) {
	return earliest(d.Deprecations, v)
}

// earliest is the earliest date of those of list that cover v.
func earliest(list []Scheduled, v Version) (time.Time, bool) {
	var first time.Time
	found := false
	for _, s := range list {
		_, at, err := s.parse()
		if err != nil || !s.Covers(v) {
			continue
		}
		if !found || at.Before(first) {
			first, found = at, true
		}
	}
	return first, found
}

// Retired reports whether a request of version v is answered 410
// version_retired at the server's clock now: v is below the floor, or a
// sunset that covers it has its date at or before now (PROTOCOL.md §11.17).
func (d *ServerDocument) Retired(v Version, now time.Time) bool {
	if d.MinVersion != "" {
		if p, err := ParsePolicyVersion(d.MinVersion); err == nil && p.Below(v) {
			return true
		}
	}
	at, ok := d.SunsetFor(v)
	return ok && !now.Before(at)
}

// FormatSunset writes t as Sunset carries it, an HTTP-date in its preferred
// form, IMF-fixdate (RFC 8594 §3, RFC 9110 §5.6.7).
func FormatSunset(t time.Time) string { return t.UTC().Format(http.TimeFormat) }

// FormatDeprecation writes t as Deprecation carries it, a Structured Field
// Date, "@" and the Unix time in seconds (RFC 9745 §2.1, RFC 9651 §3.3.7).
func FormatDeprecation(t time.Time) string { return "@" + strconv.FormatInt(t.Unix(), 10) }

// deprecationGrammar is a Deprecation's value: an Item that is a Date, "@"
// and an Integer, an optional "-" and 1 to 15 digits (RFC 9651 §3.3.1,
// §3.3.7), with no parameters.
var deprecationGrammar = regexp.MustCompile(`\A@-?[0-9]{1,15}\z`)

// ParseDeprecation reads a Deprecation's value as RFC 9745 §2.1 writes it,
// a Date, exactly, and false for a value of any other form, which is none
// (PROTOCOL.md §11.17).
func ParseDeprecation(v string) (time.Time, bool) {
	if !deprecationGrammar.MatchString(v) {
		return time.Time{}, false
	}
	n, err := strconv.ParseInt(v[1:], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(n, 0).UTC(), true
}

// ParseSunset reads a Sunset's value as an HTTP-date, in any of the three
// forms RFC 9110 §5.6.7 has a recipient take (http.ParseTime), and false for
// a value of any other form, which is none (PROTOCOL.md §11.17).
func ParseSunset(v string) (time.Time, bool) {
	if v == "" {
		return time.Time{}, false
	}
	t, err := http.ParseTime(v)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}
