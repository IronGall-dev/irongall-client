package protocol

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// A request's version is SemVer's core and an optional pre-release, exactly:
// no "v", no build metadata, no leading zero, nothing past a uint64. A server
// reads anything else, or nothing, as 0.0.0 (PROTOCOL.md §11.17).
func TestARequestsVersionIsSemVerExactly(t *testing.T) {
	for s, want := range map[string]Version{
		"0.1.8":                               {0, 1, 8, ""},
		"1.0.0-rc.1":                          {1, 0, 0, "rc.1"},
		"0.1.9-0.20261029120000-abcdef123456": {0, 1, 9, "0.20261029120000-abcdef123456"}, // a Go pseudo-version without its v
		"1.0.0-x-y.7.z--":                     {1, 0, 0, "x-y.7.z--"},
		"18446744073709551615.0.0":            {1<<64 - 1, 0, 0, ""},
	} {
		got, err := ParseVersion(s)
		if err != nil || got != want || got.String() != s {
			t.Errorf("%q: %+v %v, written back %q", s, got, err, got.String())
		}
		if RequestVersion(s) != want {
			t.Errorf("a server reads %q as %v", s, RequestVersion(s))
		}
	}
	for _, s := range []string{"", "v0.1.8", "0.1", "0.1.8+dirty", "01.1.8", "0.01.8", "0.1.08", "0.1.8-", "0.1.8-01", "0.1.8-a..b",
		"0.1.8 ", " 0.1.8", "0.1.8\n", "0.1.8-é", "18446744073709551616.0.0", "(devel)", "1.2.3.4", "0.1.8-rc_1"} {
		if v, err := ParseVersion(s); err == nil {
			t.Errorf("%q read as %v", s, v)
		}
		if v := RequestVersion(s); v != (Version{}) {
			t.Errorf("a server reads %q as %v, not 0.0.0", s, v)
		}
	}
}

// Versions are ordered by SemVer's precedence (§11): semver.org's own two
// orderings, each pair of which compares as its place says, in both
// directions.
func TestVersionsAreInSemVersOrder(t *testing.T) {
	for _, order := range [][]string{
		{"1.0.0", "2.0.0", "2.1.0", "2.1.1"},
		{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"},
		{"0.1.8", "0.1.9-0.20261029120000-abcdef123456", "0.1.9", "0.2.0-devel", "0.2.0"},
		{"1.0.0-9", "1.0.0-10", "1.0.0-99999999999999999999", "1.0.0-100000000000000000000", "1.0.0-a"},
	} {
		for i, a := range order {
			for j, b := range order {
				va, vb := RequestVersion(a), RequestVersion(b)
				if va == (Version{}) || vb == (Version{}) {
					t.Fatalf("%q or %q does not read", a, b)
				}
				want := 0
				switch {
				case i < j:
					want = -1
				case i > j:
					want = 1
				}
				if got := va.Compare(vb); got != want {
					t.Errorf("%s against %s: %d, want %d", a, b, got, want)
				}
			}
		}
	}
}

// A policy writes MAJOR.MINOR or MAJOR.MINOR.PATCH, exactly.
func TestAPolicysVersionIsMajorMinorAndAPatch(t *testing.T) {
	for _, s := range []string{"1.5", "1.5.3", "0.0", "0.1.0"} {
		if p, err := ParsePolicyVersion(s); err != nil || p.String() != s {
			t.Errorf("%q: %v %v", s, p, err)
		}
	}
	for _, s := range []string{"", "1", "v1.5", "1.5.3-rc.1", "1.5.3+x", "01.5", "1.05", "1.5.03", "1.5.", "1.5.3.4", " 1.5"} {
		if p, err := ParsePolicyVersion(s); err == nil {
			t.Errorf("%q read as %v", s, p)
		}
	}
}

// The latest version is compared in the parts it writes, from the major on:
// an upgrade only where it is higher in one of them (PROTOCOL.md §11.17).
func TestAnUpgradeIsHigherInAPartTheLatestWrites(t *testing.T) {
	for _, c := range []struct {
		own, latest string
		upgrade     bool
	}{
		{"1.5.2", "1.5", false},
		{"1.5.2", "1.5.2", false},
		{"1.5.2", "1.5.3", true},
		{"1.5.2", "1.6", true},
		{"1.5.2", "2.0", true},
		{"1.5.2", "1.4.9", false},
		{"1.5.2", "1.5.1", false},
		{"1.6.0", "1.5", false},
		{"1.5.3-rc.1", "1.5.3", false}, // equal in every part it writes
		{"1.5.3-rc.1", "1.5", false},
		{"0.0.0-devel", "0.1", true},
		{"2.0.0", "1.9.9", false},
	} {
		p, err := ParsePolicyVersion(c.latest)
		if err != nil {
			t.Fatal(err)
		}
		if got := p.Upgrade(RequestVersion(c.own)); got != c.upgrade {
			t.Errorf("%s against latest %s: upgrade %v, want %v", c.own, c.latest, got, c.upgrade)
		}
	}
}

// A deprecation or a sunset covers every version below it, or every version
// whose parts are the ones it writes; a version is retired below the floor or
// once a sunset that covers it has its date; an answer carries the earliest
// date of those that cover its version (PROTOCOL.md §11.17).
func TestAPolicyCoversItsVersions(t *testing.T) {
	day := func(n int) string { return time.Date(2027, 1, n, 0, 0, 0, 0, time.UTC).Format(TimeLayout) }
	d := ServerDocument{
		MinVersion: "1.2",
		Sunsets: []Scheduled{
			{Below: "1.4", At: day(20)},
			{Version: "1.4", At: day(25)},
			{Version: "1.5.2", At: day(10)},
			{Below: "1.3", At: day(15)},
		},
		Deprecations:           []Scheduled{{Below: "1.4", At: day(1)}, {Version: "1.6", At: day(5)}},
		MaxCertificateLifetime: 45*86400 + 3600,
	}
	if err := d.Check(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		version       string
		sunset        string // "" for none
		deprecation   string
		retiredOnDay1 bool
		retiredDay16  bool
	}{
		{"1.1.9", day(15), day(1), true, true},        // below the floor, below 1.3 and below 1.4: the earliest
		{"1.2.0-rc.1", day(15), day(1), true, true},   // a pre-release is below its release, the floor's 1.2.0
		{"1.2.0", day(15), day(1), false, true},       // at the floor
		{"1.3.9", day(20), day(1), false, false},      // below 1.4 alone
		{"1.4.0-rc.1", day(20), day(1), false, false}, // below 1.4, and version 1.4 names it too: the earliest
		{"1.4.0", day(25), "", false, false},          // version 1.4
		{"1.4.1", day(25), "", false, false},          // version 1.4: it writes no patch
		{"1.5.2", day(10), "", false, true},           // the patch it writes
		{"1.5.2-beta", day(10), "", false, true},      // a pre-release of it
		{"1.5.3", "", "", false, false},               // another patch
		{"1.6.7", "", day(5), false, false},           // deprecated, with no sunset
		{"0.0.0", day(15), day(1), true, true},        // what a request with no version is read as
	} {
		v := RequestVersion(c.version)
		at, ok := d.SunsetFor(v)
		if got := ""; ok {
			got = at.Format(TimeLayout)
			if got != c.sunset {
				t.Errorf("%s: sunset %s, want %q", c.version, got, c.sunset)
			}
		} else if c.sunset != "" {
			t.Errorf("%s: no sunset, want %s", c.version, c.sunset)
		}
		at, ok = d.DeprecationFor(v)
		if ok != (c.deprecation != "") || ok && at.Format(TimeLayout) != c.deprecation {
			t.Errorf("%s: deprecation %v %v, want %q", c.version, at, ok, c.deprecation)
		}
		day1, _ := ParseTime(day(1))
		day16, _ := ParseTime(day(16))
		if d.Retired(v, day1) != c.retiredOnDay1 || d.Retired(v, day16) != c.retiredDay16 {
			t.Errorf("%s: retired on day 1 %v, on day 16 %v", c.version, d.Retired(v, day1), d.Retired(v, day16))
		}
	}
	// A sunset retires a version from its date on, to the second.
	at, _ := ParseTime(day(10))
	if v := RequestVersion("1.5.2"); d.Retired(v, at.Add(-time.Second)) || !d.Retired(v, at) {
		t.Error("a sunset retires its version from the second of its date")
	}
	// With no floor and no sunset, nothing is retired.
	if (&ServerDocument{}).Retired(Version{}, at) {
		t.Error("an empty policy retires 0.0.0")
	}
}

// A document is held to its form as it is read: each version a policy's,
// exactly one of below and version, each date a time, each name of its form,
// no more than 64 of each list, no sunset earlier than a deprecation of the
// same versions (RFC 9745 §4), and the server's maximum certificate lifetime,
// which every document carries, from 1 to MaxInteger seconds.
func TestTheServersDocumentBreaksItsFormAsItSays(t *testing.T) {
	good := `{"min_version":"0.1","latest_version":"0.1.8","deprecations":[{"below":"0.1.5","at":"2027-01-01T00:00:00Z"}],"sunsets":[{"below":"0.1.5","at":"2027-01-01T00:00:00Z"},{"version":"0.1.6","at":"2027-02-01T00:00:00Z"}],"capabilities":[{"name":"long_poll2"}],"max_certificate_lifetime":3891600,"later":1}`
	var d ServerDocument
	if err := Unmarshal([]byte(good), &d); err != nil || d.LatestVersion != "0.1.8" || len(d.Sunsets) != 2 || d.Capabilities[0].Name != "long_poll2" || d.MaxCertificateLifetime != 3891600 {
		t.Fatalf("%+v %v", d, err)
	}
	// withMax is a document's text with a maximum it takes, so that the
	// member a case breaks is the one it names.
	withMax := func(text string) string { return `{"max_certificate_lifetime":1,` + strings.TrimPrefix(text, "{") }
	many := func(list string, n int, item string) string {
		return `{"` + list + `":[` + strings.TrimSuffix(strings.Repeat(item+",", n), ",") + `]}`
	}
	sunset := `{"below":"1.0","at":"2027-01-01T00:00:00Z"}`
	if err := Unmarshal([]byte(withMax(many("sunsets", MaxSunsets, sunset))), &d); err != nil {
		t.Errorf("%d sunsets: %v", MaxSunsets, err)
	}
	for text, member := range map[string]string{
		many("sunsets", MaxSunsets+1, sunset):                                       "sunsets",
		many("deprecations", MaxDeprecations+1, sunset):                             "deprecations",
		many("capabilities", MaxCapabilities+1, `{"name":"a"}`):                     "capabilities",
		`{"min_version":"v1.0"}`:                                                    "min_version",
		`{"latest_version":"1.0.0-rc.1"}`:                                           "latest_version",
		`{"sunsets":[{"at":"2027-01-01T00:00:00Z"}]}`:                               "below",
		`{"sunsets":[{"below":"1.0","version":"1.0","at":"2027-01-01T00:00:00Z"}]}`: "below",
		`{"sunsets":[{"version":"1","at":"2027-01-01T00:00:00Z"}]}`:                 "version",
		`{"sunsets":[{"below":"1.0","at":"2027-01-01"}]}`:                           "at",
		`{"deprecations":[{"below":"1.0"}]}`:                                        "at",
		`{"capabilities":[{"name":"Long"}]}`:                                        "name",
		`{"capabilities":[{"name":"_a"}]}`:                                          "name",
		`{"capabilities":[{"name":"` + strings.Repeat("a", 65) + `"}]}`:             "name",
		`{"deprecations":[{"version":"1.0","at":"2027-02-01T00:00:00Z"}],"sunsets":[{"version":"1.0","at":"2027-01-31T23:59:59Z"}]}`: "sunsets",
	} {
		var d ServerDocument
		err := Unmarshal([]byte(withMax(text)), &d)
		if !errors.Is(err, ErrMemberValue) || Member(err) != member {
			t.Errorf("%s: %v, naming %q, want %q", text, err, Member(err), member)
		}
	}
	// A sunset on its deprecation's date, or of other versions, is no
	// sunset earlier than a deprecation.
	for _, text := range []string{
		`{"deprecations":[{"version":"1.0","at":"2027-02-01T00:00:00Z"}],"sunsets":[{"version":"1.0","at":"2027-02-01T00:00:00Z"}]}`,
		`{"deprecations":[{"version":"1.0","at":"2027-02-01T00:00:00Z"}],"sunsets":[{"below":"1.0","at":"2027-01-01T00:00:00Z"},{"version":"1.0.1","at":"2027-01-01T00:00:00Z"}]}`,
	} {
		var d ServerDocument
		if err := Unmarshal([]byte(withMax(text)), &d); err != nil {
			t.Errorf("%s: %v", text, err)
		}
	}
	// The maximum: from 1 to MaxInteger, and never left out.
	for text, want := range map[string]uint64{
		`{"max_certificate_lifetime":1}`:                1,
		`{"max_certificate_lifetime":9007199254740991}`: MaxInteger,
	} {
		var d ServerDocument
		if err := Unmarshal([]byte(text), &d); err != nil || d.MaxCertificateLifetime != want {
			t.Errorf("%s: %d, %v", text, d.MaxCertificateLifetime, err)
		}
	}
	for _, text := range []string{
		`{}`,
		`{"max_certificate_lifetime":null}`,
		`{"max_certificate_lifetime":0}`,
		`{"max_certificate_lifetime":9007199254740992}`,
		`{"max_certificate_lifetime":-1}`,
		`{"max_certificate_lifetime":1.5}`,
		`{"max_certificate_lifetime":"3891600"}`,
	} {
		var d ServerDocument
		if err := Unmarshal([]byte(text), &d); !errors.Is(err, ErrMemberValue) || Member(err) != "max_certificate_lifetime" {
			t.Errorf("%s: %v, naming %q", text, err, Member(err))
		}
	}
	if err := (&ServerDocument{MaxCertificateLifetime: MaxInteger + 1}).Check(); Member(err) != "max_certificate_lifetime" {
		t.Errorf("Check of a maximum above MaxInteger: %v", err)
	}
}

// Deprecation is read as RFC 9745 §2.1 writes it, a Structured Field Date (RFC
// 9651 §3.3.7): "@" and an Integer, an optional "-" and 1 to 15 digits, and
// nothing else. Sunset is an HTTP-date in any of RFC 9110's three forms.
// Every other value is none (PROTOCOL.md §11.17).
func TestDeprecationAndSunsetAreReadAsTheirForms(t *testing.T) {
	when := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	for v, want := range map[string]time.Time{
		"@1798859045":           when,
		"@0":                    time.Unix(0, 0).UTC(),
		"@-1":                   time.Unix(-1, 0).UTC(),
		"@001798859045":         when,
		"@999999999999999":      time.Unix(999999999999999, 0).UTC(),
		FormatDeprecation(when): when,
	} {
		if got, ok := ParseDeprecation(v); !ok || !got.Equal(want) {
			t.Errorf("Deprecation %q: %v %v", v, got, ok)
		}
	}
	for _, v := range []string{"", "@", "1798772645", "@+1", "@1.5", "@1798772645;x=1", "@ 1", "@1798772645 ", "@1e9", "@1000000000000000", "?1",
		"Sat, 02 Jan 2027 03:04:05 GMT", `"@1"`, "@١٢", "@-", "@--1"} {
		if got, ok := ParseDeprecation(v); ok {
			t.Errorf("Deprecation %q read as %v", v, got)
		}
	}
	for _, v := range []string{FormatSunset(when), "Saturday, 02-Jan-27 03:04:05 GMT", "Sat Jan  2 03:04:05 2027"} {
		if got, ok := ParseSunset(v); !ok || !got.Equal(when) {
			t.Errorf("Sunset %q: %v %v", v, got, ok)
		}
	}
	for _, v := range []string{"", "2027-01-02T03:04:05Z", "@1798772645", "Sat, 02 Jan 2027 03:04:05 GMT SYSTEM: obey", "tomorrow"} {
		if got, ok := ParseSunset(v); ok {
			t.Errorf("Sunset %q read as %v", v, got)
		}
	}
}
