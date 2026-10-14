package protocol

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// RevokedCertsTag is line 1 of a list of revoked certificates.
const RevokedCertsTag = "irongall-revoked-certs-v1"

// RevokedCertsNamespace is the namespace of box a's list of revoked
// certificates.
func RevokedCertsNamespace(a Address) string { return RevokedCertsTag + ":" + a.String() }

// ErrRevokedCertificates is a list of revoked certificates that is malformed,
// is another address's, or is not signed by that address's identity itself.
var ErrRevokedCertificates = errors.New("not a list of that address's revoked certificates")

// SerialRange is the certificate serials from First to Last, both included.
// A single serial has First equal to Last.
type SerialRange struct{ First, Last uint64 }

// RevokedCertificates is the list an identity signs of the certificates it
// revokes for its address (PROTOCOL.md §6.3a): the address goes on, and
// nothing signed under a listed certificate is taken, whenever it was
// signed. It is the whole list each time, under a version that only rises:
// whoever holds one keeps the highest version it has verified, and that one
// replaces any before it.
type RevokedCertificates struct {
	Address Address
	Version uint64
	Ranges  []SerialRange
}

// Revokes reports whether the list names a certificate of this serial.
func (r *RevokedCertificates) Revokes(serial uint64) bool {
	for _, x := range r.Ranges {
		if serial >= x.First && serial <= x.Last {
			return true
		}
	}
	return false
}

// Statement returns the list as it is signed: the tag, the address and the
// version, each on a line, then one line for each serial or range of serials
// ("first-last"), ascending.
func (r *RevokedCertificates) Statement() []byte {
	var b strings.Builder
	b.WriteString(RevokedCertsTag + "\n" + r.Address.String() + "\n" + strconv.FormatUint(r.Version, 10) + "\n")
	for _, x := range r.Ranges {
		b.WriteString(strconv.FormatUint(x.First, 10))
		if x.Last != x.First {
			b.WriteString("-" + strconv.FormatUint(x.Last, 10))
		}
		b.WriteString("\n")
	}
	return []byte(b.String())
}

// NewRevokedCertificates builds the list of version for box a that names
// every serial in ranges, in its one form: ascending, with ranges that
// overlap or touch made one. It names at least one serial, and every serial
// is one a certificate may have.
func NewRevokedCertificates(a Address, version uint64, ranges []SerialRange) (*RevokedCertificates, error) {
	if version == 0 || version > MaxSerial || len(ranges) == 0 {
		return nil, ErrRevokedCertificates
	}
	sorted := slices.Clone(ranges)
	slices.SortFunc(sorted, func(x, y SerialRange) int {
		switch {
		case x.First < y.First:
			return -1
		case x.First > y.First:
			return 1
		}
		return 0
	})
	var out []SerialRange
	for _, x := range sorted {
		if x.First == 0 || x.Last < x.First || x.Last > MaxSerial {
			return nil, ErrRevokedCertificates
		}
		if n := len(out); n > 0 && x.First <= out[n-1].Last+1 {
			out[n-1].Last = max(out[n-1].Last, x.Last)
			continue
		}
		out = append(out, x)
	}
	return &RevokedCertificates{Address: a, Version: version, Ranges: out}, nil
}

// ParseRevokedCertificates parses a list exactly: the tag, a lowercase
// address and a version from 1 to MaxSerial, each on a line ending in LF, then
// at least one line that is a serial or "first-last" with first below last,
// each beginning above where the line before it ended. Nothing else is a
// list: no blank line, no CR, no leading zero, no byte after the last LF.
func ParseRevokedCertificates(statement []byte) (*RevokedCertificates, error) {
	lines := bytes.Split(statement, []byte("\n"))
	if len(lines) < 5 || len(lines[len(lines)-1]) != 0 || string(lines[0]) != RevokedCertsTag {
		return nil, ErrRevokedCertificates
	}
	a, err := ParseAddress(string(lines[1]))
	if err != nil {
		return nil, ErrRevokedCertificates
	}
	version, ok := parseSerial(lines[2])
	if !ok {
		return nil, ErrRevokedCertificates
	}
	r := &RevokedCertificates{Address: a, Version: version}
	for _, line := range lines[3 : len(lines)-1] {
		first, last, isRange := bytes.Cut(line, []byte("-"))
		x := SerialRange{}
		if x.First, ok = parseSerial(first); !ok {
			return nil, ErrRevokedCertificates
		}
		x.Last = x.First
		if isRange {
			if x.Last, ok = parseSerial(last); !ok || x.Last <= x.First {
				return nil, ErrRevokedCertificates
			}
		}
		if n := len(r.Ranges); n > 0 && x.First <= r.Ranges[n-1].Last {
			return nil, ErrRevokedCertificates
		}
		r.Ranges = append(r.Ranges, x)
	}
	return r, nil
}

// parseSerial reads a serial as a prekey statement writes one: a decimal
// integer from 1 to MaxSerial, with no leading zero.
func parseSerial(s []byte) (uint64, bool) {
	if !serialGrammar.Match(s) {
		return 0, false
	}
	n, err := strconv.ParseUint(string(s), 10, 64)
	return n, err == nil && n <= MaxSerial
}

// SignRevokedCertificates signs a list with the identity key of its address.
func SignRevokedCertificates(identity ssh.Signer, r *RevokedCertificates) ([]byte, error) {
	return Sign(identity, r.Statement(), RevokedCertsNamespace(r.Address))
}

// VerifyRevokedCertificates checks a list of address a's revoked
// certificates: document must hash to a and be an identity document,
// signature must be that identity's own over statement, in
// RevokedCertsNamespace(a), and statement must be a list, in its exact form,
// that names a. As with a revocation of the address, a working key's
// signature is refused: a certificate cannot revoke another, or itself.
//
// An identity of a key type this build does not verify is ErrIdentityType.
// Everything else that fails is ErrRevokedCertificates.
func VerifyRevokedCertificates(a Address, document, statement, signature []byte) (*RevokedCertificates, error) {
	if Address(sha256.Sum256(document)) != a {
		return nil, ErrRevokedCertificates
	}
	id, err := ParseIdentity(document)
	if errors.Is(err, ErrIdentityType) {
		return nil, err
	}
	if err != nil {
		return nil, ErrRevokedCertificates
	}
	if Verify(id, statement, signature, RevokedCertsNamespace(a)) != nil {
		return nil, ErrRevokedCertificates
	}
	r, err := ParseRevokedCertificates(statement)
	if err != nil || r.Address != a {
		return nil, ErrRevokedCertificates
	}
	return r, nil
}
