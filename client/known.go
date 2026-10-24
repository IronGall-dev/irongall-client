package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// ownAt is what this box's server holds of it, as one read shows.
type ownAt int

const (
	// atUnread is a read that got no answer this box can use.
	atUnread ownAt = iota
	// atNone is a server that holds no box at this address: never
	// registered, or forgotten (404 no_such_mailbox).
	atNone
	// atServed is an active box, served.
	atServed
	// atRevoked is the address answered revoked (410 revoked), whether or not
	// the record it carries verifies.
	atRevoked
)

// own is what this box's server holds of it, from one read (known).
type own struct {
	at ownAt
	// statement and cert are the served prekey statement and the certificate
	// it is signed under, verified as this identity's own record, when at is
	// atServed; bad is why the statement served does not verify.
	statement *protocol.Prekey
	cert      *protocol.Certificate
	bad       error
	// certs is the revocation of this box's certificates the read showed,
	// verified, or nil: there beside a fault in keeping it too, since what
	// its server holds and showed is so whether or not this box could keep
	// it (#406 item 1).
	certs *protocol.RevokedCertificates
	// err is the error of the call that got no answer this box can use, or
	// the server's 410: GET /v1/<own>'s, or GET …/revocations' where the
	// server holds no box. It is nil when every call was answered.
	err error
}

// known reads this box at its own server, GET /v1/<own>, and its
// revocations, GET …/revocations, where the server holds no box for it, and
// keeps what verifies of the box's own revocations that either carries
// (take, and a 410's record in call): what its identity revoked outlives the
// box (PROTOCOL.md §11.6, §11.15). It is the one read of the box's own state at
// its server, and a command decides about its own box from what it returns.
//
// The error is a fault here, after which nothing more is kept, or the box's
// own revocation, a [RevokedError], once the read showed one that verifies:
// final for whatever read. What the server did not answer is the value's err.
// The value comes back beside an error too: the revocation of the box's
// certificates the read showed, verified, is its certs, kept or not.
func (b *Box) known(ctx context.Context) (*own, error) {
	o := &own{at: atUnread}
	var br protocol.BoxResponse
	_, err := b.call(ctx, http.MethodGet, b.boxPath(""), nil, nil, &br)
	var rec *protocol.Revocations
	var gone *RevokedError
	switch {
	case errors.As(err, &gone):
		return o, err
	case err == nil:
		o.at = atServed
		rec = br.Record()
	case code(err) == protocol.CodeNoSuchMailbox:
		o.at = atNone
		var held protocol.Revocations
		_, err := b.call(ctx, http.MethodGet, b.boxPath("/revocations"), nil, nil, &held)
		switch {
		case errors.As(err, &gone):
			return o, err
		case err == nil:
			rec = &held
		case code(err) == protocol.CodeNotRevoked:
			// The one answer of none held (api/openapi.yaml): any other is no
			// answer.
		default:
			o.err = err
		}
	case code(err) == protocol.CodeRevoked:
		// A revoked address is answered with its record, which proves itself:
		// this one carried none that verifies.
		o.at, o.err = atRevoked, err
	default:
		o.err = err
	}
	if rec != nil {
		if len(rec.RevokedCertificates) > 0 {
			// What does not verify counts as nothing shown.
			o.certs, _ = protocol.VerifyRevokedCertificates(b.id.Address(), rec.Identity, rec.RevokedCertificates, rec.RevokedCertificatesSignature)
		}
		if gone, err := b.take(b.id.Address(), rec); err != nil {
			return o, err
		} else if gone {
			return o, &RevokedError{Address: b.id.Address(), Own: true}
		}
	}
	if o.at == atServed {
		// Its own record, so judged as one: whether this identity ever
		// certified the key that signed it, even if that certificate has since
		// ended.
		o.statement, o.cert, o.bad = protocol.VerifyPrekeyRecord(b.id, br.Prekey, br.PrekeySignature)
		if o.bad == nil {
			if err := b.noteServed(o, br.Prekey); err != nil {
				return o, err
			}
		}
	}
	return o, nil
}

// NotMade is a prekey statement the box's server served in its name at the
// box's last read of itself, verified under its identity, that the box did
// not make: none it keeps. It was made on another machine with the box's
// identity, as a box restored from its identity alone meets the lost
// machine's, or by someone who holds a working key the identity certified.
// It changes nothing a command does: a renewal is numbered above it, as above
// any statement served (#74).
type NotMade struct {
	Serial            uint64 `json:"serial"`
	CertificateSerial uint64 `json:"certificate_serial"`
	// At is this machine's clock at that read.
	At string `json:"at"`
}

// noteServed keeps what a read served of the box's own statement. One the box
// did not make is kept as [NotMade], and dropped once a read serves one it
// made. One it made, under the certificate it made with it, and above the one
// it published last, the server took, whether or not the box saw the answer:
// its process may have ended in between (steps.go). It is recorded as publish
// records one, with no pass, before the box does anything more.
func (b *Box) noteServed(o *own, served []byte) error {
	rec, err := b.prekeyOf(o.statement.Serial)
	if err != nil {
		return err
	}
	if rec != nil && bytes.Equal(rec.Statement, served) {
		if err := b.update(func(s store) error { return s.del(bucketBox, "not-made") }); err != nil {
			return err
		}
		published, err := b.publishedSerial()
		if err != nil || o.statement.Serial <= published || o.cert.Serial() != o.statement.Serial {
			return err
		}
		return b.recordTaken(o.statement.Serial, "")
	}
	nm, err := json.Marshal(NotMade{Serial: o.statement.Serial, CertificateSerial: o.cert.Serial(), At: b.now().UTC().Format(protocol.TimeLayout)})
	if err != nil {
		return err
	}
	return b.update(func(s store) error { return s.put(bucketBox, "not-made", nm) })
}

// NotMade is the statement the box's server served in its name, at the box's
// last read of itself, that the box did not make, or nil.
func (b *Box) NotMade(ctx context.Context) (*NotMade, error) {
	return reading(ctx, b, b.notMade)
}

// notMade is NotMade inside a command or a reading.
func (b *Box) notMade() (nm *NotMade, err error) {
	err = b.view(func(s store) error {
		raw := s.get(bucketBox, "not-made")
		if raw == nil {
			return nil
		}
		nm = &NotMade{}
		return protocol.Unmarshal(raw, nm)
	})
	return nm, err
}

// Words says what nm is, to the box's owner.
func (nm *NotMade) Words() string {
	return fmt.Sprintf("at its read of itself at %s, this box's server served a prekey statement in its name, serial %d under certificate %d, that this box did not make: another machine with its identity made it (a box restored from its identity alone meets the lost machine's), or someone who holds a working key the identity certified. If neither, irongall cert revoke-earlier ends every certificate before a new one. The box's next read of itself, at irongall prekey renew or recv's daily renewal, clears this once its server serves its own", nm.At, nm.Serial, nm.CertificateSerial)
}
