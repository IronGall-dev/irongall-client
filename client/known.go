package client

import (
	"context"
	"net/http"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// ownAt is what this box's server holds of it, as one read shows.
type ownAt int

const (
	// atUnread is a read that got no answer this box can use.
	atUnread ownAt = iota
	// atNone is a server that holds no box at this address: never
	// registered, deleted by its owner, or forgotten (404 no_such_mailbox).
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
	// err is the error of the call that got no answer this box can use, or
	// the server's 410: GET /v1/<own>'s, or GET …/revocations' where the
	// server holds no box. It is nil when every call was answered.
	err error
}

// known reads this box at its own server, GET /v1/<own>, and its
// revocations, GET …/revocations, where the server holds no box for it, and
// keeps what verifies of the box's own revocations that either carries
// (take): what its identity revoked outlives the box (PROTOCOL.md §3a,
// §6.3). It is the one read of the box's own state at its server, and a
// command decides about its own box from what it returns.
//
// The error is a fault here, after which nothing more is kept; what the
// server did not answer is the value's err.
func (b *Box) known(ctx context.Context) (*own, error) {
	o := &own{at: atUnread}
	var br protocol.BoxResponse
	_, err := b.call(ctx, http.MethodGet, b.boxPath(""), nil, nil, &br)
	rec := br.Record()
	switch {
	case err == nil:
		o.at = atServed
	case code(err) == protocol.CodeNoSuchMailbox:
		o.at = atNone
		var held protocol.Revocations
		_, err := b.call(ctx, http.MethodGet, b.boxPath("/revocations"), nil, nil, &held)
		switch {
		case err == nil:
			rec = &held
		case code(err) == protocol.CodeNotRevoked, code(err) == protocol.CodeNoSuchMailbox:
		default:
			o.err = err
		}
	case code(err) == protocol.CodeRevoked:
		// A revoked address is answered with its record, which proves itself.
		o.at, o.err = atRevoked, err
		rec = recordOf(err)
	default:
		o.err = err
	}
	if rec != nil {
		if _, err := b.take(b.id.Address(), rec); err != nil {
			return o, err
		}
	}
	if o.at == atServed {
		// Its own record, so judged as one: whether this identity ever
		// certified the key that signed it, even if that certificate has since
		// ended.
		o.statement, o.cert, o.bad = protocol.VerifyPrekeyRecord(b.id, br.Prekey, br.PrekeySignature)
	}
	return o, nil
}
