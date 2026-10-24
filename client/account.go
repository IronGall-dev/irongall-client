package client

import (
	"context"
	"net/http"
	"regexp"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// Adopt puts the box in the account an adopt key names, and returns the
// account's id as the server gives it. An account can lift the box's
// limits; the server can tell who pays for the box, and nothing else about
// its mail changes. Keep the key secret: anyone holding it can adopt a box
// into the account until it is spent or expires.
func (b *Box) Adopt(ctx context.Context, key string) (string, error) {
	return locked(ctx, b, func() (string, error) {
		var ar protocol.AccountResponse
		if _, err := b.owner(ctx, http.MethodPut, b.boxPath("/account"), protocol.AdoptRequest{Key: key}, &ar); err != nil {
			return "", err
		}
		if !accountID.MatchString(ar.Account) {
			return "", refuse("the server's answer does not name an account as the protocol writes one, 1 to 32 of a-z, 0-9 and -")
		}
		return ar.Account, nil
	})
}

// accountID is an account id as PROTOCOL.md §11.16 writes one: what Adopt
// returns is checked to it, so what adopt prints names no more than that.
var accountID = regexp.MustCompile(`\A[a-z0-9-]{1,32}\z`)

// Leave takes the box out of its account: it has the server's own limits
// again.
func (b *Box) Leave(ctx context.Context) error {
	return b.lockedDo(ctx, func() error {
		_, err := b.owner(ctx, http.MethodDelete, b.boxPath("/account"), nil, nil)
		return err
	})
}
