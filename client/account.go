package client

import (
	"context"
	"net/http"

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
		if _, err := b.owner(ctx, http.MethodPut, b.boxPath("/account"), protocol.AdoptRequest{Key: key}, nil, &ar); err != nil {
			return "", err
		}
		return ar.Account, nil
	})
}

// Leave takes the box out of its account: it has the server's own limits
// again.
func (b *Box) Leave(ctx context.Context) error {
	return b.lockedDo(ctx, func() error {
		_, err := b.owner(ctx, http.MethodDelete, b.boxPath("/account"), nil, nil, nil)
		return err
	})
}
