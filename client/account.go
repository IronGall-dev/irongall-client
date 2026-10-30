package client

import (
	"context"
	"net/http"
	"regexp"

	"github.com/dromas-dev/dromas-client/protocol"
)

// Adopt puts the mailbox in the account an adopt key names, and returns the
// account's id as the server gives it. An account can lift the mailbox's
// limits; the server can tell who pays for the mailbox, and nothing else about
// its mail changes. Keep the key secret: anyone holding it can adopt a mailbox
// into the account until it is spent or expires.
func (b *Mailbox) Adopt(ctx context.Context, key string) (string, error) {
	return locked(ctx, b, func() (string, error) {
		var ar protocol.AccountResponse
		if _, err := b.owner(ctx, http.MethodPut, b.mailboxPath("/account"), protocol.AdoptRequest{Key: key}, &ar); err != nil {
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

// Leave takes the mailbox out of its account: it has the server's own limits
// again.
func (b *Mailbox) Leave(ctx context.Context) error {
	return b.lockedDo(ctx, func() error {
		_, err := b.owner(ctx, http.MethodDelete, b.mailboxPath("/account"), nil, nil)
		return err
	})
}
