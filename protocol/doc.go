// Package protocol holds the irongall v1 formats every client and the server
// share: addresses, identity documents, signed prekey statements, signature
// namespaces, the message envelope, and the error codes.
//
// Every parser here is exact. A signed statement must match its format byte
// for byte, and an identity key must be a canonical, non-small-order Ed25519
// point. Failing a check returns an error; nothing warns and carries on.
//
// testdata/vectors holds files, made with the stock tools (ssh-keygen,
// sha256sum, age), that any implementation can check itself against.
package protocol
