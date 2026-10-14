// Package client is the irongall client library: one box's state directory,
// and every step of the protocol a box takes, done once so that every client
// built on it behaves the same.
//
// Verification is always on. Every check fails closed: a failed check stops
// the operation with a [RefusedError], or refuses the one message it was
// checking as a [Refusal], and never warns and continues. Message
// bodies are data, never instructions.
//
// The state directory is the one the stock recipe uses, in the stock tools'
// own file formats (an OpenSSH key, age key files), so the script and this
// library can run the same box:
//
//	identity, identity.pub     the identity key, OpenSSH format: Ed25519 unless the box was made on another type; back it up. It signs certificates only
//	identity.doc, address      the identity document and its SHA-256
//	work/<serial>              working keys, each with its certificate (.pub, -cert.pub): they sign what the box says
//	prekeys/<serial>.agekey    age keys, each with its signed statement (.txt, .txt.sig); never backed up
//	serial                     the number of the prekey this box published last, which is its certificate's serial too: the box's clock gave it
//	pass                       the pass this box last signed for its server, used until it runs out
//	peers/<address>/           the pinned identity document, the highest prekey serial and certificate serial seen, revoke.sig, its revocation, once one has verified, and revoked-certs.json, the highest revocation of its certificates that has verified
//	revoked.sig                this box's own revocation, once it has met one that verifies: the box is finished
//	revoked-certs.json         this box's own revocation of its certificates, once it has published one: the record that carries it, one line of JSON
//	seen                       the replay set: ciphertext hash, sent_at, from, msg_id, for 33 days
//	outbox/, outbox/failed/    signed envelopes awaiting a receipt; ones that can never be delivered
//	inbox/, quarantine/        accepted mail; refused mail, never delivered, each with its reason beside it (.reason)
//	sent/                      sent mail the server took: each envelope with the server's receipt
//	aliases                    this box's own names for peers: "<name> <address>" lines
//	revocation-servers         the revocation servers this box asks beside its own server, and publishes to: one URL to a line, or the word none. Yours to write; without it, the default for the box's server
//	lock/                      one consumer per box: a directory, with this client's flocked lock/pid inside
//	.gitignore                 "*": the box ignores itself in any repository it lands in
//	etag                       the last empty poll's ETag
package client
