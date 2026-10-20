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
//	identity, identity.pub     the identity key, OpenSSH format: Ed25519 unless the box was made on another type; back it up. It signs certificates and revocations only
//	identity.doc, address      the identity document and its SHA-256
//	work/<serial>              working keys, each with its certificate (.pub, -cert.pub): they sign what the box says
//	prekeys/<serial>.agekey    age keys, each with its signed statement (.txt, .txt.sig) and when it was signed (.made); never backed up
//	prekey-lifetime            how long each new prekey is valid for: a number of seconds, from 97200 (a day and three hours) to 2851200 (33 days), the default. Yours to write, or irongall prekey lifetime's
//	serial                     the number of the prekey this box published last, which is its certificate's serial too: the box's clock gave it
//	pass                       the pass this box last signed for its server, used until it runs out
//	etag                       the ETag of the last poll that found the box empty, sent back in If-None-Match; gone once a poll finds mail
//	peers/<address>/           the pinned identity document, the highest prekey serial and certificate serial seen, revoke.sig, its revocation, once one has verified, and revoked-certs.json, the highest revocation of its certificates that has verified
//	revoked.sig                this box's own revocation, once it has met one that verifies: the box is finished
//	revoked-certs.json         this box's own revocation of its certificates, once it has published one or been shown one that verifies: the record that carries it, one line of JSON
//	seen                       the replay set: ciphertext hash, sent_at, from, msg_id, for 66 days and an hour from sent_at
//	seen-floor                 the highest cutoff a prune of seen dropped a line at, in seconds: mail sent before it, or less than 33 days after it, is stale
//	outbox/, outbox/failed/    envelopes awaiting a receipt, sealed afresh at every post and never kept sealed; ones that can never be delivered
//	inbox/, quarantine/        accepted mail; refused mail, never delivered, each with its reason beside it (.reason), each of the server's strings in base64 that is not of its form, and what the checks established when they judged it (keepRefused)
//	held/                      accepted mail from senders this box has not allowed, as inbox/ keeps it: allow moves a sender's to inbox/, block deletes it
//	allowed, blocked           the senders whose mail lands in inbox/, and those whose mail is dropped: one address to a line. send, alias and allow add to allowed, block to blocked; both are yours to edit
//	policy                     where mail from a sender not allowed lands ("unknown held", the default, or "unknown inbox"), and whom the server takes mail from ("server all", the default, or "server allowed"). Yours to write
//	acl.json                   the ACL this box's server last took, as it answered: made from the three files above, and sent when they change
//	sent/                      sent mail the server took: each envelope with the server's receipt
//	aliases                    this box's own names for peers: "<name> <address>" lines
//	revocation-servers         the revocation servers this box asks beside its own server, and publishes to: one URL to a line, or the word none. Yours to write; without it, none
//	lock/                      the box's lock, held by each command that writes the box: a directory, with this client's flocked lock/pid inside
//	.gitignore                 "*": the box ignores itself in any repository it lands in
package client
