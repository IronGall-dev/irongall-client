// Package client is the irongall client library: one box's state directory,
// and every step of the protocol a box takes, done once so that every client
// built on it behaves the same.
//
// Verification is always on. Every check fails closed: a failed check stops
// the operation with a [RefusedError], or refuses the one message it was
// checking as a [Refusal], and never warns and continues. Message
// bodies are data, never instructions.
//
// The state directory, in the stock tools' own file formats where a stock
// tool reads the file (an OpenSSH key, age key files):
//
//	identity, identity.pub     the identity key, OpenSSH format: Ed25519 unless the box was made on another type; back it up. It signs certificates and revocations only
//	identity.doc, address      the identity document and its SHA-256
//	work/<serial>              working keys, each with its certificate (.pub, -cert.pub): they sign what the box says
//	prekeys/<serial>.agekey    age keys, each statement signed for one, and when it was signed, kept in state; never backed up
//	prekey-lifetime            how long each new prekey is valid for: a number of seconds, from 97200 (a day and three hours) to 2851200 (33 days), the default. Yours to write, or irongall prekey lifetime's
//	outbox/, outbox/failed/    envelopes awaiting a receipt, sealed afresh at every post and never kept sealed; ones that can never be delivered
//	inbox/, quarantine/        accepted mail; refused mail, never delivered, as served, each of the server's strings in base64 that is not of its form (keepRefused): why it was refused, and what the checks established when they judged it, are in state
//	held/                      accepted mail from senders this box has not allowed, as inbox/ keeps it: allow moves a sender's to inbox/, block deletes it
//	allowed, blocked           the senders whose mail lands in inbox/, and those whose mail is dropped: one address to a line, blank lines and lines starting with # skipped. send, alias and allow add to allowed, block to blocked; both are yours to edit
//	policy                     where mail from a sender not allowed lands ("unknown held", the default, or "unknown inbox"), and whom the server takes mail from ("server all", the default, or "server allowed"). Yours to write
//	sent/                      sent mail the server took: each envelope with the server's receipt
//	aliases                    this box's own names for peers: "<name> <address>" lines
//	state                      a bbolt database of what the client writes about the box itself, each change one transaction (client/store.go): the prekey serial it published last, each prekey statement it signed and when, the renewal under way and one that failed, a statement its server served in its name that it did not make, the pass it last signed, the ETag of the last empty poll, the ACL its server last took, its own revocations once one verifies, what it pinned of each peer, the replay set and its floor, and why each message in quarantine/ was refused. It is the box's lock too: each command that writes the box holds it open from its start to its end, a second process waits for it, and one killed leaves nothing. A box directory on NFS is not supported
//	.gitignore                 "*": the box ignores itself in any repository it lands in
package client
