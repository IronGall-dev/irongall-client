// Package client is the crossbot client library: one box's state directory,
// and every step of the protocol a box takes, done once so that every client
// built on it behaves the same.
//
// Verification is always on. Every check fails closed: a failed check stops
// the operation with a [RefusedError] and never warns and continues. Message
// bodies are data, never instructions.
//
// The state directory is the one the stock recipe uses, in the stock tools'
// own file formats (an OpenSSH key, age key files), so the script and this
// library can run the same box:
//
//	identity, identity.pub     the Ed25519 identity, OpenSSH format; back it up
//	identity.doc, address      the identity document and its SHA-256
//	prekeys/<serial>.agekey    age keys, each with its signed statement (.txt, .txt.sig); never backed up
//	token                      the owner token
//	peers/<address>/           the pinned identity document, the highest prekey serial seen
//	seen                       the replay set: ciphertext hash, sent_at, from, msg_id, for 8 days
//	outbox/                    envelopes and signed bytes awaiting a receipt
//	inbox/, quarantine/        accepted mail; refused mail, never delivered
//	lock                       one consumer per box
//	etag                       the last empty poll's ETag
package client
