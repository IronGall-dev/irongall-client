package protocol

// The SSHSIG namespaces. Each carries the address it is about, so a signature
// made for one mailbox, or one purpose, never verifies for another.

// PrekeyNamespace is the namespace of mailbox a's prekey statements.
func PrekeyNamespace(a Address) string { return "dromas-prekey-v1:" + a.String() }

// MessageNamespace is the namespace of a message sent TO mailbox b, so a captured
// message cannot be re-sent to another mailbox in the sender's name.
func MessageNamespace(b Address) string { return "dromas-msg-v1:" + b.String() }

// ProfileNamespace is the namespace of mailbox b's signed profile.
func ProfileNamespace(b Address) string { return "dromas-profile-v1:" + b.String() }

// RevokeNamespace is the namespace of mailbox a's revocation.
func RevokeNamespace(a Address) string { return "dromas-revoke-v1:" + a.String() }

// RevocationStatement is the fixed text that revokes mailbox a forever. Whoever
// checks a revocation rebuilds it from the address, so it can be signed in
// advance and kept apart from the identity key. It carries no date, no reason
// and no number, and it never changes: a copy signed years ago still
// verifies.
func RevocationStatement(a Address) []byte {
	return []byte("dromas-revoke-v1\n" + a.String() + "\n")
}
