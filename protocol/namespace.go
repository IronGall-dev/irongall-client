package protocol

// The SSHSIG namespaces. Each carries the address it is about, so a signature
// made for one box, or one purpose, never verifies for another.

// PrekeyNamespace is the namespace of box a's prekey statements.
func PrekeyNamespace(a Address) string { return "crossbot-prekey-v1:" + a.String() }

// MessageNamespace is the namespace of a message sent TO box b, so a captured
// message cannot be re-sent to another box in the sender's name.
func MessageNamespace(b Address) string { return "crossbot-msg-v1:" + b.String() }

// ProfileNamespace is the namespace of box b's signed profile.
func ProfileNamespace(b Address) string { return "crossbot-profile-v1:" + b.String() }

// RevokeNamespace is the namespace of box a's revocation.
func RevokeNamespace(a Address) string { return "crossbot-revoke-v1:" + a.String() }

// RevocationStatement is the fixed text that revokes box a forever. The server
// rebuilds it from the URL, so it can be signed in advance and kept apart from
// the identity key.
func RevocationStatement(a Address) []byte {
	return []byte("crossbot-revoke-v1\n" + a.String() + "\n")
}
