# crossbot v1 test vectors

Files any crossbot implementation can check itself against, made with stock tools only (`generate.sh`: bash, od, base64, sha256sum, ssh-keygen, and age ≥ 1.3 for the one ciphertext). Every vector is judged at the time in `now`.

**The keys are public test keys.** Box A's identity is the key of RFC 8032 §7.1 TEST 1 and box B's is TEST 2 (`input/*.ed25519`: the seed, then the public key, in hex). The age recipients in `input/` are public keys whose secret keys were discarded, so nothing here decrypts.

| Path | What | Expected |
|---|---|---|
| `a/`, `b/` | each box's `identity.doc` and `address`, its prekey statements `prekey-<serial>.txt` with `.sig`, and A's `revoke.txt` with `revoke.sig` | all valid. `a/prekey-1` is post-quantum, `a/prekey-2` X25519 only (`--no-pq`); `a/prekey-1.txt.sha256.sig` signs with SHA-256 instead of SHA-512, which verifiers accept |
| `message/` | `a-to-b.age`, an age file encrypted to B's prekey; `.sig`, A's signature for B | verifies for B. `a-to-b.age.for-another-box.sig` is A's signature of the same bytes for A's own box, and must not verify for B |
| `identity/*.doc` | malformed identity documents, and well-formed ones holding a small-order or non-canonical Ed25519 key | every one rejected |
| `prekey/bad-*` | prekey statements with a `.sig` by A, in A's namespace except where the name says otherwise | every one rejected |
| `prekey/expired` | a valid statement whose `not_after` is `now` | valid, but expired: a sender must not encrypt to it |
| `prekey/too-long` | a valid statement valid for 33 days and one second | not expired, but a server must refuse to publish it |
| `envelope/accept-*`, `refuse-*` | decrypted envelopes of a message signed by A and received by B | accepted or refused, as named. Keys match exactly and none may appear twice, so every reader takes the same values: in `accept-case-variant-key` the body is `"benign"` (`BODY` is an unknown key, ignored); `refuse-duplicate-key` has two `from`s; `refuse-version-string` has `"v":"1"`, which is not the number 1; `refuse-not-utf8` and `refuse-two-objects` are not one UTF-8 JSON object. Strict on what a loose reader lets through: `refuse-msg-id-newline` ends its `msg_id` with a newline, `refuse-subject-number` has a number where a string goes, and `refuse-sent-at-second-60` names a second some date parsers carry into the next minute |

Ed25519 signatures are deterministic, so an implementation that signs these statements with these keys must produce byte-identical `.sig` files. `message/a-to-b.age` is made once and kept, since age encryption is randomised; everything else regenerates byte for byte.
