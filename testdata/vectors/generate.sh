#!/usr/bin/env bash
# Regenerates the crossbot v1 test vectors with stock tools only: bash, od, base64, fold,
# sha256sum and ssh-keygen (OpenSSH >= 8.1), plus age >= 1.3 for the one ciphertext.
# Everything is deterministic (Ed25519 signatures are), except message/a-to-b.age, which is
# made once and kept. Inputs are in input/: the two identity keys are the PUBLISHED test keys
# of RFC 8032 §7.1 (TEST 1 and TEST 2), and the age recipients' secret keys were discarded.
# Every vector is judged at the time in ./now.
set -euo pipefail
umask 077
cd "$(dirname "$0")"
NOW=2026-10-10T00:00:00Z
NOT_AFTER=2026-11-11T00:00:00Z # NOW + 32 days exactly: the longest a prekey may be valid
MSG_ID=6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b

# Hex helpers. Binary goes through hex strings, never through shell variables.
asc() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }
str() { printf '%08x%s' $(( ${#1} / 2 )) "$1"; }           # an RFC 4251 string, from hex
bin() { printf "$(printf '%s' "$1" | sed 's/../\\x&/g')"; } # hex → bytes on stdout
b64() { base64 | tr -d '\n'; }

# An unencrypted OpenSSH Ed25519 private key file, from the seed and public key in hex.
openssh_key() { # <seed hex> <public hex> <file>
  local pw priv pad="" n i=1
  pw=$(str "$(asc ssh-ed25519)")$(str "$2")
  priv=0000000000000000$(str "$(asc ssh-ed25519)")$(str "$2")$(str "$1$2")$(str "")
  n=$(( ${#priv} / 2 )); while (( n % 8 )); do pad+=$(printf '%02x' $i); i=$((i + 1)); n=$((n + 1)); done
  { echo '-----BEGIN OPENSSH PRIVATE KEY-----'
    bin "$(asc openssh-key-v1)00$(str "$(asc none)")$(str "$(asc none)")$(str "")00000001$(str "$pw")$(str "$priv$pad")" | b64 | fold -w 70; echo
    echo '-----END OPENSSH PRIVATE KEY-----'; } > "$3"
}
# An identity document for a raw 32-byte Ed25519 key in hex, valid or not.
identity_doc() { printf 'crossbot-v1\nssh-ed25519 %s\n' "$(bin "$(str "$(asc ssh-ed25519)")$(str "$1")" | b64)"; }

KEYS=$(mktemp -d) # private keys live only here, and only while this runs
cleanup() { rm -f "$KEYS/a" "$KEYS/b" "$KEYS/a.pub" "$KEYS/b.pub"; rmdir "$KEYS"; }
trap cleanup EXIT

printf '%s\n' "$NOW" > now
mkdir -p a b message identity prekey envelope
for box in a b; do
  { read -r seed; read -r pub; } < "input/$box.ed25519"
  openssh_key "$seed" "$pub" "$KEYS/$box"
  ssh-keygen -y -f "$KEYS/$box" > "$KEYS/$box.pub"
  [ "$(cut -d' ' -f2 "$KEYS/$box.pub")" = "$(bin "$(str "$(asc ssh-ed25519)")$(str "$pub")" | b64)" ] || { echo "the $box key file does not hold the RFC 8032 key" >&2; exit 1; }
  printf 'crossbot-v1\n%s\n' "$(cut -d' ' -f1,2 "$KEYS/$box.pub")" > "$box/identity.doc"
  sha256sum < "$box/identity.doc" | cut -c1-64 > "$box/address"
done
A=$(cat a/address); B=$(cat b/address)

sign() { ssh-keygen -q -Y sign -n "$2" -f "$KEYS/$1" "${@:3}"; } # <box> <namespace> [-O …] < message > signature
statement() { printf 'crossbot-prekey-v1\n%s\n%s\n%s\n%s\n' "$@"; } # <address> <serial> <recipient> <not_after>

# The two boxes, their prekeys and A's revocation.
statement "$A" 1 "$(cat input/a-1.pq)" "$NOT_AFTER" > a/prekey-1.txt
statement "$A" 2 "$(cat input/a-2.classic)" "$NOT_AFTER" > a/prekey-2.txt
statement "$B" 1 "$(cat input/b-1.pq)" "$NOT_AFTER" > b/prekey-1.txt
for f in a/prekey-1 a/prekey-2; do sign a "crossbot-prekey-v1:$A" < "$f.txt" > "$f.txt.sig"; done
sign a "crossbot-prekey-v1:$A" -O hashalg=sha256 < a/prekey-1.txt > a/prekey-1.txt.sha256.sig
sign b "crossbot-prekey-v1:$B" < b/prekey-1.txt > b/prekey-1.txt.sig
printf 'crossbot-revoke-v1\n%s\n' "$A" > a/revoke.txt
sign a "crossbot-revoke-v1:$A" < a/revoke.txt > a/revoke.sig

# Identity documents every implementation must reject.
GOOD=$(sed -n 2p a/identity.doc)
printf 'crossbot-v1\n%s comment\n' "$GOOD" > identity/comment.doc
printf 'crossbot-v1\r\n%s\r\n' "$GOOD" > identity/crlf.doc
printf 'crossbot-v1\n%s' "$GOOD" > identity/no-final-newline.doc
printf 'crossbot-v1\n%s\n \n' "$GOOD" > identity/padded.doc
printf 'crossbot-v2\n%s\n' "$GOOD" > identity/wrong-tag.doc
printf 'crossbot-v1\nssh-rsa %s\n' "$(cut -d' ' -f2 "$KEYS/a.pub")" > identity/key-type-mismatch.doc
identity_doc f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f > identity/non-canonical.doc # y = p + 3: a large-order point, encoded non-canonically
identity_doc 0100000000000000000000000000000000000000000000000000000000000080 > identity/negative-zero.doc
identity_doc 0100000000000000000000000000000000000000000000000000000000000000 > identity/small-order-1.doc
identity_doc ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f > identity/small-order-2.doc
identity_doc 0000000000000000000000000000000000000000000000000000000000000000 > identity/small-order-4a.doc
identity_doc 0000000000000000000000000000000000000000000000000000000000000080 > identity/small-order-4b.doc
identity_doc 26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05 > identity/small-order-8a.doc
identity_doc 26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85 > identity/small-order-8b.doc
identity_doc c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a > identity/small-order-8c.doc
identity_doc c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa > identity/small-order-8d.doc
identity_doc eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f > identity/small-order-non-canonical.doc # y = p + 1

# Prekey statements of box A. bad-*: signature or format must be refused. expired-*: valid, but
# expired at ./now, so a sender must not encrypt to it. too-long-*: valid and not expired, but a
# server must refuse to publish it. Each is signed by A in A's prekey namespace unless its name
# says otherwise.
PQ=$(cat input/a-1.pq)
bad() { local name=$1; shift; printf "$@" > "prekey/$name.txt"; sign a "crossbot-prekey-v1:$A" < "prekey/$name.txt" > "prekey/$name.txt.sig"; }
cp a/prekey-1.txt prekey/bad-wrong-namespace.txt; sign a "crossbot-msg-v1:$A" < a/prekey-1.txt > prekey/bad-wrong-namespace.txt.sig
cp a/prekey-1.txt prekey/bad-signed-by-b.txt; sign b "crossbot-prekey-v1:$A" < a/prekey-1.txt > prekey/bad-signed-by-b.txt.sig
bad bad-names-another-box 'crossbot-prekey-v1\n%s\n1\n%s\n%s\n' "$B" "$PQ" "$NOT_AFTER"
bad bad-serial-zero 'crossbot-prekey-v1\n%s\n0\n%s\n%s\n' "$A" "$PQ" "$NOT_AFTER"
bad bad-serial-leading-zero 'crossbot-prekey-v1\n%s\n01\n%s\n%s\n' "$A" "$PQ" "$NOT_AFTER"
bad bad-serial-19-digits 'crossbot-prekey-v1\n%s\n1000000000000000000\n%s\n%s\n' "$A" "$PQ" "$NOT_AFTER"
bad bad-serial-negative 'crossbot-prekey-v1\n%s\n-1\n%s\n%s\n' "$A" "$PQ" "$NOT_AFTER"
bad bad-never 'crossbot-prekey-v1\n%s\n1\n%s\nnever\n' "$A" "$PQ"
bad bad-time-lowercase-z 'crossbot-prekey-v1\n%s\n1\n%s\n2026-11-11T00:00:00z\n' "$A" "$PQ"
bad bad-time-fraction 'crossbot-prekey-v1\n%s\n1\n%s\n2026-11-11T00:00:00.5Z\n' "$A" "$PQ"
bad bad-time-offset 'crossbot-prekey-v1\n%s\n1\n%s\n2026-11-11T00:00:00+00:00\n' "$A" "$PQ"
bad bad-tag 'crossbot-prekey-v2\n%s\n1\n%s\n%s\n' "$A" "$PQ" "$NOT_AFTER"
bad bad-address-uppercase 'crossbot-prekey-v1\n%s\n1\n%s\n%s\n' "$(printf '%s' "$A" | tr a-f A-F)" "$PQ" "$NOT_AFTER"
bad bad-four-lines 'crossbot-prekey-v1\n%s\n1\n%s\n' "$A" "$PQ"
bad bad-six-lines 'crossbot-prekey-v1\n%s\n1\n%s\n%s\n\n' "$A" "$PQ" "$NOT_AFTER"
bad bad-crlf 'crossbot-prekey-v1\r\n%s\r\n1\r\n%s\r\n%s\r\n' "$A" "$PQ" "$NOT_AFTER"
bad bad-no-final-newline 'crossbot-prekey-v1\n%s\n1\n%s\n%s' "$A" "$PQ" "$NOT_AFTER"
bad bad-recipient-uppercase-pq 'crossbot-prekey-v1\n%s\n1\n%s\n%s\n' "$A" "$(printf '%s' "$PQ" | tr a-z A-Z)" "$NOT_AFTER"
bad bad-recipient-uppercase-classic 'crossbot-prekey-v1\n%s\n2\n%s\n%s\n' "$A" "$(tr a-z A-Z < input/a-2.classic)" "$NOT_AFTER"
bad bad-recipient-not-age 'crossbot-prekey-v1\n%s\n1\n%s\n%s\n' "$A" "$GOOD" "$NOT_AFTER"
bad bad-recipient-small-order-pq 'crossbot-prekey-v1\n%s\n1\n%s\n%s\n' "$A" "$(cat input/small-order.pq)" "$NOT_AFTER"
bad bad-recipient-small-order-classic 'crossbot-prekey-v1\n%s\n1\n%s\n%s\n' "$A" "$(cat input/small-order.classic)" "$NOT_AFTER"
bad expired 'crossbot-prekey-v1\n%s\n1\n%s\n%s\n' "$A" "$PQ" "$NOW"
bad too-long 'crossbot-prekey-v1\n%s\n1\n%s\n2026-11-11T00:00:01Z\n' "$A" "$PQ"

# Decrypted envelopes, judged as a message signed by A, received by box B, at ./now.
case_env() { local name=$1; shift; printf "$@" > "envelope/$name.json"; }
H='"v":1,"from":"%s","to":"%s"'
case_env accept-minimal "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env accept-every-field "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\",\"subject\":\"hi\",\"in_reply_to\":\"$MSG_ID\",\"supersedes\":\"$MSG_ID\",\"pad\":\"xxxx\"}" "$A" "$B"
case_env accept-json-body "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":{\"task\":\"ping\",\"n\":1}}" "$A" "$B"
case_env accept-null-body "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":null}" "$A" "$B"
case_env accept-unknown-field "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\",\"later\":true}" "$A" "$B"
case_env accept-8-days-old "{$H,\"sent_at\":\"2026-10-02T00:00:00Z\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-8-days-and-1s-old "{$H,\"sent_at\":\"2026-10-01T23:59:59Z\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-from-not-signer "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$B" "$B"
case_env refuse-to-another-box "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$A"
case_env refuse-from-uppercase "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$(printf '%s' "$A" | tr a-f A-F)" "$B"
case_env refuse-version-2 "{\"v\":2,\"from\":\"%s\",\"to\":\"%s\",\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-no-version "{\"from\":\"%s\",\"to\":\"%s\",\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-no-body "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\"}" "$A" "$B"
case_env refuse-no-msg-id "{$H,\"sent_at\":\"$NOW\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-msg-id-uppercase "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$(printf '%s' "$MSG_ID" | tr a-f A-F)\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-sent-at-malformed "{$H,\"sent_at\":\"2026-10-10 00:00:00\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-not-json "not json"
case_env refuse-msg-id-newline "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\\\\n\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-subject-number "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\",\"subject\":5}" "$A" "$B"
case_env refuse-sent-at-second-60 "{$H,\"sent_at\":\"2026-10-09T23:59:60Z\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
# Parser differentials: every reader must take the same values from one envelope.
case_env accept-case-variant-key "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"benign\",\"BODY\":\"evil\"}" "$A" "$B"
case_env refuse-version-string "{\"v\":\"1\",\"from\":\"%s\",\"to\":\"%s\",\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-duplicate-key "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\",\"from\":\"%s\"}" "$B" "$B" "$A"
case_env refuse-two-objects "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}{}" "$A" "$B"
case_env refuse-not-utf8 "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"\xff\xfe\"}" "$A" "$B"

# A message from A to B: envelope/accept-minimal.json encrypted to B's prekey, made once and
# kept (age is randomised), then signed for B only.
[ -e message/a-to-b.age ] || age -r "$(cat input/b-1.pq)" -o message/a-to-b.age < envelope/accept-minimal.json
sign a "crossbot-msg-v1:$B" < message/a-to-b.age > message/a-to-b.age.sig
sign a "crossbot-msg-v1:$A" < message/a-to-b.age > message/a-to-b.age.for-another-box.sig
