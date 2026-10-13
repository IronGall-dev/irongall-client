#!/usr/bin/env bash
# Regenerates the irongall v1 test vectors with stock tools only: bash, od, base64, fold,
# sha256sum and ssh-keygen, plus age >= 1.3 for the one ciphertext.
# Everything is deterministic (Ed25519 signatures are), except what is made once and kept:
# each certificate (ssh-keygen puts a random nonce in one, and an ECDSA signature differs each
# time it is made) and message/a-to-b.age.
# Inputs are in input/: every Ed25519 key is a PUBLISHED test key of RFC 8032 (§7.1: the
# identities of A and B are TEST 1 and TEST 2, their working keys TEST 3, TEST 1024 and
# TEST SHA(abc); §7.2: C's working key is the first Ed25519ctx test's key), C's P-256 identity
# is the PUBLISHED test key of RFC 6979 §A.2.5, and the age recipients' secret keys were
# discarded. Every vector is judged at the time in ./now.
set -euo pipefail
umask 077
cd "$(dirname "$0")"
NOW=2026-10-10T00:00:00Z
NOT_AFTER=2026-11-12T00:00:00Z # NOW + 33 days exactly: the longest a prekey may be valid
MSG_ID=6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b
# A certificate's validity, as ssh-keygen -V takes it. A client asks for 65 days from a minute before now.
V_OK=20261009235900Z:20261214000000Z
V_SHORT=20261009235900Z:20261020000000Z    # ends 10 days after NOW: a 33-day prekey statement outlives it
V_ENDED=20260801000000Z:20261010000000Z    # ends at NOW
V_NOT_BEGUN=20261010000001Z:20261214000000Z
V_TOO_LONG=20261009235900Z:20261215000001Z # ends 66 days and a second after NOW

# Hex helpers. Binary goes through hex strings, never through shell variables.
asc() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }
str() { printf '%08x%s' $(( ${#1} / 2 )) "$1"; }           # an RFC 4251 string, from hex
bin() { printf "$(printf '%s' "$1" | sed 's/../\\x&/g')"; } # hex → bytes on stdout
b64() { base64 | tr -d '\n'; }

# An unencrypted OpenSSH private key file, from the public key and the private part as the format writes each, in hex.
keyfile() { # <public key hex> <private part hex> <file>
  local priv pad="" n i=1
  priv=0000000000000000$1$2$(str "")
  n=$(( ${#priv} / 2 )); while (( n % 8 )); do pad+=$(printf '%02x' $i); i=$((i + 1)); n=$((n + 1)); done
  { echo '-----BEGIN OPENSSH PRIVATE KEY-----'
    bin "$(asc openssh-key-v1)00$(str "$(asc none)")$(str "$(asc none)")$(str "")00000001$(str "$1")$(str "$priv$pad")" | b64 | fold -w 70; echo
    echo '-----END OPENSSH PRIVATE KEY-----'; } > "$3"
}
# An Ed25519 key file, from the seed and public key in hex.
openssh_key() { keyfile "$(str "$(asc ssh-ed25519)")$(str "$2")" "$(str "$1$2")" "$3"; } # <seed hex> <public hex> <file>
# A P-256 public key in SSH wire form, in hex: <the point, hex> [curve name].
p256_wire() { printf '%s' "$(str "$(asc ecdsa-sha2-nistp256)")$(str "$(asc "${2:-nistp256}")")$(str "$1")"; }
# A P-256 key file, from the private scalar and the public point (x then y) in hex. The scalar is written as a
# signed number, so one whose first bit is set takes a leading 00.
openssh_p256_key() { local d=$1; [[ $d =~ ^[89a-f] ]] && d=00$d; keyfile "$(p256_wire "04$2")" "$(str "$d")" "$3"; } # <scalar hex> <point hex> <file>
# An identity document for a raw 32-byte Ed25519 key in hex, valid or not.
identity_doc() { printf 'irongall-v1\nssh-ed25519 %s\n' "$(bin "$(str "$(asc ssh-ed25519)")$(str "$1")" | b64)"; }
# An identity document for a P-256 point in hex, valid or not: <the point, hex> [curve name].
p256_doc() { printf 'irongall-v1\necdsa-sha2-nistp256 %s\n' "$(bin "$(p256_wire "$@")" | b64)"; }

KEYS=$(mktemp -d) # private keys live only here, and only while this runs
cleanup() { local k; for k in a b c a-work b-work a-work-2 c-work; do rm -f "$KEYS/$k" "$KEYS/$k.pub" "$KEYS/$k-cert.pub"; done; rmdir "$KEYS"; }
trap cleanup EXIT

printf '%s\n' "$NOW" > now
mkdir -p a b c message identity prekey envelope cert plain
for box in a b a-work b-work a-work-2 c-work; do
  { read -r seed; read -r pub; } < "input/$box.ed25519"
  openssh_key "$seed" "$pub" "$KEYS/$box"
  ssh-keygen -y -f "$KEYS/$box" > "$KEYS/$box.pub"
  [ "$(cut -d' ' -f2 "$KEYS/$box.pub")" = "$(bin "$(str "$(asc ssh-ed25519)")$(str "$pub")" | b64)" ] || { echo "the $box key file does not hold the RFC 8032 key" >&2; exit 1; }
done
for box in a b; do
  printf 'irongall-v1\n%s\n' "$(cut -d' ' -f1,2 "$KEYS/$box.pub")" > "$box/identity.doc"
  sha256sum < "$box/identity.doc" | cut -c1-64 > "$box/address"
done
A=$(cat a/address); B=$(cat b/address)

# Box C, whose identity is of the optional type ecdsa-sha2-nistp256.
{ read -r scalar; read -r POINT; } < input/c.p256
openssh_p256_key "$scalar" "$POINT" "$KEYS/c"
ssh-keygen -y -f "$KEYS/c" > "$KEYS/c.pub"
[ "$(cut -d' ' -f2 "$KEYS/c.pub")" = "$(bin "$(p256_wire "04$POINT")" | b64)" ] || { echo "the c key file does not hold the RFC 6979 key" >&2; exit 1; }
printf 'irongall-v1\n%s\n' "$(cut -d' ' -f1,2 "$KEYS/c.pub")" > c/identity.doc
sha256sum < c/identity.doc | cut -c1-64 > c/address
C=$(cat c/address)

# A certificate: what "ssh-keygen -s" writes for a working key, made once and kept without its comment.
cert() { # <kept file> <signing key> <certified key> <ssh-keygen options…>
  local keep=$1 ca=$2 key=$3; shift 3
  [ -e "$keep" ] || { ssh-keygen -q -s "$KEYS/$ca" "$@" "$KEYS/$key.pub" && cut -d' ' -f1,2 "$KEYS/$key-cert.pub" > "$keep"; }
}
good() { echo -I irongall-cert-v1 -n "$1" -z "${2:-1}" -V "${3:-$V_OK}" -O clear; } # <address> [serial] [validity] → the options of a certificate every check passes
sign() { ssh-keygen -q -Y sign -n "$2" -f "$KEYS/$1" "${@:3}"; } # <key> <namespace> [-O …] < message > signature, by a bare key: an identity's, for a revocation
under() { cp "$2" "$KEYS/$1-cert.pub"; ssh-keygen -q -Y sign -n "$3" -f "$KEYS/$1-cert.pub" "${@:4}"; } # <working key> <certificate> <namespace> [-O …] < message > signature under that certificate
statement() { printf 'irongall-prekey-v1\n%s\n%s\n%s\n%s\n' "$@"; } # <address> <serial> <recipient> <not_after>

# Each box's working key, certified by its identity.
cert a/work-cert.pub a a-work $(good "$A")
cert b/work-cert.pub b b-work $(good "$B")
cert c/work-cert.pub c c-work $(good "$C")

# The two boxes, their prekeys and A's revocation.
statement "$A" 1 "$(cat input/a-1.pq)" "$NOT_AFTER" > a/prekey-1.txt
statement "$A" 2 "$(cat input/a-2.classic)" "$NOT_AFTER" > a/prekey-2.txt
statement "$B" 1 "$(cat input/b-1.pq)" "$NOT_AFTER" > b/prekey-1.txt
for f in a/prekey-1 a/prekey-2; do under a-work a/work-cert.pub "irongall-prekey-v1:$A" < "$f.txt" > "$f.txt.sig"; done
under a-work a/work-cert.pub "irongall-prekey-v1:$A" -O hashalg=sha256 < a/prekey-1.txt > a/prekey-1.txt.sha256.sig
under b-work b/work-cert.pub "irongall-prekey-v1:$B" < b/prekey-1.txt > b/prekey-1.txt.sig
statement "$C" 1 "$(cat input/c-1.classic)" "$NOT_AFTER" > c/prekey-1.txt
under c-work c/work-cert.pub "irongall-prekey-v1:$C" < c/prekey-1.txt > c/prekey-1.txt.sig
printf 'irongall-revoke-v1\n%s\n' "$A" > a/revoke.txt
sign a "irongall-revoke-v1:$A" < a/revoke.txt > a/revoke.sig

# A pass of box A for a server it calls irongall.example, good for ten minutes from NOW, and the header it travels in.
printf 'irongall-pass-v1\n%s\nirongall.example\n2026-10-10T00:10:00Z\n' "$A" > a/pass.txt
under a-work a/work-cert.pub "irongall-pass-v1:$A" < a/pass.txt > a/pass.sig
printf 'irongall-pass address="%s", not_after="2026-10-10T00:10:00Z", signature="%s"\n' "$A" "$(b64 < a/pass.sig)" > a/pass.authorization

# Certificates every implementation must refuse for box A at ./now, each with a signature made under
# it over a/prekey-1.txt in A's prekey namespace: the signature itself is good, the certificate is not.
badcert() { # <name> <signing key> <certified key> <ssh-keygen options…>
  local name=$1 key=$3
  cert "cert/$name.pub" "${@:2}"
  under "$key" "cert/$name.pub" "irongall-prekey-v1:$A" < a/prekey-1.txt > "cert/$name.sig"
}
badcert bad-extensions a a-work -I irongall-cert-v1 -n "$A" -z 1 -V "$V_OK" # no -O clear: ssh-keygen adds five extensions
badcert bad-critical-option a a-work $(good "$A") -O force-command=true
badcert bad-key-id a a-work -I irongall-cert-v2 -n "$A" -z 1 -V "$V_OK" -O clear
badcert bad-two-principals a a-work -I irongall-cert-v1 -n "$A,$B" -z 1 -V "$V_OK" -O clear
badcert bad-principal-another-box a a-work $(good "$B")
badcert bad-serial-zero a a-work $(good "$A" 0)
badcert bad-host-certificate a a-work $(good "$A") -h
badcert bad-signed-by-b b a-work $(good "$A")
badcert bad-certifies-the-identity a a $(good "$A")
badcert bad-ended a a-work $(good "$A" 1 "$V_ENDED")
badcert bad-not-begun a a-work $(good "$A" 1 "$V_NOT_BEGUN")
badcert bad-too-long a a-work $(good "$A" 1 "$V_TOO_LONG")

# Identity documents every implementation must reject.
GOOD=$(sed -n 2p a/identity.doc)
printf 'irongall-v1\n%s comment\n' "$GOOD" > identity/comment.doc
printf 'irongall-v1\r\n%s\r\n' "$GOOD" > identity/crlf.doc
printf 'irongall-v1\n%s' "$GOOD" > identity/no-final-newline.doc
printf 'irongall-v1\n%s\n \n' "$GOOD" > identity/padded.doc
printf 'irongall-v2\n%s\n' "$GOOD" > identity/wrong-tag.doc
printf 'irongall-v1\nssh-rsa %s\n' "$(cut -d' ' -f2 "$KEYS/a.pub")" > identity/key-type-mismatch.doc
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
# The same for the P-256 type. With p the field's size and n the group's order: a point is 04, x, y, and OpenSSH
# refuses a coordinate of 128 bits or fewer, or of n - 1 or more, which no key made from a private key has.
GOOD_C=$(sed -n 2p c/identity.doc); X=${POINT:0:64}; Y=${POINT:64}
Y5=459243b9aa581806fe913bce99817ade11ca503c64d9a3c533415c083248fbcc # a square root of 5^3 - 3*5 + b mod p: (5, Y5) is on the curve
printf 'irongall-v1\n%s comment\n' "$GOOD_C" > identity/p256-comment.doc
p256_doc "0$((2 + (0x${Y: -1} & 1)))$X" > identity/p256-compressed.doc # 02 or 03 by y's last bit, then x: the same key, in the encoding the format does not take
p256_doc "04$POINT" nistp384 > identity/p256-curve-name-mismatch.doc
p256_doc "04${POINT}00" > identity/p256-trailing-byte.doc
p256_doc "04$X${Y:0:63}$(printf '%x' $((0x${Y: -1} ^ 1)))" > identity/p256-off-curve.doc # y with its last bit flipped
p256_doc "04ffffffff00000001000000000000000000000001000000000000000000000004$Y5" > identity/p256-coordinate-not-reduced.doc # x = p + 5: the point (5, Y5), x not reduced
p256_doc "040000000000000000000000000000000000000000000000000000000000000005$Y5" > identity/p256-short-coordinate.doc # x = 5: on the curve; the Go library takes it and OpenSSH does not
p256_doc "04ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632554484f0c0fda434ef0a808458914f328715d7a545e198ac7eee31dffe861b5d23f" > identity/p256-coordinate-over-order.doc # x = n + 3, the first from n - 1 up that is on the curve; likewise
# A well-formed document of a key type no client verifies: a name, and a wire key that begins with that name.
NOTYPE=no-such-key-type@irongall.invalid
printf 'irongall-v1\n%s %s\n' "$NOTYPE" "$(bin "$(str "$(asc "$NOTYPE")")$(str "$(asc 'not a key')")" | b64)" > identity/unsupported-type.doc
# A NUL byte, which a shell variable drops and a C string ends at. Each of the first four is as long as a good
# document: one line feed is gone and the NUL is in its place, or elsewhere.
printf 'irongall-v1\n%s\0' "$GOOD" > identity/nul-for-the-final-newline.doc
printf 'iron\0gall-v1\n%s' "$GOOD" > identity/nul-in-the-tag.doc
printf 'irongall-v1\n%s\0%s' "${GOOD:0:40}" "${GOOD:40}" > identity/nul-in-the-key.doc
printf 'irongall-v1\n%s\0' "$GOOD_C" > identity/p256-nul-for-the-final-newline.doc
printf 'irongall-v1\n%s\0' "$(sed -n 2p identity/unsupported-type.doc)" > identity/nul-in-an-unknown-type.doc

# Prekey statements of box A. bad-*: signature or format must be refused. expired-*: valid, but
# expired at ./now, so a sender must not encrypt to it. too-long-*: valid and not expired, but a
# server must refuse to publish it. Each is signed by A in A's prekey namespace unless its name
# says otherwise.
PQ=$(cat input/a-1.pq)
bad() { local name=$1; shift; printf "$@" > "prekey/$name.txt"; under a-work a/work-cert.pub "irongall-prekey-v1:$A" < "prekey/$name.txt" > "prekey/$name.txt.sig"; }
cp a/prekey-1.txt prekey/bad-wrong-namespace.txt; under a-work a/work-cert.pub "irongall-msg-v1:$A" < a/prekey-1.txt > prekey/bad-wrong-namespace.txt.sig
cp a/prekey-1.txt prekey/bad-signed-by-b.txt; under b-work b/work-cert.pub "irongall-prekey-v1:$A" < a/prekey-1.txt > prekey/bad-signed-by-b.txt.sig
cp a/prekey-1.txt prekey/bad-signed-by-the-identity.txt; sign a "irongall-prekey-v1:$A" < a/prekey-1.txt > prekey/bad-signed-by-the-identity.txt.sig
cp a/prekey-1.txt prekey/bad-signed-by-a-bare-working-key.txt; sign a-work "irongall-prekey-v1:$A" < a/prekey-1.txt > prekey/bad-signed-by-a-bare-working-key.txt.sig
# A statement may not outlive the certificate it is signed under: this one's certificate ends in 10 days.
cert prekey/bad-outlives-its-certificate.cert.pub a a-work-2 $(good "$A" 2 "$V_SHORT")
cp a/prekey-1.txt prekey/bad-outlives-its-certificate.txt; under a-work-2 prekey/bad-outlives-its-certificate.cert.pub "irongall-prekey-v1:$A" < a/prekey-1.txt > prekey/bad-outlives-its-certificate.txt.sig
bad bad-names-another-box 'irongall-prekey-v1\n%s\n1\n%s\n%s\n' "$B" "$PQ" "$NOT_AFTER"
bad bad-serial-zero 'irongall-prekey-v1\n%s\n0\n%s\n%s\n' "$A" "$PQ" "$NOT_AFTER"
bad bad-serial-leading-zero 'irongall-prekey-v1\n%s\n01\n%s\n%s\n' "$A" "$PQ" "$NOT_AFTER"
bad bad-serial-19-digits 'irongall-prekey-v1\n%s\n1000000000000000000\n%s\n%s\n' "$A" "$PQ" "$NOT_AFTER"
bad bad-serial-negative 'irongall-prekey-v1\n%s\n-1\n%s\n%s\n' "$A" "$PQ" "$NOT_AFTER"
bad bad-never 'irongall-prekey-v1\n%s\n1\n%s\nnever\n' "$A" "$PQ"
bad bad-time-lowercase-z 'irongall-prekey-v1\n%s\n1\n%s\n2026-11-11T00:00:00z\n' "$A" "$PQ"
bad bad-time-fraction 'irongall-prekey-v1\n%s\n1\n%s\n2026-11-11T00:00:00.5Z\n' "$A" "$PQ"
bad bad-time-offset 'irongall-prekey-v1\n%s\n1\n%s\n2026-11-11T00:00:00+00:00\n' "$A" "$PQ"
bad bad-tag 'irongall-prekey-v2\n%s\n1\n%s\n%s\n' "$A" "$PQ" "$NOT_AFTER"
bad bad-address-uppercase 'irongall-prekey-v1\n%s\n1\n%s\n%s\n' "$(printf '%s' "$A" | tr a-f A-F)" "$PQ" "$NOT_AFTER"
bad bad-four-lines 'irongall-prekey-v1\n%s\n1\n%s\n' "$A" "$PQ"
bad bad-six-lines 'irongall-prekey-v1\n%s\n1\n%s\n%s\n\n' "$A" "$PQ" "$NOT_AFTER"
bad bad-crlf 'irongall-prekey-v1\r\n%s\r\n1\r\n%s\r\n%s\r\n' "$A" "$PQ" "$NOT_AFTER"
bad bad-no-final-newline 'irongall-prekey-v1\n%s\n1\n%s\n%s' "$A" "$PQ" "$NOT_AFTER"
bad bad-recipient-uppercase-pq 'irongall-prekey-v1\n%s\n1\n%s\n%s\n' "$A" "$(printf '%s' "$PQ" | tr a-z A-Z)" "$NOT_AFTER"
bad bad-recipient-uppercase-classic 'irongall-prekey-v1\n%s\n2\n%s\n%s\n' "$A" "$(tr a-z A-Z < input/a-2.classic)" "$NOT_AFTER"
bad bad-recipient-not-age 'irongall-prekey-v1\n%s\n1\n%s\n%s\n' "$A" "$GOOD" "$NOT_AFTER"
bad bad-recipient-small-order-pq 'irongall-prekey-v1\n%s\n1\n%s\n%s\n' "$A" "$(cat input/small-order.pq)" "$NOT_AFTER"
bad bad-recipient-small-order-classic 'irongall-prekey-v1\n%s\n1\n%s\n%s\n' "$A" "$(cat input/small-order.classic)" "$NOT_AFTER"
bad expired 'irongall-prekey-v1\n%s\n1\n%s\n%s\n' "$A" "$PQ" "$NOW"
bad too-long 'irongall-prekey-v1\n%s\n1\n%s\n2026-11-12T00:00:01Z\n' "$A" "$PQ"

# Envelopes, judged as a message whose signature by A verified, received by box B, at ./now.
case_env() { local name=$1; shift; printf "$@" > "envelope/$name.json"; }
H='"v":1,"from":"%s","to":"%s"'
case_env accept-minimal "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env accept-every-field "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\",\"subject\":\"hi\",\"in_reply_to\":\"$MSG_ID\",\"supersedes\":\"$MSG_ID\",\"identity\":\"$(b64 < a/identity.doc)\"}" "$A" "$B"
case_env accept-json-body "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":{\"task\":\"ping\",\"n\":1}}" "$A" "$B"
case_env accept-null-body "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":null}" "$A" "$B"
case_env accept-unknown-field "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\",\"later\":true}" "$A" "$B"
case_env accept-33-days-old "{$H,\"sent_at\":\"2026-09-07T00:00:00Z\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-33-days-and-1s-old "{$H,\"sent_at\":\"2026-09-06T23:59:59Z\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
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

# A message from A to B. What is encrypted is three parts: the envelope as one line, the
# signature over that line as ssh-keygen wrote it, and padding. The line carries A's identity
# document, and the signature is by A's working key, for B only.
ID_A=$(b64 < a/identity.doc); ID_B=$(b64 < b/identity.doc)
line() { printf '{"v":1,"from":"%s","to":"%s","sent_at":"%s","msg_id":"%s","identity":"%s","body":"hello"}\n' "$1" "$2" "$NOW" "$MSG_ID" "$3"; } # <from> <to> <identity, base64>
line "$A" "$B" "$ID_A" > message/a-to-b.line
under a-work a/work-cert.pub "irongall-msg-v1:$B" < message/a-to-b.line > message/a-to-b.sig
# Padding makes the age file a whole number of 1 KiB blocks (PROTOCOL.md §4.3a). To a post-quantum
# key a file of one chunk is its plaintext and 1,659 bytes more.
n=$(( $(wc -c < message/a-to-b.line) + $(wc -c < message/a-to-b.sig) ))
SEALED=$(( (1659 + n + 1023) / 1024 * 1024 ))
{ cat message/a-to-b.line message/a-to-b.sig; head -c $((SEALED - 1659 - n)) /dev/zero | tr '\0' .; } > message/a-to-b.plain
[ -e message/a-to-b.age ] || age -r "$(cat input/b-1.pq)" -o message/a-to-b.age < message/a-to-b.plain
[ "$(wc -c < message/a-to-b.age)" -eq "$SEALED" ] || { echo "message/a-to-b.age is not the $SEALED bytes its padding was made for" >&2; exit 1; }

# What box B decrypts, judged at ./now: accept-* are delivered, refuse-* are not.
GOOD_SIG=message/a-to-b.sig
cat message/a-to-b.line "$GOOD_SIG" > plain/accept-no-padding.txt
cp message/a-to-b.plain plain/accept-padded.txt
{ cat message/a-to-b.line "$GOOD_SIG"; cat message/a-to-b.line; under b-work b/work-cert.pub "irongall-msg-v1:$B" < message/a-to-b.line; echo "nothing after the first END line is read"; } > plain/accept-anything-after-the-signature.txt
printf '{"v":1,"from":"%s","to":"%s","sent_at":"%s","msg_id":"%s","identity":"%s","body":{"task":"ping"},"subject":"hi","in_reply_to":"%s","supersedes":"%s","later":true}\n' "$A" "$B" "$NOW" "$MSG_ID" "$ID_A" "$MSG_ID" "$MSG_ID" > plain/every-field.line
{ cat plain/every-field.line; under a-work a/work-cert.pub "irongall-msg-v1:$B" < plain/every-field.line; } > plain/accept-every-field.txt
rm plain/every-field.line
refuse() { # <name> <line file> <signature command…>: the line, then the signature the command makes over it
  local name=$1 l=$2; shift 2
  { cat "$l"; "$@" < "$l"; } > "plain/$name.txt"
}
L=$(mktemp)
# The signature.
refuse refuse-signed-for-another-box message/a-to-b.line under a-work a/work-cert.pub "irongall-msg-v1:$A"
refuse refuse-signed-by-the-identity message/a-to-b.line sign a "irongall-msg-v1:$B"
refuse refuse-signed-by-a-bare-working-key message/a-to-b.line sign a-work "irongall-msg-v1:$B"
refuse refuse-certificate-ended message/a-to-b.line under a-work cert/bad-ended.pub "irongall-msg-v1:$B"
sed 's/"body":"hello"/"body":"hellp"/' message/a-to-b.line > "$L"; cat "$L" "$GOOD_SIG" > plain/refuse-line-changed-after-signing.txt
# A sender whose identity is of the optional type: delivered by a client that verifies ecdsa-sha2-nistp256, and refused
# with unsupported_key_type by one that does not. Then one of a type nobody verifies: refused so if the document is
# the sender's, and as reattributed if it is not.
line "$C" "$B" "$(b64 < c/identity.doc)" > "$L"; refuse accept-p256-sender "$L" under c-work c/work-cert.pub "irongall-msg-v1:$B"
line "$(sha256sum < identity/unsupported-type.doc | cut -c1-64)" "$B" "$(b64 < identity/unsupported-type.doc)" > "$L"; refuse refuse-unsupported-key-type "$L" under a-work a/work-cert.pub "irongall-msg-v1:$B"
line "$A" "$B" "$(b64 < identity/unsupported-type.doc)" > "$L"; refuse refuse-from-is-not-the-identity-of-an-unknown-type "$L" under a-work a/work-cert.pub "irongall-msg-v1:$B"
# Who it is from. The first is the forgery an identity member invites: A's document beside a
# certificate that B's identity signed. The signature is good and the certificate is B's own.
refuse refuse-another-box-s-identity-document message/a-to-b.line under b-work b/work-cert.pub "irongall-msg-v1:$B"
line "$B" "$B" "$ID_A" > "$L"; refuse refuse-from-is-not-the-identity "$L" under a-work a/work-cert.pub "irongall-msg-v1:$B"
printf '{"v":1,"from":"%s","to":"%s","sent_at":"%s","msg_id":"%s","body":"hello"}\n' "$A" "$B" "$NOW" "$MSG_ID" > "$L"; refuse refuse-no-identity "$L" under a-work a/work-cert.pub "irongall-msg-v1:$B"
line "$A" "$B" "not base64" > "$L"; refuse refuse-identity-not-base64 "$L" under a-work a/work-cert.pub "irongall-msg-v1:$B"
line "$(sha256sum < identity/small-order-1.doc | cut -c1-64)" "$B" "$(b64 < identity/small-order-1.doc)" > "$L"; refuse refuse-identity-of-small-order "$L" under a-work a/work-cert.pub "irongall-msg-v1:$B"
line "$A" "$A" "$ID_A" > "$L"; refuse refuse-to-another-box "$L" under a-work a/work-cert.pub "irongall-msg-v1:$B"
# The layout. Each part has one place, and nothing is searched for.
head -c -1 message/a-to-b.line > plain/refuse-no-line-feed.txt
cp message/a-to-b.line plain/refuse-no-signature.txt
{ cat message/a-to-b.line; echo; cat "$GOOD_SIG"; } > plain/refuse-blank-line-before-the-signature.txt
cat "$GOOD_SIG" message/a-to-b.line > plain/refuse-signature-first.txt
{ cat message/a-to-b.line; grep -v -e '-----END' "$GOOD_SIG"; } > plain/refuse-no-end-line.txt
{ cat message/a-to-b.line; head -c -1 "$GOOD_SIG"; } > plain/refuse-end-line-without-its-line-feed.txt
sed 's/$/\r/' message/a-to-b.line > "$L"; { cat "$L"; under a-work a/work-cert.pub "irongall-msg-v1:$B" < "$L" | sed 's/$/\r/'; } > plain/refuse-crlf.txt
printf '{\n"v":1,"from":"%s","to":"%s","sent_at":"%s","msg_id":"%s","identity":"%s","body":"hello"}\n' "$A" "$B" "$NOW" "$MSG_ID" "$ID_A" > "$L"; refuse refuse-envelope-on-two-lines "$L" under a-work a/work-cert.pub "irongall-msg-v1:$B"
rm -f "$L"
