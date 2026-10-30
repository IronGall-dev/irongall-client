#!/usr/bin/env bash
# Regenerates the dromas v1 test vectors with stock tools only: bash, od, base64, fold,
# sha256sum, ssh-keygen, openssl (dgst -sha384) and base32, plus age >= 1.3 for the two ciphertexts.
# Everything is deterministic (Ed25519 signatures are), except what is made once and kept:
# each certificate (ssh-keygen puts a random nonce in one, and an ECDSA signature differs each
# time it is made) and each message/*.age.
# Inputs are in input/: every Ed25519 key is a PUBLISHED test key of RFC 8032 (§7.1: the
# identities of A and B are TEST 1 and TEST 2, their working keys TEST 3, TEST 1024 and
# TEST SHA(abc); §7.2: C's working key is the first Ed25519ctx test's key), C's P-256 identity
# is the PUBLISHED test key of RFC 6979 §A.2.5. B's and C's prekeys are the PUBLISHED test identities of the
# C2SP age testkit (CCTV age/internal/testkit: TestHybridIdentity, TestX25519Identity), in input/b-1.pq.key and
# input/c-1.classic.key, so the two messages decrypt with any age; the other age recipients' secret keys were
# discarded. Every vector is judged at the time in ./now.
set -euo pipefail
umask 077
cd "$(dirname "$0")"
NOW=2026-10-10T00:00:00Z
NOT_AFTER=2026-11-12T00:00:00Z # NOW + 33 days exactly: what a client asks for. A server takes one that ends up to an hour later
MSG_ID=6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b
# A certificate's validity, as ssh-keygen -V takes it. These begin a minute before NOW, where a client
# dates its own from an hour back (PROTOCOL.md §5): a verifier asks only that one has begun.
V_OK=20261009235900Z:20261213000000Z # ends 64 days after NOW: what a client asks for
V_BEGINS_NOW=20261010000000Z:20261213000000Z # begins at NOW: begun
V_SHORT=20261009235900Z:20261020000000Z    # ends 10 days after NOW: a 33-day prekey statement outlives it
V_ENDED=20260801000000Z:20261010000000Z    # ends at NOW
V_NOT_BEGUN=20261010000001Z:20261213000000Z
V_TOO_LONG=20261009235900Z:20261213010001Z # ends 64 days, an hour and a second after NOW: a second past what a verifier takes

# Hex helpers. Binary goes through hex strings, never through shell variables.
asc() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }
str() { printf '%08x%s' $(( ${#1} / 2 )) "$1"; }           # an RFC 4251 string, from hex
bin() { printf "$(printf '%s' "$1" | sed 's/../\\x&/g')"; } # hex → bytes on stdout
b64() { base64 | tr -d '\n'; }
address() { openssl dgst -sha384 -binary | base32 -w 0 | tr -d = | tr A-Z a-z; echo; } # stdin → its SHA-384 in base32 (RFC 4648 §6), lowercase, without padding, as an address file holds it
# An age recipient as age writes one: Bech32 (BIP 173) of bytes under a human-readable part, in lowercase, with no
# limit on its length (age has none).
bech32() { # <human-readable part> <bytes, hex>
  local h=$1 x=$2 cs=qpzry9x8gf2tvdw0s3jn54khce6mua7l v=() d=() acc=0 bits=0 chk=1 top i k out="" g=(0x3b6a57b2 0x26508e6d 0x1ea119fa 0x3d4233dd 0x2a1462b3)
  for ((i = 0; i < ${#h}; i++)); do v+=($(($(printf %d "'${h:i:1}") >> 5))); done; v+=(0)
  for ((i = 0; i < ${#h}; i++)); do v+=($(($(printf %d "'${h:i:1}") & 31))); done
  for ((i = 0; i < ${#x}; i += 2)); do acc=$(((acc << 8) | 16#${x:i:2})); bits=$((bits + 8))
    while ((bits >= 5)); do bits=$((bits - 5)); d+=($(((acc >> bits) & 31))); done; acc=$((acc & ((1 << bits) - 1))); done
  ((bits == 0)) || d+=($(((acc << (5 - bits)) & 31)))
  for k in "${v[@]}" "${d[@]}" 0 0 0 0 0 0; do top=$((chk >> 25)); chk=$((((chk & 0x1ffffff) << 5) ^ k)); for i in 0 1 2 3 4; do ((top >> i & 1)) && chk=$((chk ^ g[i])); done; done
  chk=$((chk ^ 1)); for k in "${d[@]}"; do out+=${cs:k:1}; done; for i in 0 1 2 3 4 5; do out+=${cs:$(((chk >> (25 - 5 * i)) & 31)):1}; done
  printf '%s1%s' "$h" "$out"
}
# An armored signature: its blob, from hex, as ssh-keygen writes one; and the other way, a blob in hex from a signature ssh-keygen wrote.
armor() { printf -- '-----BEGIN SSH SIGNATURE-----\n'; bin "$1" | b64 | fold -w 70; printf -- '\n-----END SSH SIGNATURE-----\n'; }
blob() { sed '1d;$d' "$1" | tr -d '\n' | base64 -d | od -An -v -tx1 | tr -d ' \n'; }
# A blob in hex with S + L in place of the S at a hex offset: the other encoding of an Ed25519 signature's S, which
# RFC 8032 §5.1.7 refuses and ssh-keygen before the cut PROTOCOL.md Appendix A gives takes. S and L are 32 bytes, little-endian.
plusl() { # <blob hex> <hex offset of S>
  local x=$1 o=$2 s=${1:$2:64} l=edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010 r="" c=0 i t
  for ((i = 0; i < 64; i += 2)); do t=$((16#${s:i:2} + 16#${l:i:2} + c)); c=$((t >> 8)); r+=$(printf %02x $((t & 255))); done
  [ "$c" -eq 0 ] || { echo "S + L does not fit in 32 bytes" >&2; exit 1; }
  printf %s "${x:0:o}$r${x:o+64}"
}

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
identity_doc() { printf 'dromas-v1\nssh-ed25519 %s\n' "$(bin "$(str "$(asc ssh-ed25519)")$(str "$1")" | b64)"; }
# An identity document for a P-256 point in hex, valid or not: <the point, hex> [curve name].
p256_doc() { printf 'dromas-v1\necdsa-sha2-nistp256 %s\n' "$(bin "$(p256_wire "$@")" | b64)"; }

KEYS=$(mktemp -d) # private keys live only here, and only while this runs
cleanup() { local k; for k in a b c a-work b-work a-work-2 c-work small-work; do rm -f "$KEYS/$k" "$KEYS/$k.pub" "$KEYS/$k-cert.pub"; done; rm -f "$KEYS/padded.sig"; rmdir "$KEYS"; }
trap cleanup EXIT

printf '%s\n' "$NOW" > now
mkdir -p a b c message identity prekey envelope cert plain
for mailbox in a b a-work b-work a-work-2 c-work; do
  { read -r seed; read -r pub; } < "input/$mailbox.ed25519"
  openssh_key "$seed" "$pub" "$KEYS/$mailbox"
  ssh-keygen -y -f "$KEYS/$mailbox" > "$KEYS/$mailbox.pub"
  [ "$(cut -d' ' -f2 "$KEYS/$mailbox.pub")" = "$(bin "$(str "$(asc ssh-ed25519)")$(str "$pub")" | b64)" ] || { echo "the $mailbox key file does not hold the RFC 8032 key" >&2; exit 1; }
done
for mailbox in a b; do
  printf 'dromas-v1\n%s\n' "$(cut -d' ' -f1,2 "$KEYS/$mailbox.pub")" > "$mailbox/identity.doc"
  address < "$mailbox/identity.doc" > "$mailbox/address"
done
A=$(cat a/address); B=$(cat b/address)

# Mailbox C, whose identity is of the optional type ecdsa-sha2-nistp256.
{ read -r scalar; read -r POINT; } < input/c.p256
openssh_p256_key "$scalar" "$POINT" "$KEYS/c"
ssh-keygen -y -f "$KEYS/c" > "$KEYS/c.pub"
[ "$(cut -d' ' -f2 "$KEYS/c.pub")" = "$(bin "$(p256_wire "04$POINT")" | b64)" ] || { echo "the c key file does not hold the RFC 6979 key" >&2; exit 1; }
printf 'dromas-v1\n%s\n' "$(cut -d' ' -f1,2 "$KEYS/c.pub")" > c/identity.doc
address < c/identity.doc > c/address
C=$(cat c/address)

# A certificate: what "ssh-keygen -s" writes for a working key, made once and kept without its comment.
cert() { # <kept file> <signing key> <certified key> <ssh-keygen options…>
  local keep=$1 ca=$2 key=$3; shift 3
  [ -e "$keep" ] || { ssh-keygen -q -s "$KEYS/$ca" "$@" "$KEYS/$key.pub" && cut -d' ' -f1,2 "$KEYS/$key-cert.pub" > "$keep"; }
}
good() { echo -I dromas-cert-v1 -n "$1" -z "${2:-1}" -V "${3:-$V_OK}" -O clear; } # <address> [serial] [validity] → the options of a certificate every check passes
sign() { ssh-keygen -q -Y sign -n "$2" -f "$KEYS/$1" "${@:3}"; } # <key> <namespace> [-O …] < message > signature, by a bare key: an identity's, for a revocation
under() { cp "$2" "$KEYS/$1-cert.pub"; ssh-keygen -q -Y sign -n "$3" -f "$KEYS/$1-cert.pub" "${@:4}"; } # <working key> <certificate> <namespace> [-O …] < message > signature under that certificate
statement() { printf 'dromas-prekey-v1\n%s\n%s\n%s\n%s\n' "$@"; } # <address> <serial> <recipient> <not_after>

# Each mailbox's working key, certified by its identity.
cert a/work-cert.pub a a-work $(good "$A")
cert b/work-cert.pub b b-work $(good "$B")
cert c/work-cert.pub c c-work $(good "$C")

# The two mailboxes, their prekeys and A's revocation.
for k in b-1.pq c-1.classic; do [ "$(age-keygen -y "input/$k.key")" = "$(cat "input/$k")" ] || { echo "input/$k is not the recipient of input/$k.key" >&2; exit 1; }; done
statement "$A" 1 "$(cat input/a-1.pq)" "$NOT_AFTER" > a/prekey-1.txt
statement "$A" 2 "$(cat input/a-2.classic)" "$NOT_AFTER" > a/prekey-2.txt
statement "$B" 1 "$(cat input/b-1.pq)" "$NOT_AFTER" > b/prekey-1.txt
for f in a/prekey-1 a/prekey-2; do under a-work a/work-cert.pub "dromas-prekey-v1:$A" < "$f.txt" > "$f.txt.sig"; done
under a-work a/work-cert.pub "dromas-prekey-v1:$A" -O hashalg=sha256 < a/prekey-1.txt > a/prekey-1.txt.sha256.sig
under b-work b/work-cert.pub "dromas-prekey-v1:$B" < b/prekey-1.txt > b/prekey-1.txt.sig
statement "$C" 1 "$(cat input/c-1.classic)" "$NOT_AFTER" > c/prekey-1.txt
under c-work c/work-cert.pub "dromas-prekey-v1:$C" < c/prekey-1.txt > c/prekey-1.txt.sig
printf 'dromas-revoke-v1\n%s\n' "$A" > a/revoke.txt
sign a "dromas-revoke-v1:$A" < a/revoke.txt > a/revoke.sig

# Revocations. A's again with the other hash SSHSIG allows, and C's, by a P-256 identity: an ECDSA
# signature differs each time it is made, so C's is made once and kept. Then signatures every
# implementation must refuse as a revocation of mailbox A: by a working key under A's own certificate, by
# another mailbox's identity, in another namespace, and A's signature over the revocation of another mailbox.
mkdir -p revoke
sign a "dromas-revoke-v1:$A" -O hashalg=sha256 < a/revoke.txt > a/revoke.sha256.sig
printf 'dromas-revoke-v1\n%s\n' "$C" > c/revoke.txt
[ -e c/revoke.sig ] || sign c "dromas-revoke-v1:$C" < c/revoke.txt > c/revoke.sig
under a-work a/work-cert.pub "dromas-revoke-v1:$A" < a/revoke.txt > revoke/bad-by-a-working-key.sig
sign b "dromas-revoke-v1:$A" < a/revoke.txt > revoke/bad-by-another-identity.sig
sign a "dromas-prekey-v1:$A" < a/revoke.txt > revoke/bad-another-namespace.sig
X=$(blob a/revoke.sig); armor "$(plusl "$X" $((${#X} - 64)))" > revoke/bad-s-plus-l.sig      # A's own, with L added to its S
printf 'dromas-revoke-v1\n%s\n' "$B" | sign a "dromas-revoke-v1:$B" > revoke/bad-of-another-mailbox.sig

# Revocations of mailbox A's certificates (PROTOCOL.md §10.2): the tag, the address and the serial every certificate up
# to and including which is revoked, each on a line, signed by A's identity itself in A's namespace for them. Then what
# is not one. Each bad-* is signed by A's identity in that namespace, so only what its name says is wrong with it, but
# for the first two.
mkdir -p revoked
through() { printf 'dromas-revoke-certs-v1\n%s\n%s\n' "$2" "$3" > "revoked/$1.txt"; }   # <name> <address> <serial>
thsig() { sign a "dromas-revoke-certs-v1:$A" < "revoked/$1.txt" > "revoked/$1.sig"; }
through ok-through-4 "$A" 4; thsig ok-through-4
through ok-through-the-highest "$A" 9007199254740991; thsig ok-through-the-highest      # 2^53 - 1, the highest serial
sign a "dromas-revoke-certs-v1:$A" -O hashalg=sha256 < revoked/ok-through-4.txt > revoked/ok-through-4.sha256.sig
cp revoked/ok-through-4.txt revoked/bad-by-a-working-key.txt; under a-work a/work-cert.pub "dromas-revoke-certs-v1:$A" < revoked/bad-by-a-working-key.txt > revoked/bad-by-a-working-key.sig
cp revoked/ok-through-4.txt revoked/bad-another-namespace.txt; sign a "dromas-revoke-v1:$A" < revoked/bad-another-namespace.txt > revoked/bad-another-namespace.sig
through bad-another-address "$B" 4; thsig bad-another-address
cp revoked/ok-through-4.txt revoked/bad-s-plus-l.txt; X=$(blob revoked/ok-through-4.sig); armor "$(plusl "$X" $((${#X} - 64)))" > revoked/bad-s-plus-l.sig      # a good one, its signature with L added to S
printf 'dromas-revoke-certs-v1\n%s\n' "$A" > revoked/bad-no-serial.txt; thsig bad-no-serial
through bad-serial-zero "$A" 0; thsig bad-serial-zero
through bad-serial-leading-zero "$A" 04; thsig bad-serial-leading-zero
through bad-serial-19-digits "$A" 1000000000000000000; thsig bad-serial-19-digits
through bad-serial-above-2-53 "$A" 9007199254740992; thsig bad-serial-above-2-53
through bad-a-range "$A" 1-4; thsig bad-a-range
through bad-a-sign "$A" +4; thsig bad-a-sign
through bad-trailing-space "$A" "4 "; thsig bad-trailing-space
printf 'dromas-revoke-certs-v1\n%s\n4\n6\n' "$A" > revoked/bad-a-second-serial.txt; thsig bad-a-second-serial
printf 'dromas-revoke-certs-v1\n%s\n4\n\n' "$A" > revoked/bad-blank-line.txt; thsig bad-blank-line
printf 'dromas-revoked-certs-v1\n%s\n1\n1-4\n' "$A" > revoked/bad-a-list.txt; thsig bad-a-list      # a list of serials and ranges
printf 'dromas-revoke-certs-v1\r\n%s\r\n4\r\n' "$A" > revoked/bad-crlf.txt; thsig bad-crlf
printf 'dromas-revoke-certs-v1\n%s\n4' "$A" > revoked/bad-no-final-newline.txt; thsig bad-no-final-newline
printf 'dromas-revoke-certs-v2\n%s\n4\n' "$A" > revoked/bad-another-tag.txt; thsig bad-another-tag
through bad-address-in-uppercase "$(tr a-z A-Z <<< "$A")" 4; thsig bad-address-in-uppercase
printf 'dromas-revoke-certs-v1\n%s\n4\0\n' "$A" > revoked/bad-nul.txt; thsig bad-nul      # a NUL, which a shell variable drops: a reader that tests the variable alone takes it

# A pass of mailbox A for a server it calls dromas.example, good for ten minutes from NOW, and the header it travels in.
printf 'dromas-pass-v1\n%s\ndromas.example\n2026-10-10T00:10:00Z\n' "$A" > a/pass.txt
under a-work a/work-cert.pub "dromas-pass-v1:$A" < a/pass.txt > a/pass.sig
printf 'dromas-pass address="%s", not_after="2026-10-10T00:10:00Z", signature="%s"\n' "$A" "$(b64 < a/pass.sig)" > a/pass.authorization

# That pass in the forms a server reads (PROTOCOL.md §8, as RFC 9110 §11 lets a recipient): each file is an
# Authorization value with no line feed after it. ok-* is read as the same three values as a/pass.authorization;
# bad-* is no pass. A sender writes only ok-as-a-sender-writes-it.
mkdir -p pass
PT=2026-10-10T00:10:00Z PS=$(b64 < a/pass.sig)
pv() { local name=$1; shift; printf "$@" > "pass/$name.authorization"; } # <name> <printf format…>: \\ in the format is one backslash
pv ok-as-a-sender-writes-it 'dromas-pass address="%s", not_after="%s", signature="%s"' "$A" "$PT" "$PS"
pv ok-the-scheme-in-capitals 'DROMAS-PASS address="%s", not_after="%s", signature="%s"' "$A" "$PT" "$PS"
pv ok-the-scheme-in-mixed-case 'Dromas-Pass address="%s", not_after="%s", signature="%s"' "$A" "$PT" "$PS"
pv ok-the-names-in-capitals 'dromas-pass ADDRESS="%s", Not_After="%s", SIGNATURE="%s"' "$A" "$PT" "$PS"
pv ok-another-order 'dromas-pass signature="%s", address="%s", not_after="%s"' "$PS" "$A" "$PT"
pv ok-no-space-after-a-comma 'dromas-pass address="%s",not_after="%s",signature="%s"' "$A" "$PT" "$PS"
pv ok-spaces-around-commas-and-equals 'dromas-pass address = "%s" , not_after= "%s" ,signature ="%s"' "$A" "$PT" "$PS"
pv ok-tabs-around-commas-and-equals 'dromas-pass address\t=\t"%s"\t,\tnot_after="%s",\tsignature="%s"' "$A" "$PT" "$PS"
pv ok-spaces-after-the-scheme 'dromas-pass   address="%s", not_after="%s", signature="%s"' "$A" "$PT" "$PS"
pv ok-the-address-as-a-token 'dromas-pass address=%s, not_after="%s", signature="%s"' "$A" "$PT" "$PS"
pv ok-empty-list-elements 'dromas-pass ,address="%s",, not_after="%s" , ,signature="%s",' "$A" "$PT" "$PS"
pv ok-a-tab-before-an-empty-element 'dromas-pass \t,address="%s", not_after="%s", signature="%s"' "$A" "$PT" "$PS" # 1*SP, then OWS "," (RFC 9110 §11.4, §5.6.1.2)
pv bad-a-tab-after-the-scheme 'dromas-pass\taddress="%s", not_after="%s", signature="%s"' "$A" "$PT" "$PS"
pv bad-the-scheme-with-a-long-s 'dromas-pa\xc5\xbf\xc5\xbf address="%s", not_after="%s", signature="%s"' "$A" "$PT" "$PS" # a token is ASCII: U+017F folds to s only by Unicode's rules (RFC 9110 §5.6.2)
pv bad-another-scheme 'dromas-pass-v1 address="%s", not_after="%s", signature="%s"' "$A" "$PT" "$PS"
pv bad-no-parameters 'dromas-pass'
pv bad-a-token68 'dromas-pass %s' "$PS"
pv bad-a-parameter-twice 'dromas-pass address="%s", address="%s", not_after="%s", signature="%s"' "$A" "$A" "$PT" "$PS"
pv bad-a-parameter-twice-in-another-case 'dromas-pass address="%s", ADDRESS="%s", not_after="%s", signature="%s"' "$A" "$A" "$PT" "$PS"
pv bad-a-parameter-it-has-not 'dromas-pass address="%s", not_after="%s", signature="%s", server="dromas.example"' "$A" "$PT" "$PS"
pv bad-a-parameter-missing 'dromas-pass address="%s", not_after="%s"' "$A" "$PT"
pv bad-a-backslash-in-a-quoted-value 'dromas-pass address="\\%s", not_after="%s", signature="%s"' "$A" "$PT" "$PS" # a quoted-pair, which RFC 9110 reads as the character after it
pv bad-a-quoted-value-not-closed 'dromas-pass address="%s", not_after="%s", signature="%s' "$A" "$PT" "$PS"
pv bad-not-after-as-a-token 'dromas-pass address="%s", not_after=%s, signature="%s"' "$A" "$PT" "$PS" # ":" is not a token's
pv bad-a-space-in-the-signature 'dromas-pass address="%s", not_after="%s", signature="%s %s"' "$A" "$PT" "${PS:0:8}" "${PS:8}"
pv bad-the-address-in-capitals 'dromas-pass address="%s", not_after="%s", signature="%s"' "$(tr a-z A-Z <<< "$A")" "$PT" "$PS"
pv bad-a-semicolon-between-parameters 'dromas-pass address="%s"; not_after="%s"; signature="%s"' "$A" "$PT" "$PS"
pv bad-a-line-feed-at-the-end 'dromas-pass address="%s", not_after="%s", signature="%s"\n' "$A" "$PT" "$PS"
pv bad-a-quoted-name 'dromas-pass "address"="%s", not_after="%s", signature="%s"' "$A" "$PT" "$PS"
pv bad-no-equals-sign 'dromas-pass address "%s", not_after="%s", signature="%s"' "$A" "$PT" "$PS"
pv bad-a-value-neither-a-token-nor-quoted 'dromas-pass address=@%s, not_after="%s", signature="%s"' "$A" "$PT" "$PS"
pv bad-a-control-character-in-a-quoted-value 'dromas-pass address="\001%s", not_after="%s", signature="%s"' "$A" "$PT" "$PS"
pv bad-an-address-of-63-hex 'dromas-pass address="%s", not_after="%s", signature="%s"' "${A:0:63}" "$PT" "$PS"
pv bad-not-after-not-a-time 'dromas-pass address="%s", not_after="%s", signature="%s"' "$A" 2026-13-10T00:10:00Z "$PS" # month 13, quoted, so it is read to its form
pv bad-the-signature-with-padding-bits-set 'dromas-pass address="%s", not_after="%s", signature="%sLR=="' "$A" "$PT" "${PS:0:${#PS}-4}" # the pattern's, and no writer's: "LQ==" is that byte (RFC 4648 §3.5)
# The longest a value may be (§8: the form a client writes with a signature of the most any identity key type
# allows, 16,384 bytes), made so with empty list elements, one for each byte that signature's base64 is longer than
# A's, and a byte longer.
printf -v PC '%*s' $(( (16384 + 2) / 3 * 4 - ${#PS} )) ''
pv ok-as-long-as-a-pass-can-be 'dromas-pass address="%s", not_after="%s", signature="%s"%s' "$A" "$PT" "$PS" "${PC// /,}"
pv bad-a-byte-longer-than-a-pass-can-be 'dromas-pass address="%s", not_after="%s", signature="%s"%s,' "$A" "$PT" "$PS" "${PC// /,}"

# Certificates every implementation must refuse for mailbox A at ./now, each with a signature made under
# it over a/prekey-1.txt in A's prekey namespace: the signature itself is good, the certificate is not.
badcert() { # <name> <signing key> <certified key> <ssh-keygen options…>
  local name=$1 key=$3
  cert "cert/$name.pub" "${@:2}"
  under "$key" "cert/$name.pub" "dromas-prekey-v1:$A" < a/prekey-1.txt > "cert/$name.sig"
}
badcert bad-critical-option a a-work $(good "$A") -O force-command=true
# Extensions are ignored, each in its one encoding: a name once, in lexical order, and a value nothing or one string that
# is not empty, as Go's x/crypto/ssh reads them. ssh-keygen writes a name twice when told to, and a value of one empty string.
badcert bad-extension-twice a a-work $(good "$A") -O extension:nobody-defines@dromas.invalid -O extension:nobody-defines@dromas.invalid
badcert bad-extension-value-an-empty-string a a-work $(good "$A") -O extension:nobody-defines@dromas.invalid=
badcert bad-key-id a a-work -I dromas-cert-v2 -n "$A" -z 1 -V "$V_OK" -O clear
badcert bad-two-principals a a-work -I dromas-cert-v1 -n "$A,$B" -z 1 -V "$V_OK" -O clear
badcert bad-principal-another-mailbox a a-work $(good "$B")
badcert bad-serial-zero a a-work $(good "$A" 0)
badcert bad-serial-above-2-53 a a-work $(good "$A" 9007199254740992)
badcert bad-host-certificate a a-work $(good "$A") -h
badcert bad-signed-by-b b a-work $(good "$A")
badcert bad-certifies-the-identity a a $(good "$A")
badcert bad-ended a a-work $(good "$A" 1 "$V_ENDED")
badcert bad-not-begun a a-work $(good "$A" 1 "$V_NOT_BEGUN")
badcert bad-too-long a a-work $(good "$A" 1 "$V_TOO_LONG")
# And one every implementation must take, at the edge of the rule bad-not-begun is past.
okcert() { badcert "$@"; }
okcert ok-begins-now a a-work $(good "$A" 1 "$V_BEGINS_NOW")
okcert ok-valid-from-0 a a-work $(good "$A" 1 "always:${V_OK#*:}")      # begins at 0, as -V always: writes it
# Extensions a verifier does not know, and it knows none, are ignored (draft-ietf-sshm-cert-01 §2.1.1): ssh-keygen's five,
# without -O clear, and one nobody defines, with a value, so the slot stays in use (RFC 9170). And one more, made by
# protocol's TestVectorsReservedField, since ssh-keygen writes the reserved field empty: cert/ok-reserved-field, whose
# reserved field holds bytes, which a verifier ignores as well.
okcert ok-extensions a a-work -I dromas-cert-v1 -n "$A" -z 1 -V "$V_OK"
okcert ok-unknown-extension a a-work $(good "$A") -O extension:nobody-defines@dromas.invalid=not-read

# One signature, a/prekey-1.txt.sig, in forms a verifier reads as ssh-keygen -Y verify reads them (OpenSSH's
# sshsig_dearmor), and in a file of at most 4096 bytes in all (PROTOCOL.md §3.2): ok-* are taken, bad-* refused. Then
# what ssh-keygen takes and a verifier here refuses: more than 4096 bytes, and an Ed25519 S that is not below L.
mkdir -p sig
S=a/prekey-1.txt.sig; X=$(blob "$S")
[ "$(armor "$X" | sha256sum)" = "$(sha256sum < "$S")" ] || { echo "armor() does not armor as ssh-keygen does" >&2; exit 1; }
sed 's/$/\r/' "$S" > sig/ok-crlf.sig
sed '1s/$/\r/' "$S" > sig/ok-crlf-after-begin-only.sig
sed "2s/\$/ /; 3s/^/"$'\t'"/" "$S" > sig/ok-space-and-tab.sig
sed "2s/\$/"$'\v'"/; 3s/^/"$'\f'"/" "$S" > sig/ok-vt-and-ff.sig
{ sed '$d' "$S"; echo; tail -n 1 "$S"; } > sig/ok-blank-line-before-end.sig
{ head -n 1 "$S"; sed '1d;$d' "$S" | tr -d '\n'; echo; tail -n 1 "$S"; } > sig/ok-one-line.sig
head -c -1 "$S" > sig/ok-no-line-feed-after-end.sig
{ cat "$S"; echo "nothing after the END line is read"; } > sig/ok-text-after-end.sig
{ cat "$S"; head -c $((4096 - $(wc -c < "$S"))) /dev/zero | tr '\0' .; } > sig/ok-4096-bytes.sig
skip() { echo $(($2 + 8 + 2 * 16#${1:$2:8})); } # <blob hex> <hex offset of a string> → the offset after it
o=$(skip "$X" "$(skip "$X" 20)")      # after the signing key and the namespace: the reserved field, empty
[ "${X:o:8}" = 00000000 ] || { echo "no empty reserved field where it should be" >&2; exit 1; }
armor "${X:0:o}$(str "$(asc 'not read')")${X:o+8}" > sig/ok-reserved-not-empty.sig      # the key signed an empty one
{ cat "$S"; head -c $((4097 - $(wc -c < "$S"))) /dev/zero | tr '\0' .; } > sig/bad-4097-bytes.sig
sed "2s/\$/$(printf "%$((4097 - $(wc -c < "$S")))s" '')/" "$S" > sig/bad-4097-bytes-before-end.sig
sed '1s/$/ /' "$S" > sig/bad-space-after-begin.sig
{ echo "text before the BEGIN line"; cat "$S"; } > sig/bad-text-before-begin.sig
sed '$d' "$S" > sig/bad-no-end-line.sig
sed '$s/^/ /' "$S" > sig/bad-end-line-indented.sig
sed '2s/^./!/' "$S" > sig/bad-not-base64.sig
{ head -n 1 "$S"; printf '\0'; tail -n +2 "$S"; } > sig/bad-nul.sig
# The padding forms need a blob whose length is no multiple of 3. When S's is one, P is S with a byte in its reserved
# field, which a verifier ignores (ok-reserved-not-empty): the padding is then all that is wrong with each.
P=$S; [ $(( ${#X} / 2 % 3 )) -ne 0 ] || { P=$KEYS/padded.sig; armor "${X:0:o}$(str "$(asc .)")${X:o+8}" > "$P"; }
t=$(sed -n 'x;$p' "$P"); p=${t##*[!=]}; t=${t%"$p"}; c=${t: -1}; B64=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/; i=${B64%%"$c"*}      # the last base64 line: its padding p, one = or two, and the character before it
# Before one = the last character has 2 unused bits, before two 4: none may be set yet, and setting the lowest sets one of them.
[ -n "$p" ] && [ $(( ${#i} % (${#p} == 1 ? 4 : 16) )) -eq 0 ] || { echo "the last base64 line has no padding, or its last character already has a padding bit set" >&2; exit 1; }
sed "$(( $(wc -l < "$P") - 1 ))s/$c$p\$/${B64:${#i}+1:1}$p/" "$P" > sig/bad-padding-bits.sig      # one of the unused bits of the last character set
sed "$(( $(wc -l < "$P") - 1 ))s/=*\$//" "$P" > sig/bad-no-padding.sig
armor "$(plusl "$X" $((${#X} - 64)))" > sig/bad-s-plus-l.sig      # the working key's S
armor "$(plusl "$X" $((28 + 2 * 16#${X:20:8} - 64)))" > sig/bad-certificate-s-plus-l.sig      # the identity's S on the certificate, its last 32 bytes
armor "${X}00" > sig/bad-trailing-byte-in-the-blob.sig
# What every OpenSSH build takes, as they all read it (PROTOCOL.md §3.2), and what they all refuse beside each: one NUL as the
# last byte before the END line; version 0; and one NUL at the end of a string nothing signs, which OpenSSH reads with
# sshbuf_get_cstring and builds the signed data without. Two NULs, or version 2, are refused.
content() { printf %s "${1:$2+8:2*16#${1:$2:8}}"; } # <hex> <hex offset of a string> → what the string holds
restr() { printf %s "${1:0:$2}$(str "$3")${1:$(skip "$1" "$2")}"; } # <hex> <hex offset of a string> <what it now holds, hex> → the hex with that string replaced
nuls() { local z; printf -v z '%*s' "${3:-1}" ''; restr "$1" "$2" "$(content "$1" "$2")${z// /00}"; } # <hex> <hex offset of a string> [how many] → that string ending in one NUL more, or as many as given
{ sed '$d' "$S" | head -c -1; printf '\0\n'; tail -n 1 "$S"; } > sig/ok-nul-before-end.sig
{ sed '$d' "$S" | head -c -1; printf '\0\0\n'; tail -n 1 "$S"; } > sig/bad-two-nuls-before-end.sig
armor "${X:0:12}00000000${X:20}" > sig/ok-version-0.sig
armor "${X:0:12}00000002${X:20}" > sig/bad-version-2.sig
o=$(skip "$X" 20)      # the namespace
armor "$(nuls "$X" "$o")" > sig/ok-namespace-nul.sig
armor "$(nuls "$X" "$o" 2)" > sig/bad-namespace-two-nuls.sig
o=$(skip "$X" "$(skip "$X" "$o")")      # the hash name, after the namespace and reserved
armor "$(nuls "$X" "$o")" > sig/ok-hash-nul.sig
o=$(skip "$X" "$o")      # the working key's signature: its type, then its bytes
armor "$(restr "$X" "$o" "$(nuls "$(content "$X" "$o")" 0)")" > sig/ok-type-nul.sig
Y=$(restr "$X" "$o" "$(nuls "$(content "$X" "$o")" 0)"); armor "$(plusl "$Y" $((${#Y} - 64)))" > sig/bad-type-nul-s-plus-l.sig      # and S + L: still Ed25519's, refused
k=$(content "$X" 20); c=$((${#k} - 174))      # the certificate, whose last field is the identity's Ed25519 signature on it, 87 bytes
[ "${k:c:38}" = "00000053$(str "$(asc ssh-ed25519)")" ] || { echo "no Ed25519 signature at the end of the certificate" >&2; exit 1; }
armor "$(restr "$X" 20 "$(restr "$k" "$c" "$(nuls "$(content "$k" "$c")" 0)")")" > sig/ok-certificate-type-nul.sig
armor "$(restr "$X" 20 "$(nuls "$k" 0)")" > sig/bad-certificate-own-type-nul.sig      # the identity signed the certificate's type: OpenSSH checks its signature over the bytes as they came
# Two more, made by protocol's TestVectorsEd25519R, since they need arithmetic on the curve: sig/ok-r-small-order.sig, whose
# R is the neutral point, and sig/bad-r-plus-order-2.sig, whose R has a point of order 2 added. OpenSSH's own Ed25519 from
# 10.6p1 judges both the other way (PROTOCOL.md Appendix A).
# A certificate of a working key of small order, the neutral point, which ssh-keygen certifies as it reads any 32 bytes,
# and a signature under it over a/prekey-1.txt that Ed25519's equation takes, R the neutral point and S zero: the check
# on the working key is all that refuses it.
printf 'ssh-ed25519 %s\n' "$(bin "$(str "$(asc ssh-ed25519)")$(str 01$(printf '%062d' 0))" | b64)" > "$KEYS/small-work.pub"
cert cert/bad-working-key-small-order.pub a small-work $(good "$A")
X=$(blob a/prekey-1.txt.sig); X=$(restr "$X" 20 "$(cut -d' ' -f2 cert/bad-working-key-small-order.pub | base64 -d | od -An -v -tx1 | tr -d ' \n')")
o=$(skip "$X" "$(skip "$X" "$(skip "$X" "$(skip "$X" 20)")")")      # the signature: its type, then R and S in one string
armor "$(restr "$X" "$o" "$(str "$(asc ssh-ed25519)")$(str 01$(printf '%0126d' 0))")" > cert/bad-working-key-small-order.sig
# A revocation's key is the identity's own, and nothing signs it: its type may end in a NUL, and a P-256 key's curve
# too. And C's ECDSA signature with r at the most OpenSSH reads, 2,049 bytes with the zeros before it, and a byte over.
X=$(blob a/revoke.sig)
armor "$(restr "$X" 20 "$(nuls "$(content "$X" 20)" 0)")" > revoke/ok-key-type-nul.sig
X=$(blob c/revoke.sig); k=$(content "$X" 20)
armor "$(restr "$X" 20 "$(nuls "$k" "$(skip "$k" 0)")")" > revoke/c-ok-curve-nul.sig
o=$(skip "$X" "$(skip "$X" "$(skip "$X" "$(skip "$X" 20)")")")      # the signature: its type, then r and s in one string
g=$(content "$X" "$o"); i=$(skip "$g" 0); rs=$(content "$g" "$i"); n=$((16#${rs:0:8}))
for want in 2049:ok 2050:bad; do
  printf -v z '%*s' $((${want%:*} - n)) ''
  armor "$(restr "$X" "$o" "$(restr "$g" "$i" "$(restr "$rs" 0 "${z// /00}$(content "$rs" 0)")")")" > "revoke/c-${want#*:}-r-${want%:*}-bytes.sig"
done

# Identity documents every implementation must reject, but ok-*, which every one takes.
GOOD=$(sed -n 2p a/identity.doc)
printf 'dromas-v1\n%s comment\n' "$GOOD" > identity/comment.doc
printf 'dromas-v1\r\n%s\r\n' "$GOOD" > identity/crlf.doc
printf 'dromas-v1\n%s' "$GOOD" > identity/no-final-newline.doc
printf 'dromas-v1\n%s\n \n' "$GOOD" > identity/padded.doc
printf 'dromas-v2\n%s\n' "$GOOD" > identity/wrong-tag.doc
printf 'dromas-v1\nssh-rsa %s\n' "$(cut -d' ' -f2 "$KEYS/a.pub")" > identity/key-type-mismatch.doc
printf 'dromas-v1\nssh-ed25519 %s\n' "$(bin "$(str "$(asc ssh-ed25519)")00000021$(printf %s "${GOOD#* }" | base64 -d | tail -c 32 | od -An -v -tx1 | tr -d ' \n')" | b64)" > identity/length-field.doc # A's key, its length written 33: no key OpenSSH reads, and its 26th character is not A to P
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
identity_doc 0200000000000000000000000000000000000000000000000000000000000000 > identity/off-curve.doc # y = 2: x^2 = 3/(4d + 1) is no square mod p, so no point has it. ssh-keygen reads any 32 bytes as a key
printf 'dromas-v1\nssh-ed25519 %s\n' "$(bin "$(str "$(asc ssh-ed25519)00")$(str "$(printf %s "${GOOD#* }" | base64 -d | tail -c 32 | od -An -v -tx1 | tr -d ' \n')")" | b64)" > identity/type-name-ending-in-nul.doc # A's key, its type name ending in a NUL: ssh-keygen reads it as A's key and writes it back without the NUL
# The same for the P-256 type. With p the field's size and n the group's order: a point is 04, x, y, on the curve, each
# coordinate below p, and nothing more (PROTOCOL.md §4.1). OpenSSH up to 10.2p1 also refused a coordinate of 128 bits or
# fewer, or of n - 1 or more, and takes those from 10.3p1, as the protocol does.
GOOD_C=$(sed -n 2p c/identity.doc); X=${POINT:0:64}; Y=${POINT:64}
Y5=459243b9aa581806fe913bce99817ade11ca503c64d9a3c533415c083248fbcc # a square root of 5^3 - 3*5 + b mod p: (5, Y5) is on the curve
printf 'dromas-v1\n%s comment\n' "$GOOD_C" > identity/p256-comment.doc
p256_doc "0$((2 + (0x${Y: -1} & 1)))$X" > identity/p256-compressed.doc # 02 or 03 by y's last bit, then x: the same key, in the encoding the format does not take
p256_doc "04$POINT" nistp384 > identity/p256-curve-name-mismatch.doc
p256_doc "04${POINT}00" > identity/p256-trailing-byte.doc
p256_doc "04$X${Y:0:63}$(printf '%x' $((0x${Y: -1} ^ 1)))" > identity/p256-off-curve.doc # y with its last bit flipped
p256_doc "04ffffffff00000001000000000000000000000001000000000000000000000004$Y5" > identity/p256-coordinate-not-reduced.doc # x = p + 5: the point (5, Y5), x not reduced
p256_doc "00" > identity/p256-point-at-infinity.doc # the point at infinity, as SEC1 writes it: one zero byte
p256_doc "040000000000000000000000000000000000000000000000000000000000000005$Y5" > identity/ok-p256-short-coordinate.doc # x = 5: on the curve, so taken; OpenSSH refused it up to 10.2p1
p256_doc "04ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632554484f0c0fda434ef0a808458914f328715d7a545e198ac7eee31dffe861b5d23f" > identity/ok-p256-coordinate-over-order.doc # x = n + 3, the first from n - 1 up that is on the curve; likewise
printf 'dromas-v1\necdsa-sha2-nistp256 %s\n' "$(bin "$(str "$(asc ecdsa-sha2-nistp256)")$(str "$(asc nistp256)00")$(str "04$POINT")" | b64)" > identity/p256-curve-name-ending-in-nul.doc # C's key, its curve name ending in a NUL: ssh-keygen reads it as C's key and writes it back without the NUL
# A well-formed document of a key type no client verifies: a name, and a wire key that begins with that name.
NOTYPE=no-such-key-type@dromas.invalid
printf 'dromas-v1\n%s %s\n' "$NOTYPE" "$(bin "$(str "$(asc "$NOTYPE")")$(str "$(asc 'not a key')")" | b64)" > identity/unsupported-type.doc
# A NUL byte, which a shell variable drops and a C string ends at. Each of the first four is as long as a good
# document: one line feed is gone and the NUL is in its place, or elsewhere.
printf 'dromas-v1\n%s\0' "$GOOD" > identity/nul-for-the-final-newline.doc
printf 'iron\0gall-v1\n%s' "$GOOD" > identity/nul-in-the-tag.doc
printf 'dromas-v1\n%s\0%s' "${GOOD:0:40}" "${GOOD:40}" > identity/nul-in-the-key.doc
printf 'dromas-v1\n%s\0' "$GOOD_C" > identity/p256-nul-for-the-final-newline.doc
printf 'dromas-v1\n%s\0' "$(sed -n 2p identity/unsupported-type.doc)" > identity/nul-in-an-unknown-type.doc

# Prekey statements of mailbox A. bad-*: signature or format must be refused. expired-*: valid, but
# expired at ./now, so a sender must not encrypt to it. longest: valid, and the longest a server
# takes, an hour past the 33 days a client asks for. too-long: a second past that, so valid and not
# expired, but a server must refuse to publish it. Each is signed by A in A's prekey namespace
# unless its name says otherwise.
PQ=$(cat input/a-1.pq)
bad() { local name=$1; shift; printf "$@" > "prekey/$name.txt"; under a-work a/work-cert.pub "dromas-prekey-v1:$A" < "prekey/$name.txt" > "prekey/$name.txt.sig"; }
cp a/prekey-1.txt prekey/bad-wrong-namespace.txt; under a-work a/work-cert.pub "dromas-msg-v1:$A" < a/prekey-1.txt > prekey/bad-wrong-namespace.txt.sig
cp a/prekey-1.txt prekey/bad-signed-by-b.txt; under b-work b/work-cert.pub "dromas-prekey-v1:$A" < a/prekey-1.txt > prekey/bad-signed-by-b.txt.sig
cp a/prekey-1.txt prekey/bad-signed-by-the-identity.txt; sign a "dromas-prekey-v1:$A" < a/prekey-1.txt > prekey/bad-signed-by-the-identity.txt.sig
cp a/prekey-1.txt prekey/bad-signed-by-a-bare-working-key.txt; sign a-work "dromas-prekey-v1:$A" < a/prekey-1.txt > prekey/bad-signed-by-a-bare-working-key.txt.sig
# A statement may not outlive the certificate it is signed under: this one's certificate ends in 10 days.
cert prekey/bad-outlives-its-certificate.cert.pub a a-work-2 $(good "$A" 2 "$V_SHORT")
cp a/prekey-1.txt prekey/bad-outlives-its-certificate.txt; under a-work-2 prekey/bad-outlives-its-certificate.cert.pub "dromas-prekey-v1:$A" < a/prekey-1.txt > prekey/bad-outlives-its-certificate.txt.sig
bad bad-names-another-mailbox 'dromas-prekey-v1\n%s\n1\n%s\n%s\n' "$B" "$PQ" "$NOT_AFTER"
bad bad-serial-zero 'dromas-prekey-v1\n%s\n0\n%s\n%s\n' "$A" "$PQ" "$NOT_AFTER"
bad bad-serial-leading-zero 'dromas-prekey-v1\n%s\n01\n%s\n%s\n' "$A" "$PQ" "$NOT_AFTER"
bad bad-serial-19-digits 'dromas-prekey-v1\n%s\n1000000000000000000\n%s\n%s\n' "$A" "$PQ" "$NOT_AFTER"
bad bad-serial-above-2-53 'dromas-prekey-v1\n%s\n9007199254740992\n%s\n%s\n' "$A" "$PQ" "$NOT_AFTER" # an answer names a serial as a JSON number, and 2^53 - 1 is the most one holds exactly
bad bad-serial-negative 'dromas-prekey-v1\n%s\n-1\n%s\n%s\n' "$A" "$PQ" "$NOT_AFTER"
bad bad-never 'dromas-prekey-v1\n%s\n1\n%s\nnever\n' "$A" "$PQ"
bad bad-time-lowercase-z 'dromas-prekey-v1\n%s\n1\n%s\n2026-11-11T00:00:00z\n' "$A" "$PQ"
bad bad-time-fraction 'dromas-prekey-v1\n%s\n1\n%s\n2026-11-11T00:00:00.5Z\n' "$A" "$PQ"
bad bad-time-offset 'dromas-prekey-v1\n%s\n1\n%s\n2026-11-11T00:00:00+00:00\n' "$A" "$PQ"
bad bad-tag 'dromas-prekey-v2\n%s\n1\n%s\n%s\n' "$A" "$PQ" "$NOT_AFTER"
bad bad-address-uppercase 'dromas-prekey-v1\n%s\n1\n%s\n%s\n' "$(printf '%s' "$A" | tr a-z A-Z)" "$PQ" "$NOT_AFTER"
bad bad-four-lines 'dromas-prekey-v1\n%s\n1\n%s\n' "$A" "$PQ"
bad bad-six-lines 'dromas-prekey-v1\n%s\n1\n%s\n%s\n\n' "$A" "$PQ" "$NOT_AFTER"
bad bad-crlf 'dromas-prekey-v1\r\n%s\r\n1\r\n%s\r\n%s\r\n' "$A" "$PQ" "$NOT_AFTER"
bad bad-no-final-newline 'dromas-prekey-v1\n%s\n1\n%s\n%s' "$A" "$PQ" "$NOT_AFTER"
# A NUL in each line, which a reader that takes a line through a shell variable drops; and a serial with a digit that is not
# ASCII (U+0661), which [0-9] takes in some locales.
bad bad-nul-in-the-tag 'dromas-prekey-v1\x00\n%s\n1\n%s\n%s\n' "$A" "$PQ" "$NOT_AFTER"
bad bad-nul-in-the-address 'dromas-prekey-v1\n%s\x00%s\n1\n%s\n%s\n' "${A:0:32}" "${A:32}" "$PQ" "$NOT_AFTER"
bad bad-nul-in-the-serial 'dromas-prekey-v1\n%s\n1\x002\n%s\n%s\n' "$A" "$PQ" "$NOT_AFTER"
bad bad-nul-in-the-recipient 'dromas-prekey-v1\n%s\n1\n%s\x00%s\n%s\n' "$A" "${PQ:0:16}" "${PQ:16}" "$NOT_AFTER"
bad bad-nul-in-not-after 'dromas-prekey-v1\n%s\n1\n%s\n%s\x00%s\n' "$A" "$PQ" "${NOT_AFTER:0:10}" "${NOT_AFTER:10}"
bad bad-serial-a-digit-not-ascii 'dromas-prekey-v1\n%s\n1\xd9\xa1\n%s\n%s\n' "$A" "$PQ" "$NOT_AFTER"
bad bad-recipient-uppercase-pq 'dromas-prekey-v1\n%s\n1\n%s\n%s\n' "$A" "$(printf '%s' "$PQ" | tr a-z A-Z)" "$NOT_AFTER"
bad bad-recipient-uppercase-classic 'dromas-prekey-v1\n%s\n2\n%s\n%s\n' "$A" "$(tr a-z A-Z < input/a-2.classic)" "$NOT_AFTER"
bad bad-recipient-not-age 'dromas-prekey-v1\n%s\n1\n%s\n%s\n' "$A" "$GOOD" "$NOT_AFTER"
bad bad-recipient-small-order-pq 'dromas-prekey-v1\n%s\n1\n%s\n%s\n' "$A" "$(cat input/small-order.pq)" "$NOT_AFTER"
bad bad-recipient-small-order-classic 'dromas-prekey-v1\n%s\n1\n%s\n%s\n' "$A" "$(cat input/small-order.classic)" "$NOT_AFTER"
bad expired 'dromas-prekey-v1\n%s\n1\n%s\n%s\n' "$A" "$PQ" "$NOW"
bad longest 'dromas-prekey-v1\n%s\n1\n%s\n2026-11-12T01:00:00Z\n' "$A" "$PQ"
bad too-long 'dromas-prekey-v1\n%s\n1\n%s\n2026-11-12T01:00:01Z\n' "$A" "$PQ"
# A well-formed age recipient of a type nobody defines, so no client has it: RFC 7748 §6.1's published X25519 test key
# (Alice's public key) under the human-readable part age1nosuchtype. Good in every other way, so a sender refuses it as
# unsupported_prekey_type, never as a statement that does not verify.
[ "$(bech32 age b77249f1180299c3eb1399abb0cced137e6923bf34ce8b2d8d50c374feafa915)" = "$(cat input/a-2.classic)" ] || { echo "bech32 does not write input/a-2.classic's key as age wrote it" >&2; exit 1; }
bad unsupported-type 'dromas-prekey-v1\n%s\n1\n%s\n%s\n' "$A" "$(bech32 age1nosuchtype 8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a)" "$NOT_AFTER"

# Envelopes, judged as a message whose signature by A verified, received by mailbox B, at ./now.
case_env() { local name=$1; shift; printf "$@" > "envelope/$name.json"; }
H='"v":1,"from":"%s","to":"%s"'
case_env accept-minimal "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env accept-every-field "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\",\"subject\":\"hi\",\"in_reply_to\":\"$MSG_ID\",\"supersedes\":\"$MSG_ID\",\"identity\":\"$(b64 < a/identity.doc)\"}" "$A" "$B"
case_env accept-json-body "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":{\"task\":\"ping\",\"n\":1}}" "$A" "$B"
case_env accept-null-body "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":null}" "$A" "$B"
case_env accept-unknown-field "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\",\"later\":true}" "$A" "$B"
# U+2028 and U+2029 raw, as a sender's JSON may leave them (Go's writer escapes them, and need not): a reader takes them as any
# other character, in a string body, and in a body's member name and value and the subject.
case_env accept-line-separators-raw-in-a-string-body "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"a\xe2\x80\xa8b\xe2\x80\xa9c\"}" "$A" "$B"
case_env accept-line-separators-raw-in-a-member "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":{\"a\xe2\x80\xa8b\":\"c\xe2\x80\xa9d\"},\"subject\":\"e\xe2\x80\xa8f\"}" "$A" "$B"
case_env accept-33-days-old "{$H,\"sent_at\":\"2026-09-07T00:00:00Z\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-33-days-and-1s-old "{$H,\"sent_at\":\"2026-09-06T23:59:59Z\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env accept-1-hour-ahead "{$H,\"sent_at\":\"2026-10-10T01:00:00Z\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-1-hour-and-1s-ahead "{$H,\"sent_at\":\"2026-10-10T01:00:01Z\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-from-not-signer "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$B" "$B"
case_env refuse-to-another-mailbox "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$A"
case_env refuse-from-uppercase "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$(printf '%s' "$A" | tr a-z A-Z)" "$B"
case_env refuse-version-2 "{\"v\":2,\"from\":\"%s\",\"to\":\"%s\",\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-no-version "{\"from\":\"%s\",\"to\":\"%s\",\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-no-body "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\"}" "$A" "$B"
case_env refuse-no-msg-id "{$H,\"sent_at\":\"$NOW\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-msg-id-uppercase "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$(printf '%s' "$MSG_ID" | tr a-f A-F)\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-msg-id-grouped-wrongly "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"${MSG_ID:0:8}${MSG_ID:9:1}-${MSG_ID:10}\",\"body\":\"hello\"}" "$A" "$B" # 36 characters and four hyphens, the first a place late
case_env refuse-sent-at-malformed "{$H,\"sent_at\":\"2026-10-10 00:00:00\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-not-json "not json"
case_env refuse-msg-id-newline "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\\\\n\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-subject-number "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\",\"subject\":5}" "$A" "$B"
case_env refuse-sent-at-second-60 "{$H,\"sent_at\":\"2026-10-09T23:59:60Z\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
# Parser differentials: every reader must take the same values from one envelope.
case_env accept-case-variant-key "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"benign\",\"BODY\":\"evil\"}" "$A" "$B"
case_env refuse-version-string "{\"v\":\"1\",\"from\":\"%s\",\"to\":\"%s\",\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-to-uppercase "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$(printf '%s' "$B" | tr a-z A-Z)"
case_env refuse-from-null "{\"v\":1,\"from\":null,\"to\":\"%s\",\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$B" # null is a member left out: it names no sender
# v is an integer member, written in digits alone (PROTOCOL.md §3.3). jq gives back 1e0 as 1, so the script takes that one: how jq reads a number, a difference that guards none of the five (AGENTS.md § The shell client).
case_env refuse-version-written-with-a-fraction "{\"v\":1.0,\"from\":\"%s\",\"to\":\"%s\",\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-version-written-with-an-exponent "{\"v\":1e0,\"from\":\"%s\",\"to\":\"%s\",\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-version-a-decimal-just-above-1 "{\"v\":1.00000000000000001,\"from\":\"%s\",\"to\":\"%s\",\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-nul-after-the-version "{\"v\":1\\0,\"from\":\"%s\",\"to\":\"%s\",\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}\n" "$A" "$B" # jq ends a number at a NUL and drops it
case_env refuse-sent-at-ending-in-a-line-feed "{$H,\"sent_at\":\"$NOW\\\\n\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-sent-at-ending-in-a-nul "{$H,\"sent_at\":\"$NOW\\\\u0000\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-duplicate-key "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\",\"from\":\"%s\"}" "$B" "$B" "$A"
case_env refuse-two-objects "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}{}" "$A" "$B"
case_env refuse-not-utf8 "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"\xff\xfe\"}" "$A" "$B"
# The envelope is a JSON text as PROTOCOL.md §3.3 reads one, the sender's body in it included (json/ has each rule alone).
E="{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":"
case_env accept-body-nested-to-32 "$E$(printf '%.0s[' $(seq 31))$(printf '%.0s]' $(seq 31))}" "$A" "$B"
case_env refuse-body-nested-to-33 "$E$(printf '%.0s[' $(seq 32))$(printf '%.0s]' $(seq 32))}" "$A" "$B"
case_env refuse-key-twice-in-the-body "$E{\"x\":1,\"x\":2}}" "$A" "$B"
case_env refuse-nan-in-the-body "${E}NaN}" "$A" "$B"
case_env refuse-leading-zero-in-the-body "$E[01]}" "$A" "$B"
case_env refuse-number-past-binary64-in-the-body "$E{\"n\":1e400}}" "$A" "$B"
case_env accept-body-jq-spells-otherwise "$E{\"n\":1e5,\"s\":\"a\\\\/b \\\\u00e9\"}}" "$A" "$B" # the same value, which the script delivers in jq's spelling: a difference that guards none of the five (AGENTS.md § The shell client)
case_env accept-body-more-precise-than-binary64 "$E{\"b\":{\"z\":1,\"a\":2},\"n\":9007199254740993,\"m\":-0}}" "$A" "$B" # delivered as it is: a number binary64 does not hold exactly, a zero's sign, members in the order given
case_env refuse-noncharacter-in-the-body "$E\"\\\\uffff\"}" "$A" "$B"
case_env refuse-above-u10ffff-in-the-body "$E\"\xf4\x90\x80\x80\"}" "$A" "$B"
case_env refuse-byte-order-mark "\xef\xbb\xbf{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"

# A message from A to B. What is encrypted is three parts: the envelope as one line, the
# signature over that line as ssh-keygen wrote it, and padding. The line carries A's identity
# document, and the signature is by A's working key, for B only.
ID_A=$(b64 < a/identity.doc); ID_B=$(b64 < b/identity.doc)
line() { printf '{"v":1,"from":"%s","to":"%s","sent_at":"%s","msg_id":"%s","identity":"%s","body":"hello"}\n' "$1" "$2" "$NOW" "$MSG_ID" "$3"; } # <from> <to> <identity, base64>
line "$A" "$B" "$ID_A" > message/a-to-b.line
under a-work a/work-cert.pub "dromas-msg-v1:$B" < message/a-to-b.line > message/a-to-b.sig
# Padding makes the age file a whole number of 1 KiB blocks (PROTOCOL.md §9.3). To a post-quantum
# key a file of one chunk is its plaintext and 1,659 bytes more.
n=$(( $(wc -c < message/a-to-b.line) + $(wc -c < message/a-to-b.sig) ))
SEALED=$(( (1659 + n + 1023) / 1024 * 1024 ))
{ cat message/a-to-b.line message/a-to-b.sig; head -c $((SEALED - 1659 - n)) /dev/zero | tr '\0' .; } > message/a-to-b.plain
[ -e message/a-to-b.age ] || age -r "$(cat input/b-1.pq)" -o message/a-to-b.age < message/a-to-b.plain
[ "$(wc -c < message/a-to-b.age)" -eq "$SEALED" ] || { echo "message/a-to-b.age is not the $SEALED bytes its padding was made for" >&2; exit 1; }
# The same from A to C, to C's X25519 prekey: to an X25519 key a file of one chunk is its plaintext and 200 bytes more.
line "$A" "$C" "$ID_A" > message/a-to-c.line
under a-work a/work-cert.pub "dromas-msg-v1:$C" < message/a-to-c.line > message/a-to-c.sig
n=$(( $(wc -c < message/a-to-c.line) + $(wc -c < message/a-to-c.sig) ))
SEALED_C=$(( (200 + n + 1023) / 1024 * 1024 ))
{ cat message/a-to-c.line message/a-to-c.sig; head -c $((SEALED_C - 200 - n)) /dev/zero | tr '\0' .; } > message/a-to-c.plain
[ -e message/a-to-c.age ] || age -r "$(cat input/c-1.classic)" -o message/a-to-c.age < message/a-to-c.plain
[ "$(wc -c < message/a-to-c.age)" -eq "$SEALED_C" ] || { echo "message/a-to-c.age is not the $SEALED_C bytes its padding was made for" >&2; exit 1; }
# Each decrypts with the published identity of its prekey to exactly what was encrypted.
for m in a-to-b:b-1.pq a-to-c:c-1.classic; do
  age -d -i "input/${m#*:}.key" "message/${m%:*}.age" | cmp -s - "message/${m%:*}.plain" || { echo "message/${m%:*}.age does not decrypt to its .plain with input/${m#*:}.key" >&2; exit 1; }
done

# What mailbox B decrypts, judged at ./now: accept-* are delivered, refuse-* are not.
GOOD_SIG=message/a-to-b.sig
cat message/a-to-b.line "$GOOD_SIG" > plain/accept-no-padding.txt
cp message/a-to-b.plain plain/accept-padded.txt
{ cat message/a-to-b.line "$GOOD_SIG"; cat message/a-to-b.line; under b-work b/work-cert.pub "dromas-msg-v1:$B" < message/a-to-b.line; echo "nothing after the first END line is read"; } > plain/accept-anything-after-the-signature.txt
printf '{"v":1,"from":"%s","to":"%s","sent_at":"%s","msg_id":"%s","identity":"%s","body":{"task":"ping"},"subject":"hi","in_reply_to":"%s","supersedes":"%s","later":true}\n' "$A" "$B" "$NOW" "$MSG_ID" "$ID_A" "$MSG_ID" "$MSG_ID" > plain/every-field.line
{ cat plain/every-field.line; under a-work a/work-cert.pub "dromas-msg-v1:$B" < plain/every-field.line; } > plain/accept-every-field.txt
rm plain/every-field.line
printf '{"v":1,"from":"%s","to":"%s","sent_at":"%s","msg_id":"%s","identity":"%s","body":{"b":{"z":1,"a":2},"n":9007199254740993,"m":-0}}\n' "$A" "$B" "$NOW" "$MSG_ID" "$ID_A" > plain/more-precise.line # delivered as it is (envelope/accept-body-more-precise-than-binary64)
{ cat plain/more-precise.line; under a-work a/work-cert.pub "dromas-msg-v1:$B" < plain/more-precise.line; } > plain/accept-body-more-precise-than-binary64.txt
rm plain/more-precise.line
refuse() { # <name> <line file> <signature command…>: the line, then the signature the command makes over it
  local name=$1 l=$2; shift 2
  { cat "$l"; "$@" < "$l"; } > "plain/$name.txt"
}
L=$(mktemp)
# The signature.
refuse refuse-signed-for-another-mailbox message/a-to-b.line under a-work a/work-cert.pub "dromas-msg-v1:$A"
refuse refuse-signed-by-the-identity message/a-to-b.line sign a "dromas-msg-v1:$B"
refuse refuse-signed-by-a-bare-working-key message/a-to-b.line sign a-work "dromas-msg-v1:$B"
refuse refuse-certificate-ended message/a-to-b.line under a-work cert/bad-ended.pub "dromas-msg-v1:$B"
sed 's/"body":"hello"/"body":"hellp"/' message/a-to-b.line > "$L"; cat "$L" "$GOOD_SIG" > plain/refuse-line-changed-after-signing.txt
# The signature block is read as ssh-keygen reads a signature (sig/), and is at most 4096 bytes from its BEGIN line through its END line.
{ cat message/a-to-b.line; sed "2s/\$/ \r/; 3s/^/"$'\t'"/" "$GOOD_SIG"; } > plain/accept-whitespace-in-the-signature.txt
{ cat message/a-to-b.line; sed "2s/\$/$(printf "%$((4097 - $(wc -c < "$GOOD_SIG")))s" '')/" "$GOOD_SIG"; } > plain/refuse-signature-over-4096-bytes.txt
# A sender whose identity is of the optional type: delivered by a client that verifies ecdsa-sha2-nistp256, and refused
# with unsupported_key_type by one that does not. Then one of a type nobody verifies: refused so if the document is
# the sender's, and as reattributed if it is not.
line "$C" "$B" "$(b64 < c/identity.doc)" > "$L"; refuse accept-p256-sender "$L" under c-work c/work-cert.pub "dromas-msg-v1:$B"
line "$(address < identity/unsupported-type.doc)" "$B" "$(b64 < identity/unsupported-type.doc)" > "$L"; refuse refuse-unsupported-key-type "$L" under a-work a/work-cert.pub "dromas-msg-v1:$B"
line "$A" "$B" "$(b64 < identity/unsupported-type.doc)" > "$L"; refuse refuse-from-is-not-the-identity-of-an-unknown-type "$L" under a-work a/work-cert.pub "dromas-msg-v1:$B"
# Who it is from. The first is the forgery an identity member invites: A's document beside a
# certificate that B's identity signed. The signature is good and the certificate is B's own.
refuse refuse-another-mailbox-s-identity-document message/a-to-b.line under b-work b/work-cert.pub "dromas-msg-v1:$B"
line "$B" "$B" "$ID_A" > "$L"; refuse refuse-from-is-not-the-identity "$L" under a-work a/work-cert.pub "dromas-msg-v1:$B"
printf '{"v":1,"from":"%s","to":"%s","sent_at":"%s","msg_id":"%s","body":"hello"}\n' "$A" "$B" "$NOW" "$MSG_ID" > "$L"; refuse refuse-no-identity "$L" under a-work a/work-cert.pub "dromas-msg-v1:$B"
line "$A" "$B" "not base64" > "$L"; refuse refuse-identity-not-base64 "$L" under a-work a/work-cert.pub "dromas-msg-v1:$B"
line "$A" "$B" "$ID_A\\n" > "$L"; refuse refuse-identity-ending-in-a-line-feed "$L" under a-work a/work-cert.pub "dromas-msg-v1:$B" # a JSON escape: the document's base64 and a line feed
line "$A" "$B" "$ID_A\\u0000" > "$L"; refuse refuse-identity-ending-in-a-nul "$L" under a-work a/work-cert.pub "dromas-msg-v1:$B"
printf '{"v":1,"from":null,"to":"%s","sent_at":"%s","msg_id":"%s","identity":"%s","body":"hello"}\n' "$B" "$NOW" "$MSG_ID" "$ID_A" > "$L"; refuse refuse-from-null "$L" under a-work a/work-cert.pub "dromas-msg-v1:$B" # null is a member left out: it names no sender
line "$(address < identity/small-order-1.doc)" "$B" "$(b64 < identity/small-order-1.doc)" > "$L"; refuse refuse-identity-of-small-order "$L" under a-work a/work-cert.pub "dromas-msg-v1:$B"
line "$(address < identity/off-curve.doc)" "$B" "$(b64 < identity/off-curve.doc)" > "$L"; refuse refuse-identity-off-curve "$L" under a-work a/work-cert.pub "dromas-msg-v1:$B"
line "$(address < identity/length-field.doc)" "$B" "$(b64 < identity/length-field.doc)" > "$L"; refuse refuse-identity-with-its-length-written-33 "$L" under a-work a/work-cert.pub "dromas-msg-v1:$B" # A's key bytes, in a document that breaks its form
line "$A" "$A" "$ID_A" > "$L"; refuse refuse-to-another-mailbox "$L" under a-work a/work-cert.pub "dromas-msg-v1:$B"
# The layout. Each part has one place, and nothing is searched for.
head -c -1 message/a-to-b.line > plain/refuse-no-line-feed.txt
cp message/a-to-b.line plain/refuse-no-signature.txt
{ cat message/a-to-b.line; echo; cat "$GOOD_SIG"; } > plain/refuse-blank-line-before-the-signature.txt
cat "$GOOD_SIG" message/a-to-b.line > plain/refuse-signature-first.txt
{ cat message/a-to-b.line; grep -v -e '-----END' "$GOOD_SIG"; } > plain/refuse-no-end-line.txt
{ cat message/a-to-b.line; head -c -1 "$GOOD_SIG"; } > plain/refuse-end-line-without-its-line-feed.txt
{ cat message/a-to-b.line; head -c -1 "$GOOD_SIG"; printf '\0\n'; } > plain/refuse-end-line-followed-by-a-nul.txt
{ cat message/a-to-b.line; printf -- '-----BEGIN SSH SIGNATURE-----\0\n'; tail -n +2 "$GOOD_SIG"; } > plain/refuse-begin-line-followed-by-a-nul.txt      # a reader that takes the line through a shell variable drops the NUL
{ cat message/a-to-b.line; printf -- '-----BEGIN SSH\0 SIGNATURE-----\n'; tail -n +2 "$GOOD_SIG"; } > plain/refuse-begin-line-holding-a-nul.txt
{ cat message/a-to-b.line; printf -- '\0'; cat "$GOOD_SIG"; } > plain/refuse-begin-line-preceded-by-a-nul.txt
{ cat message/a-to-b.line; head -c -1 "$GOOD_SIG"; printf '.\n'; tail -n 1 "$GOOD_SIG"; } > plain/refuse-end-line-followed-by-a-byte-and-a-later-one.txt      # the block ends at the first END line, whatever follows later
sed 's/$/\r/' message/a-to-b.line > "$L"; { cat "$L"; under a-work a/work-cert.pub "dromas-msg-v1:$B" < "$L" | sed 's/$/\r/'; } > plain/refuse-crlf.txt
printf '{\n"v":1,"from":"%s","to":"%s","sent_at":"%s","msg_id":"%s","identity":"%s","body":"hello"}\n' "$A" "$B" "$NOW" "$MSG_ID" "$ID_A" > "$L"; refuse refuse-envelope-on-two-lines "$L" under a-work a/work-cert.pub "dromas-msg-v1:$B"
rm -f "$L"

# JSON texts as every reader takes one (PROTOCOL.md §3.3): ok-* are taken and bad-* refused, by the server, the Go client
# and the script alike, whatever they hold. Each breaks one rule, or none.
mkdir -p json
jt() { local name=$1; shift; printf "$@" > "json/$name.json"; } # <name> <printf format…>: \\ in the format is one backslash in the text
deep() { printf '{"a":'; printf '%.0s[' $(seq "$1"); printf '%.0s]' $(seq "$1"); printf '}'; } # an object holding arrays nested <n> deep inside it
jt ok-object '{"a":1}\n'
jt ok-empty '{}'
jt ok-whitespace '{ "a" :\t[ 1 ,\r\n 2 ] }\n'
jt ok-numbers '{"a":[0,-0,1.5,-1e10,1E+2,0.5e-3,9007199254740993]}' # outside a member the protocol defines, any JSON number a binary64 holds
jt ok-number-the-largest-binary64 '{"a":[1.7976931348623157e308,-1.7976931348623157e308]}'
jt ok-number-too-small-for-binary64 '{"a":[1e-400,2e-324]}' # a binary64 reader reads each as zero
jt bad-number-past-binary64 '{"a":1e400}' # RFC 7493 §2.2's own example
jt bad-number-just-past-binary64 '{"a":1.797693134862315808e308}' # jq reads it through 17 digits, as the largest binary64: how jq reads a number, a difference that guards none of the five (AGENTS.md § The shell client)
jt bad-number-just-past-binary64-in-18-digits '{"a":1.79769313486231581e308}' # the same
jt bad-number-just-past-binary64-negative '{"a":-1.797693134862315808e308}' # the same
jt ok-escapes '{"a":"\\u0000\\\\\\"\\/\\b\\f\\n\\r\\t\\u00e9"}'
jt ok-surrogate-pair '{"a":"\\ud83d\\ude00"}'
jt ok-beside-the-noncharacters '{"a":"\xef\xb7\x8f\xef\xb7\xb0\xef\xbf\xbd"}' # U+FDCF, U+FDF0 and U+FFFD
jt ok-same-name-in-two-objects '{"a":{"x":1},"b":[{"x":2}],"x":3}'
jt ok-empty-containers '{"a":{},"b":[]}'
deep 31 > json/ok-nested-32-deep.json
deep 32 > json/bad-nested-33-deep.json
jt bad-byte-order-mark '\xef\xbb\xbf{"a":1}'
jt bad-not-utf8 '{"a":"\xff"}'
jt bad-overlong-utf8 '{"a":"\xc0\xaf"}'
jt bad-surrogate-in-utf8 '{"a":"\xed\xa0\x80"}'
jt bad-above-u10ffff '{"a":"\xf4\x90\x80\x80"}' # glibc's iconv takes it
jt bad-five-byte-utf8 '{"a":"\xf8\x88\x80\x80\x80"}'
jt bad-lone-surrogate-escaped '{"a":"\\ud800"}'
jt bad-lone-low-surrogate-escaped '{"a":"\\udc00"}' # jq reads it as U+FFFD
jt bad-lone-low-surrogate-in-a-name '{"\\udfff":1}'
jt bad-noncharacter '{"a":"\xef\xbf\xbf"}'
jt bad-noncharacter-escaped '{"a":"\\ufdd0"}'
jt bad-noncharacter-plane-16 '{"a":"\\udbff\\udfff"}'
jt bad-noncharacter-in-a-name '{"\\ufffe":1}'
jt bad-control-character '{"a":"\x01"}'
jt bad-unit-separator-in-a-string '{"a":"\x1f"}' # jq 1.7.0 takes it
jt bad-nul-after-a-number '{"a":1\0}\n' # jq ends a number at a NUL and drops it
jt bad-name-twice '{"a":1,"a":2}'
jt bad-name-twice-nested '{"b":[{"x":1,"x":1}]}'
jt bad-name-twice-escaped '{"a":1,"\\u0061":2}'
jt bad-two-values '{}{}'
jt bad-trailing-bracket '{"a":1}]'
jt bad-trailing-brace '{"a":1}}'
jt bad-an-array '[]'
jt bad-a-string '"x"'
jt bad-empty ''
jt bad-nan '{"a":NaN}'
jt bad-nan-lowercase '{"a":nan}'
jt bad-infinity '{"a":-Infinity}'
jt bad-leading-zero '{"a":01}'
jt bad-plus '{"a":+1}'
jt bad-point-first '{"a":.5}'
jt bad-point-last '{"a":1.}'
jt bad-trailing-comma '{"a":1,}'
jt bad-single-quotes "{'a':1}"
jt bad-vertical-tab '{"a":\v1}'

# Whole answers of a server, as each client reads them (PROTOCOL.md §3.3): <kind>-ok-* are taken and <kind>-bad-* are no
# answer, to the Go client and the script alike. A member a client does not know is ignored; one it reads is of its
# type or null, which is as if it were left out; a byte member is base64 in its one encoding.
mkdir -p answer
at() { local name=$1; shift; printf "$@" > "answer/$name.json"; }
REV=$(b64 < a/revoke.sig); RC=$(b64 < revoked/ok-through-4.txt); RCS=$(b64 < revoked/ok-through-4.sig); P1=$(b64 < a/prekey-1.txt); P1S=$(b64 < a/prekey-1.txt.sig); HASH=$(sha256sum < message/a-to-b.age | cut -c1-64)
wrap() { printf '%s' "$1" | fold -w 64 | sed 's/$/\\n/' | tr -d '\n' | sed 's/\\n$//'; } # base64 with a JSON \n escape after each 64 characters
# The answers whose signature member is base64 out of its one encoding take a signature whose base64 has padding: a/revoke.sig
# (399 bytes) and a/prekey-1.txt.sig (846) are written with none, so they take revoked/ok-through-4.sig, 407 bytes: one = of
# padding, and 2 unused bits, the lowest of which LASTBITS sets.
NOPAD=${RCS%%=*}; c=${NOPAD: -1}; i=${B64%%"$c"*}; LASTBITS=${NOPAD%?}${B64:${#i}+1:1}${RCS#"$NOPAD"}
[ "$NOPAD" != "$RCS" ] && [ $(( ${#i} % 4 )) -eq 0 ] || { echo "revoked/ok-through-4.sig is not base64 with padding and unused bits, which the bad answers need" >&2; exit 1; }
at record-ok-revocation-signature '{"identity":"%s","revocation_signature":"%s"}' "$ID_A" "$REV"
at record-ok-null-members '{"identity":null,"revocation_signature":null,"revoked_certificates":null,"revoked_certificates_signature":null}'
at record-ok-unknown-member '{"identity":"%s","revocation_signature":"%s","later":[1,{"x":true}]}' "$ID_A" "$REV"
at record-ok-names-in-another-case '{"Identity":"%s","REVOCATION_SIGNATURE":"%s"}' "$ID_A" "$REV" # members it does not know: a record that shows nothing
at record-ok-empty-object '{}'
at record-bad-empty ''
at record-bad-an-array '[]'
at record-bad-identity-a-number '{"identity":5,"revocation_signature":"%s"}' "$REV"
at record-bad-revocation-signature-unpadded '{"identity":"%s","revocation_signature":"%s"}' "$ID_A" "$NOPAD"
at record-bad-revocation-signature-unused-bits-set '{"identity":"%s","revocation_signature":"%s"}' "$ID_A" "$LASTBITS"
at record-bad-identity-wrapped '{"identity":"%s","revocation_signature":"%s"}' "$(wrap "$ID_A")" "$REV"
at record-bad-identity-twice '{"identity":"%s","identity":"%s","revocation_signature":"%s"}' "$ID_A" "$ID_B" "$REV"
at record-bad-null-after-a-value '{"identity":"%s","revocation_signature":"%s","revocation_signature":null}' "$ID_A" "$REV"
at record-bad-nan-beside-it '{"identity":"%s","revocation_signature":"%s","later":NaN}' "$ID_A" "$REV"
at record-bad-a-second-value '{"identity":"%s","revocation_signature":"%s"}{}' "$ID_A" "$REV"
at record-ok-type '{"type":"revocation_record","identity":"%s","revocation_signature":"%s"}' "$ID_A" "$REV" # a record names its own type
at record-ok-type-null '{"type":null,"identity":"%s","revocation_signature":"%s"}' "$ID_A" "$REV"
at record-bad-type-another '{"type":"revocation","identity":"%s","revocation_signature":"%s"}' "$ID_A" "$REV" # and never another
at record-bad-type-empty '{"type":"","identity":"%s","revocation_signature":"%s"}' "$ID_A" "$REV"
at record-bad-type-a-number '{"type":1,"identity":"%s","revocation_signature":"%s"}' "$ID_A" "$REV"
at mailbox-ok '{"identity":"%s","prekey":"%s","prekey_signature":"%s"}' "$ID_A" "$P1" "$P1S"
at mailbox-ok-sender-key-types '{"identity":"%s","prekey":"%s","prekey_signature":"%s","sender_key_types":["ecdsa-sha2-nistp256"]}' "$ID_A" "$P1" "$P1S"
at mailbox-ok-revoked-certificates '{"identity":"%s","prekey":"%s","prekey_signature":"%s","revoked_certificates":"%s","revoked_certificates_signature":"%s"}' "$ID_A" "$P1" "$P1S" "$RC" "$RCS" # the revocation of its certificates the server holds, beside the mailbox
at mailbox-bad-sender-key-types-a-string '{"identity":"%s","prekey":"%s","prekey_signature":"%s","sender_key_types":"any"}' "$ID_A" "$P1" "$P1S"
at mailbox-bad-signature-unpadded '{"identity":"%s","prekey":"%s","prekey_signature":"%s"}' "$ID_A" "$P1" "$NOPAD"
at mailbox-bad-prekey-a-number '{"identity":"%s","prekey":1,"prekey_signature":"%s"}' "$ID_A" "$P1S"
at mailbox-bad-revoked-certificates-a-number '{"identity":"%s","prekey":"%s","prekey_signature":"%s","revoked_certificates":4}' "$ID_A" "$P1" "$P1S"
at list-ok '{"count":1,"messages":[{"id":"%s","size":%s,"received_at":"%s","expires_at":"2026-11-12T00:00:00Z"}],"next_cursor":null}' "$HASH" "$(wc -c < message/a-to-b.age)" "$NOW"
at list-ok-empty '{"count":0,"messages":[],"next_cursor":null}'
at list-bad-count-negative '{"count":-1,"messages":[],"next_cursor":null}'
at list-bad-count-above-2-53 '{"count":9007199254740992,"messages":[],"next_cursor":null}'
at list-bad-count-a-fraction '{"count":0.5,"messages":[],"next_cursor":null}'
at list-bad-count-written-with-a-fraction '{"count":1.0,"messages":[],"next_cursor":null}' # an integer member is written as one
at list-bad-count-written-with-an-exponent '{"count":1e0,"messages":[],"next_cursor":null}' # jq gives it back as 1, so the script takes it: how jq reads a number, a difference that guards none of the five (AGENTS.md § The shell client)
at list-bad-size-a-string '{"count":1,"messages":[{"id":"%s","size":"2048"}],"next_cursor":null}' "$HASH"
# A size is at most 16 MiB, the largest ciphertext (PROTOCOL.md §11.10, §12.3): a list that gives a larger one is no answer, before anything is fetched
at list-ok-size-the-largest '{"count":1,"messages":[{"id":"%s","size":16777216,"received_at":"%s","expires_at":"2026-11-12T00:00:00Z"}],"next_cursor":null}' "$HASH" "$NOW"
at list-bad-size-past-the-largest '{"count":1,"messages":[{"id":"%s","size":16777217,"received_at":"%s","expires_at":"2026-11-12T00:00:00Z"}],"next_cursor":null}' "$HASH" "$NOW"
at list-bad-messages-an-object '{"count":0,"messages":{},"next_cursor":null}'
at list-bad-cursor-a-number '{"count":0,"messages":[],"next_cursor":7}'
# A cursor is opaque and URL-safe (AEP-158): one or more of A-Z, a-z, 0-9, - and _, pasted into the next query as it is
at list-ok-cursor '{"count":2,"messages":[],"next_cursor":"AZaz09-_"}'
at list-bad-cursor-a-slash '{"count":2,"messages":[],"next_cursor":"a/b"}'
at list-bad-cursor-a-percent '{"count":2,"messages":[],"next_cursor":"a%%2Fb"}'
at list-bad-cursor-empty '{"count":2,"messages":[],"next_cursor":""}'
at list-bad-id-a-number '{"count":1,"messages":[{"id":5,"size":%s}],"next_cursor":null}' "$(wc -c < message/a-to-b.age)" # the id names what is fetched and acked
at receipt-ok '{"id":"%s","received_at":"%s","expires_at":"2026-11-12T00:00:00Z"}' "$HASH" "$NOW"
at receipt-bad-id-an-array '{"id":["%s"],"received_at":"%s"}' "$HASH" "$NOW"
at problem-ok '{"type":"tag:dromas.dev,2026-10-26:errors/not_revoked","title":"Not revoked","status":404,"detail":"no revocation of this address is held here","code":"not_revoked","hint":"nothing to do"}'
at problem-bad-code-twice '{"type":"tag:dromas.dev,2026-10-26:errors/not_revoked","status":404,"code":"not_revoked","code":"revoked"}'
at problem-bad-status-a-string '{"status":"404","code":"not_revoked"}'
at problem-bad-status-a-fraction-after-the-code '{"code":"not_revoked","status":1.5}' # a reader that kept what it read before the fault would act on the code
# The members a problem carries beside its words (PROTOCOL.md §11.3), each of its type: a client reads them, never the words
at problem-ok-members '{"type":"tag:dromas.dev,2026-10-26:errors/rate_limited","title":"Rate limited","status":429,"detail":"this mailbox has sent its 20 messages a day","code":"rate_limited","hint":"wait","limit":20,"quota_id":"sends","subject":"mailbox","count":3,"prekey_serial":2,"certificate_serial":1792000000,"through":5,"key_types":["ssh-ed25519",null],"key_type":"ecdsa-sha2-nistp256","member":"prekey_serial"}'
at problem-bad-limit-negative '{"code":"rate_limited","status":429,"limit":-1}'
at problem-bad-quota-id-a-number '{"code":"rate_limited","status":429,"quota_id":5,"subject":"mailbox"}'
at problem-bad-subject-an-array '{"code":"rate_limited","status":429,"subject":["mailbox"]}'
at problem-bad-limit-written-with-an-exponent '{"code":"too_large","status":413,"limit":1e3}'
at problem-bad-through-above-2-53 '{"code":"conflict","status":409,"through":9007199254740992}'
at problem-bad-key-types-a-string '{"code":"unsupported_key_type","status":400,"key_types":"ssh-ed25519"}'
at problem-bad-member-a-number '{"code":"bad_request","status":400,"member":7}'
at problem-ok-record '{"type":"tag:dromas.dev,2026-10-26:errors/revoked","title":"Revoked","status":410,"detail":"this mailbox is revoked","code":"revoked","record":{"type":"revocation_record","identity":"%s","revocation_signature":"%s"}}' "$ID_A" "$REV" # a read of a revoked mailbox carries its record
at problem-bad-record-another-type '{"code":"revoked","status":410,"record":{"type":"revocation","identity":"%s","revocation_signature":"%s"}}' "$ID_A" "$REV" # held to its type as a record alone is
