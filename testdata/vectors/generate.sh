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
NOT_AFTER=2026-11-12T00:00:00Z # NOW + 33 days exactly: what a client asks for. A server takes one that ends up to an hour later
MSG_ID=6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b
# A certificate's validity, as ssh-keygen -V takes it. These begin a minute before NOW, where a client
# dates its own from an hour back (PROTOCOL.md §2b): a verifier asks only that one has begun.
V_OK=20261009235900Z:20261214000000Z
V_BEGINS_NOW=20261010000000Z:20261214000000Z # begins at NOW: begun
V_SHORT=20261009235900Z:20261020000000Z    # ends 10 days after NOW: a 33-day prekey statement outlives it
V_ENDED=20260801000000Z:20261010000000Z    # ends at NOW
V_NOT_BEGUN=20261010000001Z:20261214000000Z
V_TOO_LONG=20261009235900Z:20261215000001Z # ends 66 days and a second after NOW

# Hex helpers. Binary goes through hex strings, never through shell variables.
asc() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }
str() { printf '%08x%s' $(( ${#1} / 2 )) "$1"; }           # an RFC 4251 string, from hex
bin() { printf "$(printf '%s' "$1" | sed 's/../\\x&/g')"; } # hex → bytes on stdout
b64() { base64 | tr -d '\n'; }
# An armored signature: its blob, from hex, as ssh-keygen writes one; and the other way, a blob in hex from a signature ssh-keygen wrote.
armor() { printf -- '-----BEGIN SSH SIGNATURE-----\n'; bin "$1" | b64 | fold -w 70; printf -- '\n-----END SSH SIGNATURE-----\n'; }
blob() { sed '1d;$d' "$1" | tr -d '\n' | base64 -d | od -An -v -tx1 | tr -d ' \n'; }
# A blob in hex with S + L in place of the S at a hex offset: the other encoding of an Ed25519 signature's S, which
# RFC 8032 §5.1.7 refuses and ssh-keygen before 10.3p1 takes. S and L are 32 bytes, little-endian.
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

# Revocations. A's again with the other hash SSHSIG allows, and C's, by a P-256 identity: an ECDSA
# signature differs each time it is made, so C's is made once and kept. Then signatures every
# implementation must refuse as a revocation of box A: by a working key under A's own certificate, by
# another box's identity, in another namespace, and A's signature over the revocation of another box.
mkdir -p revoke
sign a "irongall-revoke-v1:$A" -O hashalg=sha256 < a/revoke.txt > a/revoke.sha256.sig
printf 'irongall-revoke-v1\n%s\n' "$C" > c/revoke.txt
[ -e c/revoke.sig ] || sign c "irongall-revoke-v1:$C" < c/revoke.txt > c/revoke.sig
under a-work a/work-cert.pub "irongall-revoke-v1:$A" < a/revoke.txt > revoke/bad-by-a-working-key.sig
sign b "irongall-revoke-v1:$A" < a/revoke.txt > revoke/bad-by-another-identity.sig
sign a "irongall-prekey-v1:$A" < a/revoke.txt > revoke/bad-another-namespace.sig
X=$(blob a/revoke.sig); armor "$(plusl "$X" $((${#X} - 64)))" > revoke/bad-s-plus-l.sig      # A's own, with L added to its S
printf 'irongall-revoke-v1\n%s\n' "$B" | sign a "irongall-revoke-v1:$B" > revoke/bad-of-another-box.sig

# Revocations of box A's certificates (PROTOCOL.md §6.3a): the tag, the address and the serial every certificate up
# to and including which is revoked, each on a line, signed by A's identity itself in A's namespace for them. Then what
# is not one. Each bad-* is signed by A's identity in that namespace, so only what its name says is wrong with it, but
# for the first two.
mkdir -p revoked
through() { printf 'irongall-revoke-certs-v1\n%s\n%s\n' "$2" "$3" > "revoked/$1.txt"; }   # <name> <address> <serial>
thsig() { sign a "irongall-revoke-certs-v1:$A" < "revoked/$1.txt" > "revoked/$1.sig"; }
through ok-through-4 "$A" 4; thsig ok-through-4
through ok-through-the-highest "$A" 9007199254740991; thsig ok-through-the-highest      # 2^53 - 1, the highest serial
sign a "irongall-revoke-certs-v1:$A" -O hashalg=sha256 < revoked/ok-through-4.txt > revoked/ok-through-4.sha256.sig
cp revoked/ok-through-4.txt revoked/bad-by-a-working-key.txt; under a-work a/work-cert.pub "irongall-revoke-certs-v1:$A" < revoked/bad-by-a-working-key.txt > revoked/bad-by-a-working-key.sig
cp revoked/ok-through-4.txt revoked/bad-another-namespace.txt; sign a "irongall-revoke-v1:$A" < revoked/bad-another-namespace.txt > revoked/bad-another-namespace.sig
through bad-another-address "$B" 4; thsig bad-another-address
cp revoked/ok-through-4.txt revoked/bad-s-plus-l.txt; X=$(blob revoked/ok-through-4.sig); armor "$(plusl "$X" $((${#X} - 64)))" > revoked/bad-s-plus-l.sig      # a good one, its signature with L added to S
printf 'irongall-revoke-certs-v1\n%s\n' "$A" > revoked/bad-no-serial.txt; thsig bad-no-serial
through bad-serial-zero "$A" 0; thsig bad-serial-zero
through bad-serial-leading-zero "$A" 04; thsig bad-serial-leading-zero
through bad-serial-19-digits "$A" 1000000000000000000; thsig bad-serial-19-digits
through bad-serial-above-2-53 "$A" 9007199254740992; thsig bad-serial-above-2-53
through bad-a-range "$A" 1-4; thsig bad-a-range
through bad-a-sign "$A" +4; thsig bad-a-sign
through bad-trailing-space "$A" "4 "; thsig bad-trailing-space
printf 'irongall-revoke-certs-v1\n%s\n4\n6\n' "$A" > revoked/bad-a-second-serial.txt; thsig bad-a-second-serial
printf 'irongall-revoke-certs-v1\n%s\n4\n\n' "$A" > revoked/bad-blank-line.txt; thsig bad-blank-line
printf 'irongall-revoked-certs-v1\n%s\n1\n1-4\n' "$A" > revoked/bad-a-list.txt; thsig bad-a-list      # the list a certificate was revoked by until 2026-10-14
printf 'irongall-revoke-certs-v1\r\n%s\r\n4\r\n' "$A" > revoked/bad-crlf.txt; thsig bad-crlf
printf 'irongall-revoke-certs-v1\n%s\n4' "$A" > revoked/bad-no-final-newline.txt; thsig bad-no-final-newline
printf 'irongall-revoke-certs-v2\n%s\n4\n' "$A" > revoked/bad-another-tag.txt; thsig bad-another-tag
through bad-address-in-uppercase "$(tr a-f A-F <<< "$A")" 4; thsig bad-address-in-uppercase
printf 'irongall-revoke-certs-v1\n%s\n4\0\n' "$A" > revoked/bad-nul.txt; thsig bad-nul      # a NUL, which a shell variable drops: a reader that tests the variable alone takes it

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

# One signature, a/prekey-1.txt.sig, in forms a verifier reads as ssh-keygen -Y verify reads them (OpenSSH's
# sshsig_dearmor), and in a file of at most 4096 bytes in all (PROTOCOL.md §3): ok-* are taken, bad-* refused. Then
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
t=$(sed -n 'x;$p' "$S"); t=${t%=}; c=${t: -1}; B64=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/; i=${B64%%"$c"*}      # the last base64 line, its one = gone
[ $(( ${#i} % 4 )) -eq 0 ] || { echo "the last character already has a padding bit set" >&2; exit 1; }
sed "$(( $(wc -l < "$S") - 1 ))s/$c=\$/${B64:${#i}+1:1}=/" "$S" > sig/bad-padding-bits.sig      # one of the unused bits of the last character set
sed "$(( $(wc -l < "$S") - 1 ))s/=\$//" "$S" > sig/bad-no-padding.sig
armor "$(plusl "$X" $((${#X} - 64)))" > sig/bad-s-plus-l.sig      # the working key's S
armor "$(plusl "$X" $((28 + 2 * 16#${X:20:8} - 64)))" > sig/bad-certificate-s-plus-l.sig      # the identity's S on the certificate, its last 32 bytes
armor "${X}00" > sig/bad-trailing-byte-in-the-blob.sig
# What every OpenSSH build takes, as they all read it (PROTOCOL.md §3), and what they all refuse beside each: one NUL as the
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
# 10.6p1 judges both the other way (PROTOCOL.md §3).
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
# The same for the P-256 type. With p the field's size and n the group's order: a point is 04, x, y, and the protocol
# refuses a coordinate of 128 bits or fewer, or of n - 1 or more, which no key made from a private key has. OpenSSH
# refused those up to 10.2p1 and takes them from 10.3p1.
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
# expired at ./now, so a sender must not encrypt to it. longest: valid, and the longest a server
# takes, an hour past the 33 days a client asks for. too-long: a second past that, so valid and not
# expired, but a server must refuse to publish it. Each is signed by A in A's prekey namespace
# unless its name says otherwise.
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
bad bad-serial-above-2-53 'irongall-prekey-v1\n%s\n9007199254740992\n%s\n%s\n' "$A" "$PQ" "$NOT_AFTER" # a send names it as a JSON number, and 2^53 - 1 is the most one holds exactly
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
bad longest 'irongall-prekey-v1\n%s\n1\n%s\n2026-11-12T01:00:00Z\n' "$A" "$PQ"
bad too-long 'irongall-prekey-v1\n%s\n1\n%s\n2026-11-12T01:00:01Z\n' "$A" "$PQ"

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
case_env accept-1-hour-ahead "{$H,\"sent_at\":\"2026-10-10T01:00:00Z\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-1-hour-and-1s-ahead "{$H,\"sent_at\":\"2026-10-10T01:00:01Z\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
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
case_env refuse-to-uppercase "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$(printf '%s' "$B" | tr a-f A-F)"
case_env refuse-from-null "{\"v\":1,\"from\":null,\"to\":\"%s\",\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$B" # null is a member left out: it names no sender
# v is an integer member, written in digits alone (PROTOCOL.md §0b). jq gives back 1e0 as 1, so the script takes that one: a known variance.
case_env refuse-version-written-with-a-fraction "{\"v\":1.0,\"from\":\"%s\",\"to\":\"%s\",\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-version-written-with-an-exponent "{\"v\":1e0,\"from\":\"%s\",\"to\":\"%s\",\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-version-a-decimal-just-above-1 "{\"v\":1.00000000000000001,\"from\":\"%s\",\"to\":\"%s\",\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-nul-after-the-version "{\"v\":1\\0,\"from\":\"%s\",\"to\":\"%s\",\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}\n" "$A" "$B" # jq ends a number at a NUL and drops it
case_env refuse-sent-at-ending-in-a-line-feed "{$H,\"sent_at\":\"$NOW\\\\n\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-sent-at-ending-in-a-nul "{$H,\"sent_at\":\"$NOW\\\\u0000\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"
case_env refuse-duplicate-key "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\",\"from\":\"%s\"}" "$B" "$B" "$A"
case_env refuse-two-objects "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}{}" "$A" "$B"
case_env refuse-not-utf8 "{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"\xff\xfe\"}" "$A" "$B"
# The envelope is a JSON text as PROTOCOL.md §0b reads one, the sender's body in it included (json/ has each rule alone).
E="{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":"
case_env accept-body-nested-to-32 "$E$(printf '%.0s[' $(seq 31))$(printf '%.0s]' $(seq 31))}" "$A" "$B"
case_env refuse-body-nested-to-33 "$E$(printf '%.0s[' $(seq 32))$(printf '%.0s]' $(seq 32))}" "$A" "$B"
case_env refuse-key-twice-in-the-body "$E{\"x\":1,\"x\":2}}" "$A" "$B"
case_env refuse-nan-in-the-body "${E}NaN}" "$A" "$B"
case_env refuse-leading-zero-in-the-body "$E[01]}" "$A" "$B"
case_env refuse-noncharacter-in-the-body "$E\"\\\\uffff\"}" "$A" "$B"
case_env refuse-above-u10ffff-in-the-body "$E\"\xf4\x90\x80\x80\"}" "$A" "$B"
case_env refuse-byte-order-mark "\xef\xbb\xbf{$H,\"sent_at\":\"$NOW\",\"msg_id\":\"$MSG_ID\",\"body\":\"hello\"}" "$A" "$B"

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
# The signature block is read as ssh-keygen reads a signature (sig/), and is at most 4096 bytes from its BEGIN line through its END line.
{ cat message/a-to-b.line; sed "2s/\$/ \r/; 3s/^/"$'\t'"/" "$GOOD_SIG"; } > plain/accept-whitespace-in-the-signature.txt
{ cat message/a-to-b.line; sed "2s/\$/$(printf "%$((4097 - $(wc -c < "$GOOD_SIG")))s" '')/" "$GOOD_SIG"; } > plain/refuse-signature-over-4096-bytes.txt
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
line "$A" "$B" "$ID_A\\n" > "$L"; refuse refuse-identity-ending-in-a-line-feed "$L" under a-work a/work-cert.pub "irongall-msg-v1:$B" # a JSON escape: the document's base64 and a line feed
line "$A" "$B" "$ID_A\\u0000" > "$L"; refuse refuse-identity-ending-in-a-nul "$L" under a-work a/work-cert.pub "irongall-msg-v1:$B"
printf '{"v":1,"from":null,"to":"%s","sent_at":"%s","msg_id":"%s","identity":"%s","body":"hello"}\n' "$B" "$NOW" "$MSG_ID" "$ID_A" > "$L"; refuse refuse-from-null "$L" under a-work a/work-cert.pub "irongall-msg-v1:$B" # null is a member left out: it names no sender
line "$(sha256sum < identity/small-order-1.doc | cut -c1-64)" "$B" "$(b64 < identity/small-order-1.doc)" > "$L"; refuse refuse-identity-of-small-order "$L" under a-work a/work-cert.pub "irongall-msg-v1:$B"
line "$A" "$A" "$ID_A" > "$L"; refuse refuse-to-another-box "$L" under a-work a/work-cert.pub "irongall-msg-v1:$B"
# The layout. Each part has one place, and nothing is searched for.
head -c -1 message/a-to-b.line > plain/refuse-no-line-feed.txt
cp message/a-to-b.line plain/refuse-no-signature.txt
{ cat message/a-to-b.line; echo; cat "$GOOD_SIG"; } > plain/refuse-blank-line-before-the-signature.txt
cat "$GOOD_SIG" message/a-to-b.line > plain/refuse-signature-first.txt
{ cat message/a-to-b.line; grep -v -e '-----END' "$GOOD_SIG"; } > plain/refuse-no-end-line.txt
{ cat message/a-to-b.line; head -c -1 "$GOOD_SIG"; } > plain/refuse-end-line-without-its-line-feed.txt
{ cat message/a-to-b.line; head -c -1 "$GOOD_SIG"; printf '\0\n'; } > plain/refuse-end-line-followed-by-a-nul.txt
sed 's/$/\r/' message/a-to-b.line > "$L"; { cat "$L"; under a-work a/work-cert.pub "irongall-msg-v1:$B" < "$L" | sed 's/$/\r/'; } > plain/refuse-crlf.txt
printf '{\n"v":1,"from":"%s","to":"%s","sent_at":"%s","msg_id":"%s","identity":"%s","body":"hello"}\n' "$A" "$B" "$NOW" "$MSG_ID" "$ID_A" > "$L"; refuse refuse-envelope-on-two-lines "$L" under a-work a/work-cert.pub "irongall-msg-v1:$B"
rm -f "$L"

# JSON texts as every reader takes one (PROTOCOL.md §0b): ok-* are taken and bad-* refused, by the server, the Go client
# and the script alike, whatever they hold. Each breaks one rule, or none.
mkdir -p json
jt() { local name=$1; shift; printf "$@" > "json/$name.json"; } # <name> <printf format…>: \\ in the format is one backslash in the text
deep() { printf '{"a":'; printf '%.0s[' $(seq "$1"); printf '%.0s]' $(seq "$1"); printf '}'; } # an object holding arrays nested <n> deep inside it
jt ok-object '{"a":1}\n'
jt ok-empty '{}'
jt ok-whitespace '{ "a" :\t[ 1 ,\r\n 2 ] }\n'
jt ok-numbers '{"a":[0,-0,1.5,-1e10,1E+2,0.5e-3,9007199254740993]}' # outside a member the protocol defines, any JSON number
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

# Whole answers of a server, as each client reads them (PROTOCOL.md §0b): <kind>-ok-* are taken and <kind>-bad-* are no
# answer, to the Go client and the script alike. A member a client does not know is ignored; one it reads is of its
# type or null, which is as if it were left out; a byte member is base64 in its one encoding.
mkdir -p answer
at() { local name=$1; shift; printf "$@" > "answer/$name.json"; }
REV=$(b64 < a/revoke.sig); P1=$(b64 < a/prekey-1.txt); P1S=$(b64 < a/prekey-1.txt.sig); CT=$(b64 < message/a-to-b.age); HASH=$(sha256sum < message/a-to-b.age | cut -c1-64)
wrap() { printf '%s' "$1" | fold -w 64 | sed 's/$/\\n/' | tr -d '\n' | sed 's/\\n$//'; } # base64 with a JSON \n escape after each 64 characters
NOPAD=${REV%%=*}; LASTBITS=$(printf '%s' "$REV" | sed 's/A==$/B==/; s/Q==$/R==/; s/g==$/h==/; s/w==$/x==/') # the revocation is 403 bytes: two = of padding, and 4 unused bits
[ "$NOPAD" != "$REV" ] && [ "$LASTBITS" != "$REV" ] || { echo "a/revoke.sig is not base64 with padding and unused bits, which the bad answers need" >&2; exit 1; }
at record-ok-revocation '{"identity":"%s","revocation":"%s"}' "$ID_A" "$REV"
at record-ok-null-members '{"identity":null,"revocation":null,"revoked_certificates":null,"revoked_certificates_signature":null}'
at record-ok-unknown-member '{"identity":"%s","revocation":"%s","later":[1,{"x":true}]}' "$ID_A" "$REV"
at record-ok-names-in-another-case '{"Identity":"%s","REVOCATION":"%s"}' "$ID_A" "$REV" # members it does not know: a record that shows nothing
at record-ok-empty-object '{}'
at record-bad-empty ''
at record-bad-an-array '[]'
at record-bad-identity-a-number '{"identity":5,"revocation":"%s"}' "$REV"
at record-bad-revocation-unpadded '{"identity":"%s","revocation":"%s"}' "$ID_A" "$NOPAD"
at record-bad-revocation-unused-bits-set '{"identity":"%s","revocation":"%s"}' "$ID_A" "$LASTBITS"
at record-bad-identity-wrapped '{"identity":"%s","revocation":"%s"}' "$(wrap "$ID_A")" "$REV"
at record-bad-identity-twice '{"identity":"%s","identity":"%s","revocation":"%s"}' "$ID_A" "$ID_B" "$REV"
at record-bad-null-after-a-value '{"identity":"%s","revocation":"%s","revocation":null}' "$ID_A" "$REV"
at record-bad-nan-beside-it '{"identity":"%s","revocation":"%s","later":NaN}' "$ID_A" "$REV"
at record-bad-a-second-value '{"identity":"%s","revocation":"%s"}{}' "$ID_A" "$REV"
at identity-ok '{"identity":"%s","prekey":"%s","prekey_signature":"%s"}' "$ID_A" "$P1" "$P1S"
at identity-ok-sender-key-types '{"identity":"%s","prekey":"%s","prekey_signature":"%s","sender_key_types":["ecdsa-sha2-nistp256"]}' "$ID_A" "$P1" "$P1S"
at identity-bad-sender-key-types-a-string '{"identity":"%s","prekey":"%s","prekey_signature":"%s","sender_key_types":"any"}' "$ID_A" "$P1" "$P1S"
at identity-bad-signature-unpadded '{"identity":"%s","prekey":"%s","prekey_signature":"%s"}' "$ID_A" "$P1" "${P1S%%=*}"
at identity-bad-prekey-a-number '{"identity":"%s","prekey":1,"prekey_signature":"%s"}' "$ID_A" "$P1S"
at list-ok '{"count":1,"messages":[{"id":"%s","from":"%s","size":%s,"received_at":"%s","expires_at":"2026-11-12T00:00:00Z"}],"next_cursor":null,"poll_after":60}' "$HASH" "$A" "$(wc -c < message/a-to-b.age)" "$NOW"
at list-ok-empty '{"count":0,"messages":[],"next_cursor":null,"poll_after":60}'
at list-bad-count-negative '{"count":-1,"messages":[],"next_cursor":null,"poll_after":60}'
at list-bad-count-above-2-53 '{"count":9007199254740992,"messages":[],"next_cursor":null,"poll_after":60}'
at list-bad-count-a-fraction '{"count":0.5,"messages":[],"next_cursor":null,"poll_after":60}'
at list-bad-count-written-with-a-fraction '{"count":1.0,"messages":[],"next_cursor":null,"poll_after":60}' # an integer member is written as one
at list-bad-size-a-string '{"count":1,"messages":[{"id":"%s","from":"%s","size":"2048"}],"next_cursor":null,"poll_after":60}' "$HASH" "$A"
at list-bad-messages-an-object '{"count":0,"messages":{},"next_cursor":null,"poll_after":60}'
at list-bad-cursor-a-number '{"count":0,"messages":[],"next_cursor":7,"poll_after":60}'
at message-ok '{"id":"%s","from":"%s","received_at":"%s","expires_at":"2026-11-12T00:00:00Z","ciphertext":"%s"}' "$HASH" "$A" "$NOW" "$CT"
at message-bad-ciphertext-wrapped '{"id":"%s","from":"%s","ciphertext":"%s"}' "$HASH" "$A" "$(wrap "$CT")"
at message-bad-from-a-number '{"id":"%s","from":5,"ciphertext":"%s"}' "$HASH" "$CT"
at receipt-ok '{"id":"%s","received_at":"%s","expires_at":"2026-11-12T00:00:00Z"}' "$HASH" "$NOW"
at receipt-bad-id-an-array '{"id":["%s"],"received_at":"%s"}' "$HASH" "$NOW"
at problem-ok '{"type":"https://irongall.dev/errors/not_revoked","title":"Not revoked","status":404,"detail":"no revocation of this address is held here","code":"not_revoked","hint":"nothing to do"}'
at problem-bad-code-twice '{"type":"https://irongall.dev/errors/not_revoked","status":404,"code":"not_revoked","code":"revoked"}'
at problem-bad-status-a-string '{"status":"404","code":"not_revoked"}'
at problem-bad-status-a-fraction-after-the-code '{"code":"not_revoked","status":1.5}' # a reader that kept what it read before the fault would act on the code
