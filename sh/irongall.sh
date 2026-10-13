#!/usr/bin/env bash
# irongall.sh: the irongall client in stock tools (bash, age, ssh-keygen, curl, jq, iconv and coreutils).
#
# The same protocol, checks and on-disk box as the Go client in this repo, so either can run a box. It fails CLOSED:
# a failed check prints one "REFUSED: <reason>" line and stops (recv refuses that one message, "REFUSED <id>: <code>: <words>", and goes on), and every API error prints its code and what the server says.
# Get it from https://github.com/IronGall-dev/irongall-client at a commit you have read, never from the irongall.dev
# server: a server that could hand you this script could hand you one without its checks.
#
#   bash irongall.sh init [--no-pq]                  make and register this box; prints its link, $IG_BASE/to/<address>
#   bash irongall.sh addr                            print it again: give it to whoever should write to this box
#   bash irongall.sh send [options] <link> [file]    one message (the body from stdin without a file); an address or an alias works too.
#                                                    Options: --subject <text>, --reply-to <msg_id>, --supersedes <msg_id>
#   bash irongall.sh alias [<name> <link>]           name a peer for this box only, so send takes the name; without arguments, list them
#   bash irongall.sh flush                           retry what is still in outbox/
#   bash irongall.sh recv                            verified mail only, one JSON line each; refused mail goes to quarantine/
#   bash irongall.sh rekey [--no-pq]                 a new prekey, working key and certificate: at least monthly, as a prekey is valid for 33 days
#   The README has the rest: https://github.com/IronGall-dev/irongall-client#readme
#
# Or source it at the top of every shell call and call the ig_* functions. Agent tools run each command in a fresh
# shell, so all state lives in files in the box's directory, never in variables.
#
# It gives up conveniences the Go client has: recv drains once and never waits for mail, and each step runs several
# programs. Needs bash >= 4, age >= 1.3 (1.2 makes and reaches --no-pq boxes only), OpenSSH
# >= 9.1, curl >= 7.76, jq >= 1.6, iconv, and coreutils (sha256sum, base64, od, sync).

# recipe: setup
set -o pipefail; umask 077
IG_BASE=${IG_BASE:-https://irongall.dev}
IG=${IRONGALL_HOME:-${XDG_CONFIG_HOME:-$HOME/.config}/irongall/${IRONGALL_BOX:-default}}   # one box per directory; never the working directory
IG_SENDERS='["ssh-ed25519","ecdsa-sha2-nistp256"]'   # the identity key types ig_idcheck verifies. A box declares them with each prekey it publishes, and the server then refuses it mail from a box whose identity is of any other type
ig_refuse(){ printf 'REFUSED: %s\n' "$*" >&2; return 1; }
ig_hex(){ [[ $1 =~ ^[0-9a-f]{64}$ ]]; }
ig_b64(){ base64 < "$1" | tr -d '\n'; }
ig_now(){ date -u +%s; }   # the one clock every check reads
ig_time(){ # <timestamp> → its Unix time, only for exactly YYYY-MM-DDTHH:MM:SSZ naming a real time
  local s; [[ $1 =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || return 1
  s=$(jq -nr --arg t "$1" '$t | fromdateiso8601 | select(todate == $t)' 2> /dev/null) && [ -n "$s" ] && echo "$s"
}
ig_api(){ # <METHOD> <PATH> [JSON file] [curl args…] → the body on stdout. Any non-2xx: prints its code, then what the server says (its detail, with the limit hit and the seconds to wait, and its hint) in quotes, as ITS words: one line, printable ASCII, cut short. Keeps the answer in $IG/error.json, returns 1
  local m=$1 p=$2 f=${3-}; shift 2; [ $# -gt 0 ] && shift
  rm -f "$IG/error.json"
  curl -sS --max-time 60 --max-filesize 16777216 --fail-with-body -X "$m" ${f:+-H 'Content-Type: application/json' --data-binary "@$f"} "$@" "$IG_BASE$p" > "$IG/response.json" && { cat "$IG/response.json"; return 0; }
  mv "$IG/response.json" "$IG/error.json"
  jq -er '"ERROR \(.status | numbers) \(.code | strings | select(test("\\A[a-z0-9_]{1,40}\\z"))); the server says: \([.detail, .hint] | map(strings | gsub("[^ -~]"; " ") | .[0:200] | select(. != "")) | join("; ") | tojson)"' "$IG/error.json" >&2 2> /dev/null ||
    echo "ERROR: the server's answer is not an error this client knows (it is kept in $IG/error.json)" >&2; return 1
}
ig_code(){ jq -r .code "$IG/error.json" 2> /dev/null; }   # the code of the last API error
ig_opt(){ [ -z "$1" ] || [ "$1" = --no-pq ] || ig_refuse "unknown option $1: the only one is --no-pq (no post-quantum encryption, X25519 only)"; }
ig_stamp(){ jq -nr --argjson t "$1" '$t | strftime("%Y%m%d%H%M%SZ")'; }      # <Unix time> → the time as ssh-keygen takes one, in UTC
ig_asc(){ printf %s "$1" | od -An -v -tx1 | tr -d ' \n'; }      # <text> → its bytes in hex
ig_owner(){ # ig_api as this box: adds its pass. If the server refuses the pass (it ran out sooner by the server's clock, or is under a certificate the server no longer takes), signs another and tries once more
  local p; p=$(ig_pass) || return 1
  ig_api "$1" "$2" "${3-}" -H "Authorization: $p" && return 0
  case $(ig_code) in pass_expired | unauthorized) ;; *) return 1 ;; esac
  rm -f "$IG/pass"; p=$(ig_pass) && ig_api "$1" "$2" "${3-}" -H "Authorization: $p"
}
ig_pass(){ # [serial] → the Authorization value of a call as this box. Without a serial: the pass kept in $IG/pass while it has more than 30 seconds left, otherwise a new one, signed by the working key in use and kept. With one: a pass signed by that working key, for the call that publishes its prekey, left in $IG/pass.new until the server has taken it
  local A n=${1-} na h; A=$(cat "$IG/address") || return 1
  if [ -z "$n" ]; then
    na=$(ig_time "$(sed -n 's/.* not_after="\([^"]*\)".*/\1/p' "$IG/pass" 2> /dev/null)") && [ $((na - $(ig_now))) -gt 30 ] && { cat "$IG/pass"; return; }
    n=$(cat "$IG/serial" 2> /dev/null) || ig_refuse "this box has published no prekey: run init, or rekey for a box restored from its identity" || return 1
  fi
  h=${IG_BASE#*://}; h=${h%%/*}; na=$(jq -nr --argjson t "$(ig_now)" '$t + 600 | todate')      # who is calling, which server, and until when: ten minutes
  printf 'irongall-pass-v1\n%s\n%s\n%s\n' "$A" "${h,,}" "$na" | ssh-keygen -q -Y sign -n "irongall-pass-v1:$A" -f "$IG/work/$n-cert.pub" > "$IG/pass.sig" 2> /dev/null ||
    ig_refuse "this box cannot sign a pass with working key $n: rekey makes a new working key, certificate and prekey" || return 1
  printf 'irongall-pass address="%s", not_after="%s", signature="%s"\n' "$A" "$na" "$(ig_b64 "$IG/pass.sig")" > "$IG/pass.new" || return 1
  [ -n "${1-}" ] || mv "$IG/pass.new" "$IG/pass" || return 1
  cat "$IG/pass${1:+.new}"
}
ig_lock(){ # [seconds] → takes $IG/lock, one consumer per box, waiting up to that long while another holds it
  local end=$((SECONDS + ${1:-0}))
  [ -s "$IG/address" ] || { ig_refuse "no box in $IG: run init first"; return 1; }
  until mkdir "$IG/lock" 2> /dev/null; do
    [ "$SECONDS" -lt "$end" ] || { ig_refuse "another consumer holds $IG/lock: one consumer per box (remove it if stale)"; return 1; }
    sleep 1
  done
}

# recipe: keys and registration
ig_work(){ # <serial> → work/<serial>, .pub and -cert.pub: a NEW working key, and the certificate this box's identity gives it, with that serial, good for 65 days. The working key signs what the box says; the identity signs certificates and nothing else
  local A w="$IG/work/$1" t; A=$(cat "$IG/address") || return 1; mkdir -p "$IG/work" || return 1
  [ -s "$w" ] && [ -s "$w-cert.pub" ] && return 0
  rm -f "$w" "$w.pub" "$w-cert.pub"; t=$(ig_now)
  ssh-keygen -q -t ed25519 -N '' -C '' -f "$w" < /dev/null &&
  ssh-keygen -q -s "$IG/identity" -I irongall-cert-v1 -n "$A" -z "$1" -V "$(ig_stamp $(((t - 59) / 60 * 60))):$(ig_stamp $((t + 65*86400)))" -O clear "$w.pub"      # one principal, the address; no option and no extension
}
ig_prekey(){ # <serial> [--no-pq] → prekeys/<serial>.agekey and its statement, signed by a NEW working key (ig_work): a NEW key, valid for 33 days. A re-run reuses the key a failed attempt left, whatever its type
  local A p="$IG/prekeys/$1"; A=$(cat "$IG/address") || return 1
  [ -s "$p.txt.sig" ] && return 0
  if [ ! -e "$p.agekey" ]; then if [ "${2-}" = --no-pq ]; then age-keygen -o "$p.agekey"; else age-keygen -pq -o "$p.agekey"; fi 2> /dev/null || ig_refuse "age-keygen failed: post-quantum needs age >= 1.3 (or make a box with --no-pq)" || return 1; fi
  ig_work "$1" || return 1
  printf 'irongall-prekey-v1\n%s\n%s\n%s\n%s\n' "$A" "$1" "$(age-keygen -y "$p.agekey")" "$(jq -nr --argjson t "$(ig_now)" '$t + 33*86400 | todate')" > "$p.txt" &&
  ssh-keygen -q -Y sign -n "irongall-prekey-v1:$A" -f "$IG/work/$1-cert.pub" < "$p.txt" > "$p.txt.sig"      # stdin to stdout: never a stale .sig
}
ig_init(){ # [--no-pq] → creates this box, or finishes a half-done init, and registers it; prints its link. The registration carries a pass the new working key signs, so the box is in use at once
  ig_opt "${1-}" || return 1
  mkdir -p "$IG/work" "$IG/prekeys" "$IG/peers" "$IG/inbox" "$IG/quarantine" "$IG/outbox" "$IG/sent" && printf '*\n' > "$IG/.gitignore" || return 1
  [ -e "$IG/identity" ] || ssh-keygen -q -t ed25519 -N '' -C '' -f "$IG/identity" < /dev/null || return 1
  printf 'irongall-v1\n%s\n' "$(cut -d' ' -f1,2 "$IG/identity.pub")" > "$IG/identity.doc"
  sha256sum < "$IG/identity.doc" | cut -c1-64 > "$IG/address" || return 1
  [ ! -s "$IG/serial" ] || { ig_addr; return; }      # registered already
  local A p="$IG/prekeys/1" h; A=$(cat "$IG/address"); ig_prekey 1 "${1-}" || return 1
  jq -n --arg i "$(ig_b64 "$IG/identity.doc")" --arg p "$(ig_b64 "$p.txt")" --arg s "$(ig_b64 "$p.txt.sig")" --argjson k "$IG_SENDERS" '{identity:$i, prekey:$p, prekey_signature:$s, sender_key_types:$k}' > "$IG/register.json"
  h=$(ig_pass 1) && ig_api PUT "/v1/$A" "$IG/register.json" -H "Authorization: $h" > /dev/null && mv "$IG/pass.new" "$IG/pass" && echo 1 > "$IG/serial" && ig_addr
}
ig_addr(){ local a; a=$(cat "$IG/address") && echo "$IG_BASE/to/$a"; }      # the box's link: what to give whoever should write to it
ig_dest(){ # <link, address or alias> → the address: 64 hex, or taken from a link to this box's server, $IG_BASE/to/<address>, or the one address $IG/aliases gives the name
  local a=${1#"$IG_BASE/to/"}
  if ig_name "$1"; then a=$(awk -v n="$1" '$1 == n {print $2}' "$IG/aliases" 2> /dev/null | sort -u); [ -n "$a" ] || { ig_refuse "no alias named $1: ig_alias lists them, and names one"; return 1; }; fi
  ig_hex "$a" && { echo "$a"; return 0; }
  [[ $1 != *://* || $1 = "$IG_BASE/"* ]] || { ig_refuse "a link to another server: this box's server is $IG_BASE"; return 1; }
  ig_refuse "not an address, a link to one, or an alias naming one address: $1"
}
ig_name(){ [[ $1 =~ ^[a-z0-9][a-z0-9._-]{0,31}$ ]]; }   # an alias: never 64 hex, never a link
ig_alias(){ # [<name> <link or address>] → names a peer for this box only, one "<name> <address>" line in $IG/aliases; without arguments, lists them. A name is never moved: to change or drop one, delete its line
  [ $# -gt 0 ] || { cat "$IG/aliases" 2> /dev/null; return 0; }
  local a have
  ig_name "$1" || { ig_refuse "not an alias: $1 (1 to 32 of a-z, 0-9, '.', '_' and '-', starting with a letter or a digit)"; return 1; }
  a=$(ig_dest "${2-}") || return 1
  have=$(awk -v n="$1" '$1 == n {print $2}' "$IG/aliases" 2> /dev/null | sort -u)
  [ -z "$have" ] || [ "$have" = "$a" ] || { ig_refuse "alias $1 already names $have: delete its line in $IG/aliases first"; return 1; }
  [ -n "$have" ] || echo "$1 $a" >> "$IG/aliases" || return 1
  echo "$1 $a"
}

# recipe: verify a peer
ig_keycheck(){ # <32 bytes in hex> → 0 only for an Ed25519 key that is canonical and not of small order
  [[ $1 =~ ^[0-9a-f]{64}$ && ! $1 =~ ^(e[d-f]|f[0-9a-f])(ff){30}(7f|ff)$ ]] || return 1      # y >= p: not canonical
  case $1 in      # the eight points of small order, and the two with x = 0 marked negative
    0100000000000000000000000000000000000000000000000000000000000000 | 0100000000000000000000000000000000000000000000000000000000000080 | \
    ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f | ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff | \
    0000000000000000000000000000000000000000000000000000000000000000 | 0000000000000000000000000000000000000000000000000000000000000080 | \
    26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05 | 26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85 | \
    c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a | c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa) return 1 ;;
  esac
}
ig_idcheck(){ # <identity document> [address] → 0 only for a two-line document in the one exact form of its key type, its key passing that type's checks (and hashing to the address, given one). 2 for a well-formed document of a key type this script does not verify: nothing is wrong with it, and nothing it signed can be checked here. 1 for anything else
  local f=$1 l t n
  l=$(sed -n 2p "$f"); t=${l%% *}; n=$(wc -c < "$f")
  [ "$(printf 'irongall-v1\n%s\n' "$l" | sha256sum)" = "$(sha256sum < "$f")" ] || return 1      # exactly the tag line and one more, each ending in LF, and not a byte else: the file against itself rebuilt from its second line. A shell variable drops a NUL, so a test of the variable alone would pass a file that holds one
  [ -z "${2-}" ] || [ "$(sha256sum < "$f" | cut -c1-64)" = "$2" ] || return 1
  case $t in
    ssh-ed25519)      # 93 bytes: a canonical point that is not of small order
      [ "$n" -eq 93 ] && grep -Eqx 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{43}' <<< "$l" && ig_keycheck "$(printf %s "${l#* }" | base64 -d | tail -c 32 | od -An -v -tx1 | tr -d ' \n')" ;;
    ecdsa-sha2-nistp256)      # 173 bytes: an uncompressed point. ssh-keygen refuses one that is off the curve, or has a coordinate of 128 bits or fewer, or of the group's order less one or more
      [ "$n" -eq 173 ] && grep -Eqx 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBB[A-P][A-Za-z0-9+/]{84}[AEIMQUYcgkosw048]=' <<< "$l" && ssh-keygen -l -f - <<< "$l" > /dev/null 2>&1 || return 1 ;;
    *)      # a type this script does not verify. A document all the same, if line 2 is a key type's name (printable ASCII with no comma, at most 64 characters), one space, and the base64, in its one encoding, of a wire key that begins with that name
      [ "$n" -eq $((13 + ${#l})) ] && LC_ALL=C grep -Eqx '[!-+.-~-]{1,64} [A-Za-z0-9+/]+={0,2}' <<< "$l" && [ "$(printf %s "${l#* }" | base64 -d 2> /dev/null | base64 | tr -d '\n')" = "${l#* }" ] &&
        [ "$(printf %s "${l#* }" | base64 -d | head -c $((4 + ${#t})) | od -An -v -tx1 | tr -d ' \n')" = "$(printf %08x "${#t}")$(ig_asc "$t")" ] && return 2
      return 1 ;;
  esac
}
ig_cert(){ # <signature> <identity document> <address> → "<serial> <valid after> <valid before>", as Unix times, for the certificate the signature carries, only if it is in its one form (below) and names that identity as its signer. Its fields are read from its bytes, in order: ssh-keygen -Y verify takes a certificate with extensions or an option, and checks no key id. Whether the identity's signature on it is good, and whether it holds now, are ig_certified's
  local x o=20 l v k n a b      # x: the bytes being read, in hex; o: how far into them; v: the field just read
  x=$(sed '1d;$d' "$1" | tr -d '\n' | base64 -d 2> /dev/null | od -An -v -tx1 | tr -d ' \n')
  [[ $x =~ ^[0-9a-f]*$ && ${x:0:20} = 53534853494700000001 ]] || return 1      # "SSHSIG", version 1, then the signing key as a string: here, the certificate
  ig_str || return 1; x=$v; o=0
  ig_str && [ "$v" = "$(ig_asc ssh-ed25519-cert-v01@openssh.com)" ] || return 1      # a certificate for an Ed25519 key
  ig_str || return 1      # the nonce
  ig_str && k=$v && ig_keycheck "$k" || return 1      # the working key, held to the identity's own key checks
  ig_u64 && n=$v && [ "$n" -ge 1 ] && [ "$n" -le 999999999999999999 ] || return 1      # the serial: 1 or more, at most 18 digits, as a prekey's
  [ "${x:o:8}" = 00000001 ] || return 1; o=$((o + 8))      # a user certificate
  ig_str && [ "$v" = "$(ig_asc irongall-cert-v1)" ] || return 1      # the key id
  ig_str && [ "$v" = "00000040$(ig_asc "$3")" ] || return 1      # exactly one principal: the address
  ig_u64 && a=$v && ig_u64 && b=$v || return 1      # valid after, valid before
  ig_str && [ -z "$v" ] && ig_str && [ -z "$v" ] && ig_str && [ -z "$v" ] || return 1      # no critical option, no extension, nothing reserved
  ig_str && [ "$v" = "$(sed -n 2p "$2" | cut -d' ' -f2 | base64 -d | od -An -v -tx1 | tr -d ' \n')" ] && [ "$v" != "0000000b$(ig_asc ssh-ed25519)00000020$k" ] || return 1      # signed by the identity's key, byte for byte, which is never the working key
  echo "$n $a $b"
}
ig_str(){ [[ ${x:o:8} =~ ^[0-9a-f]{8}$ ]] || return 1; l=$((16#${x:o:8} * 2)); [ $((o + 8 + l)) -le ${#x} ] || return 1; v=${x:o+8:l}; o=$((o + 8 + l)); }      # ig_cert's: the next length-prefixed string of x, in hex, into v
ig_u64(){ [[ ${x:o:16} =~ ^[0-7][0-9a-f]{15}$ ]] || return 1; v=$((16#${x:o:16})); o=$((o + 16)); }      # ig_cert's: the next 64-bit number of x into v. One with its top bit set is no time and no serial here
ig_certified(){ # <address> <identity document> <namespace> <signature> <message> [at] → "<certificate serial> <its valid before>" only for a signature by a working key under a certificate of that identity that holds at the time given (now, without one): begun, not ended, and ending at most 66 days on. 1 otherwise; 2 when only the time fails. A signature by the identity itself, or by a key with no certificate, is refused
  local A=$1 r n a b t=${6:-$(ig_now)}
  r=$(ig_cert "$4" "$2" "$A") || return 1; read -r n a b <<< "$r"
  printf '%s cert-authority %s\n' "$A" "$(sed -n 2p "$2")" > "$IG/signers"      # ONE line, built from checked bytes: only a certificate this identity signed, for this address
  ssh-keygen -Y verify -f "$IG/signers" -I "$A" -n "$3" -s "$4" -O verify-time="$(ig_stamp "$a")" < "$5" > /dev/null 2>&1 || return 1      # the two signatures, the identity's on the certificate and the working key's on the message, judged where the certificate begins; the time is the next line's
  [ "$a" -le "$t" ] && [ "$t" -lt "$b" ] && [ "$b" -le $((t + 66*86400)) ] || return 2
  echo "$n $b"
}
ig_prekeycheck(){ # <statement> <signature> <address> <identity document> [at] → "<serial> <age recipient> <not_after as Unix time> <certificate serial>" only for five LF-ended lines naming that address, signed by a working key its identity certified, not outliving that certificate, holding a key age will encrypt to; otherwise the reason, and 1
  local p=$1 B=$3 s k na c
  c=$(ig_certified "$B" "$4" "irongall-prekey-v1:$B" "$2" "$p" ${5-}) || { echo "$B's prekey is not signed by a working key its identity certified, under a certificate that holds now"; return 1; }
  [ "$(wc -l < "$p")" -eq 5 ] && [ "$(tail -c 1 "$p" | od -An -tx1 | tr -d ' \n')" = 0a ] && [ "$(sed -n 1p "$p")" = irongall-prekey-v1 ] && [ "$(sed -n 2p "$p")" = "$B" ] ||
    { echo "the prekey statement is not $B's: five lines, each ending in LF"; return 1; }
  s=$(sed -n 3p "$p"); [[ $s =~ ^[1-9][0-9]{0,17}$ ]] || { echo "$B's prekey serial is malformed"; return 1; }
  k=$(sed -n 4p "$p")
  if ! age -r "$k" < /dev/null > /dev/null 2>&1; then
    if [[ $k = age1pq1* ]]; then echo "$B's prekey is post-quantum, and this age ($(age --version 2> /dev/null)) cannot encrypt to one: that takes age >= 1.3"; else echo "$B's prekey is not an age key that age will encrypt to"; fi; return 1
  fi
  na=$(ig_time "$(sed -n 5p "$p")") || { echo "$B's prekey has no valid not_after"; return 1; }
  [ "$na" -le "${c#* }" ] || { echo "$B's prekey statement outlives the certificate it is signed under"; return 1; }
  echo "$s $k $na ${c% *}"
}
ig_resolve(){ # <address> → prints "<serial> <age recipient>" only when EVERY check passes; otherwise there is nothing to encrypt to. The identity is the pinned one, or at first contact the served one, kept only once its prekey statement has verified
  local B=$1 d="$IG/peers/$1" f r s k na c
  ig_hex "$B" || ig_refuse "not an address" || return 1
  ig_api GET "/v1/$B/identity" > "$IG/peer.json" || return 1
  f="$d/identity.doc"      # a pin always wins
  [ -e "$f" ] || { f="$IG/new.doc"; jq -er .identity "$IG/peer.json" 2> /dev/null | base64 -d > "$f" 2> /dev/null || ig_refuse "no identity for $B in the response" || return 1; }
  [ "$(sha256sum < "$f" | cut -c1-64)" = "$B" ] || ig_refuse "the identity the server sent does not hash to $B" || return 1
  ig_idcheck "$f"; case $? in 0) ;;
    2) ig_refuse "$B's identity is of a key type this script does not verify, so nothing it signs can be checked here and nothing is sent"; return 1 ;;
    *) ig_refuse "$B's identity is not a two-line identity document in the one form of its key type, with a valid key"; return 1 ;;
  esac
  jq -er .prekey "$IG/peer.json" | base64 -d > "$IG/peer.txt" && jq -er .prekey_signature "$IG/peer.json" | base64 -d > "$IG/peer.sig" || ig_refuse "no prekey for $B in the response" || return 1
  r=$(ig_prekeycheck "$IG/peer.txt" "$IG/peer.sig" "$B" "$f") || ig_refuse "$r" || return 1
  read -r s k na c <<< "$r"
  [ "$s" -ge "$(cat "$d/serial" 2> /dev/null || echo 0)" ] || ig_refuse "rollback: $B's prekey serial $s is below one already seen" || return 1
  [ "$c" -ge "$(cat "$d/cert-serial" 2> /dev/null || echo 0)" ] || ig_refuse "rollback: $B's prekey is signed under certificate $c, below one already seen" || return 1
  [ "$na" -gt "$(ig_now)" ] || ig_refuse "$B's prekey has expired: its owner must publish a new one" || return 1
  ig_meet "$B" "$f" && echo "$s" > "$d/serial" && echo "$c" > "$d/cert-serial" && cp "$IG/peer.txt" "$d/prekey.txt" && cp "$IG/peer.sig" "$d/prekey.sig" || return 1      # recorded only after every check passed
  echo "$s $k"
}
ig_meet(){ local d="$IG/peers/$1"; mkdir -p "$d" && { [ -e "$d/identity.doc" ] || cp "$2" "$d/identity.doc"; }; }      # <address> <its checked identity document> → pinned, unless it is already: called only for an identity that signed something this box verified

# recipe: send
ig_uuid(){ local h; h=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n'); printf '%s-%s-4%s-%x%s-%s\n' "${h:0:8}" "${h:8:4}" "${h:13:3}" $(( 0x${h:16:1} & 3 | 8 )) "${h:17:3}" "${h:20:12}"; }
ig_send(){ # [--subject <text>] [--reply-to <msg_id>] [--supersedes <msg_id>] <link, address or alias> [body file] → one logical message, its envelope built ONCE. To retry, run ig_flush, never ig_send again
  local B f A id s= r= x= v
  while [[ ${1-} = --* ]]; do      # --reply-to: the msg_id recv printed for the message this answers. --supersedes: an earlier message of this box's, as sent/ names it
    [ $# -ge 2 ] || { ig_refuse "$1 needs a value"; return 1; }
    case $1 in --subject) s=$2 ;; --reply-to) r=$2 ;; --supersedes) x=$2 ;; *) ig_refuse "unknown option $1: --subject, --reply-to or --supersedes, before the link"; return 1 ;; esac; shift 2
  done
  for v in "$r" "$x"; do [[ -z $v || $v =~ ^[0-9a-f-]{36}$ ]] || { ig_refuse "not a msg_id: $v (the 36-character msg_id in a message's envelope, never the 64-character id the server gives it)"; return 1; }; done
  f=${2-}; A=$(cat "$IG/address") && B=$(ig_dest "${1-}") || return 1
  mkdir -p "$IG/outbox" || return 1
  [ -n "$f" ] || { f="$IG/body.txt"; cat > "$f" || return 1; }
  iconv -f UTF-8 -t UTF-8 < "$f" > /dev/null 2>&1 && printf %s "$s" | iconv -f UTF-8 -t UTF-8 > /dev/null 2>&1 || ig_refuse "the body or the subject is not UTF-8 text" || return 1
  id=$(ig_uuid) || return 1
  jq -cn --arg from "$A" --arg to "$B" --arg id "$id" --argjson t "$(ig_now)" --arg i "$(ig_b64 "$IG/identity.doc")" --rawfile body "$f" --arg s "$s" --arg r "$r" --arg x "$x" \
    '{v:1, from:$from, to:$to, sent_at:($t|todate), msg_id:$id, identity:$i, body:$body} + ([{subject:$s}, {in_reply_to:$r}, {supersedes:$x}] | map(select(.[] != "")) | add // {})' > "$IG/outbox/$B.$id.P" || return 1      # ONE line, ending in a line feed: exactly the bytes that are signed. It carries this box's identity document, so its reader need not ask the server who wrote it
  ig_post "$B" "$IG/outbox/$B.$id"
}
ig_agehead(){ if [[ $1 = age1pq1* ]]; then echo 1627; else echo 168; fi; }      # <age recipient> → the size of an age file's header for one key of its type: its fields are fixed-size, so it never varies
ig_sealed(){ echo $(($(ig_agehead "$2") + 16 + $1 + 16 * ($1 > 65536 ? ($1 + 65535) / 65536 : 1))); }      # <plaintext bytes> <age recipient> → the size of the age file holding them: the header, a 16-byte nonce, and a 16-byte tag after each 64 KiB chunk
ig_blocks(){ # <size> → the size rounded up to a whole number of blocks. A block is 1/16 of the size, rounded up to a power of two, and never under 1 KiB: 1 KiB blocks up to 16 KiB, 2 KiB up to 32 KiB, and on
  local b=1024; while [ $((16 * b)) -lt "$1" ]; do b=$((b * 2)); done; echo $((($1 + b - 1) / b * b))
}
ig_padding(){ # <message bytes: the envelope's line and its signature> <age recipient> → "<padding bytes> <age file size>": the padding after the signature that makes the age file a whole number of blocks, so the server sees a message's size only to within a block. A message already on a block gets none
  local n=$1 s c; s=$(ig_blocks "$(ig_sealed "$n" "$2")"); c=$((s - $(ig_agehead "$2") - 16))      # what a file of that size has for its chunks, each with its tag
  echo "$((c - 16 * (c > 65552 ? (c + 65551) / 65552 : 1) - n)) $s"
}
ig_seal(){ # <address> <outbox stem> → <stem>.json: the envelope <stem>.P signed for that recipient only, by the working key in use, then the line, the signature and the padding encrypted to the recipient's VERIFIED prekey. It is git's layout for a signed tag: the signed bytes as they are, then the signature block. The envelope is read as its recipient will read it first
  local B=$1 o=$2 A r k n f t c why; A=$(cat "$IG/address") && n=$(cat "$IG/serial") || return 1
  why=$(ig_envcheck "$o.P" "$A" "$B") && [ "$(wc -l < "$o.P")" -eq 1 ] && [ "$(jq -r .identity "$o.P")" = "$(ig_b64 "$IG/identity.doc")" ] || ig_refuse "the outbox entry is not an envelope this box made for that address${why:+: $why}" || return 1
  c=$(ig_cert "$IG/prekeys/$n.txt.sig" "$IG/identity.doc" "$A") && [ $((${c##* } - $(ig_now))) -gt $((33*86400)) ] ||      # the certificate in use: the one this box's published prekey is signed under
    ig_refuse "this box's certificate ends within 33 days, too soon to sign mail that may wait that long (or it has no working key): rekey makes a new one" || return 1
  r=$(ig_resolve "$B") || return 1; k=${r#* }
  ssh-keygen -q -Y sign -n "irongall-msg-v1:$B" -f "$IG/work/$n-cert.pub" < "$o.P" > "$o.sig" || return 1
  read -r f t <<< "$(ig_padding $(($(wc -c < "$o.P") + $(wc -c < "$o.sig"))) "$k")" && [ -n "$t" ] || return 1
  { cat "$o.P" "$o.sig" && head -c "$f" /dev/zero | tr '\0' .; } | age -r "$k" > "$o.age" || return 1
  [ "$(wc -c < "$o.age")" -eq "$t" ] || ig_refuse "the encrypted message is not the $t bytes its padding was made for: it is not sent at a size that tells its length" || return 1
  ig_b64 "$o.age" > "$o.b64" && jq -n --argjson n "${r%% *}" --rawfile c "$o.b64" '{prekey_serial:$n, ciphertext:$c}' > "$o.json" && rm -f "$o.b64"      # no signature beside it: the server knows the sender from the pass the post carries
}
ig_post(){ # <address> <outbox stem> → POSTs it, sealing it first; on 409 stale_prekey, re-encrypts the SAME envelope, once. One that can never be delivered moves to outbox/failed/
  local B=$1 o=$2 sa
  if sa=$(ig_time "$(jq -r .sent_at "$o.P" 2> /dev/null)") && [ "$sa" -lt $(($(ig_now) - 33*86400)) ]; then      # the server would take it, and every recipient refuses it
    ig_failed "$o"; ig_refuse "its envelope is older than 33 days, and every recipient refuses that: moved to outbox/failed/"; return 1
  fi
  rm -f "$IG/error.json"
  { [ -e "$o.json" ] || ig_seal "$B" "$o"; } && ig_owner POST "/v1/$B" "$o.json" > "$IG/receipt.json" && { ig_sent "$o"; return; }
  if [ "$(ig_code)" = stale_prekey ]; then ig_seal "$B" "$o" && ig_owner POST "/v1/$B" "$o.json" > "$IG/receipt.json" && { ig_sent "$o"; return; }; fi
  case $(ig_code) in
    revoked | sender_revoked | bad_address | too_large | conflict) ig_failed "$o"; echo "it can never be delivered: moved to outbox/failed/" >&2 ;;
    *) echo "kept in the outbox: retry with ig_flush" >&2 ;;
  esac
  return 1
}
ig_sent(){ # <outbox stem> → sent/<address>.<msg_id>.json: the envelope as one line, as the recipient's recv delivers it, with the server's receipt. Stored, and only then does the outbox entry go. sent/ is yours to prune
  local t="$IG/sent/${1##*/}.json"
  mkdir -p "$IG/sent" && ig_line "$1.P" "$IG/receipt.json" > "$t" && sync "$t" "$IG/sent" && rm -f "$1.P" "$1.age" "$1.sig" "$1.json" || { echo "sent, but not recorded in sent/ (still in the outbox: ig_flush records it)" >&2; return 1; }
}
ig_failed(){ # <outbox stem> → moves its files to outbox/failed/, where ig_flush no longer sees them. Delete them there to drop the message
  local f; mkdir -p "$IG/outbox/failed" || return 1
  for f in "$1.P" "$1.age" "$1.sig" "$1.json"; do [ ! -e "$f" ] || mv "$f" "$IG/outbox/failed/" || return 1; done
}
ig_flush(){ # re-POSTs every message still in the outbox, unchanged: a retry gets the original receipt. One that fails never stops the others
  local f n rc=0; for f in "$IG"/outbox/*.P; do [ -e "$f" ] || continue; n=$(basename "$f" .P); ig_post "${n%%.*}" "${f%.P}" || rc=1; done; return $rc
}

# recipe: receive
ig_recv(){ # drains the box, every page up to a drain's limits. ACCEPT → inbox/ and one line on stdout. REFUSED → quarantine/, never delivered. Both are acked
  ig_lock || return 1
  ig_drain; local rc=$?; rmdir "$IG/lock"; ig_prune; return $rc
}
ig_drain(){ # stops at a transient error or a fault of this box, leaving the rest on the server for the next drain. And at a number of messages and of pages (below): a server that lists mail without end costs one run that much
  local B c="" n i id k=0 pages=0; B=$(cat "$IG/address") || return 1
  if [ -e "$IG/seen" ]; then awk -v c=$(($(ig_now) - 33*86400)) '$2 >= c' "$IG/seen" > "$IG/seen.new" && mv "$IG/seen.new" "$IG/seen" && sync "$IG/seen" "$IG" || return 1; fi
  while :; do
    [ $((pages += 1)) -le 100 ] || { echo "this run stopped at the most one drain takes: run recv again for the rest, which is still on the server" >&2; return 0; }
    ig_owner GET "/v1/$B/messages${c:+?cursor=$c}" > "$IG/list.json" && n=$(jq -er '.messages | length' "$IG/list.json") || return 1
    for ((i = 0; i < n; i++)); do
      id=$(jq -r ".messages[$i].id" "$IG/list.json"); ig_hex "$id" || continue
      [ $((k += 1)) -le 1000 ] || { echo "this run stopped at the most one drain takes: run recv again for the rest, which is still on the server" >&2; return 0; }
      if ! grep -q "^$id " "$IG/seen" 2> /dev/null; then ig_one "$B" "$id" || return 1; fi   # an id already handled is only acked again
      ig_owner DELETE "/v1/$B/messages/$id" > /dev/null || [ "$(ig_code)" = no_such_message ] || return 1
    done
    c=$(jq -r '.next_cursor // empty' "$IG/list.json"); [ -n "$c" ] || return 0
  done
}
ig_one(){ # <me> <id> → 0 once the message is judged and its verdict is on disk; 1 on a transient error or a fault of this box, so it is not acked
  local B=$1 id=$2 m="$IG/msg" A why rc h
  rm -f "$m.json" "$m.age" "$m.sig" "$m.P" "$m.T" "$m.doc"
  ig_owner GET "/v1/$B/messages/$id" > "$m.json" || { [ "$(ig_code)" = no_such_message ]; return; }      # already gone
  h=$(jq -er .ciphertext "$m.json" 2> /dev/null | base64 -d 2> /dev/null | sha256sum | cut -c1-64)      # files are named by the hash computed here, never the server's id
  why=$(ig_judge "$B" "$(jq -r .from "$m.json")" "$m"); rc=$?
  if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then [ "$h" = "$id" ] || { why="bad_id: the server's id for it is not the SHA-256 of its ciphertext"; rc=1; }; fi
  case $rc in
    0) A=$(jq -r .from "$m.P") && ig_line "$m.P" > "$IG/inbox/$h.json" && sync "$IG/inbox/$h.json" "$IG/inbox" && ig_seen "$A" "$m" "$h" || return 1      # stored, then seen, both on disk before the ack: a crash delivers again, never loses
       cat "$IG/inbox/$h.json" && echo ;;
    2) echo "duplicate of a message already delivered, not delivered again: $h" >&2 ;;
    3) echo "$why: nothing is judged or acked until this box is fixed" >&2; return 1 ;;
    *) cp "$m.json" "$IG/quarantine/$h.json" && printf '%s\n' "$why" > "$IG/quarantine/$h.reason" && sync "$IG/quarantine/$h.json" "$IG/quarantine/$h.reason" "$IG/quarantine" || return 1      # the message as served, and beside it why: "<code>: <words>", this script's own words, never the message's
       echo "REFUSED $h: $why" >&2 ;;
  esac
}
ig_judge(){ # <me> <the server's from> <message stem> → 0 only if EVERY check passes, in this order; 2 for a resend of an accepted msg_id; 1 refused, with "<code>: <words>" on stdout, the words this script's own and never the message's; 3 a fault of this box, no verdict. Nothing is asked of the server about the sender: the message carries what proves it
  local B=$1 m=$3 ids=() k h A
  jq -er .ciphertext "$m.json" | base64 -d > "$m.age" || { echo "bad_message: its ciphertext is not base64"; return 1; }
  for k in "$IG"/prekeys/*.agekey; do [ -e "$k" ] || continue; [ -r "$k" ] || { echo "cannot read $k"; return 3; }; ids+=(-i "$k"); done
  [ ${#ids[@]} -gt 0 ] || { echo "this box has no prekeys"; return 3; }
  age -d "${ids[@]}" < "$m.age" > "$m.T" 2> /dev/null || { echo "undecryptable: it does not decrypt with this box's prekeys"; return 1; }
  A=$(ig_open "$B" "$m") || { echo "$A"; return 1; }      # the sender, proved by what was decrypted
  [ "$2" = "$A" ] || { echo "reattributed: the server lists it as from another box than the one that signed it"; return 1; }
  [ ! -e "$IG/seen" ] || [ -r "$IG/seen" ] || { echo "cannot read $IG/seen"; return 3; }
  h=$(sha256sum < "$m.age" | cut -c1-64)
  ! grep -q "^$h " "$IG/seen" 2> /dev/null || { echo "replay: this ciphertext was already received"; return 1; }
  ig_meet "$A" "$m.doc" || { echo "cannot write under $IG/peers"; return 3; }
  ! grep -q " $A $(jq -r .msg_id "$m.P")\$" "$IG/seen" 2> /dev/null || return 2
}
ig_open(){ # <me> <message stem> → the sender's address, only if what was decrypted, <stem>.T, is a message for this box that its sender signed; otherwise "<code>: <words>", and 1. It leaves the envelope in <stem>.P, its signature in <stem>.sig and the sender's identity document in <stem>.doc
  local B=$1 m=$2 A
  # Line 1 is the envelope, line 2 begins the signature, the first END line ends it, and nothing after that is read. Each part has one place; nothing is searched for
  head -n 1 "$m.T" > "$m.P"; sed -n '2,/^-----END SSH SIGNATURE-----$/p' "$m.T" > "$m.sig"
  [ "$(tail -c 1 "$m.P" | od -An -tx1 | tr -d ' \n')" = 0a ] && [ "$(sed -n 1p "$m.sig")" = "-----BEGIN SSH SIGNATURE-----" ] && [ "$(tail -n 1 "$m.sig")" = "-----END SSH SIGNATURE-----" ] && [ "$(tail -c 1 "$m.sig" | od -An -tx1 | tr -d ' \n')" = 0a ] ||
    { echo "bad_message: what was decrypted is not an envelope line and then a signature block"; return 1; }
  ig_envform "$m.P" || return 1
  jq -e '.from | . == null or type == "string"' "$m.P" > /dev/null 2>&1 || { echo "bad_envelope: the envelope is malformed: its from is not what that field holds"; return 1; }
  jq -e 'has("identity")' "$m.P" > /dev/null 2>&1 || { echo "bad_identity: the envelope carries no identity document"; return 1; }
  jq -ejr '.identity | strings' "$m.P" 2> /dev/null | base64 -d > "$m.doc" 2> /dev/null && [ -s "$m.doc" ] && [ "$(ig_b64 "$m.doc")" = "$(jq -r .identity "$m.P")" ] || { echo "bad_identity: the envelope's identity is not base64 of an identity document"; return 1; }      # the one encoding of its bytes
  ig_idcheck "$m.doc"; case $? in 0) ;;      # a well-formed document of a key type this script does not verify has its own code, once it is known to be the sender's
    2) jq -e --arg a "$(sha256sum < "$m.doc" | cut -c1-64)" '.from == $a' "$m.P" > /dev/null 2>&1 || { echo "reattributed: the envelope's from is not the address of the identity it carries"; return 1; }
       echo "unsupported_key_type: the sender's identity is of a key type this client does not verify"; return 1 ;;
    *) echo "bad_identity: the envelope's identity document breaks its format or its key checks"; return 1 ;;
  esac
  A=$(sha256sum < "$m.doc" | cut -c1-64)      # the sender: the hash of the identity document the envelope carries. The document proves itself, and the signature must now verify under it
  jq -e --arg a "$A" '.from == $a' "$m.P" > /dev/null 2>&1 || { echo "reattributed: the envelope's from is not the address of the identity it carries"; return 1; }
  ig_certified "$A" "$m.doc" "irongall-msg-v1:$B" "$m.sig" "$m.P" > /dev/null; case $? in      # over line 1 exactly as decrypted, never over anything rebuilt
    0) ;; 2) echo "bad_signature: the certificate of the key that signed it has ended, or has not begun"; return 1 ;;
    *) echo "bad_signature: it is not signed for this box by a working key the sender's identity certified"; return 1 ;;
  esac
  ig_envcheck "$m.P" "$A" "$B" || return 1
  echo "$A"
}
ig_envform(){ # <envelope> → 0 only for UTF-8 that is one JSON object with no key twice; otherwise the reason, and 1
  iconv -f UTF-8 -t UTF-8 < "$1" > /dev/null 2>&1 || { echo "bad_envelope: the envelope is not UTF-8"; return 1; }
  [ "$(jq -n --stream '[inputs | select((length == 2 and (.[0] | length) == 1) or (length == 1 and (.[0] | length) == 2))] | length' "$1" 2> /dev/null)" = "$(jq length "$1" 2> /dev/null)" ] ||
    { echo "bad_envelope: the envelope is not one JSON object with no key twice"; return 1; }      # its members, counted as streamed, against its length: a key twice (jq keeps the last, another reader the first) or a second value breaks the count
}
ig_envcheck(){ # <envelope> <signer> <this box> → 0 only for one UTF-8 JSON object, keys exact and none twice, v the number 1, from the signer, to this box, a msg_id, a body, string optional fields, and sent_at no older than 33 days; otherwise the reason, and 1
  local e=$1 sa
  ig_envform "$e" || return 1
  jq -e '.v == 1 and has("body") and (.msg_id | type == "string" and test("\\A[0-9a-f-]{36}\\z")) and all(.subject, .in_reply_to, .supersedes, .identity; . == null or type == "string")' "$e" > /dev/null 2>&1 ||
    { echo "bad_envelope: the envelope is malformed: v the number 1, a body, a msg_id, and optional fields that are strings"; return 1; }
  jq -e --arg a "$2" --arg b "$3" '.from == $a and .to == $b' "$e" > /dev/null 2>&1 || { echo "reattributed: the inner from/to do not match the signer and this box (re-attribution)"; return 1; }
  sa=$(ig_time "$(jq -r .sent_at "$e")") || { echo "bad_envelope: the envelope's sent_at is not a UTC timestamp to the second"; return 1; }
  [ "$sa" -ge $(($(ig_now) - 33*86400)) ] || { echo "stale: sent_at is older than 33 days"; return 1; }
}
ig_line(){ # <checked envelope> [receipt] → the one line delivered: built from the checked fields, never the sender's bytes, with U+0085, U+2028 and U+2029 escaped (Python's splitlines and Node's readline end lines there). ig_sent adds the server's receipt as its last member
  jq -j --slurpfile r "${2:-/dev/null}" '{v: 1, from, to, sent_at, msg_id, body} + ([{subject}, {in_reply_to}, {supersedes}] | map(select(.[] | . != null and . != "")) | add // {}) + ($r[0] | if . then {receipt: {id, received_at, expires_at}} else {} end) | tojson | gsub("\u0085"; "\\u0085") | gsub("\u2028"; "\\u2028") | gsub("\u2029"; "\\u2029")' "$1"
}
ig_seen(){ # <sender> <message stem> <hash> → the message, in the replay set and on disk
  local new=; [ -e "$IG/seen" ] || new=$IG
  printf '%s %s %s %s\n' "$3" "$(ig_time "$(jq -r .sent_at "$2.P")")" "$1" "$(jq -r .msg_id "$2.P")" >> "$IG/seen" && sync "$IG/seen" ${new:+"$new"}
}

# recipe: new prekey (monthly)
ig_rekey(){ # [--no-pq] → publishes a new prekey, signed by a new working key under a new certificate, under the lock: a NEW key at the next serial, or the statement an earlier run signed and the server did not take, sent again as it is (waiting up to a minute for a drain). Needs only the identity, so it also recovers a box that lost its prekeys or its working key
  ig_opt "${1-}" && ig_lock 60 || return 1
  ig_renew "${1-}"; local rc=$?; rmdir "$IG/lock"; return $rc
}
ig_renew(){ # [--no-pq] → what ig_rekey does, the lock held. A serial is signed ONCE
  local A r s t na h c f; A=$(cat "$IG/address") || return 1; mkdir -p "$IG/prekeys"
  ig_api GET "/v1/$A/identity" > "$IG/self.json" || return 1
  jq -er .prekey "$IG/self.json" | base64 -d > "$IG/self.txt" && jq -er .prekey_signature "$IG/self.json" | base64 -d > "$IG/self.sig" || ig_refuse "the server sent no prekey for this box" || return 1
  c=$(ig_cert "$IG/self.sig" "$IG/identity.doc" "$A") && c=${c#* } && r=$(ig_prekeycheck "$IG/self.txt" "$IG/self.sig" "$A" "$IG/identity.doc" "${c% *}") || ig_refuse "this box's current prekey, as served: ${r:-it is not signed under a certificate of this identity}" || return 1      # its own record, judged where its certificate begins: whether this identity ever certified the key that signed it, even if that certificate has since ended
  s=${r%% *}
  [ "$s" -ge "$(cat "$IG/serial" 2> /dev/null || echo 0)" ] || ig_refuse "rollback: the server serves this box's prekey serial $s, below $(cat "$IG/serial"), which this box published" || return 1
  s=$((s + 1)); t=$(ls "$IG/prekeys" | sed -n 's/\.txt\.sig$//p' | sort -n | tail -n 1)      # the highest serial this box signed: nothing at or below it is signed anew
  if [ "${t:-0}" -ge "$s" ]; then s=$t; na=$(ig_time "$(sed -n 5p "$IG/prekeys/$s.txt")") && [ "$na" -gt "$(ig_now)" ] && [ -s "$IG/work/$s-cert.pub" ] || s=$((s + 1)); fi      # signed and never seen published: sent again AS IT IS until it expires, then the next serial. Signed again, the same key would get 33 more days from a server that keeps what it refuses
  [ -s "$IG/prekeys/$s.txt.sig" ] || rm -f "$IG/prekeys/$s.txt"; ig_prekey "$s" "${1-}" || return 1
  jq -n --arg p "$(ig_b64 "$IG/prekeys/$s.txt")" --arg g "$(ig_b64 "$IG/prekeys/$s.txt.sig")" --argjson k "$IG_SENDERS" '{prekey:$p, prekey_signature:$g, sender_key_types:$k}' > "$IG/rekey.json"
  h=$(ig_pass "$s") && ig_api PUT "/v1/$A/prekey" "$IG/rekey.json" -H "Authorization: $h" > /dev/null || return 1      # a pass under the NEW certificate: that is how a box moves to one, and the server then takes no pass under an older
  [ "$s" -le "$(cat "$IG/serial" 2> /dev/null || echo 0)" ] || echo "$s" > "$IG/serial" || return 1
  mv "$IG/pass.new" "$IG/pass" || return 1
  for f in "$IG"/work/*-cert.pub; do t=$(basename "$f" -cert.pub); [[ $t =~ ^[0-9]+$ ]] && [ "$t" -lt "$s" ] && rm -f "$IG/work/$t" "$IG/work/$t.pub" "$f"; done      # older working keys: what they signed is signed, and the server takes no pass under them
  ig_prune
}
ig_prune(){ # deletes every retired prekey past its deletion time: its not_after + the 33 days mail is kept. After that, mail encrypted to it is unrecoverable. (The Go client also deletes them sooner.)
  local f n top na; top=$(ls "$IG/prekeys" | sed -n 's/\.agekey$//p' | sort -n | tail -n 1); [ -n "$top" ] || return 0
  for f in "$IG"/prekeys/*.txt; do
    [ -e "$f" ] || continue
    n=$(basename "$f" .txt); [ "$n" -lt "$top" ] || continue      # never the newest
    na=$(ig_time "$(sed -n 5p "$f")") || continue
    [ "$(ig_now)" -lt $((na + 33*86400)) ] || rm -f "$IG/prekeys/$n.agekey" "$IG/work/$n" "$IG/work/$n.pub" "$IG/work/$n-cert.pub"      # and the working key made with it, if a renewal the server never took left one
  done
}

# Run as a command, not sourced.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case ${1-} in
    init | addr | send | alias | flush | recv | rekey) cmd=ig_$1; shift; "$cmd" "$@"; exit ;;
    *) sed -n '9,17p' "$0" | sed 's/^# *//' >&2; exit 2 ;;
  esac
fi
