#!/usr/bin/env bash
# irongall.sh: the irongall client in stock tools (bash, age, ssh-keygen, curl, jq, iconv and coreutils).
#
# The same protocol, checks and on-disk box as the Go client in this repo, so either can run a box. It fails CLOSED:
# a failed check prints an error line, "REFUSED: <reason>", and stops (recv refuses that one message with a refused line, its code and its words, and goes on), and every API error prints its status and its code, and none of the server's words.
# It prints JSON lines, as the Go client does, each with its "type" first: what a command did and met on stdout, and on stderr the
# line that says it failed ("error", here sometimes more than one), that its command line was wrong ("usage_error"), or that it waits.
# Get it from https://github.com/IronGall-dev/irongall-client at a commit you have read, never from the irongall.dev
# server: a server that could hand you this script could hand you one without its checks.
#
#   bash irongall.sh init [--no-pq]                  make and register this box; prints its link, $IG_BASE/to/<address>
#   bash irongall.sh addr                            print it again: give it to whoever should write to this box
#   bash irongall.sh send [options] <link> [file]    one message (the body from stdin without a file); an address or an alias works too.
#                                                    Options: --subject <text>, --reply-to <msg_id>, --supersedes <msg_id>, --json (the body is one JSON value)
#   bash irongall.sh recv                            verified mail, a "mail" line each; refused mail goes to quarantine/, with a "refused" line
#   bash irongall.sh alias add <name> <link>         name a peer for this box only, so send takes the name
#   bash irongall.sh alias list                      list the names
#   bash irongall.sh outbox flush                    retry what is still in outbox/
#   bash irongall.sh prekey renew [--no-pq]          a new prekey, working key and certificate: at least monthly, as a prekey is valid for 33 days, or within the lifetime a prekey-lifetime file sets
#   bash irongall.sh revocation make                 print this box's revocation record, one "revocation_record" line, and publish nothing: keep it somewhere other than this box
#   bash irongall.sh revocation publish <address> [record]
#                                                    revoke this box's address FOR GOOD (the address in full is the confirmation), or publish a record made earlier
#   bash irongall.sh revocation keep <record>        keep a revocation of another box that someone handed you: nothing goes to it or comes from it again
#   bash irongall.sh help [<command>]                this, or a command's lines; --help after a command does the same, and runs nothing
#   The README has the rest: https://github.com/IronGall-dev/irongall-client#readme
#
# Or source it at the top of every shell call and call the ig_* functions. Agent tools run each command in a fresh
# shell, so all state lives in files in the box's directory, never in variables.
#
# It gives up conveniences the Go client has: recv drains once and never waits for mail, and each step runs several
# programs. Needs bash >= 4, age >= 1.3 (1.2 makes and reaches --no-pq boxes only), OpenSSH
# >= 9.1, curl >= 7.76, jq >= 1.7.1 (1.7.0 can abort on a number a sender writes, CVE-2023-50246; Ubuntu 24.04's
# fixed jq prints jq-1.7), iconv, and coreutils (sha256sum, base64, od, sync).

# recipe: setup
set -o pipefail; umask 077
IG_BASE=${IG_BASE:-https://irongall.dev}
IG=${IRONGALL_HOME:-${XDG_CONFIG_HOME:-$HOME/.config}/irongall/${IRONGALL_BOX:-default}}   # one box per directory; never the working directory
IG_LOCK_WAIT=${IG_LOCK_WAIT:-120}   # how many seconds a command waits for the box's lock while another command of the box holds it: what apt waits for its own lock when no one is at a terminal
IG_SENDERS='["ssh-ed25519","ecdsa-sha2-nistp256"]'   # the identity key types ig_idcheck verifies. A box declares them with each prekey it publishes, and the server then refuses it mail from a box whose identity is of any other type
ig_out(){ jq -cn --arg type "$1" "${@:2}" '$ARGS.named'; }      # <type> [--arg <name> <text> | --argjson <name> <JSON>]… → one line of JSON on stdout, its type first and then each member in turn, as the Go client prints one: what a command did or met on the way
ig_err(){ jq -cn --arg m "$*" '{type:"error", message:$m}' >&2; }      # <words> → the line on stderr that says a command failed, in this script's own words
ig_refuse(){ ig_err "REFUSED: $*"; return 1; }
ig_hex(){ [[ $1 =~ ^[0-9a-f]{64}$ ]]; }
ig_b64(){ base64 < "$1" | tr -d '\n'; }
ig_now(){ date -u +%s; }   # the one clock every check reads
ig_time(){ # <timestamp> → its Unix time, only for exactly YYYY-MM-DDTHH:MM:SSZ naming a real time
  local s; [[ $1 =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || return 1
  s=$(jq -nr --arg t "$1" '$t | fromdateiso8601 | select(todate == $t)' 2> /dev/null) && [ -n "$s" ] && echo "$s"
}
ig_api(){ # <METHOD> <PATH> [body file] [curl args…] → the body on stdout, as curl -o wrote it. The body file is sent as it is: a message's ciphertext, POSTed to …/messages, as application/octet-stream (PROTOCOL.md §4.5), and any other body as JSON. Any non-2xx: an error line with its status, its code (ig_code) and the wait its Retry-After asks for, and nothing the server wrote: its detail, hint and title are for a person reading the body (PROTOCOL.md §13). No answer at all: an error line with curl's words. Keeps the answer in $IG/error.json and its headers in $IG/error.headers, returns 1
  local m=$1 p=$2 f=${3-} t=application/json s c w; shift 2; [ $# -gt 0 ] && shift
  [[ "$m $p" == "POST /v1/"*"/messages?"* ]] && t=application/octet-stream
  ig_tls "$IG_BASE" || return 1
  rm -f "$IG/error.json" "$IG/error.headers" "$IG/response.body"
  curl -sS --max-time 60 --max-filesize 16777216 --fail-with-body -D "$IG/response.headers" -o "$IG/response.body" -X "$m" ${f:+-H "Content-Type: $t" --data-binary "@$f"} "$@" "$IG_BASE$p" 2> "$IG/curl.err" &&
    [[ $(LC_ALL=C sed -n 's/^HTTP\/[0-9.]* \([0-9][0-9][0-9]\).*/\1/p' "$IG/response.headers" | tail -n 1) = 2?? ]] && { cat "$IG/response.body"; return 0; }      # only a 2xx is an answer: curl, which follows no redirect without -L, exits 0 on a 3xx too
  mv "$IG/response.body" "$IG/error.json" 2> /dev/null; mv "$IG/response.headers" "$IG/error.headers" 2> /dev/null
  s=$(ig_status); c=$(ig_code); w=$(ig_wait)
  [ -n "$s" ] || { ig_err "no answer from $IG_BASE: $(tr '\n' ' ' < "$IG/curl.err")"; return 1; }
  jq -cn --argjson s "$s" --arg c "$c" --arg w "$w" '{type:"error", status:$s} + (if $c != "" then {code:$c} else {} end) + (if $w != "" then {retry_after:($w | tonumber)} else {} end) +
    {message:("ERROR \($s)" + (if $c != "" then " \($c)" elif $s >= 300 and $s <= 399 then ": a redirect, which this client never follows: the API answers where it is called" else ": an answer this client does not know" end) + (if $w != "" then "; the server asks to wait \($w) seconds" else "" end))}' >&2; return 1
}
IG_TYPE='tag:irongall.dev,2026-10-17:errors/'      # an error's type is this and its code, which names the problem and resolves to nothing (PROTOCOL.md §13): a code counts only beside its own
IG_CODES='{"bad_request":400,"bad_address":400,"bad_encoding":400,"identity_mismatch":400,"bad_key":400,"prekey_not_new":400,"prekey_time":400,"unsupported_key_type":400,"not_age":400,"wrong_recipient_type":400,"bad_revocation":400,"unauthorized":401,"pass_expired":401,"certificate_not_current":401,"certificate_revoked":401,"unknown_sender":403,"sender_revoked":403,"sender_not_allowed":403,"sender_key_type":403,"adopt_key_refused":403,"no_such_mailbox":404,"no_such_message":404,"not_revoked":404,"conflict":409,"box_changed":409,"stale_prekey":409,"prekey_expired":409,"revoked":410,"too_large":413,"rate_limited":429,"renewals_spent":429,"certificates_spent":429,"certificate_revocations_spent":429,"sends_spent":429,"fetch_paced":429,"refetch_spent":429,"pair_full":429,"mailbox_full":429,"mailbox_busy":429,"unavailable":503}'      # every code, and its status (PROTOCOL.md §13)
ig_status(){ LC_ALL=C sed -n 's/^HTTP\/[0-9.]* \([0-9][0-9][0-9]\).*/\1/p' "$IG/error.headers" 2> /dev/null | tail -n 1; }      # the status of the last API error
ig_code(){ local s; s=$(ig_status) && [ -n "$s" ] && ig_shape "$IG/error.json" problem && jq -r --argjson codes "$IG_CODES" --argjson s "$s" --arg t "$IG_TYPE" '(.code | strings) as $c | select($codes[$c] == $s and .type == $t + $c) | $c' "$IG/error.json" 2> /dev/null; }   # the code of the last API error: one this client knows, under its own status, beside its own type, from an answer the Go client would read the same. Any other is no code
ig_wait(){ LC_ALL=C sed -n 's/^[Rr][Ee][Tt][Rr][Yy]-[Aa][Ff][Tt][Ee][Rr]: *\([0-9]\{1,\}\)\r\{0,1\}$/\1/p' "$IG/error.headers" 2> /dev/null | tail -n 1 | sed 's/^0*\([0-9]\)/\1/' | awk '$1 > 0 { print ($1 > 86400 ? 86400 : $1) }'; }      # the seconds the last API error's Retry-After asks to wait, as a number of at most a day, or nothing. It is delay-seconds, digits alone (PROTOCOL.md §13): an HTTP-date asks for no wait
ig_dated(){ local d; d=$(LC_ALL=C sed -n 's/^[Dd][Aa][Tt][Ee]: *\([A-Za-z0-9 ,:]*\)\r\{0,1\}$/\1/p' "$IG/error.headers" 2> /dev/null | tail -n 1) && [ -n "$d" ] && jq -nr --arg d "$d" '$d | strptime("%a, %d %b %Y %H:%M:%S GMT") | mktime | todate' 2> /dev/null; }      # the time the last API error's Date header gives, the server's word
ig_json(){ # <file> → 0 only for a JSON text as PROTOCOL.md §0b reads one: UTF-8 with no byte-order mark; one object; every number in JSON's own grammar; no member named twice in any object; nested at most 32 deep; and no Unicode noncharacter in a name or a string (I-JSON, RFC 7493). jq skips a byte-order mark and takes NaN, 01, +1 and .5, which JSON does not, so the numbers are read from the text, its strings taken out
  local n
  iconv -f UTF-8 -t UTF-8 < "$1" > /dev/null 2>&1 && ! LC_ALL=C grep -Eq $'[\xf5-\xff]|\xf4[\x90-\xbf]' "$1" && [ "$(od -An -N3 -tx1 "$1" | tr -d ' \n')" != efbbbf ] || return 1      # glibc's iconv takes a code point above U+10FFFF, which UTF-8 has none of
  cmp -s "$1" <(tr -d '\000-\010\013\014\016-\037' < "$1") || return 1      # no control byte but tab, LF and CR, and those only as whitespace (RFC 8259 §2, §7): jq ends a number at a NUL and drops it
  ! LC_ALL=C sed -E 's/\\\\//g; s/\\u[dD][89abAB][0-9a-fA-F]{2}\\u[dD][c-fC-F][0-9a-fA-F]{2}//g' "$1" | LC_ALL=C grep -aqE '\\u[dD][89a-fA-F][0-9a-fA-F]{2}' || return 1      # no escaped surrogate but in a pair: jq reads a lone low one as U+FFFD
  ! LC_ALL=C sed -E 's/"([^"\\]|\\.)*"//g' "$1" | tr '{}\133\135,: \t\r' '\n\n\n\n\n\n\n\n\n' | LC_ALL=C grep -aEqv '^$|^(true|false|null|-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?)$' || return 1
  n=$(jq -n --stream '[inputs | if length == 2 then .[0] else .[0][:-1] end | select(length > 0 and (.[-1] | type) == "string")] | length' "$1" 2> /dev/null) &&      # every member of every object, as written: one named twice is counted twice here, and once below
    jq -en --argjson n "$n" '[inputs] | length == 1 and (.[0] | type == "object" and ([.. | objects | length] | add) == $n and ([paths(type == "object" or type == "array") | length] | max // 0) < 32 and ([.. | strings, (objects | keys[])] | all(test("[\\x{FDD0}-\\x{FDEF}\\x{FFFE}\\x{FFFF}\\x{1FFFE}\\x{1FFFF}\\x{2FFFE}\\x{2FFFF}\\x{3FFFE}\\x{3FFFF}\\x{4FFFE}\\x{4FFFF}\\x{5FFFE}\\x{5FFFF}\\x{6FFFE}\\x{6FFFF}\\x{7FFFE}\\x{7FFFF}\\x{8FFFE}\\x{8FFFF}\\x{9FFFE}\\x{9FFFF}\\x{AFFFE}\\x{AFFFF}\\x{BFFFE}\\x{BFFFF}\\x{CFFFE}\\x{CFFFF}\\x{DFFFE}\\x{DFFFF}\\x{EFFFE}\\x{EFFFF}\\x{FFFFE}\\x{FFFFF}\\x{10FFFE}\\x{10FFFF}]") | not)))' "$1" > /dev/null 2>&1
}
ig_shape(){ # <answer> <box|list|record|receipt|problem> → 0 only for an answer of that kind as the Go client reads one: a JSON text ig_json takes, each member the Go client reads of its type, and null as if the member were left out. An integer is from 0 to 2^53 - 1, written as one: jq from 1.7 gives back 1.0 and 1e2 as written, though it gives back as digits a number whose exponent or fraction cancels (0.5e1 as 5, 1e0 as 1), which the Go client refuses. A byte member is a string, read by ig_bytes. Members it does not read are ignored
  ig_json "$1" && jq -e --arg k "$2" 'def s: . == null or type == "string"; def n: . == null or (type == "number" and . == floor and . >= 0 and . <= 9007199254740991 and (tostring | test("\\A(0|[1-9][0-9]*)\\z")));
    def record: all(.identity, .revocation_signature, .revoked_certificates, .revoked_certificates_signature; s) and (.type | . == null or . == "revocation_record");
    {box: (all(.identity, .prekey, .prekey_signature, .revoked_certificates, .revoked_certificates_signature; s) and (.sender_key_types | . == null or (type == "array" and all(.[]; s)))),
     list: (all(.count; n) and (.next_cursor | . == null or (type == "string" and test("\\A[A-Za-z0-9_-]+\\z"))) and (.messages | . == null or (type == "array" and all(.[]; . == null or (type == "object" and all(.id, .from, .received_at, .expires_at; s) and (.size | n)))))),
     record: record,
     receipt: all(.id, .received_at, .expires_at; s),
     problem: (all(.type, .title, .detail, .code, .hint, .oldest_expires_at, .key_type, .member; s) and all(.status, .unacked, .limit, .count, .version, .prekey_serial, .certificate_serial, .through; n) and (.key_types | . == null or (type == "array" and all(.[]; s))) and (.record | . == null or (type == "object" and record)))}[$k]' "$1" > /dev/null 2>&1
}
ig_bytes(){ # <answer> <member> <file> → the member's bytes into the file, only for base64 in its one encoding (RFC 4648 §3): padded, nothing outside the alphabet, a line break included, and the unused bits zero, which is what encoding the bytes again gives back. A member null or left out is no bytes. 1 for anything else
  jq -ejr --arg m "$2" '.[$m] | if . == null then "" else strings end' "$1" > "$3.b64" 2> /dev/null && base64 -d < "$3.b64" > "$3" 2> /dev/null && [ "$(ig_b64 "$3" | sha256sum)" = "$(sha256sum < "$3.b64")" ] || { rm -f "$3.b64"; return 1; }
  rm -f "$3.b64"
}
ig_opt(){ [ -z "$1" ] || [ "$1" = --no-pq ] || ig_refuse "unknown option $1: the only one is --no-pq (no post-quantum encryption, X25519 only)"; }
ig_stamp(){ jq -nr --argjson t "$1" '$t | strftime("%Y%m%d%H%M%SZ")'; }      # <Unix time> → the time as ssh-keygen takes one, in UTC
ig_asc(){ printf %s "$1" | od -An -v -tx1 | tr -d ' \n'; }      # <text> → its bytes in hex
ig_owner(){ # <METHOD> <PATH> [body file] [curl args…] → ig_api as this box: adds its pass. If the server refuses the pass (it ran out sooner by the server's clock, or is under a certificate the server no longer takes), signs another and tries once more. A pass refused twice for its time is the clock: it says what this one reads, beside the server's words
  local p; p=$(ig_pass) || return 1
  ig_api "$1" "$2" "${3-}" -H "Authorization: $p" "${@:4}" && return 0
  case $(ig_code) in unauthorized | pass_expired | certificate_not_current | certificate_revoked) ;; *) return 1 ;; esac
  rm -f "$IG/pass"; p=$(ig_pass) && ig_api "$1" "$2" "${3-}" -H "Authorization: $p" "${@:4}" && return 0
  ig_clock; return 1
}
ig_look(){ # <address> → ig_api GET of another box from this box's server (GET /v1/<address>), with this box's pass, so the call is counted against this box and not against the address it comes from (PROTOCOL.md §4.1). About itself, or with no pass to sign, without one: those are asked when the pass may be what is wrong
  [ "$1" != "$(cat "$IG/address" 2> /dev/null)" ] && ig_pass > /dev/null 2>&1 || { ig_api GET "/v1/$1"; return; }
  ig_owner GET "/v1/$1" 2> "$IG/look.err" && return 0
  case $(ig_code) in unauthorized | pass_expired | certificate_not_current | certificate_revoked | unknown_sender | sender_revoked) ig_api GET "/v1/$1" ;;      # what was refused is this box's pass, not the lookup: what is public is asked again without it
    *) cat "$IG/look.err" >&2; return 1 ;; esac
}
ig_clock(){ # after a call the server refused: if it refused the pass, or a prekey statement, for its time, says what the server dates its answer and what this machine's clock reads. A new pass does not cure that, so it is nearly always a clock. The date is the server's word: a clock set by a server's lie makes an ended certificate valid again, so this sends its reader to a time source of their own
  local d; case $(ig_code) in pass_expired | prekey_time) ;; *) return 0 ;; esac
  d=$(ig_dated) && d="the server dates its answer $d, and "
  ig_err "${d}this machine's clock reads $(jq -nr --argjson t "$(ig_now)" '$t | todate'). A server refuses a pass from a clock 10 minutes or more behind its own, or more than 50 ahead, and a certificate or prekey statement this machine dated more than an hour ahead of it. Check this machine's clock against a time source you trust, not against the server"
}
ig_server(){ # <URL> → the server's name, as a pass names it: the URL's host, lowercase, and its port only when that is not the scheme's default, as an origin is written (PROTOCOL.md §6.1b): the port as a number, and none for https on 443 or http on 80. A user and an @ before the host are no part of it, as Go's url.Parse has it
  local s=${1%%://*} h=${1#*://} p=
  h=${h%%[/?#]*}; h=${h##*@}; h=${h,,}
  if [[ $h =~ ^(.*):([0-9]*)$ ]]; then h=${BASH_REMATCH[1]}; p=${BASH_REMATCH[2]}; fi      # an IPv6 address ends in ], so a colon there begins no port
  [ -z "$p" ] || { p=$((10#$p)); case ${s,,}:$p in https:443 | http:80) ;; *) h+=:$p ;; esac; }
  echo "$h"
}
ig_tls(){ # <URL> → 0 when it is a server this box may call: https, or http only to a server on this machine, by its address: an IPv4 address in 127.0.0.0/8, or [::1]. A name is not, since localhost is what a resolver says it is (RFC 8252 §8.3), so that a pass, or the address a lookup asks about, never crosses a network in the clear (PROTOCOL.md §0). Otherwise a refusal, and 1
  local h=${1#*://}; h=${h%%[/?#]*}; h=${h##*@}; h=${h,,}
  [[ $h =~ ^(.*):[0-9]*$ ]] && h=${BASH_REMATCH[1]}      # an IPv6 address ends in ], so a colon there begins no port
  [[ ${1,,} = https://?* ]] || { [[ ${1,,} = http://?* ]] && [[ $h = '[::1]' || $h =~ ^127(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$ ]]; } ||
    ig_refuse "$(printf '%.80s' "$1") is not a server this client calls: one is https, or http only to this machine, by its address (127.0.0.0/8, ::1)"
}
ig_pass(){ # [serial] → the Authorization value of a call as this box. Without a serial: the pass kept in $IG/pass while it has more than 30 seconds left and no more than the ten minutes it was signed for, otherwise a new one, signed by the working key in use and kept. With one: a pass signed by that working key, for the call that publishes its prekey, left in $IG/pass.new until the server has taken it
  local A n=${1-} na h; A=$(cat "$IG/address") || return 1
  if [ -z "$n" ]; then
    na=$(ig_time "$(sed -n 's/.* not_after="\([^"]*\)".*/\1/p' "$IG/pass" 2> /dev/null)") && [ $((na - $(ig_now))) -gt 30 ] && [ $((na - $(ig_now))) -le 600 ] && { cat "$IG/pass"; return; }      # more than ten minutes left: this machine's clock has gone back since it was signed, so a new one, dated by the clock as it is
    n=$(cat "$IG/serial" 2> /dev/null) || ig_refuse "this box has published no prekey: run init, or rekey for a box restored from its identity" || return 1
  fi
  h=$(ig_server "$IG_BASE"); na=$(jq -nr --argjson t "$(ig_now)" '$t + 600 | todate')      # who is calling, which server, and until when: ten minutes
  printf 'irongall-pass-v1\n%s\n%s\n%s\n' "$A" "$h" "$na" | ssh-keygen -q -Y sign -n "irongall-pass-v1:$A" -f "$IG/work/$n-cert.pub" > "$IG/pass.sig" 2> /dev/null ||
    ig_refuse "this box cannot sign a pass with working key $n: rekey makes a new working key, certificate and prekey" || return 1
  printf 'irongall-pass address="%s", not_after="%s", signature="%s"\n' "$A" "$na" "$(ig_b64 "$IG/pass.sig")" > "$IG/pass.new" || return 1
  [ -n "${1-}" ] || mv "$IG/pass.new" "$IG/pass" || return 1
  cat "$IG/pass${1:+.new}"
}
ig_lock(){ # <command> [args] → runs that ig_ command with $IG/lock, the box's lock, held. Every command that writes the box runs so, from start to end, so one runs at a time and none reads a file another is writing. While another holds it, says so once and waits up to $IG_LOCK_WAIT seconds. If the command dies, the shell's EXIT trap removes it; a kill -9 leaves it behind
  local end=$((SECONDS + IG_LOCK_WAIT)) said= me=$IG outer=${IG_HELD-} trap rc
  [ -s "$IG/address" ] || { ig_refuse "no box in $IG: run init first"; return 1; }
  until mkdir "$me/lock" 2> /dev/null; do
    [ -n "$said" ] || { jq -cn '{type:"waiting", for:"lock", message:"waiting for this box'"'"'s lock: another command of this box is running, and a box'"'"'s commands write its files one at a time"}' >&2; said=1; }
    [ "$SECONDS" -lt "$end" ] || { ig_refuse "another command of this box held its lock, $me/lock, for as long as a command waits for it. If none is running, one that crashed left it behind: remove it"; return 1; }
    sleep 1
  done
  trap=$(trap -p EXIT); IG_HELD=$me; trap 'rmdir "$IG_HELD/lock" 2> /dev/null' EXIT
  "$@"; rc=$?
  rmdir "$me/lock"; IG_HELD=$outer; eval "${trap:-trap - EXIT}"; return $rc      # and the caller's own EXIT trap back
}
ig_held(){ [ "${IG_HELD-}" = "$IG" ]; }      # whether this shell holds this box's lock: a command another command runs works under its caller's

# recipe: keys and registration
ig_work(){ # <serial> → work/<serial>, .pub and -cert.pub: a NEW working key, and the certificate this box's identity gives it, with that serial, good from an hour ago for 65 days. The working key signs what the box says; the identity signs certificates and nothing else
  local A w="$IG/work/$1" t; A=$(cat "$IG/address") || return 1; mkdir -p "$IG/work" || return 1
  [ -s "$w" ] && [ -s "$w-cert.pub" ] && return 0
  rm -f "$w" "$w.pub" "$w-cert.pub"; t=$(ig_now)
  ssh-keygen -q -t ed25519 -N '' -C '' -f "$w" < /dev/null &&
  ssh-keygen -q -s "$IG/identity" -I irongall-cert-v1 -n "$A" -z "$1" -V "$(ig_stamp $((t - 3600))):$(ig_stamp $((t + 65*86400)))" -O clear "$w.pub"      # one principal, the address; no option and no extension. It starts an hour back, as -V -1h:+65d dates one, so that a verifier whose clock is behind this one takes it at once
}
ig_lifetime(){ # → the seconds each new prekey of this box is valid for: what its prekey-lifetime file names, a number of seconds alone on its line from 93600 (a day and two hours) to 2851200 (33 days), or 2851200 when it has none. A file that names anything else is a refusal, never the default: no prekey is signed until it is put right (PROTOCOL.md §6.4)
  local l; [ -e "$IG/prekey-lifetime" ] || { echo 2851200; return 0; }
  l=$(cat "$IG/prekey-lifetime" 2> /dev/null) && [[ $l =~ ^[1-9][0-9]{0,9}$ ]] && { printf '%s\n' "$l" | cmp -s - "$IG/prekey-lifetime" || printf '%s' "$l" | cmp -s - "$IG/prekey-lifetime"; } && [ "$l" -ge 93600 ] && [ "$l" -le 2851200 ] && echo "$l" ||      # compared with itself rebuilt: $(…) drops line feeds and NULs
    ig_refuse "this box's prekey-lifetime file names no lifetime: one is a number of seconds, alone on its line, from 93600 (a day and two hours) to 2851200 (33 days)"
}
ig_prekey(){ # <serial> [--no-pq] → prekeys/<serial>.agekey and its statement, signed by a NEW working key (ig_work): a NEW key, valid for the box's prekey lifetime (ig_lifetime), and prekeys/<serial>.made, when it was signed, which the Go client times its renewals by. A re-run reuses the key a failed attempt left, whatever its type
  local A p="$IG/prekeys/$1" l t; A=$(cat "$IG/address") || return 1
  [ -s "$p.txt.sig" ] && return 0
  l=$(ig_lifetime) || return 1
  if [ ! -e "$p.agekey" ]; then if [ "${2-}" = --no-pq ]; then age-keygen -o "$p.agekey"; else age-keygen -pq -o "$p.agekey"; fi 2> /dev/null || ig_refuse "age-keygen failed: post-quantum needs age >= 1.3 (or make a box with --no-pq)" || return 1; fi
  ig_work "$1" && t=$(ig_now) || return 1
  printf 'irongall-prekey-v1\n%s\n%s\n%s\n%s\n' "$A" "$1" "$(age-keygen -y "$p.agekey")" "$(jq -nr --argjson t "$t" --argjson l "$l" '$t + $l | todate')" > "$p.txt" &&
  jq -nr --argjson t "$t" '$t | todate' > "$p.made" &&      # before the signature: a statement is signed once its record is there
  ssh-keygen -q -Y sign -n "irongall-prekey-v1:$A" -f "$IG/work/$1-cert.pub" < "$p.txt" > "$p.txt.sig"      # stdin to stdout: never a stale .sig
}
ig_init(){ # [--no-pq] → creates this box, or finishes a half-done init, and registers it; prints its address and link. The registration carries a pass the new working key signs, so the box is in use at once
  ig_opt "${1-}" || return 1
  mkdir -p "$IG/work" "$IG/prekeys" "$IG/peers" "$IG/inbox" "$IG/quarantine" "$IG/outbox" "$IG/sent" && printf '*\n' > "$IG/.gitignore" || return 1
  [ -e "$IG/identity" ] || ssh-keygen -q -t ed25519 -N '' -C '' -f "$IG/identity" < /dev/null || return 1
  printf 'irongall-v1\n%s\n' "$(cut -d' ' -f1,2 "$IG/identity.pub")" > "$IG/identity.doc"
  sha256sum < "$IG/identity.doc" | cut -c1-64 > "$IG/address" || return 1
  [ ! -s "$IG/serial" ] || { ig_addr; return; }      # registered already
  local A n p h c; A=$(cat "$IG/address")
  n=$(ls "$IG/prekeys" | sed -n 's/\.agekey$//p; s/\.txt\.sig$//p' | sort -n | tail -n 1); [ -n "$n" ] || n=$(ig_now); [ "$n" -ge 1 ] || n=1; p="$IG/prekeys/$n"      # the box's first prekey, working key and certificate take their number as every later one does, from this machine's clock in seconds (ig_renew): a second machine handed the same identity then makes no certificate of a serial this one used. An attempt that got as far as a key keeps the number it took, so a registration whose answer was lost is sent again as it was
  if c=$(ig_cert "$p.txt.sig" "$IG/identity.doc" "$A" 2> /dev/null) && c=${c#* } && [ "${c% *}" -gt "$(ig_now)" ]; then      # a first statement an earlier attempt left, under a certificate that has not begun by this machine's clock: made while the clock read more than an hour ahead. The working key, its certificate and the statement are made again. The prekey's own key stays: a server may have taken a registration whose answer was lost, and then mail may be waiting that only this key opens
    rm -f "$p.txt" "$p.made" "$p.txt.sig" "$IG/work/$n" "$IG/work/$n.pub" "$IG/work/$n-cert.pub" "$IG/pass.new"
  fi
  ig_prekey "$n" "${1-}" || return 1
  jq -n --arg i "$(ig_b64 "$IG/identity.doc")" --arg p "$(ig_b64 "$p.txt")" --arg s "$(ig_b64 "$p.txt.sig")" --argjson k "$IG_SENDERS" '{identity:$i, prekey:$p, prekey_signature:$s, sender_key_types:$k}' > "$IG/register.json"
  h=$(ig_pass "$n") && { ig_api PUT "/v1/$A" "$IG/register.json" -H "Authorization: $h" > /dev/null || { ig_clock; false; }; } && mv "$IG/pass.new" "$IG/pass" && echo "$n" > "$IG/serial" && ig_addr
}
ig_addr(){ local a; a=$(cat "$IG/address") && ig_out box --arg address "$a" --arg link "$IG_BASE/to/$a"; }      # the box's address and its link: what to give whoever should write to it
ig_dest(){ # <link, address or alias> → the address: 64 hex, or taken from a link to this box's server, $IG_BASE/to/<address>, or the one address $IG/aliases gives the name
  local a=${1#"$IG_BASE/to/"}
  if ig_name "$1"; then a=$(awk -v n="$1" '$1 == n {print $2}' "$IG/aliases" 2> /dev/null | sort -u); [ -n "$a" ] || { ig_refuse "no alias named $1: ig_alias lists them, and names one"; return 1; }; fi
  ig_hex "$a" && { echo "$a"; return 0; }
  [[ $1 != *://* || $1 = "$IG_BASE/"* ]] || { ig_refuse "a link to another server: this box's server is $IG_BASE"; return 1; }
  ig_refuse "not an address, a link to one, or an alias naming one address: $1"
}
ig_name(){ [[ $1 =~ ^[a-z0-9][a-z0-9._-]{0,31}$ ]]; }   # an alias: never 64 hex, never a link
ig_alias(){ # [<name> <link or address>] → names a peer for this box only, one "<name> <address>" line in $IG/aliases, and prints an alias line; without arguments, an alias line for each. A name is never moved: to change or drop one, delete its line
  [ $# -gt 0 ] || { [ ! -s "$IG/aliases" ] || awk 'NF == 2 { print $1, $2 }' "$IG/aliases" | jq -cR 'split(" ") | {type:"alias", name:.[0], address:.[1]}'; return; }
  ig_held || { ig_lock ig_alias "$@"; return; }
  local a have
  ig_name "$1" || { ig_refuse "not an alias: $1 (1 to 32 of a-z, 0-9, '.', '_' and '-', starting with a letter or a digit)"; return 1; }
  a=$(ig_dest "${2-}") || return 1
  have=$(awk -v n="$1" '$1 == n {print $2}' "$IG/aliases" 2> /dev/null | sort -u)
  [ -z "$have" ] || [ "$have" = "$a" ] || { ig_refuse "alias $1 already names $have: delete its line in $IG/aliases first"; return 1; }
  [ -n "$have" ] || echo "$1 $a" >> "$IG/aliases" || return 1
  ig_out alias --arg name "$1" --arg address "$a"
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
    ecdsa-sha2-nistp256)      # 173 bytes: an uncompressed point. ssh-keygen refuses one that is off the curve, and up to 10.2p1 one with a coordinate of 128 bits or fewer, or of the group's order less one or more; from 10.3p1 it takes those, a known variance (PROTOCOL.md §3)
      [ "$n" -eq 173 ] && grep -Eqx 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBB[A-P][A-Za-z0-9+/]{84}[AEIMQUYcgkosw048]=' <<< "$l" && ssh-keygen -l -f - <<< "$l" > /dev/null 2>&1 || return 1 ;;
    *)      # a type this script does not verify. A document all the same, if line 2 is a key type's name (printable ASCII with no comma, at most 64 characters), one space, and the base64, in its one encoding, of a wire key that begins with that name
      [ "$n" -eq $((13 + ${#l})) ] && LC_ALL=C grep -Eqx '[!-+.-~-]{1,64} [A-Za-z0-9+/]+={0,2}' <<< "$l" && [ "$(printf %s "${l#* }" | base64 -d 2> /dev/null | base64 | tr -d '\n')" = "${l#* }" ] &&
        [ "$(printf %s "${l#* }" | base64 -d | head -c $((4 + ${#t})) | od -An -v -tx1 | tr -d ' \n')" = "$(printf %08x "${#t}")$(ig_asc "$t")" ] && return 2
      return 1 ;;
  esac
}
ig_sigmax(){ case $(sed -n 2p "$1" | cut -d' ' -f1) in ssh-ed25519 | ecdsa-sha2-nistp256) echo 4096 ;; *) return 1 ;; esac; }      # <identity document> → the most bytes a signature by a box of its key type may be, every byte of the file (PROTOCOL.md §3): each type states its own. Nothing for a type this script does not verify
ig_bound(){ local m; m=$(ig_sigmax "$2") && [ "$(wc -c < "$1")" -le "$m" ]; }      # <signature file> <identity document> → 0 only for a signature no longer than its identity's key type allows
ig_blob(){ # <signature file> → the SSHSIG blob it armors, in hex, read as ssh-keygen -Y verify reads it (OpenSSH's sshsig_dearmor), and only if the file is at most 4096 bytes in all, the most any identity key type allows (ig_sigmax): the BEGIN line first, ending in LF or CRLF; then base64 in its one encoding, with space, tab, LF, VT, FF and CR skipped wherever they are; then LF and the END line, after which nothing is read; one NUL may be the last byte before that LF, as OpenSSH's sshbuf_dup_string takes it. 1 for anything else, any other NUL included. The bytes are read as hex, never through a shell variable, which would drop a NUL
  local h b e t B E
  [ "$(wc -c < "$1")" -le 4096 ] || return 1      # the bound counts every byte of the file, what follows the END line too
  B=$(printf %s '-----BEGIN SSH SIGNATURE-----' | od -An -v -tx1 | tr -s ' \n' '  '); E=$(printf '\n%s' '-----END SSH SIGNATURE-----' | od -An -v -tx1 | tr -s ' \n' '  ')
  h=$(od -An -v -tx1 < "$1" | tr -s ' \n' '  ')      # every byte as " xx", and one space at the end: a match of " xx … xx " falls on whole bytes
  [[ $h == "$B"* ]] || return 1; h=" ${h#"$B"}"
  case $h in " 0d 0a "*) h=${h#" 0d 0a"} ;; " 0a "*) h=${h#" 0a"} ;; *) return 1 ;; esac
  b=${h%%"$E"*}; [ "$b" != "$h" ] || return 1      # up to the first LF and END line
  b=${b%" 00"}      # one NUL as its last byte
  for e in 20 09 0a 0b 0c 0d; do b=${b// $e/}; done
  [[ $b =~ ^( (3[0-9]|4[1-9a-f]|5[0-9a]|6[1-9a-f]|7[0-9a]|2b|2f|3d))*$ ]] || return 1      # nothing left but the base64 alphabet and its padding
  t=$(printf "${b// /\\x}")
  [ -n "$t" ] && [ "$(printf %s "$t" | base64 -d 2> /dev/null | base64 | tr -d '\n')" = "$t" ] || return 1      # in its one encoding: padded, and the unused bits of the last character zero, as OpenSSH's decoder holds it
  printf %s "$t" | base64 -d | od -An -v -tx1 | tr -d ' \n'
}
ig_s(){ # <an SSH signature in hex: its type as a string, then its bytes as one> → 1 only for an Ed25519 signature that is not 64 bytes, or whose S is not below the group's order L: such a signature is invalid (RFC 8032 §5.1.7), and ssh-keygen before 10.3p1 takes one with L added to S. Its type may end in one NUL, as OpenSSH reads it. 0 for any other, which ssh-keygen judges
  local s="" i a b o= e L=1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
  e=$(ig_asc ssh-ed25519)
  [ "${1:0:30}" = "0000000b$e" ] && o=30; [ "${1:0:32}" = "0000000c${e}00" ] && o=32
  [ -n "$o" ] || return 0
  [ ${#1} -eq $((o + 136)) ] && [ "${1:o:8}" = 00000040 ] || return 1
  for ((i = o + 134; i >= o + 72; i -= 2)); do s+=${1:i:2}; done      # S is the signature's last 32 bytes, little-endian: here it is read the other way round, to compare with L
  for i in 0 8 16 24 32 40 48 56; do a=$((16#${s:i:8})); b=$((16#${L:i:8})); [ "$a" -lt "$b" ] && return 0; [ "$a" -gt "$b" ] && return 1; done
  return 1
}
ig_sshsig(){ # <signature file> → 0 only for a signature ig_blob reads that is an SSHSIG of version 0 or 1 (OpenSSH refuses only a higher one), five fields and nothing after them, whose own signature passes ig_s. It leaves the blob in x and its signing key in k, both in hex, for its caller, whose locals they are. The reserved field is read and skipped, as OpenSSH does: ssh-keygen verifies over an empty one
  local o=20 l v
  x=$(ig_blob "$1") && [[ ${x:0:20} =~ ^5353485349470000000[01]$ ]] || return 1      # "SSHSIG", version 0 or 1
  ig_str && k=$v && ig_str && ig_str && ig_str && ig_str && ig_s "$v" && [ "$o" -eq "${#x}" ]      # the signing key, the namespace, reserved, the hash, the signature: and nothing after
}
ig_cert(){ # <signature> <identity document> <address> → "<serial> <valid after> <valid before>", as Unix times, for the certificate the signature carries, only if it is in its one form (below) and names that identity as its signer. Its fields are read from its bytes, in order: ssh-keygen -Y verify takes a certificate with a critical option, or with extensions out of their order, and checks no key id. Whether the identity's signature on it is good, and whether it holds now, are ig_certified's
  local x o=20 l v k n a b      # x: the bytes being read, in hex; o: how far into them; v: the field just read
  ig_sshsig "$1" || return 1; x=$k; o=0      # the signing key: here, the certificate
  ig_str && [ "$v" = "$(ig_asc ssh-ed25519-cert-v01@openssh.com)" ] || return 1      # a certificate for an Ed25519 key
  ig_str || return 1      # the nonce
  ig_str && k=$v && ig_keycheck "$k" || return 1      # the working key, held to the identity's own key checks
  ig_u64 && n=$v && [ "$n" -ge 1 ] && [ "$n" -le 9007199254740991 ] || return 1      # the serial: from 1 to 2^53 - 1, as a prekey's
  [ "${x:o:8}" = 00000001 ] || return 1; o=$((o + 8))      # a user certificate
  ig_str && [ "$v" = "$(ig_asc irongall-cert-v1)" ] || return 1      # the key id
  ig_str && [ "$v" = "00000040$(ig_asc "$3")" ] || return 1      # exactly one principal: the address
  ig_u64 && a=$v && ig_u64 && b=$v || return 1      # valid after, valid before
  ig_str && [ -z "$v" ] || return 1      # no critical option: one a verifier does not know is refused, and none is known here
  ig_str && ig_exts "$v" && ig_str || return 1      # the extensions, each ignored, as one a verifier does not know is; then reserved, whatever it holds, ignored too
  ig_str && [ "$v" = "$(sed -n 2p "$2" | cut -d' ' -f2 | base64 -d | od -An -v -tx1 | tr -d ' \n')" ] && [ "$v" != "0000000b$(ig_asc ssh-ed25519)00000020$k" ] || return 1      # signed by the identity's key, byte for byte, which is never the working key
  ig_str && ig_s "$v" && [ "$o" -eq "${#x}" ] || return 1      # the identity's signature on it, and nothing after
  echo "$n $a $b"
}
ig_exts(){ # ig_cert's: <a certificate's extensions, in hex> → 0 only for them in their one encoding, as the Go client's library reads them: each name once, in lexical order, and its value nothing or one string that is not empty. What each says is never read: none is known here
  local x=$1 o=0 l v n p=
  while [ "$o" -lt "${#x}" ]; do
    ig_str && n=$v && { [ -z "$p" ] || [ "$p" \< "$n" ]; } && ig_str || return 1      # the name, after the last; [ compares bytes, as their hex compares
    [ -z "$v" ] || { [[ ${v:0:8} =~ ^[0-9a-f]{8}$ ]] && [ $((16#${v:0:8})) -gt 0 ] && [ $((8 + 2 * 16#${v:0:8})) -eq ${#v} ]; } || return 1      # the value
    p=$n
  done
}
ig_str(){ [[ ${x:o:8} =~ ^[0-9a-f]{8}$ ]] || return 1; l=$((16#${x:o:8} * 2)); [ $((o + 8 + l)) -le ${#x} ] || return 1; v=${x:o+8:l}; o=$((o + 8 + l)); }      # ig_cert's: the next length-prefixed string of x, in hex, into v
ig_u64(){ [[ ${x:o:16} =~ ^[0-7][0-9a-f]{15}$ ]] || return 1; v=$((16#${x:o:16})); o=$((o + 16)); }      # ig_cert's: the next 64-bit number of x into v. One with its top bit set is no time and no serial here
ig_certified(){ # <address> <identity document> <namespace> <signature> <message> [at] → "<certificate serial> <its valid before>" only for a signature by a working key under a certificate of that identity that holds at the time given (now, without one): begun, not ended, and ending at most 66 days on. 1 otherwise; 2 when all that fails is that it has ended, 3 that it has not begun. A signature by the identity itself, or by a key with no certificate, is refused
  local A=$1 r n a b t=${6:-$(ig_now)}
  ig_bound "$4" "$2" && r=$(ig_cert "$4" "$2" "$A") || return 1; read -r n a b <<< "$r"
  printf '%s cert-authority %s\n' "$A" "$(sed -n 2p "$2")" > "$IG/signers"      # ONE line, built from checked bytes: only a certificate this identity signed, for this address
  ssh-keygen -Y verify -f "$IG/signers" -I "$A" -n "$3" -s "$4" -O verify-time="$(ig_stamp $((a > 0 ? a : 1)))" < "$5" > /dev/null 2>&1 || return 1      # the two signatures, the identity's on the certificate and the working key's on the message, judged where the certificate begins (a second in, for one that begins at 0: ssh-keygen takes no verify-time of 0); the time is the next line's
  [ "$a" -le "$t" ] || return 3; [ "$t" -lt "$b" ] || return 2; [ "$b" -le $((t + 66*86400)) ] || return 1
  echo "$n $b"
}
ig_bech32(){ # <string> → its human-readable part, only for a Bech32 string (BIP 173) as age writes a recipient: in lowercase, its checksum good, and its data whole bytes, with fewer than five bits left over and those zero. age takes one of any length, where BIP 173 stops at 90, and so does this. 1 for anything else
  local s=$1 h d cs=qpzry9x8gf2tvdw0s3jn54khce6mua7l v=() i c k m n chk=1 top g=(0x3b6a57b2 0x26508e6d 0x1ea119fa 0x3d4233dd 0x2a1462b3)
  [[ $s = *1* ]] || return 1; h=${s%1*}; d=${s##*1}; [ ${#h} -ge 1 ] && [ ${#d} -ge 6 ] || return 1      # split at the last 1: a part before it, and six characters of checksum at least after it
  for ((i = 0; i < ${#h}; i++)); do c=$(printf %d "'${h:i:1}"); ((c >= 33 && c <= 126 && (c < 65 || c > 90))) || return 1; v+=($((c >> 5))); done; v+=(0)      # printable ASCII, no capital
  for ((i = 0; i < ${#h}; i++)); do v+=($(($(printf %d "'${h:i:1}") & 31))); done
  for ((i = 0; i < ${#d}; i++)); do k=${cs%%"${d:i:1}"*}; [ ${#k} -lt 32 ] || return 1; v+=(${#k}); done      # each character's value is its place in the alphabet
  for k in "${v[@]}"; do top=$((chk >> 25)); chk=$((((chk & 0x1ffffff) << 5) ^ k)); for i in 0 1 2 3 4; do ((top >> i & 1)) && chk=$((chk ^ g[i])); done; done
  n=$((${#d} - 6)); c=$((n * 5 % 8)); k=$((n > 0 ? v[${#v[@]} - 7] : 0)); m=$(((1 << c) - 1))      # the bits left over are the low bits of the last data character
  ((chk == 1 && c < 5 && (k & m) == 0)) || return 1
  printf '%s\n' "$h"
}
ig_prekeycheck(){ # <statement> <signature> <address> <identity document> [at] → "<serial> <age recipient> <not_after as Unix time> <certificate serial>" only for five LF-ended lines naming that address, signed by a working key its identity certified, not outliving that certificate, holding a key age will encrypt to; otherwise the reason, and 1. 2, with the reason, for one good in every other way whose key is a well-formed age recipient of a type this script cannot encrypt to: its Bech32 human-readable part begins age, and is neither X25519's age nor the hybrid's age1pq. Nothing is wrong with such a statement (PROTOCOL.md §0a), so its key's type is the last thing checked
  local p=$1 B=$3 s k na c
  c=$(ig_certified "$B" "$4" "irongall-prekey-v1:$B" "$2" "$p" ${5-}); case $? in 0) ;;
    2) echo "$B's prekey: the certificate the prekey is signed under has ended"; return 1 ;;
    3) echo "$B's prekey: the certificate the prekey is signed under has not begun, by the clock that checked it"; return 1 ;;
    *) echo "$B's prekey is not signed by a working key its identity certified, under a certificate that holds now"; return 1 ;;
  esac
  [ "$(wc -l < "$p")" -eq 5 ] && [ "$(tail -c 1 "$p" | od -An -tx1 | tr -d ' \n')" = 0a ] && [ "$(sed -n 1p "$p")" = irongall-prekey-v1 ] && [ "$(sed -n 2p "$p")" = "$B" ] ||
    { echo "the prekey statement is not $B's: five lines, each ending in LF"; return 1; }
  s=$(sed -n 3p "$p"); [[ $s =~ ^[1-9][0-9]{0,15}$ ]] && [ "$s" -le 9007199254740991 ] || { echo "$B's prekey serial is malformed"; return 1; }      # from 1 to 2^53 - 1, as every serial is written
  na=$(ig_time "$(sed -n 5p "$p")") || { echo "$B's prekey has no valid not_after"; return 1; }
  [ "$na" -le "${c#* }" ] || { echo "$B's prekey statement outlives the certificate it is signed under"; return 1; }
  k=$(sed -n 4p "$p")
  case $(ig_bech32 "$k") in      # the key's type is its human-readable part, read before age is: age 1.3 encrypts to more types than the protocol defines, and to an SSH key
    age | age1pq) if ! age -r "$k" < /dev/null > /dev/null 2>&1; then
        if [[ $k = age1pq1* ]]; then echo "$B's prekey is post-quantum, and this age ($(age --version 2> /dev/null)) cannot encrypt to one: that takes age >= 1.3"; else echo "$B's prekey is not an age key that age will encrypt to"; fi; return 1
      fi ;;
    age*) echo "$B's prekey is an age recipient of a type this script cannot encrypt to, so nothing is sent"; return 2 ;;
    *) echo "$B's prekey is not an age key that age will encrypt to"; return 1 ;;
  esac
  echo "$s $k $na ${c% *}"
}
ig_resolve(){ # <address> [the box ig_lookup read] → prints "<serial> <age recipient> <certificate serial>" only when EVERY check passes; otherwise there is nothing to encrypt to. The identity is the pinned one, or at first contact the served one, kept only once its prekey statement has verified. Without a box read for it, it reads one, and keeps what verifies of the revocation of certificates it carries before the statement is checked against it
  local B=$1 d="$IG/peers/$1" f r s k na c sc
  ig_hex "$B" || ig_refuse "not an address" || return 1
  ig_gone "$B"; case $? in      # a peer this box holds a revocation of is refused before anything is asked, whatever the server now serves for it
    0) ig_err "REVOKED: $B is revoked, for good, and the revocation verifies: ask its owner for their new address"; return 1 ;;
    3) ig_refuse "the revocation kept for $B does not verify"; return 1 ;;
  esac
  if [ -n "${2-}" ] && [ -s "$2" ]; then cp "$2" "$IG/peer.json" || return 1
  else ig_look "$B" > "$IG/peer.json" || return 1
    ig_isbox "$IG/peer.json" && jq -c '{identity, revoked_certificates, revoked_certificates_signature}' "$IG/peer.json" > "$IG/rev.json" ||
      ig_refuse "the server's answer for $B is not one this client reads: a JSON object as PROTOCOL.md §0b reads one, each byte field base64 in its one encoding" || return 1
    ig_take "$B"; [ $? != 3 ] || ig_refuse "what this box keeps about $B does not verify, or could not be written" || return 1
  fi
  ig_shape "$IG/peer.json" box && ig_bytes "$IG/peer.json" identity "$IG/new.doc" && ig_bytes "$IG/peer.json" prekey "$IG/peer.txt" && ig_bytes "$IG/peer.json" prekey_signature "$IG/peer.sig" ||
    ig_refuse "the server's answer for $B is not one this client reads: a JSON object as PROTOCOL.md §0b reads one, each byte field base64 in its one encoding" || return 1
  f="$d/identity.doc"      # a pin always wins
  [ -e "$f" ] || { f="$IG/new.doc"; [ -s "$f" ] || ig_refuse "no identity for $B in the response" || return 1; }
  [ "$(sha256sum < "$f" | cut -c1-64)" = "$B" ] || ig_refuse "the identity the server sent does not hash to $B" || return 1
  ig_idcheck "$f"; case $? in 0) ;;
    2) ig_refuse "$B's identity is of a key type this script does not verify, so nothing it signs can be checked here and nothing is sent"; return 1 ;;
    *) ig_refuse "$B's identity is not a two-line identity document in the one form of its key type, with a valid key"; return 1 ;;
  esac
  [ -s "$IG/peer.txt" ] && [ -s "$IG/peer.sig" ] || ig_refuse "no prekey for $B in the response" || return 1
  r=$(ig_prekeycheck "$IG/peer.txt" "$IG/peer.sig" "$B" "$f"); case $? in 0) ;;
    2) jq -cn --arg m "REFUSED: $r" '{type:"error", code:"unsupported_prekey_type", message:$m}' >&2; return 1 ;;      # a refusal with a code of its own: nothing is wrong with the statement
    *) ig_refuse "$r"; return 1 ;;
  esac
  read -r s k na c <<< "$r"
  sc=$(cat "$d/cert-serial" 2> /dev/null || echo 0)      # a box's statements are ordered by their certificate first, then by their own serial: a later certificate outranks any serial under an earlier one, so a box that moved to a new certificate is followed whatever serial it publishes
  [ "$c" -ge "$sc" ] || ig_refuse "rollback: $B's prekey is signed under certificate $c, below one already seen" || return 1
  [ "$c" -gt "$sc" ] || [ "$s" -ge "$(cat "$d/serial" 2> /dev/null || echo 0)" ] || ig_refuse "rollback: $B's prekey serial $s is below one already seen" || return 1
  ig_certrevoked "$B" "$c"; case $? in      # by what this box holds: only the identity's own signature revokes a certificate
    0) ig_refuse "$B's prekey is signed under a certificate its identity has revoked: its owner must publish a new one"; return 1 ;;
    3) ig_refuse "the revocation of certificates kept for $B does not verify"; return 1 ;;
  esac
  [ "$na" -gt "$(ig_now)" ] || ig_refuse "$B's prekey has expired: its owner must publish a new one" || return 1
  ig_meet "$B" "$f" && echo "$s" > "$d/serial" && echo "$c" > "$d/cert-serial" && cp "$IG/peer.txt" "$d/prekey.txt" && cp "$IG/peer.sig" "$d/prekey.sig" || return 1      # recorded only after every check passed
  echo "$s $k $c"
}
ig_meet(){ local d="$IG/peers/$1"; mkdir -p "$d" && { [ -e "$d/identity.doc" ] || cp "$2" "$d/identity.doc"; }; }      # <address> <its checked identity document> → pinned, unless it is already: called only for an identity that signed something this box verified

# recipe: revocation
ig_revcheck(){ # <address> <identity document> <signature> → 0 only for a revocation of that address: the document hashes to it and is one this script verifies, and the signature is that identity's OWN over the fixed statement. The signers line names the identity's key with no cert-authority, so a working key's signature, which carries a certificate, is not taken: a working key can be stolen without the identity, and must not end the address
  local x k
  ig_idcheck "$2" "$1" && ig_bound "$3" "$2" && ig_sshsig "$3" || return 1
  printf '%s %s\n' "$1" "$(sed -n 2p "$2")" > "$IG/signers"
  printf 'irongall-revoke-v1\n%s\n' "$1" | ssh-keygen -Y verify -f "$IG/signers" -I "$1" -n "irongall-revoke-v1:$1" -s "$3" > /dev/null 2>&1
}
ig_gone(){ # <address> → 0 if this box holds a revocation of it: peers/<address>/revoke.sig beside its pinned identity, or revoked.sig for this box's own. It is checked again each time. 1 if none is kept. 3 if one is kept and does not verify: a fault of this box, never a quiet "not revoked"
  local d="$IG/peers/$1/identity.doc" s="$IG/peers/$1/revoke.sig"
  [ "$1" != "$(cat "$IG/address" 2> /dev/null)" ] || { d="$IG/identity.doc"; s="$IG/revoked.sig"; }
  [ -e "$s" ] || return 1
  ig_revcheck "$1" "$d" "$s" || return 3
}
ig_certscheck(){ # <address> <identity document> <statement> <signature> → the serial it revokes through, only for a revocation of that address's certificates: signed by its identity's OWN key, as a revocation of the address is (no cert-authority, so a certificate cannot revoke another, or itself), and in its one exact form, the tag, the address and a serial, each on a line ending in LF, and nothing else. The serial is from 1 to 2^53 - 1 with no leading zero, compared by bash, whose numbers are exact there where awk's are not
  local L x k
  ig_idcheck "$2" "$1" && ig_bound "$4" "$2" && ig_sshsig "$4" || return 1
  printf '%s %s\n' "$1" "$(sed -n 2p "$2")" > "$IG/signers"
  ssh-keygen -Y verify -f "$IG/signers" -I "$1" -n "irongall-revoke-certs-v1:$1" -s "$4" < "$3" > /dev/null 2>&1 || return 1
  mapfile -t L < "$3"
  [ "$(printf '%s\n' "${L[@]}" | sha256sum)" = "$(sha256sum < "$3")" ] || return 1      # the file against itself rebuilt from its lines: every line ends in LF, and nothing is in it that a shell variable drops (a NUL)
  [ ${#L[@]} -eq 3 ] && [ "${L[0]}" = irongall-revoke-certs-v1 ] && [ "${L[1]}" = "$1" ] && [[ ${L[2]} =~ ^[1-9][0-9]{0,15}$ ]] && [ "${L[2]}" -le 9007199254740991 ] || return 1
  echo "${L[2]}"
}
ig_certskept(){ # <address> → the serial through which this box holds that address's certificates revoked, checked again as it is read. It is kept as the record that carries it, one line of JSON {type, identity, revoked_certificates, revoked_certificates_signature}: peers/<address>/revoked-certs.json beside the pinned identity, or revoked-certs.json for this box's own. 1 if none is kept. 3 if one is kept and does not verify under the identity this box holds for the address: a fault of this box, never a quiet "nothing revoked"
  local d="$IG/peers/$1/identity.doc" f="$IG/peers/$1/revoked-certs.json"
  [ "$1" != "$(cat "$IG/address" 2> /dev/null)" ] || { d="$IG/identity.doc"; f="$IG/revoked-certs.json"; }
  [ -e "$f" ] || return 1
  ig_shape "$f" record && ig_bytes "$f" revoked_certificates "$IG/kept.certs" && ig_bytes "$f" revoked_certificates_signature "$IG/kept.csig" &&
    ig_certscheck "$1" "$d" "$IG/kept.certs" "$IG/kept.csig" || return 3
}
ig_certrevoked(){ # <address> <certificate serial> → 0 if the address's identity has revoked the certificate, by what this box holds. 1 if nothing is kept, or what is kept runs below it. 3 if what is kept does not verify
  local x
  x=$(ig_certskept "$1") || return
  [ "$2" -le "$x" ]
}
ig_keepcerts(){ # <address> <identity document> <statement> <signature> → keeps the revocation of the address's certificates, if it verifies and runs through a higher serial than the one this box holds: the highest stands, and a certificate once revoked stays so. One that does not verify, or runs no higher, changes nothing. 1 only for a fault of this box
  local f="$IG/peers/$1/revoked-certs.json" v h
  [ "$1" != "$(cat "$IG/address" 2> /dev/null)" ] || f="$IG/revoked-certs.json"
  v=$(ig_certscheck "$1" "$2" "$3" "$4") || return 0
  h=$(ig_certskept "$1"); case $? in 0) [ "$v" -gt "$h" ] || return 0 ;; 1) ;; *) return 1 ;; esac
  [ "$f" = "$IG/revoked-certs.json" ] || ig_meet "$1" "$2" || return 1
  ig_b64 "$2" > "$f.i" && ig_b64 "$3" > "$f.l" && ig_b64 "$4" > "$f.g" && jq -cn --rawfile i "$f.i" --rawfile l "$f.l" --rawfile g "$f.g" '{type:"revocation_record", identity:$i, revoked_certificates:$l, revoked_certificates_signature:$g}' > "$f.new" && mv "$f.new" "$f" && rm -f "$f.i" "$f.l" "$f.g"      # one file, moved into place whole: a statement is never kept without the signature that goes with it
}
ig_keep(){ # <address> <its identity document> <signature> → the revocation, kept for good: called only once ig_revcheck took it. A revoked address stays revoked
  if [ "$1" = "$(cat "$IG/address" 2> /dev/null)" ]; then cp "$3" "$IG/revoked.sig"; else ig_meet "$1" "$2" && cp "$3" "$IG/peers/$1/revoke.sig"; fi
}
ig_record(){ # <record> → the address it is a revocation of, only if it verifies; its parts are left in $IG/rev.doc and $IG/rev.sig. A record is one line of JSON, {type, identity, revocation_signature}: its type, revocation_record, which a record may leave out and may name no other, then the identity document and the signature, each base64
  local A
  ig_isrecord "$1" && ig_bytes "$1" identity "$IG/rev.doc" && ig_bytes "$1" revocation_signature "$IG/rev.sig" || return 1
  A=$(sha256sum < "$IG/rev.doc" | cut -c1-64) && ig_revcheck "$A" "$IG/rev.doc" "$IG/rev.sig" && echo "$A"
}
ig_handed(){ # <record> → the address, only for a record handed over whose every part verifies: the revocation of the address (ig_record), and a revocation of its certificates beside it, if there is one (ig_certscheck). A record with a part that does not verify is refused whole, as the Go client refuses it; its parts are left as ig_record leaves them
  local A
  A=$(ig_record "$1") && ig_bytes "$1" revoked_certificates "$IG/rev.certs" && ig_bytes "$1" revoked_certificates_signature "$IG/rev.csig" || return 1
  [ ! -s "$IG/rev.certs" ] || ig_certscheck "$A" "$IG/rev.doc" "$IG/rev.certs" "$IG/rev.csig" > /dev/null || return 1
  echo "$A"
}
ig_isrecord(){ # <file> → 0 only for a record as the Go client reads one: an answer ig_shape takes as a record, and each of its four byte members base64 in its one encoding, or left out. What it holds is checked by whoever uses it
  local m r=0
  ig_shape "$1" record || return 1
  for m in identity revocation_signature revoked_certificates revoked_certificates_signature; do ig_bytes "$1" $m "$IG/record.part" || { r=1; break; }; done
  rm -f "$IG/record.part"; return $r
}
ig_isbox(){ # <file> → 0 only for a box as the Go client reads one: an answer ig_shape takes as a box, and each of its byte members base64 in its one encoding, or left out. What it holds is checked by whoever uses it
  local m r=0
  ig_shape "$1" box || return 1
  for m in identity prekey prekey_signature revoked_certificates revoked_certificates_signature; do ig_bytes "$1" $m "$IG/box.part" || { r=1; break; }; done
  rm -f "$IG/box.part"; return $r
}
ig_revservers(){ # → the revocation servers this box asks beside its own server, and publishes to (PROTOCOL.md §6.3), one to a line: those $IG_REVOCATION_SERVERS names, with spaces or commas between; or else those the box's revocation-servers file names, one to a line; or else none, since the box's own server is one already. The one word "none" is none. Each is https://host or https://host:port, in lowercase, with nothing after it, and each learns which addresses this box asks about: name one only if you mean to tell it. Read from the file each time: state lives in files
  local l=${IG_REVOCATION_SERVERS-} s seen=" "; local -a a
  [[ $l =~ [^[:space:],] ]] || l=      # text that names nothing is as if it were not there
  [ -n "$l" ] || [ ! -s "$IG/revocation-servers" ] || l=$(cat "$IG/revocation-servers") || return 1
  [[ $l =~ [^[:space:],] ]] || l=
  l=${l//,/ }; l=${l//$'\n'/ }; l=${l//$'\r'/ }; read -ra a <<< "$l"
  [ "${#a[@]}" != 1 ] || [ "${a[0]}" != none ] || return 0
  for s in "${a[@]}"; do
    [[ $s =~ ^https?://(\[[0-9a-f:]+\]|[a-z0-9]([a-z0-9.-]*[a-z0-9])?)(:[0-9]{1,5})?$ ]] && ig_tls "$s" 2> /dev/null || { ig_refuse "this box's list of revocation servers names something that is not one: each is https://host or https://host:port, in lowercase, with nothing after it, and http only for a server on this machine, by its address (127.0.0.0/8, ::1); the one word none means none"; return 1; }
    [ "$s" = "$IG_BASE" ] || [[ $seen = *" $s "* ]] || echo "$s"      # the box's own server is asked anyway, and each of the others once
    seen="$seen$s "
  done
}
ig_take(){ # <address> → keeps what verifies of $IG/rev.json, a server's answer about the address: a revocation of its certificates, of the address, or both. 0: this box now holds a revocation of the address. 1: it does not: what the answer showed of one does not verify, which counts as nothing shown. 3: a fault of this box
  if ig_bytes "$IG/rev.json" identity "$IG/rev.doc" && ig_bytes "$IG/rev.json" revoked_certificates "$IG/rev.certs" && [ -s "$IG/rev.certs" ] &&
    ig_bytes "$IG/rev.json" revoked_certificates_signature "$IG/rev.csig"; then      # a revocation of certificates rides in the same record. It is taken or not on its own: the address may well go on
    ig_keepcerts "$1" "$IG/rev.doc" "$IG/rev.certs" "$IG/rev.csig" || return 3
  fi
  [ "$(ig_record "$IG/rev.json")" = "$1" ] || return 1
  ig_keep "$1" "$IG/rev.doc" "$IG/rev.sig" || return 3
}
ig_lookup(){ # <address> → reads the address's box from this box's server (GET /v1/<address>, ig_look), keeps what verifies of the revocations it carries, then asks each revocation server this box lists (ig_revservers), printing a no_answer line for each that gave none. A box served carries the revocation of its certificates the server holds, and a revoked address is answered 410 revoked with its record. The box served is left in $IG/box.json, for the seal that follows. 0: this box holds a revocation of the address, and that is final. 1: none: the server served the box, or holds no such box, or said revoked and showed nothing that verifies, which comes to the same: only the identity's own signature revokes. 2: no answer from the box's own server, which is not "none". 3: a fault of this box: what it keeps for the address does not verify, or cannot be written, or its list of revocation servers cannot be read. A revocation server can only add: what it shows is checked and kept as anything is, and neither its "none held" nor its silence changes the answer. It is asked with no pass, for ten seconds at most
  local s l r
  rm -f "$IG/box.json"
  ig_gone "$1"; case $? in 0) return 0 ;; 3) return 3 ;; esac
  l=$(ig_revservers) || return 3
  if ig_look "$1" > "$IG/look.json" 2> "$IG/read.err"; then ig_isbox "$IG/look.json" || return 2; mv "$IG/look.json" "$IG/box.json"      # a 2xx that is no box is no answer, as one that is no JSON is
    jq -c '{identity, revoked_certificates, revoked_certificates_signature}' "$IG/box.json" > "$IG/rev.json" && ig_take "$1"; r=$?; [ $r = 1 ] || return $r
  else case $(ig_code) in
    revoked) if jq -ce '.record | objects' "$IG/error.json" > "$IG/rev.json" 2> /dev/null && ig_isrecord "$IG/rev.json"; then ig_take "$1"; r=$?; [ $r = 1 ] || return $r; fi ;;      # the record it carries proves itself, or counts as nothing shown
    no_such_mailbox) ;;
    *) cat "$IG/read.err" >&2; return 2 ;; esac; fi      # no answer: its error line, the status, the code and the wait, and none of the server's words
  while IFS= read -r s <&3; do [ -n "$s" ] || continue
    if IG_BASE=$s ig_api GET "/v1/$1/revocations" "" --max-time 10 > "$IG/rev.json" 2> /dev/null && ig_isrecord "$IG/rev.json"; then ig_take "$1"; r=$?; [ $r = 1 ] || return $r
    else case $(ig_code) in not_revoked | no_such_mailbox) ;; *) ig_out no_answer --arg server "$s" --arg message "the revocation server $s gave no answer, which changes nothing here" ;; esac; fi
  done 3<<< "$l"
  return 1
}
ig_own(){ # after a call as this box failed: if the server said this box is revoked, asks it for the revocation, and says which it is. A server's word revokes nothing
  [ "$(ig_code)" = revoked ] || return 0
  if ig_lookup "$(cat "$IG/address")"; then ig_err "REVOKED: this box's own address is revoked, for good, and the revocation verifies. It can send and receive nothing more: make a new box and give its address to those who write to this one"
  else ig_err "the server showed no revocation of this box that verifies, so this box does not take itself as revoked"; fi
}
ig_revocation(){ # → this box's revocation record as one revocation_record line, {type, identity, revocation_signature}: the identity document, and the identity's own signature over the fixed statement, which has no date in it. The line is the record every server takes. It publishes nothing. Whoever publishes the record ends this address for good, with no key: keep it where only you can read it, somewhere other than this box, for the day the box is lost
  ig_held || { ig_lock ig_revocation "$@"; return; }
  local A; A=$(cat "$IG/address") || return 1
  printf 'irongall-revoke-v1\n%s\n' "$A" | ssh-keygen -q -Y sign -n "irongall-revoke-v1:$A" -f "$IG/identity" > "$IG/rev.new" 2> /dev/null || ig_refuse "this box's identity key did not sign" || return 1
  ig_out revocation_record --arg identity "$(ig_b64 "$IG/identity.doc")" --arg revocation_signature "$(ig_b64 "$IG/rev.new")"; rm -f "$IG/rev.new"
}
ig_revoke(){ # <address> [record] → revokes the address at the server and at each revocation server this box lists, FOR GOOD: nothing undoes it. Without a record it is this box's own address, written out in full as the confirmation, and its identity signs now. With one, a record ig_revocation made earlier is published as it is, which needs no box here: only the file. Every server is tried whatever the others answer, and it fails, saying which did not take it, unless every one did: run it again
  ig_held || [ ! -s "$IG/address" ] || { ig_lock ig_revoke "$@"; return; }      # with no box here, a record of another box is published and nothing is kept
  local A=${1-} f=${2-} s l took= r=0
  ig_hex "$A" || ig_refuse "revocation publish takes the 64-character address in full: it is the confirmation, and a revocation cannot be undone" || return 1
  mkdir -p "$IG" || return 1
  if [ -z "$f" ]; then
    [ "$A" = "$(cat "$IG/address" 2> /dev/null)" ] || ig_refuse "that is not this box's address: nothing was published. revocation publish takes this box's own address, or a record of another" || return 1
    f="$IG/revoke.json"; ig_revocation > "$f" || return 1
  fi
  [ "$(ig_handed "$f")" = "$A" ] || ig_refuse "the record is not a revocation of $A whose every part verifies: nothing was published" || return 1
  jq -c '{type: "revocation_record"} + ({identity, revocation_signature, revoked_certificates, revoked_certificates_signature} | with_entries(select(.value != null)))' "$f" > "$IG/revoke.put" || return 1      # what is sent is the record's own members, its type first, whatever else a handed file carries
  l=$(ig_revservers) || return 1
  if ig_api PUT "/v1/$A/revocations" "$IG/revoke.put" > /dev/null 2> "$IG/put.err" || { [ "$(ig_code)" = revoked ] && ! ig_api GET "/v1/$A" > /dev/null 2>&1 && [ "$(ig_code)" = revoked ] && jq -ce '.record | objects' "$IG/error.json" > "$IG/held.json" 2> /dev/null && [ "$(ig_record "$IG/held.json")" = "$A" ]; }; then took=$IG_BASE      # revoked, from a server that holds the address revoked, is taken once the record its read of the box carries verifies: the address is ended there already
  else r=1; cat "$IG/put.err" >&2; ig_err "NOT taken by $IG_BASE"; fi
  while IFS= read -r s <&3; do [ -n "$s" ] || continue
    if IG_BASE=$s ig_api PUT "/v1/$A/revocations" "$IG/revoke.put" --max-time 10 > /dev/null 2> "$IG/put.err" || { [ "$(ig_code)" = revoked ] && IG_BASE=$s ig_api GET "/v1/$A/revocations" "" --max-time 10 > "$IG/held.json" 2> /dev/null && [ "$(ig_record "$IG/held.json")" = "$A" ]; }; then took="$took $s"      # revoked is taken once the record it serves verifies, as from the box's own server
    else r=1; cat "$IG/put.err" >&2; ig_err "NOT taken by the revocation server $s"; fi
  done 3<<< "$l"
  [ -n "$took" ] || return 1      # once any server has taken it, it is out: if the box it is about is the one here, it keeps it too
  [ "$A" != "$(cat "$IG/address" 2> /dev/null)" ] || { [ "$(ig_record "$f")" = "$A" ] && ig_keep "$A" "$IG/rev.doc" "$IG/rev.sig"; } || return 1
  [ $r = 0 ] || { ig_err "the revocation of $A is not at every server: whoever asks one that did not take it is not shown it. Run this again: a server that holds it answers as before"; return 1; }
  ig_out revoked --arg address "$A" --arg message "published to the server and to each revocation server"
}
ig_revoked(){ # <record> → keeps a revocation of another box that someone handed over, once it verifies: nothing is sent to that address or taken from it again, whatever a server says. It is the answer to a server that hides a revocation
  ig_held || { ig_lock ig_revoked "$@"; return; }
  local A; A=$(ig_handed "${1-}") || ig_refuse "the file is not a revocation record whose every part verifies: one is a line of JSON with identity and revocation, as revocation prints, and a revocation of certificates beside them must verify too" || return 1
  ig_keep "$A" "$IG/rev.doc" "$IG/rev.sig" && ig_out revoked --arg address "$A"
}

# recipe: send
ig_uuid(){ local h; h=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n'); printf '%s-%s-4%s-%x%s-%s\n' "${h:0:8}" "${h:8:4}" "${h:13:3}" $(( 0x${h:16:1} & 3 | 8 )) "${h:17:3}" "${h:20:12}"; }
ig_send(){ # [--json] [--subject <text>] [--reply-to <msg_id>] [--supersedes <msg_id>] <link, address or alias> [body file] → one logical message, its envelope built ONCE. To retry, run ig_flush, never ig_send again. With --json the body is one JSON value, sent as that value and not as text
  ig_held || { ig_lock ig_send "$@"; return; }
  local B f A id s= r= x= j= v how=--rawfile why
  while [[ ${1-} = --* ]]; do      # --reply-to: the msg_id recv printed for the message this answers. --supersedes: an earlier message of this box's, as sent/ names it
    [ "$1" = --json ] && { j=1; how=--slurpfile; shift; continue; }
    [ $# -ge 2 ] || { ig_refuse "$1 needs a value"; return 1; }
    case $1 in --subject) s=$2 ;; --reply-to) r=$2 ;; --supersedes) x=$2 ;; *) ig_refuse "unknown option $1: --json, --subject, --reply-to or --supersedes, before the link"; return 1 ;; esac; shift 2
  done
  for v in "$r" "$x"; do [[ -z $v || $v =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || { ig_refuse "not a msg_id: $v (the 36-character msg_id in a message's envelope, never the 64-character id the server gives it)"; return 1; }; done
  f=${2-}; A=$(cat "$IG/address") && B=$(ig_dest "${1-}") || return 1
  mkdir -p "$IG/outbox" || return 1
  [ -n "$f" ] || { f="$IG/body.txt"; cat > "$f" || return 1; }
  iconv -f UTF-8 -t UTF-8 < "$f" > /dev/null 2>&1 && printf %s "$s" | iconv -f UTF-8 -t UTF-8 > /dev/null 2>&1 || ig_refuse "the body or the subject is not UTF-8 text" || return 1
  if [ -n "$j" ]; then      # held to what its reader holds a body to (PROTOCOL.md §0b): ig_json on it in the body's place. jq keeps the last of a name given twice, so it reads the body (--slurpfile, below) only once ig_json has; and a text such as 1,"x":2, which would make a second member in the body's place, is none jq reads
    { printf '{"body":'; cat "$f"; printf '}'; } > "$IG/body.json" && ig_json "$IG/body.json" || ig_refuse "the body is not one JSON value its reader takes (PROTOCOL.md §0b): nothing is sent" || return 1
  fi
  id=$(ig_uuid) || return 1
  jq -cn --arg from "$A" --arg to "$B" --arg id "$id" --argjson t "$(ig_now)" --arg i "$(ig_b64 "$IG/identity.doc")" "$how" body "$f" --arg j "$j" --arg s "$s" --arg r "$r" --arg x "$x" \
    '{v:1, from:$from, to:$to, sent_at:($t|todate), msg_id:$id, identity:$i, body:(if $j == "" then $body else $body[0] end)} + ([{subject:$s}, {in_reply_to:$r}, {supersedes:$x}] | map(select(.[] != "")) | add // {})' > "$IG/send.P" || return 1      # ONE line, ending in a line feed: exactly the bytes that are signed. It carries this box's identity document, so its reader need not ask the server who wrote it
  why=$(ig_envcheck "$IG/send.P" "$A" "$B") || { rm -f "$IG/send.P"; ig_refuse "nothing is written or sent, since its reader would refuse this message: ${why#*: }"; return 1; }      # read back as its reader will, and as ig_seal does, before the outbox keeps it: a noncharacter in the body or the subject, which ig_seal would refuse at every ig_flush
  mv "$IG/send.P" "$IG/outbox/$B.$id.P" || return 1
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
ig_seal(){ # <address> <outbox stem> [the box ig_lookup read] → what to post: $IG/seal.age, the envelope <stem>.P dated at this post ($IG/seal.P: its sent_at this clock, and nothing else changed, as a signed request's time is when it was signed, made anew for each attempt), signed for that recipient only, by the working key in use, then the line, the signature and the padding encrypted to the recipient's VERIFIED prekey; and $IG/seal.query, the query that names that prekey. It is git's layout for a signed tag: the signed bytes as they are, then the signature block. The envelope is read as its recipient will read it first. A seal is made for one post and never kept: the outbox keeps the envelope, and ig_post seals it again at every post
  local B=$1 o=$2 s="$IG/seal" A r k n f t c why ps pc d l; rm -f "$s.P" "$s.sig" "$s.age" "$s.query"; A=$(cat "$IG/address") && n=$(cat "$IG/serial") || return 1
  why=$(ig_envcheck "$o.P" "$A" "$B") && [ "$(wc -l < "$o.P")" -eq 1 ] && [ "$(jq -r .identity "$o.P")" = "$(ig_b64 "$IG/identity.doc")" ] || ig_refuse "the outbox entry is not an envelope this box made for that address${why:+: $why}" || return 1
  d=$(jq -nr --argjson t "$(ig_now)" '$t | todate') && l=$(cat "$o.P") && [[ $l == *'"sent_at":"'* ]] || return 1      # the line, its one line feed dropped by $(…): ig_envcheck holds it to no control byte
  printf '%s"sent_at":"%s%s\n' "${l%%'"sent_at":"'*}" "$d" "$(t=${l#*'"sent_at":"'}; printf '%s' "${t:20}")" > "$s.P" || return 1      # the first sent_at member's 20 characters replaced: both clients write it before the body
  why=$(ig_envcheck "$s.P" "$A" "$B") && [ "$(wc -l < "$s.P")" -eq 1 ] && jq -e --arg d "$d" --slurpfile w "$o.P" '.sent_at == $d and del(.sent_at) == ($w[0] | del(.sent_at))' "$s.P" > /dev/null 2>&1 ||
    ig_refuse "the outbox entry does not read back as itself once dated at this post${why:+: $why}" || return 1
  c=$(ig_cert "$IG/prekeys/$n.txt.sig" "$IG/identity.doc" "$A") && [ $((${c##* } - $(ig_now))) -gt $((33*86400)) ] ||      # the certificate in use: the one this box's published prekey is signed under
    ig_refuse "this box's certificate ends within 33 days, too soon to sign mail that may wait that long (or it has no working key): rekey makes a new one" || return 1
  r=$(ig_resolve "$B" "${3-}") && read -r ps k pc <<< "$r" && [ -n "$pc" ] || return 1
  ssh-keygen -q -Y sign -n "irongall-msg-v1:$B" -f "$IG/work/$n-cert.pub" < "$s.P" > "$s.sig" || return 1
  read -r f t <<< "$(ig_padding $(($(wc -c < "$s.P") + $(wc -c < "$s.sig"))) "$k")" && [ -n "$t" ] || return 1
  { cat "$s.P" "$s.sig" && head -c "$f" /dev/zero | tr '\0' .; } | age -r "$k" > "$s.age" || return 1
  [ "$(wc -c < "$s.age")" -eq "$t" ] || { rm -f "$s.age"; ig_refuse "the encrypted message is not the $t bytes its padding was made for: it is not sent at a size that tells its length"; return 1; }
  printf 'prekey_serial=%s&certificate_serial=%s\n' "$ps" "$pc" > "$s.query"      # the prekey is named by both serials, its own and its certificate's, written as the digits ig_resolve checked. The body is the age file as it is, and no signature is beside it: the server knows the sender from the pass the post carries
}
ig_post(){ # <address> <outbox stem> → seals it and POSTs it; on 409 stale_prekey, seals the SAME envelope again, once, to the box read again. One that can never be delivered moves to outbox/failed/. Before anything is sealed, the recipient's box is read and the revocation servers asked (ig_lookup), and the seal is made to what this box then holds. A post whose answer was lost is posted again as a new ciphertext, which its reader drops by its msg_id
  local B=$1 o=$2 sa c
  if sa=$(ig_time "$(jq -r .sent_at "$o.P" 2> /dev/null)") && [ "$sa" -lt $(($(ig_now) - 33*86400)) ]; then      # the outbox keeps the envelope as written, and posts it, dated afresh each time, for 33 days from then: a reader's replay set reaches back that far past a first post (66 days and an hour), and no further
    ig_failed "$o"; ig_refuse "it was written more than 33 days ago, and an outbox posts a message no longer than that: moved to outbox/failed/"; return 1
  fi
  if [ -n "$sa" ] && [ "$sa" -gt "$(ig_now)" ]; then      # dated ahead of this clock: written while the clock read ahead of where it reads now. Not posted until the clock passes that time: the outbox's 33 days are counted from when it was written, and a reader's replay set reaches back that far past a first post and no further
    ig_refuse "its envelope is dated $(jq -r .sent_at "$o.P"), ahead of this machine's clock: it was written while the clock read ahead of where it reads now, and the outbox counts its 33 days from when it was written. It is kept in the outbox, and ig_flush sends it once the clock passes that time"; return 1
  fi
  rm -f "$IG/error.json"
  ig_lookup "$B"; case $? in      # asked before every post: what verifies is kept, and "none held" is the server's word, kept nowhere
    0) ig_failed "$o"; ig_err "REVOKED: $B is revoked, for good, and the revocation verifies, so it can never be delivered: moved to outbox/failed/"; return 1 ;;
    1) rm -f "$IG/error.json" ;;      # its 404 is an answer, and not one about the message
    2) rm -f "$IG/error.json"; ig_err "the box $B could not be read, so nothing is posted: kept in the outbox, retry with ig_flush"; return 1 ;;      # no answer is not "none held". Whatever code the failed lookup carried is no answer about the message
    *) ig_refuse "what this box keeps about $B does not verify, or could not be written: kept in the outbox"; return 1 ;;
  esac
  ig_seal "$B" "$o" "$IG/box.json" && ig_owner POST "/v1/$B/messages?$(cat "$IG/seal.query")" "$IG/seal.age" > "$IG/receipt.json" && ig_receipt && { ig_sent "$o"; return; }      # sealed to the box the lookup read
  if [ "$(ig_code)" = stale_prekey ]; then ig_seal "$B" "$o" && ig_owner POST "/v1/$B/messages?$(cat "$IG/seal.query")" "$IG/seal.age" > "$IG/receipt.json" && ig_receipt && { ig_sent "$o"; return; }; fi
  c=$(ig_code)
  case $c in revoked) ig_lookup "$B" ;; sender_revoked) ig_lookup "$(cat "$IG/address")" ;; esac      # a server's "revoked" is checked: with the revocation in hand it is final, and without one it is a call that failed
  if ig_gone "$B" || ig_gone "$(cat "$IG/address")"; then ig_failed "$o"; ig_err "REVOKED: the revocation verifies, so it can never be delivered: moved to outbox/failed/"; return 1; fi
  case $c in
    revoked | sender_revoked) ig_err "the server showed no revocation that verifies, so this box does not take that address as revoked: kept in the outbox, retry with ig_flush" ;;
    bad_address | too_large | conflict | sender_not_allowed) ig_failed "$o"; ig_err "it can never be delivered: moved to outbox/failed/" ;;
    *) ig_err "kept in the outbox: retry with ig_flush" ;;
  esac
  return 1
}
ig_receipt(){ # → 0 only for a receipt in $IG/receipt.json that names the ciphertext this box posted, $IG/seal.age (its id the SHA-256 of it, PROTOCOL.md §4.5), and whose times are times. Anything else is no receipt: the entry stays in the outbox
  ig_shape "$IG/receipt.json" receipt && [ "$(jq -r '.id | strings' "$IG/receipt.json")" = "$(sha256sum < "$IG/seal.age" | cut -c1-64)" ] &&
    ig_time "$(jq -r '.received_at | strings' "$IG/receipt.json")" > /dev/null && ig_time "$(jq -r '.expires_at | strings' "$IG/receipt.json")" > /dev/null && return 0
  ig_refuse "the server's receipt does not name the ciphertext this box posted, or its times are not times: kept in the outbox"
}
ig_sent(){ # <outbox stem> → sent/<address>.<msg_id>.json: the envelope as the post that was taken dated and signed it ($IG/seal.P), one line as the recipient's inbox/ keeps it, with the server's receipt. Stored, and only then does the outbox entry go, and a sent line is printed: the server's id, the msg_id and the address. sent/ is yours to prune
  local t="$IG/sent/${1##*/}.json" n=${1##*/}
  mkdir -p "$IG/sent" && ig_line "$IG/seal.P" "$IG/receipt.json" > "$t" && sync "$t" "$IG/sent" && rm -f "$1.P" || { ig_err "sent, but not recorded in sent/ (still in the outbox: ig_flush posts it again, and its reader drops the copy)"; return 1; }
  ig_out sent --arg id "$(jq -r .receipt.id "$t")" --arg msg_id "${n#*.}" --arg to "${n%%.*}"
}
ig_failed(){ # <outbox stem> → moves its envelope to outbox/failed/, where ig_flush no longer sees it. Delete it there to drop the message
  mkdir -p "$IG/outbox/failed" && { [ ! -e "$1.P" ] || mv "$1.P" "$IG/outbox/failed/"; }
}
ig_flush(){ # posts again every message still in the outbox, each sealed afresh to what this box holds now. One that fails never stops the others
  ig_held || { ig_lock ig_flush "$@"; return; }
  local f n rc=0; for f in "$IG"/outbox/*.P; do [ -e "$f" ] || continue; n=$(basename "$f" .P); ig_post "${n%%.*}" "${f%.P}" || rc=1; done; return $rc
}

# recipe: receive
ig_recv(){ # drains the box, every page up to a drain's limits. ACCEPT → inbox/ and a mail line on stdout. REFUSED → quarantine/, never delivered, and a refused line on stdout. Both are acked
  ig_held || { ig_lock ig_recv "$@"; return; }
  ig_drain; local rc=$?; ig_prune; return $rc
}
ig_drain(){ # stops at a transient error or a fault of this box, leaving the rest on the server for the next drain. And at a number of messages and of pages (below): a server that lists mail without end costs one run that much
  local B c="" n i id k=0 pages=0; B=$(cat "$IG/address") || return 1
  rm -f "$IG/asked"      # the senders this drain has asked the server about: one lookup each
  while :; do
    [ $((pages += 1)) -le 100 ] || { ig_out more --arg message "this run stopped at the most one drain takes: run recv again for the rest, which is still on the server"; return 0; }
    ig_owner GET "/v1/$B/messages${c:+?cursor=$c}" > "$IG/list.json" || { ig_own; return 1; }
    [ "$pages" -gt 1 ] || ig_forget || return 1      # the replay set pruned by this clock only once the server has taken a pass dated by it: a drain that a clock far off would prune is stopped at its pass first
    ig_shape "$IG/list.json" list && n=$(jq -r '.messages | length' "$IG/list.json") || { ig_err "the server's list of messages is not one this client reads, as PROTOCOL.md §0b reads JSON: the mail stays on the server"; return 1; }
    LC_ALL=C grep -Eqi $'^retry-after: *[0-9]+\r?$' "$IG/response.headers" || { ig_err "the server's list of messages carries no poll interval, a Retry-After of digits alone (PROTOCOL.md §5.1): the mail stays on the server"; return 1; }      # read and not kept: this script drains once and never waits, so it keeps no ETag either
    for ((i = 0; i < n; i++)); do
      id=$(jq -r --argjson i "$i" '.messages[$i].id | strings | select(test("\\A[0-9a-f]{64}\\z"))' "$IG/list.json") && ig_hex "$id" || continue      # tested in jq: $(…) drops trailing LFs and every NUL
      [ $((k += 1)) -le 1000 ] || { ig_out more --arg message "this run stopped at the most one drain takes: run recv again for the rest, which is still on the server"; return 0; }
      if ! grep -q "^$id " "$IG/seen" 2> /dev/null; then jq -c --argjson i "$i" '.messages[$i]' "$IG/list.json" > "$IG/entry.json" && ig_one "$B" "$id" "$IG/entry.json" || return 1; fi   # an id already handled is only acked again
      ig_owner DELETE "/v1/$B/messages/$id" > /dev/null || [ "$(ig_code)" = no_such_message ] || return 1
    done
    c=$(jq -r '.next_cursor // empty' "$IG/list.json"); [ -n "$c" ] || return 0      # one or more of A-Z, a-z, 0-9, - and _ (ig_shape), so it goes into the next query as it is
  done
}
ig_one(){ # <me> <id> <its list entry> → 0 once the message is judged and its verdict is on disk; 1 on a transient error or a fault of this box, so it is not acked. The fetch answers the ciphertext alone, of the size the list gives; who sent it, on the server's word, and when, are the list entry's
  local B=$1 id=$2 m="$IG/msg" A why rc h z
  rm -f "$m.json" "$m.age" "$m.sig" "$m.P" "$m.T" "$m.doc"
  cp "$3" "$m.json" && z=$(jq -r '.size // 0' "$m.json") || return 1      # an integer from 0 to 2^53 - 1, or null, which is 0 (ig_shape)
  if [ "$z" -le 16777216 ] && ig_owner GET "/v1/$B/messages/$id" "" --max-filesize $((z > 0 ? z : 1)) > "$m.age"; then :      # no more than the list says it holds
  elif [ "$(ig_code)" = no_such_message ]; then return 0      # already gone
  elif [ "$z" -le 16777216 ] && [[ $(ig_status) != 2?? ]]; then return 1; fi      # a 2xx that curl cut short is a body past its size
  [ "$(wc -c < "$m.age" 2> /dev/null)" = "$z" ] || { ig_err "the server's answer for message $id is not the $z bytes of ciphertext its list gives: it stays on the server"; return 1; }      # an answer that breaks its form, the server's fault and not the sender's: no verdict, and no ack
  h=$(sha256sum < "$m.age" | cut -c1-64)      # files are named by the hash computed here, never the server's id
  rm -f "$IG/said"; why=$(ig_judge "$B" "$m"); rc=$?; cat "$IG/said" 2> /dev/null; rm -f "$IG/said"      # what the judge met on the way, a revocation server with no answer, is printed here: its stdout is its verdict
  if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then [ "$h" = "$id" ] || { why="bad_id: the server's id for it is not the SHA-256 of its ciphertext"; rc=1; }; fi
  case $rc in
    0) A=$(jq -r .from "$m.P") && ig_line "$m.P" > "$IG/inbox/$h.json" && sync "$IG/inbox/$h.json" "$IG/inbox" && ig_seen "$A" "$m" "$h" || return 1      # stored, then seen, both on disk before the ack: a crash delivers again, never loses
       printf '{"type":"mail","id":"%s",' "$h" && tail -c +2 "$IG/inbox/$h.json" && echo ;;      # the line inbox/ keeps, as its bytes are: jq would write the line breaks ig_line escaped
    2) ig_out duplicate --arg id "$h" --arg message "a retry of a message already delivered: not delivered again" ;;
    3) ig_err "$why: nothing is judged or acked until this box is fixed"; return 1 ;;
    4) ig_err "$why: the message stays on the server, and the next recv asks again"; return 1 ;;
    *) ig_kept "$m" > "$IG/quarantine/$h.json" && printf '%s\n' "$why" > "$IG/quarantine/$h.reason" && sync "$IG/quarantine/$h.json" "$IG/quarantine/$h.reason" "$IG/quarantine" || return 1      # the message as served, its strings in base64 but those of their form, and beside it why: "<code>: <words>", this script's own words, never the message's
       ig_out refused --arg id "$h" --arg code "${why%%: *}" --arg message "${why#*: }" ;;
  esac
}
ig_kept(){ # <message stem> → the message as quarantine/ keeps it, the Go client's keepRefused: the members of its list entry, <stem>.json, each of the server's strings in the clear only when it has its form (an id or address 64 lowercase hex, a time one that reads back as itself), otherwise <name>_b64, the string as served in base64; and the ciphertext its fetch answered, <stem>.age, in base64; nothing else. So nothing the server chose is readable at a glance, and nothing is lost
  local rc; ig_b64 "$1.age" > "$1.b64" && jq -cj --rawfile c "$1.b64" 'def k($n; f): (.[$n] | strings | select(. != "")) as $v | if ($v | f) then {($n): $v} else {($n + "_b64"): ($v | @base64)} end;
    def hex: test("\\A[0-9a-f]{64}\\z"); def time: . as $s | test("\\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\\z") and (try (fromdateiso8601 | todate == $s) catch false);
    [k("id"; hex), k("from"; hex), k("received_at"; time), k("expires_at"; time), {ciphertext: $c}] | add' "$1.json"; rc=$?; rm -f "$1.b64"; return $rc      # base64 of the bytes, a file of ASCII, which jq carries as it is
}
ig_judge(){ # <me> <message stem> → 0 only if EVERY check passes, in this order; 2 for a resend of an accepted msg_id; 1 refused, with "<code>: <words>" on stdout, the words this script's own and never the message's; 3 a fault of this box, no verdict; 4 no answer from the server on whether the sender is revoked, no verdict. Who the sender is, is never asked of the server: the message carries what proves it. The one thing asked is whether a revocation of that sender exists, and the answer proves itself
  local B=$1 m=$2 ids=() k h A c f
  for k in "$IG"/prekeys/*.agekey; do [ -e "$k" ] || continue; [ -r "$k" ] || { echo "cannot read $k"; return 3; }; ids+=(-i "$k"); done
  [ ${#ids[@]} -gt 0 ] || { echo "this box has no prekeys"; return 3; }
  age -d "${ids[@]}" < "$m.age" > "$m.T" 2> /dev/null || { echo "undecryptable: it does not decrypt with this box's prekeys"; return 1; }
  A=$(ig_open "$B" "$m") || { echo "$A"; return 1; }      # the sender, proved by what was decrypted
  f=$(ig_floor 2> /dev/null) || { echo "$IG/seen-floor names no time"; return 3; }
  [ "$(ig_time "$(jq -r .sent_at "$m.P")")" -ge "$f" ] || { echo "stale: sent_at is before this box's replay set reaches back to, since its clock once read later than it does now"; return 1; }      # freshness has a floor too: a sent_at before the highest cutoff the replay set was pruned at may be a message whose line went. ig_open checked sent_at's grammar
  jq -e --arg a "$A" '.from == $a' "$m.json" > /dev/null 2>&1 || { echo "reattributed: the server lists it as from another box than the one that signed it"; return 1; }      # the server's from, compared in jq: $(…) drops trailing LFs and every NUL
  if ! grep -qx "$A" "$IG/asked" 2> /dev/null; then      # the server is asked once for each sender in a drain. That it holds none is an answer; no answer is not, and the message then stays where it is
    ig_lookup "$A" >> "$IG/said"; case $? in 0) ;; 1) echo "$A" >> "$IG/asked" ;; 3) echo "what this box keeps of its sender's revocations does not verify, or cannot be written"; return 3 ;; *) echo "whether its sender is revoked could not be asked"; return 4 ;; esac
  fi
  ig_gone "$A"; case $? in      # nobody can vouch for when a signature was made, so a revocation reaches back over everything that address signed
    0) echo "revoked: its sender's address is revoked, and the revocation verifies: nothing signed for that address is taken, whenever it was signed"; return 1 ;;
    3) echo "the revocation kept for $A does not verify"; return 3 ;;
  esac
  c=$(ig_cert "$m.sig" "$m.doc" "$A") || { echo "cannot read the certificate of a signature that verified"; return 3; }
  ig_certrevoked "$A" "${c%% *}"; case $? in      # the same answer carried the sender's revocation of its certificates, if it has one: the address goes on, and what a revoked certificate signed is refused the same way
    0) echo "certificate_revoked: it is signed under a certificate its sender's identity has revoked: nothing signed under it is taken, whenever it was signed"; return 1 ;;
    3) echo "the revocation of certificates kept for $A does not verify"; return 3 ;;
  esac
  [ ! -e "$IG/seen" ] || [ -r "$IG/seen" ] || { echo "cannot read $IG/seen"; return 3; }
  h=$(sha256sum < "$m.age" | cut -c1-64)
  ! grep -q "^$h " "$IG/seen" 2> /dev/null || { echo "replay: this ciphertext was already received"; return 1; }
  ig_meet "$A" "$m.doc" || { echo "cannot write under $IG/peers"; return 3; }
  ! grep -q " $A $(jq -r .msg_id "$m.P")\$" "$IG/seen" 2> /dev/null || return 2
}
ig_open(){ # <me> <message stem> → the sender's address, only if what was decrypted, <stem>.T, is a message for this box that its sender signed; otherwise "<code>: <words>", and 1. It leaves the envelope in <stem>.P, its signature in <stem>.sig and the sender's identity document in <stem>.doc
  local B=$1 m=$2 A
  # Line 1 is the envelope, line 2 begins the signature, the first END line ends it, and nothing after that is read. Each part has one place; nothing is searched for. The END line is the first line that begins so, and it must end there, in a line feed
  head -n 1 "$m.T" > "$m.P"; sed -n '2,/^-----END SSH SIGNATURE-----/p' "$m.T" > "$m.sig"
  [ "$(tail -c 1 "$m.P" | od -An -tx1 | tr -d ' \n')" = 0a ] && [ "$(sed -n 1p "$m.sig")" = "-----BEGIN SSH SIGNATURE-----" ] && tail -n 1 "$m.sig" | cmp -s - <(printf -- '-----END SSH SIGNATURE-----\n') ||
    { echo "bad_message: what was decrypted is not an envelope line and then a signature block"; return 1; }
  ig_envform "$m.P" || return 1
  jq -e '.from | . == null or type == "string"' "$m.P" > /dev/null 2>&1 || { echo "bad_envelope: the envelope is malformed: its from is not what that field holds"; return 1; }
  jq -e 'has("identity")' "$m.P" > /dev/null 2>&1 || { echo "bad_identity: the envelope carries no identity document"; return 1; }
  ig_bytes "$m.P" identity "$m.doc" && [ -s "$m.doc" ] || { echo "bad_identity: the envelope's identity is not base64 of an identity document"; return 1; }      # the one encoding of its bytes, compared as bytes
  ig_idcheck "$m.doc"; case $? in 0) ;;      # a well-formed document of a key type this script does not verify has its own code, once it is known to be the sender's
    2) jq -e --arg a "$(sha256sum < "$m.doc" | cut -c1-64)" '.from == $a' "$m.P" > /dev/null 2>&1 || { echo "reattributed: the envelope's from is not the address of the identity it carries"; return 1; }
       echo "unsupported_key_type: the sender's identity is of a key type this client does not verify"; return 1 ;;
    *) echo "bad_identity: the envelope's identity document breaks its format or its key checks"; return 1 ;;
  esac
  A=$(sha256sum < "$m.doc" | cut -c1-64)      # the sender: the hash of the identity document the envelope carries. The document proves itself, and the signature must now verify under it
  jq -e --arg a "$A" '.from == $a' "$m.P" > /dev/null 2>&1 || { echo "reattributed: the envelope's from is not the address of the identity it carries"; return 1; }
  ig_certified "$A" "$m.doc" "irongall-msg-v1:$B" "$m.sig" "$m.P" > /dev/null; case $? in      # over line 1 exactly as decrypted, never over anything rebuilt
    0) ;; 2) echo "bad_signature: the certificate of the key that signed it has ended"; return 1 ;;
    3) echo "bad_signature: the certificate of the key that signed it has not begun, by this machine's clock"; return 1 ;;
    *) echo "bad_signature: it is not signed for this box by a working key the sender's identity certified"; return 1 ;;
  esac
  ig_envcheck "$m.P" "$A" "$B" || return 1
  echo "$A"
}
ig_envform(){ # <envelope> → 0 only for a JSON text as every reader takes one (ig_json): UTF-8, one object, no key twice in any object in it, nested at most 32 deep. Otherwise the reason, and 1
  ig_json "$1" || { echo "bad_envelope: the envelope is not one JSON object in UTF-8 with no key twice, as PROTOCOL.md §0b reads one"; return 1; }
}
ig_envcheck(){ # <envelope> <signer> <this box> → 0 only for one UTF-8 JSON object, keys exact and none twice, checked in PROTOCOL.md §5 check 6's order: a body and fields that are strings, v the number 1 written as 1 (jq gives back 1e0 as 1, so that one is taken: a known variance), from the signer and to this box, a msg_id, and sent_at no older than 33 days and no more than an hour ahead; otherwise the reason, and 1
  local e=$1 sa
  ig_envform "$e" || return 1
  jq -e 'has("body") and all(.from, .to, .msg_id, .sent_at, .subject, .in_reply_to, .supersedes, .identity; . == null or type == "string") and (.v | type == "number" and tostring == "1")' "$e" > /dev/null 2>&1 ||
    { echo "bad_envelope: the envelope is malformed: a body, fields that are strings, and v the number 1"; return 1; }      # in PROTOCOL.md §5 check 6's order: a body and every member of its type, v, to, msg_id, then the time
  jq -e --arg a "$2" --arg b "$3" '.from == $a and .to == $b' "$e" > /dev/null 2>&1 || { echo "reattributed: the inner from/to do not match the signer and this box (re-attribution)"; return 1; }
  jq -e '.msg_id | type == "string" and test("\\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\z")' "$e" > /dev/null 2>&1 || { echo "bad_envelope: the envelope has no valid msg_id"; return 1; }
  jq -e '.sent_at | strings | test("\\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\\z")' "$e" > /dev/null 2>&1 && sa=$(ig_time "$(jq -r .sent_at "$e")") || { echo "bad_envelope: the envelope's sent_at is not a UTC timestamp to the second"; return 1; }      # its grammar tested in jq first: $(…) drops trailing LFs and every NUL
  [ "$sa" -ge $(($(ig_now) - 33*86400)) ] || { echo "stale: sent_at is older than 33 days"; return 1; }
  [ "$sa" -le $(($(ig_now) + 3600)) ] || { echo "future: sent_at is more than 60 minutes ahead of this machine's clock"; return 1; }
}
ig_line(){ # <checked envelope> [receipt] → the one line delivered: built from the checked fields, never the sender's bytes, with U+0085, U+2028 and U+2029 escaped (Python's splitlines and Node's readline end lines there), and every character of Unicode 18.0's Default_Ignorable_Code_Point, which nobody sees and a model reads (tag characters, BiDi controls, zero-width characters, variation selectors): the Go client's escapeUnseen, in its list and its form. ig_sent adds the server's receipt as its last member
  jq -j --slurpfile r "${2:-/dev/null}" 'def h4: . as $n | [range(3; -1; -1) | ($n / pow(16; .) | floor) % 16] | map("0123456789abcdef"[.:. + 1]) | add;
    def ig_esc: if . > 65535 then (. - 65536) as $v | "\\u" + ((55296 + ($v / 1024 | floor)) | h4) + "\\u" + ((56320 + $v % 1024) | h4) else "\\u" + h4 end;      # a code point as JSON escapes it, lowercase, as Go writes it: a surrogate pair above U+FFFF
    {v: 1, from, to, sent_at, msg_id, body} + ([{subject}, {in_reply_to}, {supersedes}] | map(select(.[] | . != null and . != "")) | add // {}) + ($r[0] | if . then {receipt: {id, received_at, expires_at}} else {} end) | tojson | gsub("(?<c>[\\x{85}\\x{2028}\\x{2029}\\x{AD}\\x{34F}\\x{61C}\\x{115F}-\\x{1160}\\x{17B4}-\\x{17B5}\\x{180B}-\\x{180F}\\x{200B}-\\x{200F}\\x{202A}-\\x{202E}\\x{2060}-\\x{206F}\\x{3164}\\x{FE00}-\\x{FE0F}\\x{FEFF}\\x{FFA0}\\x{FFF0}-\\x{FFF8}\\x{1BCA0}-\\x{1BCA3}\\x{1D173}-\\x{1D17A}\\x{E0000}-\\x{E0FFF}])"; .c | explode[0] | ig_esc)' "$1"
}
ig_forget(){ # → the replay set without the lines past 66 days and an hour from their sent_at by this clock: a retry, dated afresh, may be posted up to 33 days after a first copy that was delivered, and read up to 33 days after that, and an hour covers a clock that steps back as far as two clocks a server takes are apart. When it drops one, the floor rises to the cutoff first, so a clock that later reads further back still takes no message whose line went (ig_floor)
  local c=$(($(ig_now) - 66*86400 - 3600)) f; [ -e "$IG/seen" ] || return 0
  awk -v c="$c" '$2 >= c' "$IG/seen" > "$IG/seen.new" || return 1
  if ! cmp -s "$IG/seen" "$IG/seen.new"; then
    f=$(ig_floor) || return 1
    if [ "$f" -lt "$c" ]; then printf '%s\n' "$c" > "$IG/seen-floor.new" && sync "$IG/seen-floor.new" && mv "$IG/seen-floor.new" "$IG/seen-floor" && sync "$IG" || return 1; fi      # on disk before any line goes
  fi
  mv "$IG/seen.new" "$IG/seen" && sync "$IG/seen" "$IG"
}
ig_floor(){ # → the highest cutoff a prune of the replay set has dropped a line at, from seen-floor, or 0 when it has none: a message sent before it is stale whatever the clock now reads, since its line may be gone, as a Kerberos server that has lost its replay cache refuses until the window has passed (RFC 4120 §3.2.3). A file that names anything else is an error, never the default
  local f; [ -e "$IG/seen-floor" ] || { echo 0; return 0; }
  f=$(cat "$IG/seen-floor" 2> /dev/null) && [[ $f =~ ^(0|[1-9][0-9]{0,17})$ ]] && printf '%s\n' "$f" | cmp -s - "$IG/seen-floor" && echo "$f" ||      # compared with itself rebuilt: $(…) drops line feeds and NULs
    { ig_err "$IG/seen-floor names no time: it is a number of seconds and a line feed, written by recv"; return 1; }
}
ig_seen(){ # <sender> <message stem> <hash> → the message, in the replay set and on disk
  local new=; [ -e "$IG/seen" ] || new=$IG
  printf '%s %s %s %s\n' "$3" "$(ig_time "$(jq -r .sent_at "$2.P")")" "$1" "$(jq -r .msg_id "$2.P")" >> "$IG/seen" && sync "$IG/seen" ${new:+"$new"}
}

# recipe: new prekey (monthly)
ig_rekey(){ # [--no-pq] → publishes a new prekey, signed by a new working key under a new certificate, under the lock: a NEW key at a new number, which this machine's clock gives, or the statement an earlier run signed and the server did not take, sent again as it is. Needs only the identity, so it also recovers a box that lost its prekeys or its working key
  ig_opt "${1-}" || return 1
  ig_held || { ig_lock ig_rekey "$@"; return; }
  ig_renew "${1-}"
}
ig_renew(){ # [--no-pq] → what ig_rekey does, the lock held. A serial is signed ONCE
  local A r s t na h c f cs p new x gone u w; A=$(cat "$IG/address") || return 1; mkdir -p "$IG/prekeys"
  ig_api GET "/v1/$A" > "$IG/self.json" 2> "$IG/self.err" || { [ "$(ig_code)" = no_such_mailbox ] || { cat "$IG/self.err" >&2; return 1; }; gone=1; }      # 404: the server holds no box here any more, past its record's expiry or deleted (PROTOCOL.md §7), so nothing is served to number above or to hold to its order, and the renewal goes as a registration
  p=$(cat "$IG/serial" 2> /dev/null || echo 0)
  if [ -n "$gone" ]; then s=$p; else
    ig_shape "$IG/self.json" box && ig_bytes "$IG/self.json" identity "$IG/self.doc" && ig_bytes "$IG/self.json" prekey "$IG/self.txt" && ig_bytes "$IG/self.json" prekey_signature "$IG/self.sig" ||
      ig_refuse "the server's answer for this box is not one this client reads: a JSON object as PROTOCOL.md §0b reads one, each byte field base64 in its one encoding" || return 1
    [ -s "$IG/self.txt" ] && [ -s "$IG/self.sig" ] || ig_refuse "the server sent no prekey for this box" || return 1
    c=$(ig_cert "$IG/self.sig" "$IG/identity.doc" "$A") && c=${c#* } && r=$(ig_prekeycheck "$IG/self.txt" "$IG/self.sig" "$A" "$IG/identity.doc" "${c% *}") || ig_refuse "this box's current prekey, as served: ${r:-it is not signed under a certificate of this identity}" || return 1      # its own record, judged where its certificate begins: whether this identity ever certified the key that signed it, even if that certificate has since ended
    s=${r%% *}; cs=${r##* }      # a box's statements are ordered by certificate first, then by serial, and this box gives a renewal's certificate and prekey one number: what it published is (p, p), and the server may serve nothing ordered before it
    [ "$cs" -gt "$p" ] || { [ "$cs" -eq "$p" ] && [ "$s" -ge "$p" ]; } || ig_refuse "rollback: the server serves this box's prekey serial $s under certificate $cs, before serial $p, which this box published" || return 1
    s=$((cs > p ? cs : p))
  fi
  x=$(ig_certskept "$A"); case $? in      # above every serial this box's identity has revoked too: a certificate numbered there would be revoked as it was made
    0) [ "$x" -lt 9007199254740991 ] || ig_refuse "this box's identity has revoked its certificates through the highest serial there is, so no later certificate can be made: the address cannot renew" || return 1; [ "$x" -le "$s" ] || s=$x ;;
    1) ;;
    *) ig_refuse "the revocation of certificates kept for this box does not verify"; return 1 ;;
  esac
  [ "$s" -lt 9007199254740991 ] || ig_refuse "this box's certificate serial is the highest there is, so no later certificate can be made: the address cannot renew" || return 1
  t=$(ls "$IG/prekeys" | sed -n 's/\.agekey$//p; s/\.txt\.sig$//p' | sort -n | tail -n 1); new=1      # s is the highest number this box knows of, and the new statement goes above it: above the served CERTIFICATE's serial, never the served prekey's, since it is under a new certificate, which outranks any prekey serial under the one before. So a prekey published in this box's name at the highest serial there is holds nothing. t is the highest number this box began a prekey at
  if [ "${t:-0}" -gt "$s" ]; then s=$t; new=; [ ! -s "$IG/prekeys/$s.txt.sig" ] || { na=$(ig_time "$(sed -n 5p "$IG/prekeys/$s.txt")") && [ "$na" -gt "$(ig_now)" ] && [ -s "$IG/work/$s-cert.pub" ] && c=$(ig_cert "$IG/prekeys/$s.txt.sig" "$IG/identity.doc" "$A") && c=${c#* } && [ "${c% *}" -le "$(ig_now)" ] && u=$(ig_time "$(cat "$IG/prekeys/$s.made" 2> /dev/null)") && w=$(ig_lifetime 2> /dev/null) && [ $((na - u)) -le "$w" ]; } || new=1; fi      # a number an earlier run took, and that nothing has passed since, is kept. Signed and never seen published: sent again AS IT IS until it expires, then a new number. Signed again, the same key would get 33 more days from a server that keeps what it refuses. One under a certificate that has not begun, by this clock, was signed while the clock read over an hour ahead: a server refuses it until that time comes, so it is spent too. Never signed: its key is used
  if [ -n "$new" ]; then [ "$s" -lt 9007199254740991 ] || ig_refuse "this box's certificate serial is the highest there is, so no later certificate can be made: the address cannot renew" || return 1; t=$(ig_now); s=$((t > s ? t : s + 1)); fi      # a new number: this machine's clock, in seconds, or one above the highest this box knows of when the clock gives nothing higher. An identity is a key and keeps no record of what it signed, and a box restored from it knows only what the server shows: by the clock, its certificate is above every one made before, on whatever machine. A verifier never reads a serial as a time, it only compares two
  [ -s "$IG/prekeys/$s.txt.sig" ] || rm -f "$IG/prekeys/$s.txt" "$IG/prekeys/$s.made"; ig_prekey "$s" "${1-}" || return 1
  if [ -n "$gone" ]; then u="/v1/$A"; w='{identity:$i}'; else u="/v1/$A/prekey"; w='{}'; fi      # a registration is the identity document, then what a new prekey carries
  jq -n --arg i "$(ig_b64 "$IG/identity.doc")" --arg p "$(ig_b64 "$IG/prekeys/$s.txt")" --arg g "$(ig_b64 "$IG/prekeys/$s.txt.sig")" --argjson k "$IG_SENDERS" "$w"' + {prekey:$p, prekey_signature:$g, sender_key_types:$k}' > "$IG/rekey.json"
  h=$(ig_pass "$s") && ig_api PUT "$u" "$IG/rekey.json" -H "Authorization: $h" > /dev/null || { ig_clock; return 1; }      # a pass under the NEW certificate: that is how a box moves to one, and the server then takes no pass under an older
  [ "$s" -le "$(cat "$IG/serial" 2> /dev/null || echo 0)" ] || echo "$s" > "$IG/serial" || return 1
  mv "$IG/pass.new" "$IG/pass" || return 1
  for f in "$IG"/work/*-cert.pub; do t=$(basename "$f" -cert.pub); [[ $t =~ ^[0-9]+$ ]] && [ "$t" -lt "$s" ] && rm -f "$IG/work/$t" "$IG/work/$t.pub" "$f"; done      # older working keys: what they signed is signed, and the server takes no pass under them
  ig_prune && ig_out prekey --argjson serial "$s" --arg not_after "$(sed -n 5p "$IG/prekeys/$s.txt")"
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

# Run as a command, not sourced: the Go client's command line, for the commands this script has.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  ig_usage(){ sed -n '/^#   bash irongall\.sh /,/^#   The README/p' "$0" | sed 's/^#   //'; }      # the usage at the top
  ig_lines(){ ig_usage | awk -v w="bash irongall.sh $* " '/^bash irongall\.sh /{ on = index($0 " ", w) == 1 } /^The README/{ on = 0 } on'; }      # <words> → the usage lines of the commands they start
  ig_wrong(){ jq -cn --arg m "$1" --arg u "${2-}" --arg h "${3:-bash irongall.sh help}" '{type:"usage_error"} + (if $u != "" then {usage:$u} else {} end) + {help:$h, message:$m}' >&2; exit 2; }      # <words> [usage] [help] → the usage_error line on stderr, as the Go client prints one: what was wrong, the command's usage, and the help to read. Nothing ran
  ig_cmd= ig_n=0 ig_args=-1      # the function the command line runs, how many words name it, and how many arguments it takes (-1: its own to check)
  case ${1-} in init | addr | send | recv) ig_cmd=ig_$1 ig_n=1 ;; esac
  case "${1-} ${2-}" in
    'alias add') ig_cmd=ig_alias ig_n=2 ig_args=2 ;;
    'alias list') ig_cmd=ig_alias ig_n=2 ig_args=0 ;;
    'outbox flush') ig_cmd=ig_flush ig_n=2 ;;
    'prekey renew') ig_cmd=ig_rekey ig_n=2 ;;
    'revocation make') ig_cmd=ig_revocation ig_n=2 ig_args=0 ;;
    'revocation publish') ig_cmd=ig_revoke ig_n=2 ;;
    'revocation keep') ig_cmd=ig_revoked ig_n=2 ;;
  esac
  ig_help=0
  for a; do case $a in --help) ig_help=1 ;; -h) ig_help=1; echo "Flag shorthand -h has been deprecated, use --help" >&2 ;; esac; done      # anywhere after a command: its help, and nothing runs. -h works too, as in the Go client, and means nothing else
  if [ "${1-}" = help ] || { [ -z "$ig_cmd" ] && [ "${2-}" = help ]; }; then
    ig_help=1; [ "$1" = help ] && shift || set -- "$1"
    [ $# -eq 0 ] || case "${1-} ${2-}" in 'alias '?* | 'outbox '?* | 'prekey '?* | 'revocation '?*) ig_n=2 ;; ?*) ig_n=1 ;; esac
  fi
  if [ $ig_help = 1 ]; then      # help: the usage, or the lines of the command or group it names
    [ "$ig_n" -gt 0 ] || [ $# -eq 0 ] || [[ $1 = -* ]] || ig_n=1
    [ "$ig_n" -gt 0 ] || { ig_usage; exit 0; }
    out=$(ig_lines "${@:1:ig_n}"); [ -n "$out" ] && { echo "$out"; exit 0; }
    ig_wrong "irongall.sh has no command ${*:1:ig_n}"
  fi
  if [ -z "$ig_cmd" ]; then      # bare, a group alone, or a command it does not have
    if [ $# -eq 0 ]; then ig_wrong "irongall.sh takes a command: bash irongall.sh help lists them"
    elif [ -z "$(ig_lines "$1")" ]; then ig_wrong "irongall.sh has no command $1"
    elif [ -n "${2-}" ]; then ig_wrong "irongall.sh $1 has no command $2" "" "bash irongall.sh help $1"
    else ig_wrong "irongall.sh $1 takes a command: bash irongall.sh help $1 lists them" "" "bash irongall.sh help $1"; fi
  fi
  words=${*:1:ig_n}; shift $ig_n
  if [ $ig_args -ge 0 ] && [ $# -ne $ig_args ]; then ig_wrong "irongall.sh $words takes $ig_args arguments, and was given $#" "$(ig_lines "$words" | head -n 1 | sed 's/   .*//')" "bash irongall.sh help $words"; fi
  ig_tls "$IG_BASE" || exit 1      # refused before anything, as the Go client refuses to open a box whose server it would not call
  "$ig_cmd" "$@"; exit
fi
