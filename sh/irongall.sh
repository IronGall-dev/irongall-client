#!/usr/bin/env bash
# irongall.sh: the irongall client in stock tools (bash, age, ssh-keygen, curl, jq, iconv and coreutils).
#
# The same protocol and checks as the Go client in this repo, on a box of its own: the proof that a box made of stock tools exchanges mail with a
# Go box (AGENTS.md § The shell client), not a client to run. It fails CLOSED:
# a failed check prints an error line, "REFUSED: <reason>", and stops (recv refuses that one message with a refused line, its code and its words, and goes on), and every API error prints its status and its code, and none of the server's words.
# It prints JSON lines, as the Go client does, each with its "type" first: what a command did and met on stdout, and on stderr the
# line that says it failed ("error", here sometimes more than one), that its command line was wrong ("usage_error"), or that it waits.
# Get it from https://github.com/IronGall-dev/irongall-client at a commit you have read, never from the irongall.dev
# server: a server that could hand you this script could hand you one without its checks.
#
#   bash irongall.sh init [--no-pq]                  make and register this box; prints its link, $IG_BASE/to/<address>
#   bash irongall.sh addr                            print it again: give it to whoever should write to this box
#   bash irongall.sh send <link> [file]             one message (the body from stdin without a file); a link or an address. Posted now or not at all: nothing waits
#   bash irongall.sh recv                            verified mail, a "mail" line each; refused mail goes to quarantine/, with a "refused" line
#   bash irongall.sh prekey renew [--no-pq]          a new prekey, working key and certificate: at least monthly, as a prekey is valid for 33 days, or within the lifetime a prekey-lifetime file sets
#   bash irongall.sh help [<command>]                this, or a command's lines; --help after a command does the same, and runs nothing
#   The README has the rest: https://github.com/IronGall-dev/irongall-client#readme
#
# Or source it at the top of every shell call and call the ig_* functions. Agent tools run each command in a fresh
# shell, so all state lives in files in the box's directory, never in variables.
#
# It gives up conveniences the Go client has: recv drains once and never waits for mail, and each step runs several
# programs. Needs bash >= 4, age >= 1.3 (1.2 makes and reaches --no-pq boxes only; Ubuntu to 26.04 and Debian 13
# ship older, and go install filippo.io/age/cmd/...@v1.3.2 is current), OpenSSH >= 9.1 (the first to take a
# certificate's validity and a time to verify at in UTC), curl >= 7.84 (--fail-with-body, and -w with %header),
# jq >= 1.7.1 (1.7.0 can abort on a number a sender writes, CVE-2023-50246; Ubuntu 24.04's fixed jq prints jq-1.7),
# iconv, and coreutils (sha256sum, base64, od, sync). Dates go through jq, never date -d, and base64 is never -w0.

# recipe: setup
set -o pipefail; umask 077
export LC_ALL=C   # every pattern and tool reads bytes, as the Go client does: under another locale [0-9] can take a digit that is not ASCII, and [A-Z] can miss I
IG_BASE=${IG_BASE:-https://irongall.dev}
IG=${IG_HOME:-${XDG_CONFIG_HOME:-$HOME/.config}/irongall-sh/${IG_BOX:-default}}   # one box per directory, of this script's own: never the Go client's (its IRONGALL_HOME and ~/.config/irongall/, ig_ownbox), and never the working directory
IG_LOCK_WAIT=${IG_LOCK_WAIT:-120}   # how many seconds a command waits for the box's lock while another command of the box holds it: what apt waits for its own lock when no one is at a terminal
IG_P256='ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGD+1LolWp0xyWHrdMY1bWjASbiSO2H6bOZpYi5g8p+2eQP+EAi4vJmkGunpVii8ZPLxsgwtfp9Rd6PClNRGIpk='   # a P-256 key, box C's identity in this repo's testdata/vectors/ (RFC 6979 §A.2.5's published test key), for ig_senders to ask ssh-keygen to read
ig_senders(){ # → the identity key types ig_idcheck verifies on this build, as a JSON list. A box declares them with each prekey it publishes, and the server then refuses it mail from a box whose identity is of any other type (PROTOCOL.md §2c): ssh-ed25519, and ecdsa-sha2-nistp256 only where this build's ssh-keygen reads a P-256 key. One built without OpenSSL reads none, so ig_idcheck refuses every P-256 identity there (PROTOCOL.md §3), and a box that declared the type would be sent mail it then refuses
  if ssh-keygen -l -f - <<< "$IG_P256" > /dev/null 2>&1; then echo '["ssh-ed25519","ecdsa-sha2-nistp256"]'; else echo '["ssh-ed25519"]'; fi
}
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
ig_api(){ # <METHOD> <PATH> [body file] [curl args…] → the body on stdout, as curl -o wrote it. The body file is sent as it is: a message's ciphertext, POSTed to …/messages, as application/octet-stream (PROTOCOL.md §4.5), and any other body as JSON. Any non-2xx: an error line with its status, its code (ig_code) and the wait its Retry-After asks for, and nothing the server wrote: its detail, hint and title are for a person reading the body (PROTOCOL.md §13). No answer at all: an error line with curl's words. Keeps the answer in $IG/error.json and what curl read of it in $IG/error.meta (ig_status), returns 1
  local m=$1 p=$2 f=${3-} t=application/json s c w; local -a np=(); shift 2; [ $# -gt 0 ] && shift
  [[ "$m $p" == "POST /v1/"*"/messages?"* ]] && t=application/octet-stream
  ig_tls "$IG_BASE" || return 1
  ig_here "$IG_BASE" localhost && np=(--noproxy '*')      # a server on this machine is called directly, whatever proxy the environment names, as Go's ProxyFromEnvironment never proxies localhost or a loopback address
  rm -f "$IG/error.json" "$IG/error.meta" "$IG/response.body" "$IG/response.meta"
  curl -q -sS "${np[@]}" --max-time 60 --max-filesize 16777216 --fail-with-body -o "$IG/response.body" -w '%{response_code}\n%header{retry-after}\n%header{date}\n' -X "$m" ${f:+-H "Content-Type: $t" --data-binary "@$f"} "$@" "$IG_BASE$p" > "$IG/response.meta" 2> "$IG/curl.err" &&
    [[ $(sed -n 1p "$IG/response.meta") = 2?? ]] && { cat "$IG/response.body"; return 0; }      # -q first, or curl reads the user's .curlrc, where location, insecure or proxy change what is called. Only a 2xx is an answer: curl, which follows no redirect without -L, exits 0 on a 3xx too. The status and the two headers are the final answer's own, as curl read it: never a 1xx's line or a trailer, which the Go client never reads either
  mv "$IG/response.body" "$IG/error.json" 2> /dev/null; mv "$IG/response.meta" "$IG/error.meta" 2> /dev/null
  s=$(ig_status); c=$(ig_code); w=$(ig_wait); q=; u=
  [ "$c" = rate_limited ] && q=$(ig_member quota_id "$IG_QUOTAS") && u=$(ig_member subject '["box","ip"]')
  [ -n "$s" ] || { ig_err "no answer from $IG_BASE"; return 1; }      # curl's words, which can quote what the server sent (a certificate's name), are not printed
  jq -cn --argjson s "$s" --arg c "$c" --arg w "$w" --arg q "$q" --arg u "$u" '{type:"error", status:$s} + (if $c != "" then {code:$c} else {} end) + (if $q != "" then {quota_id:$q} else {} end) + (if $u != "" then {subject:$u} else {} end) + (if $w != "" then {retry_after:($w | tonumber)} else {} end) +
    {message:("ERROR \($s)" + (if $c != "" then " \($c)" elif $s >= 300 and $s <= 399 then ": a redirect, which this client never follows: the API answers where it is called" else ": an answer this client does not know" end) + (if $q != "" then ": the limit \($q)" else "" end) + (if $u == "box" then ", counted against this box" elif $u == "ip" then ", counted against this machine'"'"'s IP address" else "" end) + (if $w != "" then "; the server asks to wait \($w) seconds" else "" end))}' >&2; return 1
}
IG_TYPE='tag:irongall.dev,2026-10-17:errors/'      # an error's type is this and its code, which names the problem and resolves to nothing (PROTOCOL.md §13): a code counts only beside its own
IG_CODES='{"bad_request":400,"bad_address":400,"bad_encoding":400,"identity_mismatch":400,"bad_key":400,"prekey_not_new":400,"prekey_time":400,"unsupported_key_type":400,"not_age":400,"wrong_recipient_type":400,"bad_revocation":400,"unauthorized":401,"pass_expired":401,"certificate_not_current":401,"certificate_revoked":401,"unknown_sender":403,"sender_revoked":403,"sender_not_allowed":403,"sender_key_type":403,"adopt_key_refused":403,"no_such_mailbox":404,"no_such_message":404,"not_revoked":404,"conflict":409,"box_changed":409,"stale_prekey":409,"prekey_expired":409,"request_timeout":408,"revoked":410,"precondition_failed":412,"too_large":413,"rate_limited":429,"fetch_paced":429,"refetch_spent":429,"pair_full":429,"mailbox_full":429,"mailbox_busy":429,"unavailable":503}'      # every code, and its status (PROTOCOL.md §13)
IG_QUOTAS='["polls","pages","calls","sends","renewals","certificates","certificate_revocations","registrations","registrations_range","misses","sends_before_pass","requests"]'      # every limit a rate_limited may name in quota_id (PROTOCOL.md §13)
ig_member(){ jq -r --arg m "$1" --argjson known "$2" '.[$m] | strings | select(. as $v | $known | index([$v])) ' "$IG/error.json" 2> /dev/null; }      # <member> <known values, a JSON array> → the last API error's string member, only when it is one of them: a client shows no value it does not know (PROTOCOL.md §13)
ig_status(){ sed -n '1{/^[0-9][0-9][0-9]$/p;}' "$IG/error.meta" 2> /dev/null | grep -vx 000; }      # the status of the last API error. error.meta is what curl's -w read of the final answer, a line each: its status (000 for none), then its Retry-After and its Date, each the first given, trimmed, as Go's Header.Get reads one
ig_code(){ local s; s=$(ig_status) && [ -n "$s" ] && ig_shape "$IG/error.json" problem && jq -r --argjson codes "$IG_CODES" --argjson s "$s" --arg t "$IG_TYPE" '(.code | strings) as $c | select($codes[$c] == $s and .type == $t + $c) | $c' "$IG/error.json" 2> /dev/null; }   # the code of the last API error: one this client knows, under its own status, beside its own type, from an answer the Go client would read the same. Any other is no code
ig_wait(){ sed -n '2{/^[0-9]\{1,\}$/p;}' "$IG/error.meta" 2> /dev/null | sed 's/^0*\([0-9]\)/\1/' | awk '$1 > 0 { print ($1 > 86400 ? 86400 : $1) }'; }      # the seconds the last API error's Retry-After asks to wait, as a number of at most a day, or nothing. It is delay-seconds, digits alone (PROTOCOL.md §13): an HTTP-date asks for no wait
ig_dated(){ local d; d=$(sed -n '3{/^[A-Za-z0-9 ,:]*$/p;}' "$IG/error.meta" 2> /dev/null) && [ -n "$d" ] && jq -nr --arg d "$d" '$d | strptime("%a, %d %b %Y %H:%M:%S GMT") | mktime | todate' 2> /dev/null; }      # the time the last API error's Date header gives, the server's word
ig_shape(){ # <answer> <box|list|record|receipt|problem> → 0 only for one JSON object of that kind, each member this script reads of its type, and null as if the member were left out. An integer is from 0 to 2^53 - 1 and jq gives it back as digits, since bash reads it. A byte member is a string, read by ig_bytes. Members it does not read are ignored
  jq -en --arg k "$2" 'def s: . == null or type == "string"; def n: . == null or (type == "number" and . == floor and . >= 0 and . <= 9007199254740991 and (tostring | test("\\A(0|[1-9][0-9]*)\\z")));
    def record: all(.identity, .revocation_signature, .revoked_certificates, .revoked_certificates_signature; s);
    [inputs] | length == 1 and (.[0] | type == "object" and
    {box: all(.identity, .prekey, .prekey_signature, .revoked_certificates, .revoked_certificates_signature; s),
     list: ((.next_cursor | . == null or (type == "string" and test("\\A[A-Za-z0-9_-]+\\z"))) and (.messages | . == null or (type == "array" and all(.[]; . == null or (type == "object" and (.id | s) and (.size | n and (. // 0) <= 16777216)))))),
     record: record,
     receipt: all(.id, .received_at, .expires_at; s),
     problem: (all(.type, .code; s) and (.record | . == null or (type == "object" and record)))}[$k])' "$1" > /dev/null 2>&1
}
ig_bytes(){ # <answer> <member> <file> → the member's bytes into the file, only for base64 in its one encoding (RFC 4648 §3): padded, nothing outside the alphabet, a line break included, and the unused bits zero, which is what encoding the bytes again gives back. So a field has one text whatever base64 -d takes (GNU's refuses one unpadded, uutils' takes it), and the identity a plain/ vector carries is refused as the Go client refuses it. A member null or left out is no bytes. 1 for anything else
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
ig_taken(){ # → the reading of this machine's clock a server took, in Unix time: the date of the pass in $IG/pass, which the call ig_owner made, or the renewal ig_renew sent, carried once the server answered it: its not_after less the ten minutes a pass is signed for. Every deletion by the clock is by one, never by a reading of the clock (PROTOCOL.md §0): a clock far off is stopped at its pass, and one that jumps or steps back while a call is in flight deletes nothing by where it went
  local na; na=$(ig_time "$(sed -n 's/.* not_after="\([^"]*\)".*/\1/p' "$IG/pass" 2> /dev/null)") && echo $((na - 600))
}
ig_look(){ # <address> → ig_api GET of a box from this box's server (GET /v1/<address>), with no pass: the read is public, and a server reads none on it (PROTOCOL.md §4.1)
  ig_api GET "/v1/$1"
}
ig_clock(){ # after a call the server refused: if it refused the pass, or a prekey statement, for its time, says what the server dates its answer and what this machine's clock reads. A new pass does not cure that, so it is nearly always a clock. The date is the server's word: a clock set by a server's lie makes an ended certificate valid again, so this sends its reader to a time source of their own
  local d; case $(ig_code) in pass_expired | prekey_time) ;; *) return 0 ;; esac
  d=$(ig_dated) && d="the server dates its answer $d, and "
  ig_err "${d}this machine's clock reads $(jq -nr --argjson t "$(ig_now)" '$t | todate'). A server refuses a pass from a clock 10 minutes or more behind its own, or more than 50 ahead, a certificate made by a clock more than 50 ahead, and a prekey statement dated more than an hour ahead of it. Check this machine's clock against a time source you trust, not against the server"
}
ig_server(){ # <URL> → the server's name, as a pass names it: the URL's host, lowercase, and its port only when that is not the scheme's default, as an origin is written (PROTOCOL.md §6.1b): the port as a number, and none for https on 443 or http on 80. A user and an @ before the host are no part of it, as Go's url.Parse has it
  local s=${1%%://*} h=${1#*://} p=
  h=${h%%[/?#]*}; h=${h##*@}; h=${h,,}
  if [[ $h =~ ^(.*):([0-9]*)$ ]]; then h=${BASH_REMATCH[1]}; p=${BASH_REMATCH[2]}; fi      # an IPv6 address ends in ], so a colon there begins no port
  [ -z "$p" ] || { p=$((10#$p)); case ${s,,}:$p in https:443 | http:80) ;; *) h+=:$p ;; esac; }
  echo "$h"
}
ig_here(){ # <URL> [localhost] → 0 when the URL's host is this machine by its address, an IPv4 address in 127.0.0.0/8 or [::1], and with localhost, that name too. Other spellings of an IPv6 loopback address are read as no address of this machine
  local h=${1#*://}; h=${h%%[/?#]*}; h=${h##*@}; h=${h,,}
  [[ $h =~ ^(.*):[0-9]*$ ]] && h=${BASH_REMATCH[1]}      # an IPv6 address ends in ], so a colon there begins no port
  [[ $h = '[::1]' || $h =~ ^127(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$ || ( ${2-} = localhost && $h = localhost ) ]]
}
ig_tls(){ # <URL> → 0 when it is a server this box may call: https, or http only to a server on this machine, by its address: an IPv4 address in 127.0.0.0/8, or [::1]. A name is not, since localhost is what a resolver says it is (RFC 8252 §8.3), so that a pass, or the address a lookup asks about, never crosses a network in the clear (PROTOCOL.md §0). Otherwise a refusal, and 1
  [[ ${1,,} = https://?* ]] || { [[ ${1,,} = http://?* ]] && ig_here "$1"; } ||
    ig_refuse "$(printf '%.80s' "$1") is not a server this client calls: one is https, or http only to this machine, by its address (127.0.0.0/8, ::1)"
}
ig_pass(){ # [serial] → the Authorization value of a call as this box, unless it holds its own revocation (ig_finished). Without a serial: the pass kept in $IG/pass while it has more than 30 seconds left and no more than the ten minutes it was signed for, otherwise a new one, signed by the working key in use and kept. With one: a pass signed by that working key, for the call that publishes its prekey, left in $IG/pass.new until the server has taken it
  local A n=${1-} na h; A=$(cat "$IG/address") || return 1
  ig_finished || { ig_done $?; return 1; }
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
ig_lock(){ # <command> [args] → runs that ig_ command with $IG/lock, the box's lock, held, once the box's directories and identity files are made (ig_dirs, ig_identity), as the Go client's Open makes them: so a box restored from its identity alone runs. Every command that writes the box runs so, from start to end, so one runs at a time and none reads a file another is writing. While another holds it, says so once and waits up to $IG_LOCK_WAIT seconds. If the command dies, the shell's EXIT trap removes it; a kill -9 leaves it behind
  local end=$((SECONDS + IG_LOCK_WAIT)) said= me=$IG outer=${IG_HELD-} trap rc
  [ -s "$IG/identity" ] || { ig_refuse "no box in $IG: run init first"; return 1; }
  ig_ownbox || return 1
  until mkdir "$me/lock" 2> /dev/null; do
    [ -n "$said" ] || { jq -cn '{type:"waiting", for:"lock", message:"waiting for this box'"'"'s lock: another command of this box is running, and a box'"'"'s commands write its files one at a time"}' >&2; said=1; }
    [ "$SECONDS" -lt "$end" ] || { ig_refuse "another command of this box held its lock, $me/lock, for as long as a command waits for it. If none is running, one that crashed left it behind: remove it"; return 1; }
    sleep 1
  done
  trap=$(trap -p EXIT); IG_HELD=$me; trap 'rmdir "$IG_HELD/lock" 2> /dev/null' EXIT
  ig_dirs && ig_identity && "$@"; rc=$?
  rmdir "$me/lock"; IG_HELD=$outer; eval "${trap:-trap - EXIT}"; return $rc      # and the caller's own EXIT trap back
}
ig_ownbox(){ [ ! -e "$IG/state" ] || ig_refuse "$IG holds a state file: it is a box of the Go client, which this script never runs, since the two keep their records apart and would undo each other's: set IG_HOME to a directory of this script's own"; }      # whether $IG is a box of this script's, by the one file only the Go client makes
ig_held(){ [ "${IG_HELD-}" = "$IG" ]; }      # whether this shell holds this box's lock: a command another command runs works under its caller's
ig_dirs(){ mkdir -p "$IG/work" "$IG/prekeys" "$IG/peers" "$IG/inbox" "$IG/quarantine" "$IG/sent"; }      # the box's directories, made where they are missing, as the Go client's Open makes them: by init, and by every command that writes the box (ig_lock)
ig_identity(){ # → identity.pub, identity.doc and address, the identity as the box's other files name it: identity.pub made again from the identity where it is missing or empty, then the document and its SHA-256, each written beside and moved into place only where its bytes differ (ig_put), as the Go client's Open writes them. So a box restored from its identity alone gets all three, init run again rewrites nothing a command beside it reads, and a crash leaves no file empty
  local a
  [ -s "$IG/identity.pub" ] || { ssh-keygen -y -f "$IG/identity" < /dev/null > "$IG/id.pub" && ig_put "$IG/id.pub" "$IG/identity.pub"; } || ig_refuse "ssh-keygen cannot read this box's identity, $IG/identity, to make identity.pub" || return 1
  printf 'irongall-v1\n%s\n' "$(cut -d' ' -f1,2 "$IG/identity.pub")" > "$IG/id.doc" || return 1
  cmp -s "$IG/id.doc" "$IG/identity.doc" || { { ig_idcheck "$IG/id.doc"; [ $? != 1 ]; } || ig_refuse "this box's identity.pub is not a key an identity document holds: $IG/identity.pub" || return 1; ig_put "$IG/id.doc" "$IG/identity.doc" || return 1; }      # checked before it is written: a document out of form, from an identity.pub that is, would give the box another address
  a=$(sha256sum < "$IG/id.doc" | cut -c1-64) && rm -f "$IG/id.doc" "$IG/id.pub" || return 1
  printf '%s\n' "$a" | cmp -s - "$IG/address" || ig_putline "$IG/address" "$a"
}

# recipe: keys and registration
ig_work(){ # <serial> → work/<serial>, .pub and -cert.pub: a NEW working key, and the certificate this box's identity gives it, with that serial, good from an hour ago for 65 days. The working key signs what the box says; the identity signs certificates and nothing else
  local A w="$IG/work/$1" t; A=$(cat "$IG/address") || return 1; mkdir -p "$IG/work" || return 1
  [ -s "$w" ] && [ -s "$w-cert.pub" ] && return 0
  rm -f "$w" "$w.pub" "$w-cert.pub"; t=$(ig_now)
  ssh-keygen -q -t ed25519 -N '' -C '' -f "$w" < /dev/null &&
  ssh-keygen -q -s "$IG/identity" -I irongall-cert-v1 -n "$A" -z "$1" -V "$(ig_stamp $((t - 3600))):$(ig_stamp $((t + 65*86400)))" -O clear "$w.pub"      # one principal, the address; no option and no extension. It starts an hour back, as -V -1h:+65d dates one, so that a verifier whose clock is behind this one takes it at once
}
ig_lifetime(){ # → the seconds each new prekey of this box is valid for: what its prekey-lifetime file names, a number of seconds alone on its line from 97200 (a day and three hours) to 2851200 (33 days), or 2851200 when it has none. A file that names anything else is a refusal, never the default: no prekey is signed until it is put right (PROTOCOL.md §6.4)
  local l; [ -e "$IG/prekey-lifetime" ] || { echo 2851200; return 0; }
  l=$(cat "$IG/prekey-lifetime" 2> /dev/null) && [[ $l =~ ^[1-9][0-9]{0,9}$ ]] && { printf '%s\n' "$l" | cmp -s - "$IG/prekey-lifetime" || printf '%s' "$l" | cmp -s - "$IG/prekey-lifetime"; } && [ "$l" -ge 97200 ] && [ "$l" -le 2851200 ] && echo "$l" ||      # compared with itself rebuilt: $(…) drops line feeds and NULs
    ig_refuse "this box's prekey-lifetime file names no lifetime: one is a number of seconds, alone on its line, from 97200 (a day and three hours) to 2851200 (33 days)"
}
ig_prekey(){ # <serial> [--no-pq] → prekeys/<serial>.agekey and its statement, signed by a NEW working key (ig_work): a NEW key, valid for the box's prekey lifetime (ig_lifetime), and prekeys/<serial>.made, when it was signed: a statement an earlier attempt left is sent again only while it was made for no longer than the box's lifetime (ig_renew). A re-run reuses the key a failed attempt left, whatever its type, unless it is empty
  local A p="$IG/prekeys/$1" l t k; A=$(cat "$IG/address") || return 1
  [ -s "$p.txt.sig" ] && return 0
  ig_finished || { ig_done $?; return 1; }      # the one path to this box's certificates and statements: a box that holds its own revocation makes neither, init and prekey renew alike
  l=$(ig_lifetime) || return 1
  [ -s "$p.agekey" ] || { rm -f "$p.agekey"; if [ "${2-}" = --no-pq ]; then age-keygen -o "$p.agekey"; else age-keygen -pq -o "$p.agekey"; fi 2> /dev/null; } || ig_refuse "age-keygen failed: post-quantum needs age >= 1.3 (or make a box with --no-pq)" || return 1      # an empty key file, as a crash before the sync below leaves one, is no key, and no statement names it, so it is made again, as the Go client does
  k=$(age-keygen -y "$p.agekey" 2> /dev/null) || ig_refuse "age-keygen cannot read $p.agekey, the key this box began prekey $1 with (a post-quantum one needs age >= 1.3)" || return 1      # never a statement with no key in it, which a server refuses at every try
  ig_work "$1" && t=$(ig_now) || return 1
  printf 'irongall-prekey-v1\n%s\n%s\n%s\n%s\n' "$A" "$1" "$k" "$(jq -nr --argjson t "$t" --argjson l "$l" '$t + $l | todate')" > "$p.txt" &&
  jq -nr --argjson t "$t" '$t | todate' > "$p.made" &&      # before the signature: a statement is signed once its record is there
  ssh-keygen -q -Y sign -n "irongall-prekey-v1:$A" -f "$IG/work/$1-cert.pub" < "$p.txt" > "$p.txt.sig" &&      # stdin to stdout: never a stale .sig
  sync "$IG/work/$1" "$IG/work/$1.pub" "$IG/work/$1-cert.pub" "$IG/work" && sync "$p.agekey" "$p.txt" "$p.made" "$p.txt.sig" "$IG/prekeys"      # the working key first, each file in turn: a signed statement is never on disk without the key its pass needs      # on disk before any upload publishes the statement: a key lost to a crash after that is mail nobody can read
}
ig_init(){ # [--no-pq] → creates this box, or finishes a half-done init, and registers it; prints its address and link. The registration carries a pass the new working key signs, so the box is in use at once
  ig_opt "${1-}" || return 1
  ig_ownbox || return 1
  ig_dirs && ig_putline "$IG/.gitignore" '*' || return 1      # the box ignores itself, wherever it is
  [ -s "$IG/identity" ] || { rm -f "$IG/identity" "$IG/identity.pub"; ssh-keygen -q -t ed25519 -N '' -C '' -f "$IG/identity" < /dev/null; } || return 1      # an empty identity, as a crash before the sync below leaves one, is no key, and nothing was registered with it, so it is made again, as the Go client does
  if ig_held; then ig_identity; else ig_lock true; fi && sync "$IG/identity" "$IG/identity.pub" "$IG" || return 1      # identity.doc and address made under the box's lock, as every command that writes the box makes them (ig_lock): a command beside init reads them. The identity on disk before it is registered
  [ ! -s "$IG/serial" ] || { ig_addr; return; }      # registered already
  local A n p h c; A=$(cat "$IG/address")
  n=$(ls "$IG/prekeys" | sed -n 's/\.agekey$//p; s/\.txt\.sig$//p' | sort -n | tail -n 1); [ -n "$n" ] || n=$(ig_now); [ "$n" -ge 1 ] || n=1; p="$IG/prekeys/$n"      # the box's first prekey, working key and certificate take their number as every later one does, from this machine's clock in seconds (ig_renew): a second machine handed the same identity then makes no certificate of a serial this one used. An attempt that got as far as a key keeps the number it took, so a registration whose answer was lost is sent again as it was
  if c=$(ig_cert "$p.txt.sig" "$IG/identity.doc" "$A" 2> /dev/null) && c=${c#* } && [ "${c% *}" -gt $(($(ig_now) - 3600)) ]; then      # a first statement an earlier attempt left, under a certificate that began less than an hour before this machine's clock: made while the clock read ahead of where it reads now, as a pass made then is not used either (PROTOCOL.md §0), so a reader whose clock a server takes may not have reached its start. The working key, its certificate and the statement are made again. The prekey's own key stays: a server may have taken a registration whose answer was lost, and then mail may be waiting that only this key opens
    rm -f "$p.txt" "$p.made" "$p.txt.sig" "$IG/work/$n" "$IG/work/$n.pub" "$IG/work/$n-cert.pub" "$IG/pass.new"
  fi
  ig_prekey "$n" "${1-}" || return 1
  jq -n --arg i "$(ig_b64 "$IG/identity.doc")" --arg p "$(ig_b64 "$p.txt")" --arg s "$(ig_b64 "$p.txt.sig")" --argjson k "$(ig_senders)" '{identity:$i, prekey:$p, prekey_signature:$s, sender_key_types:$k}' > "$IG/register.json"
  h=$(ig_pass "$n") && { ig_api PUT "/v1/$A" "$IG/register.json" -H "Authorization: $h" > /dev/null || { ig_clock; ig_own; false; }; } && mv "$IG/pass.new" "$IG/pass" && ig_putline "$IG/serial" "$n" && ig_addr
}
ig_addr(){ local a; ig_held || { [ -s "$IG/identity" ] && [ -s "$IG/address" ]; } || { ig_lock ig_addr; return; }; a=$(cat "$IG/address") && ig_out box --arg address "$a" --arg link "$IG_BASE/to/$a"; }      # the box's address and its link: what to give whoever should write to it. Read with no lock; with no box, ig_lock's refusal, and a box restored from its identity alone has its files made under the lock first (ig_identity), as the Go client's Open makes them
ig_dest(){ # <link or address> → the address: 64 hex, or taken from a link to this box's server, $IG_BASE/to/<address>
  local a=${1#"$IG_BASE/to/"}
  ig_hex "$a" && { echo "$a"; return 0; }
  [[ $1 != *://* || $1 = "$IG_BASE/"* ]] || { ig_refuse "a link to another server: this box's server is $IG_BASE"; return 1; }
  ig_refuse "not an address or a link to one: $1"
}

# recipe: verify a peer
ig_keycheck(){ # <32 bytes in hex> → 0 only for an Ed25519 key that is a canonical point, not of small order
  [[ $1 =~ ^[0-9a-f]{64}$ && ! $1 =~ ^(e[d-f]|f[0-9a-f])(ff){30}(7f|ff)$ ]] || return 1      # y >= p: not canonical
  case $1 in      # the eight points of small order, and the two with x = 0 marked negative
    0100000000000000000000000000000000000000000000000000000000000000 | 0100000000000000000000000000000000000000000000000000000000000080 | \
    ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f | ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff | \
    0000000000000000000000000000000000000000000000000000000000000000 | 0000000000000000000000000000000000000000000000000000000000000080 | \
    26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05 | 26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85 | \
    c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a | c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa) return 1 ;;
  esac
  age -r "ssh-ed25519 $(printf "$(printf %s "0000000b$(ig_asc ssh-ed25519)00000020$1" | sed 's/../\\x&/g')" | base64 | tr -d '\n')" < /dev/null > /dev/null 2>&1      # a point on the curve: age decodes the key as the Go client's edwards25519 does, and refuses 32 bytes that are no point, which ssh-keygen reads as a key
}
ig_idcheck(){ # <identity document> [address] → 0 only for a two-line document whose key is in its one encoding and passes its type's checks (and hashing to the address, given one). 2 for a well-formed document of a key type this script does not verify: nothing is wrong with it, and nothing it signed can be checked here. 1 for anything else
  local f=$1 l t fp
  l=$(sed -n 2p "$f"); t=${l%% *}
  [ "$(printf 'irongall-v1\n%s\n' "$l" | sha256sum)" = "$(sha256sum < "$f")" ] || return 1      # exactly the tag line and one more, each ending in LF, and not a byte else: the file against itself rebuilt from its second line. A shell variable drops a NUL, so a test of the variable alone would pass a file that holds one
  [ -z "${2-}" ] || [ "$(sha256sum < "$f" | cut -c1-64)" = "$2" ] || return 1
  # the form every type shares: a key type's name (printable ASCII with no comma, at most 64 characters), one space, and the base64, in its one encoding, of a wire key that begins with that name
  grep -Eqx '[!-+.-~-]{1,64} [A-Za-z0-9+/]+={0,2}' <<< "$l" && [ "$(printf %s "${l#* }" | base64 -d 2> /dev/null | base64 | tr -d '\n')" = "${l#* }" ] &&
    [ "$(printf %s "${l#* }" | base64 -d | head -c $((4 + ${#t})) | od -An -v -tx1 | tr -d ' \n')" = "$(printf %08x "${#t}")$(ig_asc "$t")" ] || return 1
  case $t in ssh-ed25519 | ecdsa-sha2-nistp256) ;; *) return 2 ;; esac
  # the key in its one encoding: ssh-keygen reads it, and its fingerprint, the SHA-256 of the key as OpenSSH writes it back, is the SHA-256 of these bytes. ssh-keygen refuses a P-256 point off the curve, compressed, at infinity or with a coordinate not below the field's size, which is all a P-256 key is held to (PROTOCOL.md §2). Up to 10.2p1 it also refuses one with a coordinate of 128 bits or fewer, or of the group's order less one or more, which the protocol takes: a known variance (PROTOCOL.md §3)
  fp=$(ssh-keygen -l -E sha256 -f - <<< "$l" 2> /dev/null | awk '{print $2}') && fp=${fp#SHA256:} && [ -n "$fp" ] &&
    [ "$(printf '%s=' "$fp" | base64 -d | od -An -v -tx1 | tr -d ' \n')" = "$(printf %s "${l#* }" | base64 -d | sha256sum | cut -c1-64)" ] || return 1
  case $t in      # then the type's own checks: an Ed25519 key canonical and not of small order
    ssh-ed25519) ig_keycheck "$(printf %s "${l#* }" | base64 -d | tail -c 32 | od -An -v -tx1 | tr -d ' \n')" ;;
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
ig_s(){ # <an SSH signature in hex: its type as a string, then its bytes as one> → 1 only for an Ed25519 signature that is not 64 bytes, or whose S is not below the group's order L: such a signature is invalid (RFC 8032 §5.1.7), and ssh-keygen before the cut PROTOCOL.md §3 gives takes one with L added to S. Its type may end in one NUL, as OpenSSH reads it. 0 for any other, which ssh-keygen judges
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
  local p=$1 B=$3 s k na c L
  c=$(ig_certified "$B" "$4" "irongall-prekey-v1:$B" "$2" "$p" ${5-}); case $? in 0) ;;
    2) echo "$B's prekey: the certificate the prekey is signed under has ended"; return 1 ;;
    3) echo "$B's prekey: the certificate the prekey is signed under has not begun, by the clock that checked it"; return 1 ;;
    *) echo "$B's prekey is not signed by a working key its identity certified, under a certificate that holds now"; return 1 ;;
  esac
  mapfile -t L < "$p"
  [ "$(printf '%s\n' "${L[@]}" | sha256sum)" = "$(sha256sum < "$p")" ] && [ ${#L[@]} -eq 5 ] && [ "${L[0]}" = irongall-prekey-v1 ] && [ "${L[1]}" = "$B" ] ||      # the file against itself rebuilt from its lines: every line ends in LF, and nothing is in it that a shell variable drops (a NUL)
    { echo "the prekey statement is not $B's: five lines, each ending in LF"; return 1; }
  s=${L[2]}; [[ $s =~ ^[1-9][0-9]{0,15}$ ]] && [ "$s" -le 9007199254740991 ] || { echo "$B's prekey serial is malformed"; return 1; }      # from 1 to 2^53 - 1, as every serial is written
  na=$(ig_time "${L[4]}") || { echo "$B's prekey has no valid not_after"; return 1; }
  [ "$na" -le "${c#* }" ] || { echo "$B's prekey statement outlives the certificate it is signed under"; return 1; }
  k=${L[3]}
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
      ig_refuse "the server's answer for $B is not one this client reads: one JSON object, each byte field base64" || return 1
    ig_take "$B"; [ $? != 3 ] || ig_refuse "what this box keeps about $B does not verify, or could not be written" || return 1
  fi
  ig_shape "$IG/peer.json" box && ig_bytes "$IG/peer.json" identity "$IG/new.doc" && ig_bytes "$IG/peer.json" prekey "$IG/peer.txt" && ig_bytes "$IG/peer.json" prekey_signature "$IG/peer.sig" ||
    ig_refuse "the server's answer for $B is not one this client reads: one JSON object, each byte field base64" || return 1
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
  ig_meet "$B" "$f" && ig_putline "$d/serial" "$s" && ig_putline "$d/cert-serial" "$c" && ig_put "$IG/peer.txt" "$d/prekey.txt" && ig_put "$IG/peer.sig" "$d/prekey.sig" || return 1      # recorded only after every check passed
  echo "$s $k $c"
}
ig_put(){ local d; d=$(dirname "$2") && cp "$1" "$2.new" && sync "$2.new" && mv "$2.new" "$2" && sync "$d"; }      # <file> <path> → <path> holds the file's bytes, on disk before this returns: written beside it, synced, moved into place, and its directory synced, as the Go client's writeFile does. A crash leaves the old file or the new one, never an empty one
ig_putline(){ local d; d=$(dirname "$1") && printf '%s\n' "$2" > "$1.new" && sync "$1.new" && mv "$1.new" "$1" && sync "$d"; }      # <path> <value> → ig_put of the value alone on its line
ig_putout(){ local d; d=$(dirname "$1") && "${@:2}" > "$1.new" && sync "$1.new" && mv "$1.new" "$1" && sync "$d" || { rm -f "$1.new"; return 1; }; }      # <path> <command> [args] → ig_put of what the command prints: a command that fails or is stopped midway leaves no file cut short
ig_meet(){ local d="$IG/peers/$1"; mkdir -p "$d" && { [ -e "$d/identity.doc" ] || ig_put "$2" "$d/identity.doc"; }; }      # <address> <its checked identity document> → pinned, unless it is already: called only for an identity that signed something this box verified

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
  ig_b64 "$2" > "$f.i" && ig_b64 "$3" > "$f.l" && ig_b64 "$4" > "$f.g" && jq -cn --rawfile i "$f.i" --rawfile l "$f.l" --rawfile g "$f.g" '{type:"revocation_record", identity:$i, revoked_certificates:$l, revoked_certificates_signature:$g}' > "$f.new" && sync "$f.new" && mv "$f.new" "$f" && sync "$(dirname "$f")" && rm -f "$f.i" "$f.l" "$f.g"      # one file, moved into place whole and on disk before anything reads it: a statement is never kept without the signature that goes with it
}
ig_keep(){ # <address> <its identity document> <signature> → the revocation, kept for good: called only once ig_revcheck took it. A revoked address stays revoked
  if [ "$1" = "$(cat "$IG/address" 2> /dev/null)" ]; then ig_put "$3" "$IG/revoked.sig"; else ig_meet "$1" "$2" && ig_put "$3" "$IG/peers/$1/revoke.sig"; fi
}
ig_record(){ # <record> → the address it is a revocation of, only if it verifies; its parts are left in $IG/rev.doc and $IG/rev.sig. A record is one line of JSON, {type, identity, revocation_signature}: its type, revocation_record, which this script does not read, then the identity document and the signature, each base64
  local A
  ig_isrecord "$1" && ig_bytes "$1" identity "$IG/rev.doc" && ig_bytes "$1" revocation_signature "$IG/rev.sig" || return 1
  A=$(sha256sum < "$IG/rev.doc" | cut -c1-64) && ig_revcheck "$A" "$IG/rev.doc" "$IG/rev.sig" && echo "$A"
}
ig_isrecord(){ # <file> → 0 only for a record: an answer ig_shape takes as a record, and each of its four byte members base64, or left out. What it holds is checked by whoever uses it
  local m r=0
  ig_shape "$1" record || return 1
  for m in identity revocation_signature revoked_certificates revoked_certificates_signature; do ig_bytes "$1" $m "$IG/record.part" || { r=1; break; }; done
  rm -f "$IG/record.part"; return $r
}
ig_isbox(){ # <file> → 0 only for a box: an answer ig_shape takes as a box, and each of its byte members base64, or left out. What it holds is checked by whoever uses it
  local m r=0
  ig_shape "$1" box || return 1
  for m in identity prekey prekey_signature revoked_certificates revoked_certificates_signature; do ig_bytes "$1" $m "$IG/box.part" || { r=1; break; }; done
  rm -f "$IG/box.part"; return $r
}
ig_take(){ # <address> → keeps what verifies of $IG/rev.json, a server's answer about the address: a revocation of its certificates, of the address, or both. 0: this box now holds a revocation of the address. 1: it does not: what the answer showed of one does not verify, which counts as nothing shown. 3: a fault of this box
  if ig_bytes "$IG/rev.json" identity "$IG/rev.doc" && ig_bytes "$IG/rev.json" revoked_certificates "$IG/rev.certs" && [ -s "$IG/rev.certs" ] &&
    ig_bytes "$IG/rev.json" revoked_certificates_signature "$IG/rev.csig"; then      # a revocation of certificates rides in the same record. It is taken or not on its own: the address may well go on
    ig_keepcerts "$1" "$IG/rev.doc" "$IG/rev.certs" "$IG/rev.csig" || return 3
  fi
  [ "$(ig_record "$IG/rev.json")" = "$1" ] || return 1
  ig_keep "$1" "$IG/rev.doc" "$IG/rev.sig" || return 3
}
ig_lookup(){ # <address> → reads the address's box from this box's server (GET /v1/<address>, ig_look), and keeps what verifies of the revocations it carries. A box served carries the revocation of its certificates the server holds, and a revoked address is answered 410 revoked with its record. The box served is left in $IG/box.json, for the seal that follows. 0: this box holds a revocation of the address, and that is final. 1: none: the server served the box, or holds no such box, or said revoked and showed nothing that verifies, which comes to the same: only the identity's own signature revokes. 2: no answer from the box's own server, which is not "none". 3: a fault of this box: what it keeps for the address does not verify, or cannot be written
  local r
  rm -f "$IG/box.json"
  ig_gone "$1"; case $? in 0) return 0 ;; 3) return 3 ;; esac
  if ig_look "$1" > "$IG/look.json" 2> "$IG/read.err"; then ig_isbox "$IG/look.json" || return 2; mv "$IG/look.json" "$IG/box.json"      # a 2xx that is no box is no answer, as one that is no JSON is
    jq -c '{identity, revoked_certificates, revoked_certificates_signature}' "$IG/box.json" > "$IG/rev.json" && ig_take "$1"; r=$?; [ $r = 1 ] || return $r
  else case $(ig_code) in
    revoked) ig_takerecord "$1"; r=$?; [ $r = 1 ] || return $r ;;      # the record it carries proves itself, or counts as nothing shown
    no_such_mailbox) ;;
    *) cat "$IG/read.err" >&2; return 2 ;; esac; fi      # no answer: its error line, the status, the code and the wait, and none of the server's words
  return 1
}
ig_takerecord(){ # <address> → keeps what verifies of the record a 410 revoked carries, in $IG/error.json: ig_take's answer, or 1 where it carries no record
  jq -ce '.record | objects' "$IG/error.json" > "$IG/rev.json" 2> /dev/null && ig_isrecord "$IG/rev.json" || return 1
  ig_take "$1"
}
ig_finished(){ # → 0 while this box may act as its address. 1: it holds its own revocation, which verifies, and signs nothing more as that address, no pass, no mail and no certificate, whatever any server answers: a server that never saw the revocation would take it all (PROTOCOL.md §6.3). It still asks, keeps and publishes the record, which carry no pass. 3: the one it keeps does not verify, a fault of this box, which stops the same
  ig_gone "$(cat "$IG/address" 2> /dev/null)"; case $? in 1) return 0 ;; 0) return 1 ;; *) return 3 ;; esac
}
ig_done(){ # <what ig_finished returned> → says on stderr why this box acts as its address no more
  case $1 in
    1) ig_err "REVOKED: this box's own address is revoked, for good, and the revocation verifies. It can send and receive nothing more: make a new box and give its address to those who write to this one" ;;
    *) ig_refuse "this box's own revocation (revoked.sig) does not verify: a fault of this box, which acts as its address no more until it is put right" ;;
  esac
  return 1
}
ig_own(){ # after a call as this box failed: if the server said this box is revoked, asks it for the revocation, and says which it is. A server's word revokes nothing
  [ "$(ig_code)" = revoked ] || return 0
  if ig_lookup "$(cat "$IG/address")"; then ig_err "REVOKED: this box's own address is revoked, for good, and the revocation verifies. It can send and receive nothing more: make a new box and give its address to those who write to this one"
  else ig_err "the server showed no revocation of this box that verifies, so this box does not take itself as revoked"; fi
}

# recipe: send
ig_uuid(){ local h; h=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n'); printf '%s-%s-4%s-%x%s-%s\n' "${h:0:8}" "${h:8:4}" "${h:13:3}" $(( 0x${h:16:1} & 3 | 8 )) "${h:17:3}" "${h:20:12}"; }
ig_send(){ # <link or address> [body file] → one message, posted now or not at all: its envelope built once, then sealed and posted (ig_post), and nothing kept to post again. A send that fails says so and leaves nothing: run it again, and if the first post's answer was lost its reader gets two messages, under two msg_ids
  ig_held || { ig_lock ig_send "$@"; return; }
  local B f A id
  f=${2-}; A=$(cat "$IG/address") && B=$(ig_dest "${1-}") || return 1
  { if [ -n "$f" ]; then cat < "$f"; else cat; fi; } > "$IG/body.new" 2> /dev/null && mv "$IG/body.new" "$IG/body.txt" || { rm -f "$IG/body.new"; ig_err "the body${f:+ file $f} could not be read: nothing is sent"; return 1; }; f="$IG/body.txt"      # read ONCE, from the file named or stdin, into a new file moved into place: every check below and the envelope read these bytes, so a body from a pipe is sent, one changed after its check is not, and a body named $IG/body.txt is not emptied before it is read
  iconv -f UTF-8 -t UTF-8 < "$f" > /dev/null 2>&1 || ig_refuse "the body is not UTF-8 text" || return 1
  id=$(ig_uuid) || return 1
  jq -cn --arg from "$A" --arg to "$B" --arg id "$id" --argjson t "$(ig_now)" --arg i "$(ig_b64 "$IG/identity.doc")" --rawfile body "$f" \
    '{v:1, from:$from, to:$to, sent_at:($t|todate), msg_id:$id, identity:$i, body:$body}' > "$IG/send.P" 2> /dev/null || { rm -f "$IG/send.P"; ig_err "the envelope could not be built: nothing is sent"; return 1; }      # ONE line, ending in a line feed: exactly the bytes that are signed. It carries this box's identity document, so its reader need not ask the server who wrote it
  why=$(ig_envcheck "$IG/send.P" "$A" "$B") || { rm -f "$IG/send.P"; ig_refuse "nothing is sent, since its reader would refuse this message: ${why#*: }"; return 1; }      # read back as its reader will, and as ig_seal does
  ig_post "$B" "$IG/send"; local rc=$?; rm -f "$IG/send.P"; return $rc
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
ig_seal(){ # <address> <envelope stem> [the box ig_lookup read] → what to post: $IG/seal.age, the envelope <stem>.P dated at this post ($IG/seal.P: its sent_at this clock, and nothing else changed, as a signed request's time is when it was signed, made anew for each attempt), signed for that recipient only, by the working key in use, then the line, the signature and the padding encrypted to the recipient's VERIFIED prekey; and $IG/seal.query, the query that names that prekey. It is git's layout for a signed tag: the signed bytes as they are, then the signature block. The envelope is read as its recipient will read it first. A seal is made for one post and never kept: ig_post seals the envelope again for its one retry
  local B=$1 o=$2 s="$IG/seal" A r k n f t c why ps pc d; rm -f "$s.P" "$s.sig" "$s.age" "$s.query"; A=$(cat "$IG/address") && n=$(cat "$IG/serial") || return 1
  why=$(ig_envcheck "$o.P" "$A" "$B") && [ "$(wc -l < "$o.P")" -eq 1 ] && [ "$(jq -r .identity "$o.P")" = "$(ig_b64 "$IG/identity.doc")" ] || ig_refuse "the envelope is not one this box made for that address${why:+: $why}" || return 1
  d=$(jq -nr --argjson t "$(ig_now)" '$t | todate') && jq -c --arg d "$d" '.sent_at = $d' "$o.P" > "$s.P" || return 1      # written again by jq, as ig_send wrote it: the script seals only an envelope it has just built
  why=$(ig_envcheck "$s.P" "$A" "$B") && [ "$(wc -l < "$s.P")" -eq 1 ] && jq -e --arg d "$d" --slurpfile w "$o.P" '.sent_at == $d and del(.sent_at) == ($w[0] | del(.sent_at))' "$s.P" > /dev/null 2>&1 ||
    ig_refuse "the envelope does not read back as itself once dated at this post${why:+: $why}" || return 1
  c=$(ig_cert "$IG/prekeys/$n.txt.sig" "$IG/identity.doc" "$A") && [ $((${c##* } - $(ig_now))) -gt $((33*86400)) ] ||      # the certificate in use: the one this box's published prekey is signed under
    ig_refuse "this box's certificate ends within 33 days, too soon to sign mail that may wait that long (or it has no working key): rekey makes a new one" || return 1
  ig_certrevoked "$A" "${c%% *}"; case $? in      # a certificate this box's own identity has revoked signs no mail: every reader that holds the revocation refuses it, whatever this box's server took. That is the remedy's window while its renewal waits (PROTOCOL.md §6.3a): the entry waits too
    0) ig_refuse "this box's identity has revoked the certificate it signs under, so mail signed now would be refused: prekey renew publishes the new one first"; return 1 ;;
    1) ;;
    *) ig_refuse "this box's own revocation of its certificates does not verify"; return 1 ;;
  esac
  r=$(ig_resolve "$B" "${3-}") && read -r ps k pc <<< "$r" && [ -n "$pc" ] || return 1
  ssh-keygen -q -Y sign -n "irongall-msg-v1:$B" -f "$IG/work/$n-cert.pub" < "$s.P" > "$s.sig" && tail -n 1 "$s.sig" | cmp -s - <(printf -- '-----END SSH SIGNATURE-----\n') ||
    ig_refuse "the working key did not sign the message whole: nothing is sent" || return 1      # ssh-keygen does not check its write to stdout: a full disk leaves the file short and exits 0
  read -r f t <<< "$(ig_padding $(($(wc -c < "$s.P") + $(wc -c < "$s.sig"))) "$k")" && [ -n "$t" ] || return 1
  { cat "$s.P" "$s.sig" && head -c "$f" /dev/zero | tr '\0' .; } | age -r "$k" > "$s.age" || return 1
  [ "$(wc -c < "$s.age")" -eq "$t" ] || { rm -f "$s.age"; ig_refuse "the encrypted message is not the $t bytes its padding was made for: it is not sent at a size that tells its length"; return 1; }
  printf 'prekey_serial=%s&certificate_serial=%s\n' "$ps" "$pc" > "$s.query"      # the prekey is named by both serials, its own and its certificate's, written as the digits ig_resolve checked. The body is the age file as it is, and no signature is beside it: the server knows the sender from the pass the post carries
}
ig_post(){ # <address> <envelope stem> → seals it and POSTs it; on 409 stale_prekey, seals the SAME envelope again, once, to the box read again. Before each seal, the recipient's box is read (ig_lookup), and the seal is made to what this box then holds, dated after that read. A post that fails is told, and nothing is kept
  local B=$1 o=$2 c try
  ig_finished; case $? in      # a box that holds its own revocation can never deliver it: every reader that holds the revocation refuses its mail, whenever it was signed
    0) ;;
    1) ig_err "REVOKED: this box's own address is revoked, for good, and the revocation verifies, so its mail can never be delivered: nothing is sent"; return 1 ;;
    *) ig_done 3; return 1 ;;
  esac
  for try in first retry; do
    rm -f "$IG/error.json"
    ig_lookup "$B"; case $? in      # asked before every post, the retry's included: what verifies is kept, and "none held" is the server's word, kept nowhere
      0) ig_err "REVOKED: $B is revoked, for good, and the revocation verifies, so it can never be delivered: nothing is sent"; return 1 ;;
      1) rm -f "$IG/error.json" ;;      # its 404 is an answer, and not one about the message
      2) rm -f "$IG/error.json"; ig_err "the box $B could not be read, so nothing is sent"; return 1 ;;      # no answer is not "none held". Whatever code the failed lookup carried is no answer about the message
      *) ig_refuse "what this box keeps about $B does not verify, or could not be written: nothing is sent"; return 1 ;;
    esac
    ig_seal "$B" "$o" "$IG/box.json" && ig_owner POST "/v1/$B/messages?$(cat "$IG/seal.query")" "$IG/seal.age" > "$IG/receipt.json" && ig_receipt && { ig_sent "$B"; return; }      # sealed to the box the lookup read, and dated once it was read
    [ "$try" = first ] && [ "$(ig_code)" = stale_prekey ] || break      # a newer prekey: the same envelope, sealed again once, to the box read again
  done
  c=$(ig_code)
  case $c in revoked) ig_lookup "$B" ;; sender_revoked) ig_lookup "$(cat "$IG/address")" ;; esac      # a server's "revoked" is checked: with the revocation in hand it is final, and without one it is a call that failed
  if ig_gone "$B" || ig_gone "$(cat "$IG/address")"; then ig_err "REVOKED: the revocation verifies, so it can never be delivered: nothing is sent"; return 1; fi
  case $c in
    revoked | sender_revoked) ig_err "the server showed no revocation that verifies, so this box does not take that address as revoked: nothing is sent" ;;
    *) ig_err "nothing is sent" ;;
  esac
  return 1
}
ig_receipt(){ # → 0 only for a receipt in $IG/receipt.json that names the ciphertext this box posted, $IG/seal.age (its id the SHA-256 of it, PROTOCOL.md §4.5), and whose times are times. Anything else is no receipt, and nothing is recorded as sent
  ig_shape "$IG/receipt.json" receipt && jq -e --arg h "$(sha256sum < "$IG/seal.age" | cut -c1-64)" '.id == $h and all(.received_at, .expires_at; test("\\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\\z"))' "$IG/receipt.json" > /dev/null 2>&1 &&      # compared in jq: $(…) drops trailing LFs and every NUL, so a time is held to its form there before ig_time reads it
    ig_time "$(jq -r '.received_at | strings' "$IG/receipt.json")" > /dev/null && ig_time "$(jq -r '.expires_at | strings' "$IG/receipt.json")" > /dev/null && return 0
  ig_refuse "the server's receipt does not name the ciphertext this box posted, or its times are not times: it is not recorded as sent"
}
ig_sent(){ # <address> → sent/<address>.<msg_id>.json, one line, {"envelope":…,"receipt":…}: the envelope as the post that was taken dated and signed it ($IG/seal.P), as the recipient's inbox/ keeps it, and the server's receipt; and a sent line: the server's id, the msg_id and the address, both from the envelope posted. sent/ is yours to prune
  local m t; m=$(jq -r .msg_id "$IG/seal.P") && t="$IG/sent/$1.$m.json" || return 1
  mkdir -p "$IG/sent" && ig_putout "$t" ig_line "$IG/seal.P" "$IG/receipt.json" || { ig_err "sent, but not recorded in sent/"; return 1; }
  ig_out sent --arg id "$(jq -r .receipt.id "$t")" --arg msg_id "$m" --arg to "$1"
}

# recipe: receive
ig_recv(){ # drains the box, every page up to a drain's limits. ACCEPT → inbox/ and a mail line on stdout. REFUSED → quarantine/, never delivered, and a refused line on stdout. Both are acked
  ig_held || { ig_lock ig_recv "$@"; return; }
  IG_LISTED=; ig_drain; local rc=$?; [ -z "$IG_LISTED" ] || ig_prune "$IG_LISTED"; return $rc      # keys deleted by this clock only once the server has answered the list, so has taken a pass dated by it, and by that pass's date: a clock far ahead is stopped at its pass, one that moves while the list is in flight deletes nothing by where it went, and the keys that mail waits for stay (PROTOCOL.md §0)
}
ig_drain(){ # stops at a transient error or a fault of this box, leaving the rest on the server for the next drain. And at a number of messages and of pages (below): a server that lists mail without end costs one run that much
  local B c="" n i id k=0 pages=0; B=$(cat "$IG/address") || return 1
  ig_finished || { ig_done $?; return 1; }
  rm -f "$IG/asked"      # the senders this drain has asked the server about: one lookup each
  while :; do
    [ $((pages += 1)) -le 100 ] || { ig_out more --arg message "this run stopped at the most one drain takes: run recv again for the rest, which is still on the server"; return 0; }
    ig_owner GET "/v1/$B/messages${c:+?cursor=$c}" > "$IG/list.json" || { ig_own; return 1; }
    [ "$pages" -gt 1 ] || { IG_LISTED=$(ig_taken) && ig_forget "$IG_LISTED"; } || return 1      # the replay set pruned by this clock only once the server has taken a pass dated by it, and by that pass's date (ig_taken): a drain that a clock far off would prune is stopped at its pass first. IG_LISTED tells ig_recv the same reading for the keys
    ig_shape "$IG/list.json" list && n=$(jq -r '.messages | length' "$IG/list.json") || { ig_err "the server's list of messages is not one this client reads: the mail stays on the server"; return 1; }
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
  if ig_owner GET "/v1/$B/messages/$id" "" --max-filesize $((z > 0 ? z : 1)) > "$m.age"; then :      # no more than the list says it holds, and every size up to 16 MiB, the protocol's largest ciphertext, which every reader takes; the list's form holds the size to it (ig_shape; PROTOCOL.md §4.5, §5.1)
  elif [ "$(ig_code)" = no_such_message ]; then return 0      # already gone
  elif [[ $(ig_status) != 2?? ]]; then return 1; fi      # a 2xx that curl cut short is a body past its size
  [ "$(wc -c < "$m.age" 2> /dev/null)" = "$z" ] || { ig_err "the server's answer for message $id is not the $z bytes of ciphertext its list gives: it stays on the server"; return 1; }      # an answer that breaks its form, the server's fault and not the sender's: no verdict, and no ack
  h=$(sha256sum < "$m.age" | cut -c1-64)      # files are named by the hash computed here, never the server's id
  rm -f "$IG/said"; why=$(ig_judge "$B" "$m"); rc=$?; cat "$IG/said" 2> /dev/null; rm -f "$IG/said"      # what the judge met on the way is printed here: its stdout is its verdict
  if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then [ "$h" = "$id" ] || { why="bad_id: the server's id for it is not the SHA-256 of its ciphertext"; rc=1; }; fi
  case $rc in
    0) A=$(jq -r .from "$m.P") && ig_putout "$IG/inbox/$h.json" ig_line "$m.P" && ig_seen "$A" "$m" "$h" || return 1      # stored, then seen, both on disk before the ack: a crash delivers again, never loses
       printf '{"type":"mail","id":"%s","envelope":' "$h" && cat "$IG/inbox/$h.json" && echo '}' ;;      # the envelope the line inbox/ keeps, as its bytes are (jq would write the line breaks ig_line escaped), and only inside "envelope", so a member it gains later never meets the line's own (#356)
    2) ig_out duplicate --arg id "$h" --arg message "a retry of a message already delivered: not delivered again" ;;
    3) ig_err "$why: nothing is judged or acked until this box is fixed"; return 1 ;;
    4) ig_err "$why: the message stays on the server, and the next recv asks again"; return 1 ;;
    *) ig_putout "$IG/quarantine/$h.json" ig_kept "$m" "$h" && ig_putline "$IG/quarantine/$h.reason" "$why" || return 1      # the message as served, its strings in base64 but those of their form, and beside it why: "<code>: <words>", this script's own words, never the message's
       ig_out refused --arg id "$h" --arg code "${why%%: *}" --arg message "${why#*: }" ;;
  esac
}
ig_kept(){ # <message stem> <id> → the message as quarantine/ keeps it: the id this script hashed, and the ciphertext its fetch answered, <stem>.age, in base64; none of the server's strings, so nothing the server chose is there to be read
  local rc; ig_b64 "$1.age" > "$1.b64" && jq -cj -n --rawfile c "$1.b64" --arg id "$2" '{id: $id, ciphertext: $c}'; rc=$?; rm -f "$1.b64"; return $rc      # base64 of the bytes, a file of ASCII, which jq carries as it is
}
ig_judge(){ # <me> <message stem> → 0 only if EVERY check passes, in this order; 2 for a resend of an accepted msg_id; 1 refused, with "<code>: <words>" on stdout, the words this script's own and never the message's; 3 a fault of this box, no verdict; 4 no answer from the server on whether the sender is revoked, no verdict. Who the sender is, is never asked of the server: the message carries what proves it. The one thing asked is whether a revocation of that sender exists, and the answer proves itself
  local B=$1 m=$2 ids=() k h A c f
  for k in "$IG"/prekeys/*.agekey; do [ -e "$k" ] || continue; age-keygen -y "$k" > /dev/null 2>&1 || { echo "cannot read the prekey key $k"; return 3; }; ids+=(-i "$k"); done      # a key file age cannot read is a fault of this box, which stops the drain: never a message refused for it
  [ ${#ids[@]} -gt 0 ] || { echo "this box has no prekeys"; return 3; }
  age -d "${ids[@]}" < "$m.age" > "$m.T" 2> /dev/null || { echo "undecryptable: it does not decrypt with this box's prekeys"; return 1; }
  A=$(ig_open "$B" "$m") || { echo "$A"; return 1; }      # the sender, proved by what was decrypted
  f=$(ig_floor 2> /dev/null) || { echo "$IG/seen-floor names no time"; return 3; }
  [ "$f" -eq 0 ] || [ "$(ig_time "$(jq -r .sent_at "$m.P")")" -ge $((f + 33*86400)) ] || { echo "stale: sent_at is before this box's replay set reaches back to, since its clock once read later than it does now"; return 1; }      # freshness has a floor too: a sent_at before the highest cutoff the replay set was pruned at may be a message whose line went, and so may one up to 33 days above it, a retry of such a message, dated afresh up to 33 days after its first copy (check 10 knows a retry by that copy's line). ig_open checked sent_at's grammar
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
  [ "$(tail -c 1 "$m.P" | od -An -tx1 | tr -d ' \n')" = 0a ] && head -n 1 "$m.sig" | cmp -s - <(printf -- '-----BEGIN SSH SIGNATURE-----\n') && tail -n 1 "$m.sig" | cmp -s - <(printf -- '-----END SSH SIGNATURE-----\n') ||      # each compared as bytes: $(…) drops a NUL
    { echo "bad_message: what was decrypted is not an envelope line and then a signature block"; return 1; }
  ig_envform "$m.P" || return 1
  jq -e '.from | . == null or type == "string"' "$m.P" > /dev/null 2>&1 || { echo "bad_envelope: the envelope is malformed: its from is not what that field holds"; return 1; }
  jq -e 'has("identity")' "$m.P" > /dev/null 2>&1 || { echo "bad_identity: the envelope carries no identity document"; return 1; }
  ig_bytes "$m.P" identity "$m.doc" && [ -s "$m.doc" ] || { echo "bad_identity: the envelope's identity is not base64 of an identity document"; return 1; }      # its bytes, compared as bytes
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
ig_envform(){ # <envelope> → 0 only for one JSON object with no member named twice in any object in it: a name given twice could be read as two values of one signed text. Otherwise the reason, and 1
  local n; n=$(jq -n --stream '[inputs | if length == 2 then .[0] else .[0][:-1] end | select(length > 0 and (.[-1] | type) == "string")] | length' "$1" 2> /dev/null) &&      # every member of every object, as written: one named twice is counted twice here, and once below
    jq -en --argjson n "$n" '[inputs] | length == 1 and (.[0] | type == "object" and ([.. | objects | length] | add) == $n)' "$1" > /dev/null 2>&1 ||
    { echo "bad_envelope: the envelope is not one JSON object with no member named twice"; return 1; }
}
ig_envcheck(){ # <envelope> <signer> <this box> → 0 only for one JSON object, keys exact and none twice, checked in PROTOCOL.md §5 check 6's order: a body and fields that are strings, v the number 1, from the signer and to this box, a msg_id, and sent_at no older than 33 days and no more than an hour ahead; otherwise the reason, and 1
  local e=$1 sa
  ig_envform "$e" || return 1
  jq -e 'has("body") and all(.from, .to, .msg_id, .sent_at, .subject, .in_reply_to, .supersedes, .identity; . == null or type == "string") and .v == 1' "$e" > /dev/null 2>&1 ||
    { echo "bad_envelope: the envelope is malformed: a body, fields that are strings, and v the number 1"; return 1; }      # in PROTOCOL.md §5 check 6's order: a body and every member of its type, v, to, msg_id, then the time
  jq -e --arg a "$2" --arg b "$3" '.from == $a and .to == $b' "$e" > /dev/null 2>&1 || { echo "reattributed: the inner from/to do not match the signer and this box (re-attribution)"; return 1; }
  jq -e '.msg_id | type == "string" and test("\\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\z")' "$e" > /dev/null 2>&1 || { echo "bad_envelope: the envelope has no valid msg_id"; return 1; }
  jq -e '.sent_at | strings | test("\\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\\z")' "$e" > /dev/null 2>&1 && sa=$(ig_time "$(jq -r .sent_at "$e")") || { echo "bad_envelope: the envelope's sent_at is not a UTC timestamp to the second"; return 1; }      # its grammar tested in jq first: $(…) drops trailing LFs and every NUL
  [ "$sa" -ge $(($(ig_now) - 33*86400)) ] || { echo "stale: sent_at is older than 33 days"; return 1; }
  [ "$sa" -le $(($(ig_now) + 3600)) ] || { echo "future: sent_at is more than 60 minutes ahead of this machine's clock"; return 1; }
}
ig_line(){ # <checked envelope> [receipt] → the one line delivered: built from the checked fields, never the sender's bytes, with U+0085, U+2028 and U+2029 escaped (Python's splitlines and Node's readline end lines there), and every character of Unicode 18.0's Default_Ignorable_Code_Point, which nobody sees and a model reads (tag characters, BiDi controls, zero-width characters, variation selectors): the Go client's escapeUnseen, in its list and its form. With a receipt it is ig_sent's record, the envelope inside "envelope" and the receipt beside it
  jq -j --slurpfile r "${2:-/dev/null}" 'def h4: . as $n | [range(3; -1; -1) | ($n / pow(16; .) | floor) % 16] | map("0123456789abcdef"[.:. + 1]) | add;
    def ig_esc: if . > 65535 then (. - 65536) as $v | "\\u" + ((55296 + ($v / 1024 | floor)) | h4) + "\\u" + ((56320 + $v % 1024) | h4) else "\\u" + h4 end;      # a code point as JSON escapes it, lowercase, as Go writes it: a surrogate pair above U+FFFF
    ({v: 1, from, to, sent_at, msg_id, body} + ([{subject}, {in_reply_to}, {supersedes}] | map(select(.[] | . != null and . != "")) | add // {})) as $e | ($r[0] | if . then {envelope: $e, receipt: {id, received_at, expires_at}} else $e end) | tojson | gsub("(?<c>[\\x{85}\\x{2028}\\x{2029}\\x{AD}\\x{34F}\\x{61C}\\x{115F}-\\x{1160}\\x{17B4}-\\x{17B5}\\x{180B}-\\x{180F}\\x{200B}-\\x{200F}\\x{202A}-\\x{202E}\\x{2060}-\\x{206F}\\x{3164}\\x{FE00}-\\x{FE0F}\\x{FEFF}\\x{FFA0}\\x{FFF0}-\\x{FFF8}\\x{1BCA0}-\\x{1BCA3}\\x{1D173}-\\x{1D17A}\\x{E0000}-\\x{E0FFF}])"; .c | explode[0] | ig_esc)' "$1"
}
ig_forget(){ # <Unix time, one a server took (ig_taken)> → the replay set without the lines past 66 days and an hour from their sent_at by that reading: a retry, dated afresh, may be posted up to 33 days after a first copy that was delivered, and read up to 33 days after that, and an hour covers a clock that steps back as far as two clocks a server takes are apart. When it drops one, the floor rises to the cutoff first, so a clock that later reads further back still takes no message whose line went (ig_floor)
  local c=$(($1 - 66*86400 - 3600)) f; [ -e "$IG/seen" ] || return 0
  awk -v c="$c" '$2 >= c' "$IG/seen" > "$IG/seen.new" || return 1
  cmp -s "$IG/seen" "$IG/seen.new" && { rm -f "$IG/seen.new"; return 0; }      # nothing dropped: nothing written
  f=$(ig_floor) || return 1
  if [ "$f" -lt "$c" ]; then printf '%s\n' "$c" > "$IG/seen-floor.new" && sync "$IG/seen-floor.new" && mv "$IG/seen-floor.new" "$IG/seen-floor" && sync "$IG" || return 1; fi      # on disk before any line goes
  sync "$IG/seen.new" && mv "$IG/seen.new" "$IG/seen" && sync "$IG"      # on disk before it replaces the old one: a crash leaves the old set or the new, never an empty one
}
ig_floor(){ # → the highest cutoff a prune of the replay set has dropped a line at, from seen-floor, or 0 when it has none: a message sent before it, or less than 33 days after it, is stale whatever the clock now reads, since its line, or its first copy's, may be gone, as a Kerberos server that has lost its replay cache refuses until the window has passed (RFC 4120 §3.2.3). A file that names anything else is an error, never the default
  local f; [ -e "$IG/seen-floor" ] || { echo 0; return 0; }
  f=$(cat "$IG/seen-floor" 2> /dev/null) && [[ $f =~ ^(0|[1-9][0-9]{0,17})$ ]] && printf '%s\n' "$f" | cmp -s - "$IG/seen-floor" && echo "$f" ||      # compared with itself rebuilt: $(…) drops line feeds and NULs
    { ig_err "$IG/seen-floor names no time: it is a number of seconds and a line feed, written by recv"; return 1; }
}
ig_seen(){ # <sender> <message stem> <hash> → the message, in the replay set and on disk
  local new=; [ -e "$IG/seen" ] || new=$IG
  printf '%s %s %s %s\n' "$3" "$(ig_time "$(jq -r .sent_at "$2.P")")" "$1" "$(jq -r .msg_id "$2.P")" >> "$IG/seen" && sync "$IG/seen" ${new:+"$new"}
}

# recipe: new prekey (monthly)
ig_rekey(){ # [--no-pq] → publishes a new prekey, signed by a new working key under a new certificate, under the lock: a NEW key at a new number, which this machine's clock gives, or the statement an earlier run signed and the server did not take, sent again as it is. Needs only the identity (ig_lock makes the box's other files from it), so it also recovers a box that lost its prekeys or its working key
  ig_opt "${1-}" || return 1
  ig_held || { ig_lock ig_rekey "$@"; return; }
  ig_renew "${1-}"
}
ig_renew(){ # [--no-pq] → what ig_rekey does, the lock held. A serial is signed ONCE
  local A r s t na h c f cs p new x gone u w at; A=$(cat "$IG/address") || return 1; mkdir -p "$IG/prekeys"
  ig_finished || { ig_done $?; return 1; }
  ig_api GET "/v1/$A" > "$IG/self.json" 2> "$IG/self.err" || case $(ig_code) in
    no_such_mailbox) gone=1 ;;      # 404: the server holds no box here any more, past its record's expiry (PROTOCOL.md §7), so nothing is served to number above or to hold to its order, and the renewal goes as a registration
    revoked) ig_takerecord "$A"; [ $? != 3 ] || return 1; ig_finished || { ig_done $?; return 1; }; cat "$IG/self.err" >&2; return 1 ;;      # 410: the address's record, kept once it verifies, so the box signs nothing more here or at any server it is pointed at (PROTOCOL.md §6.3; #343)
    *) cat "$IG/self.err" >&2; return 1 ;;
  esac
  p=$(cat "$IG/serial" 2> /dev/null || echo 0)
  if [ -n "$gone" ]; then s=$p; else
    ig_shape "$IG/self.json" box && ig_bytes "$IG/self.json" identity "$IG/self.doc" && ig_bytes "$IG/self.json" prekey "$IG/self.txt" && ig_bytes "$IG/self.json" prekey_signature "$IG/self.sig" ||
      ig_refuse "the server's answer for this box is not one this client reads: one JSON object, each byte field base64" || return 1
    [ -s "$IG/self.txt" ] && [ -s "$IG/self.sig" ] || ig_refuse "the server sent no prekey for this box" || return 1
    c=$(ig_cert "$IG/self.sig" "$IG/identity.doc" "$A") && c=${c#* } && r=$(ig_prekeycheck "$IG/self.txt" "$IG/self.sig" "$A" "$IG/identity.doc" "${c% *}") || ig_refuse "this box's current prekey, as served: ${r:-it is not signed under a certificate of this identity}" || return 1      # its own record, judged where its certificate begins: whether this identity ever certified the key that signed it, even if that certificate has since ended
    s=${r%% *}; cs=${r##* }      # a box's statements are ordered by certificate first, then by serial, and this box gives a renewal's certificate and prekey one number: what it published is (p, p), and the server may serve nothing ordered before it
    [ "$cs" -gt "$p" ] || { [ "$cs" -eq "$p" ] && [ "$s" -ge "$p" ]; } || ig_refuse "rollback: the server serves this box's prekey serial $s under certificate $cs, before serial $p, which this box published" || return 1
    s=$((cs > p ? cs : p))
  fi
  if [ -n "$gone" ]; then      # what is held of this box's own revocations, at every renewal, so the certificate is numbered above them: from its server's answer, or for a box it holds no more, which carries none, from its revocations alone
    if ig_api GET "/v1/$A/revocations" > "$IG/rev.json" 2> "$IG/self.err"; then ig_isrecord "$IG/rev.json" || ig_refuse "the server's answer for this box's revocations is not one this client reads: a record, each byte field base64" || return 1; ig_take "$A"; [ $? != 3 ] || return 1      # a 2xx that is no record stops the renewal with a refusal, as one for the box's own read does
    else case $(ig_code) in not_revoked | no_such_mailbox) ;; *) cat "$IG/self.err" >&2; return 1 ;; esac; fi
  else jq -c '{identity, revoked_certificates, revoked_certificates_signature}' "$IG/self.json" > "$IG/rev.json" && ig_take "$A"; [ $? != 3 ] || return 1; fi
  ig_finished || { ig_done $?; return 1; }
  x=$(ig_certskept "$A"); case $? in      # above every serial this box's identity has revoked too: a certificate numbered there would be revoked as it was made
    0) [ "$x" -lt 9007199254740991 ] || ig_refuse "this box's identity has revoked its certificates through the highest serial there is, so no later certificate can be made: the address cannot renew" || return 1; [ "$x" -le "$s" ] || s=$x ;;
    1) ;;
    *) ig_refuse "the revocation of certificates kept for this box does not verify"; return 1 ;;
  esac
  t=$(ls "$IG/prekeys" | sed -n 's/\.agekey$//p; s/\.txt\.sig$//p' | sort -n | tail -n 1); new=1      # s is the highest number this box knows of, and the new statement goes above it: above the served CERTIFICATE's serial, never the served prekey's, since it is under a new certificate, which outranks any prekey serial under the one before. So a prekey published in this box's name at the highest serial there is holds nothing. t is the highest number this box began a prekey at
  if [ "${t:-0}" -gt "$s" ]; then s=$t; new=; [ ! -s "$IG/prekeys/$s.txt.sig" ] || { na=$(ig_time "$(sed -n 5p "$IG/prekeys/$s.txt")") && [ "$na" -gt "$(ig_now)" ] && [ -s "$IG/work/$s-cert.pub" ] && c=$(ig_cert "$IG/prekeys/$s.txt.sig" "$IG/identity.doc" "$A") && c=${c#* } && [ "${c% *}" -le $(($(ig_now) - 3600)) ] && u=$(ig_time "$(cat "$IG/prekeys/$s.made" 2> /dev/null)") && w=$(ig_lifetime 2> /dev/null) && [ $((na - u)) -le "$w" ]; } || new=1; fi      # a number an earlier run took, and that nothing has passed since, is kept. Signed and never seen published: sent again AS IT IS until it expires, then a new number. Signed again, the same key would get 33 more days from a server that keeps what it refuses. One under a certificate that began less than an hour before this clock was signed while the clock read ahead of where it reads now: a reader a server takes may not have reached its start, so it is spent too. Never signed: its key is used
  if [ -n "$new" ]; then [ "$s" -lt 9007199254740991 ] || ig_refuse "this box's certificate serial is the highest there is, so no later certificate can be made: the address cannot renew" || return 1; t=$(ig_now); s=$((t > s ? t : s + 1)); fi      # a new number: this machine's clock, in seconds, or one above the highest this box knows of when the clock gives nothing higher. An identity is a key and keeps no record of what it signed, and a box restored from it knows only what the server shows: by the clock, its certificate is above every one made before, on whatever machine. A verifier never reads a serial as a time, it only compares two
  [ -s "$IG/prekeys/$s.txt.sig" ] || rm -f "$IG/prekeys/$s.txt" "$IG/prekeys/$s.made"; ig_prekey "$s" "${1-}" || return 1
  if [ -n "$gone" ]; then u="/v1/$A"; w='{identity:$i}'; else u="/v1/$A/prekey"; w='{}'; fi      # a registration is the identity document, then what a new prekey carries
  jq -n --arg i "$(ig_b64 "$IG/identity.doc")" --arg p "$(ig_b64 "$IG/prekeys/$s.txt")" --arg g "$(ig_b64 "$IG/prekeys/$s.txt.sig")" --argjson k "$(ig_senders)" "$w"' + {prekey:$p, prekey_signature:$g, sender_key_types:$k}' > "$IG/rekey.json"
  h=$(ig_pass "$s") && ig_api PUT "$u" "$IG/rekey.json" -H "Authorization: $h" > /dev/null || { ig_clock; ig_own; return 1; }      # a pass under the NEW certificate: that is how a box moves to one, and the server then takes no pass under an older
  [ "$s" -le "$(cat "$IG/serial" 2> /dev/null || echo 0)" ] || ig_putline "$IG/serial" "$s" || return 1
  mv "$IG/pass.new" "$IG/pass" || return 1
  for f in "$IG"/work/*-cert.pub; do t=$(basename "$f" -cert.pub); [[ $t =~ ^[0-9]+$ ]] && [ "$t" -lt "$s" ] && rm -f "$IG/work/$t" "$IG/work/$t.pub" "$f"; done      # older working keys: what they signed is signed, and the server takes no pass under them
  at=$(ig_taken) && ig_prune "$at" && ig_out prekey --argjson serial "$s" --arg not_after "$(sed -n 5p "$IG/prekeys/$s.txt")"      # by the reading the server took the renewal at: the date of its pass, now $IG/pass
}
ig_prune(){ # <Unix time, one a server took (ig_taken)> → deletes every retired prekey past its deletion time by that reading of this machine's clock: its not_after + the 33 days mail is kept. ig_recv gives the date of the pass its list carried, ig_renew that of the renewal's: a clock a server took, never a later reading. After that, mail encrypted to it is unrecoverable. (The Go client also deletes them sooner.)
  local f n top na; top=$(ls "$IG/prekeys" | sed -n 's/\.agekey$//p' | sort -n | tail -n 1); [ -n "$top" ] || return 0
  for f in "$IG"/prekeys/*.txt; do
    [ -e "$f" ] || continue
    n=$(basename "$f" .txt); [ "$n" -lt "$top" ] || continue      # never the newest
    na=$(ig_time "$(sed -n 5p "$f")") || continue
    [ "$1" -lt $((na + 33*86400)) ] || rm -f "$IG/prekeys/$n.agekey" "$IG/work/$n" "$IG/work/$n.pub" "$IG/work/$n-cert.pub"      # and the working key made with it, if a renewal the server never took left one
  done
}

# Run as a command, not sourced: the Go client's command line, for the commands this script has.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  ig_usage(){ sed -n '/^#   bash irongall\.sh /,/^#   The README/p' "$0" | sed 's/^#   //'; }      # the usage at the top
  ig_lines(){ ig_usage | awk -v w="bash irongall.sh $* " '/^bash irongall\.sh /{ on = index($0 " ", w) == 1 } /^The README/{ on = 0 } on'; }      # <words> → the usage lines of the commands they start
  ig_wrong(){ jq -cn --arg m "$1" --arg u "${2-}" --arg h "${3:-bash irongall.sh help}" '{type:"usage_error"} + (if $u != "" then {usage:$u} else {} end) + {help:$h, message:$m}' >&2; exit 2; }      # <words> [usage] [help] → the usage_error line on stderr, as the Go client prints one: what was wrong, the command's usage, and the help to read. Nothing ran
  ig_cmd= ig_n=0 ig_min=0 ig_max=0      # the function the command line runs, how many words name it, and how many arguments it takes, at least and at most
  case ${1-} in init) ig_cmd=ig_init ig_n=1 ig_max=1 ;; addr | recv) ig_cmd=ig_$1 ig_n=1 ;; send) ig_cmd=ig_send ig_n=1 ig_min=1 ig_max=2 ;; esac
  case "${1-} ${2-}" in 'prekey renew') ig_cmd=ig_rekey ig_n=2 ig_max=1 ;; esac
  ig_help=0
  for a; do case $a in --help) ig_help=1 ;; -h) ig_help=1; echo "Flag shorthand -h has been deprecated, use --help" >&2 ;; esac; done      # anywhere after a command: its help, and nothing runs. -h works too, as in the Go client, and means nothing else
  if [ "${1-}" = help ] || { [ -z "$ig_cmd" ] && [ "${2-}" = help ]; }; then
    ig_help=1; [ "$1" = help ] && shift || set -- "$1"
    [ $# -eq 0 ] || case "${1-} ${2-}" in 'prekey '?*) ig_n=2 ;; ?*) ig_n=1 ;; esac
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
  ig_use=$(ig_lines "$words" | head -n 1 | sed 's/   .*//')
  if [ $# -lt $ig_min ] || [ $# -gt $ig_max ]; then ig_wrong "irongall.sh $words takes $([ $ig_min = $ig_max ] && echo $ig_min || echo "$ig_min to $ig_max") arguments, and was given $#" "$ig_use" "bash irongall.sh help $words"; fi
  case $ig_cmd in      # every word a command takes, and no other: a word it does not take is a wrong command line, never dropped
    ig_init | ig_rekey) [ $# -eq 0 ] || [ "$1" = --no-pq ] || ig_wrong "irongall.sh $words takes no option but --no-pq: $1" "$ig_use" "bash irongall.sh help $words" ;;
    ig_send) for a; do [[ $a != -* ]] || ig_wrong "irongall.sh send takes no option: $a" "$ig_use" "bash irongall.sh help send"; done ;;
  esac
  ig_tls "$IG_BASE" || exit 1      # refused before anything, as the Go client refuses to open a box whose server it would not call
  "$ig_cmd" "$@"; exit
fi
