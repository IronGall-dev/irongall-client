#!/usr/bin/env bash
# dromas.sh: the dromas client in stock tools (bash, age, ssh-keygen, curl, jq, iconv and coreutils).
#
# The same protocol and checks as the Go client in this repo, on a mailbox of its own: the proof that a mailbox made of stock tools exchanges messages with a
# Go mailbox (AGENTS.md § The shell client), not a client to run. It fails CLOSED:
# a failed check prints an error line, "REFUSED: <reason>", and stops (recv refuses that one message with a refused line, its code and its words, and goes on), and every API error prints its status and its code, and none of the server's words.
# It prints JSON lines, as the Go client does, each with its "type" first: what a command did and met on stdout, and on stderr the
# line that says it failed ("error", here sometimes more than one), that its command line was wrong ("usage_error"), or that it waits.
# Get it from https://github.com/dromas-dev/dromas-client at a commit you have read, never from the dromas.dev
# server: a server that could hand you this script could hand you one without its checks.
#
#   bash dromas.sh init                            make and register this mailbox; prints its link, $DR_SERVER_URL/to/<address>
#   bash dromas.sh addr                            print it again: give it to whoever should write to this mailbox
#   bash dromas.sh send <link> [file]             one message (the body from stdin without a file); a link or an address. Posted now or not at all: nothing waits
#   bash dromas.sh recv                            verified messages, a "message" line each; a refused one goes to refused/, with a "refused" line
#   bash dromas.sh prekey renew                    a new prekey, which the identity signs: at least monthly, as a prekey is valid for 33 days, or within the lifetime a prekey-lifetime file sets
#   bash dromas.sh help [<command>]                this, or a command's lines; --help after a command does the same, and runs nothing
#   The README has the rest: https://github.com/dromas-dev/dromas-client#readme
#
# Or source it at the top of every shell call and call the dr_* functions. Agent tools run each command in a fresh
# shell, so all state lives in files in the mailbox's directory, never in variables.
#
# It gives up conveniences the Go client has: recv drains once and never waits for a message, and each step runs several
# programs. And working-key mode: its own mailbox is in identity mode, where its identity signs its prekey statements, passes
# and messages (PROTOCOL.md §5), and one shown its address in working-key mode signs nothing more (dr_finished). It reads and
# writes to mailboxes of either mode. Needs bash >= 4, age >= 1.3 (the first with post-quantum keys, the one prekey type; Ubuntu to 26.04 and Debian 13
# ship older, and go install filippo.io/age/cmd/...@v1.3.2 is current), OpenSSH >= 9.1 (the first to take a
# certificate's validity and a time to verify at in UTC), curl >= 7.84 (--fail-with-body, and -w with %header),
# jq >= 1.7.1 (1.7.0 can abort on a number a sender writes, CVE-2023-50246; Ubuntu 24.04's fixed jq prints jq-1.7),
# iconv, and coreutils (sha256sum, sha384sum, base64, od, sync). Dates go through jq, never date -d, and base64 is never -w0.

# recipe: setup
set -o pipefail; umask 077
export LC_ALL=C   # every pattern and tool reads bytes, as the Go client does: under another locale [0-9] can take a digit that is not ASCII, and [A-Z] can miss I
DR_SERVER_URL=${DR_SERVER_URL:-https://dromas.dev}
DR=${DR_HOME:-${XDG_CONFIG_HOME:-$HOME/.config}/dromas-sh/${DR_MAILBOX:-default}}   # one mailbox per directory, of this script's own: never the Go client's (its DROMAS_HOME and ~/.config/dromas/, dr_ownmailbox), and never the working directory
DR_VERSION=0.1.0   # the version every request names in Dromas-Version (PROTOCOL.md §11.17): the Go client's release minor this script implements, at patch 0
DR_LOCK_WAIT=${DR_LOCK_WAIT:-120}   # how many seconds a command waits for the mailbox's lock while another command of the mailbox holds it: what apt waits for its own lock when no one is at a terminal
DR_P256='ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGD+1LolWp0xyWHrdMY1bWjASbiSO2H6bOZpYi5g8p+2eQP+EAi4vJmkGunpVii8ZPLxsgwtfp9Rd6PClNRGIpk='   # a P-256 key, mailbox C's identity in this repo's testdata/vectors/ (RFC 6979 §A.2.5's published test key), for dr_senders to ask ssh-keygen to read
dr_senders(){ # → the identity key types dr_idcheck verifies on this build, as a JSON list. A mailbox declares them with each prekey it publishes, and the server then refuses it messages from a mailbox whose identity is of any other type (PROTOCOL.md §7): ssh-ed25519, and ecdsa-sha2-nistp256 only where this build's ssh-keygen reads a P-256 key. One built without OpenSSL reads none, so dr_idcheck refuses every P-256 identity there (PROTOCOL.md Appendix A), and a mailbox that declared the type would be sent messages it then refuses
  if ssh-keygen -l -f - <<< "$DR_P256" > /dev/null 2>&1; then echo '["ssh-ed25519","ecdsa-sha2-nistp256"]'; else echo '["ssh-ed25519"]'; fi
}
dr_out(){ jq -cn --arg type "$1" "${@:2}" '$ARGS.named'; }      # <type> [--arg <name> <text> | --argjson <name> <JSON>]… → one line of JSON on stdout, its type first and then each member in turn, as the Go client prints one: what a command did or met on the way
dr_err(){ jq -cn --arg m "$*" '{type:"error", detail:$m}' >&2; }      # <words> → the line on stderr that says a command failed, in this script's own words
dr_refuse(){ dr_err "REFUSED: $*"; return 1; }
dr_hex(){ [[ $1 =~ ^[0-9a-f]{64}$ ]]; }      # a message's id: the SHA-256 of its ciphertext, 64 lowercase hex
dr_isaddr(){ [[ $1 =~ ^[a-z2-7]{76}[acegikmoqsuwy246]$ ]]; }      # an address: 77 characters of lowercase base32 (RFC 4648 §6), the last carrying 4 bits and a zero bit, so each address has one spelling, in one case
dr_address(){ local h b= o= i c a=abcdefghijklmnopqrstuvwxyz234567; h=$(sha384sum < "$1" | cut -c1-96) && [[ $h =~ ^[0-9a-f]{96}$ ]] || return 1; for ((i = 0; i < 96; i++)); do c=$((16#${h:i:1})); b+=$((c >> 3 & 1))$((c >> 2 & 1))$((c >> 1 & 1))$((c & 1)); done; b+=0000; for ((i = 0; i + 5 <= ${#b}; i += 5)); do o+=${a:$((2#${b:i:5})):1}; done; printf %s "$o"; }      # <file> → its address: the SHA-384 of its bytes in lowercase base32 without padding, 384 bits read 5 at a time with a zero bit after the last, in bash alone
dr_b64(){ base64 < "$1" | tr -d '\n'; }
dr_now(){ date -u +%s; }   # the one clock every check reads
dr_time(){ # <timestamp> → its Unix time, only for exactly YYYY-MM-DDTHH:MM:SSZ naming a real time
  local s; [[ $1 =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || return 1
  s=$(jq -nr --arg t "$1" '$t | fromdateiso8601 | select(todate == $t)' 2> /dev/null) && [ -n "$s" ] && echo "$s"
}
dr_api(){ # <METHOD> <PATH> [body file] [curl args…] → the body on stdout, as curl -o wrote it. The body file is sent as it is: a message's ciphertext, POSTed to …/messages, as application/octet-stream (PROTOCOL.md §11.10), and any other body as JSON. Any non-2xx: an error line with its status, its code (dr_code) and the wait its Retry-After asks for, and nothing the server wrote: its detail, hint and title are for a person reading the body (PROTOCOL.md §11.3). No answer at all: an error line with curl's words. Keeps the answer in $DR/error.json and what curl read of it in $DR/error.meta (dr_status), returns 1
  local m=$1 p=$2 f=${3-} t=application/json s c w v; local -a np=(); shift 2; [ $# -gt 0 ] && shift
  [[ "$m $p" == "POST /v1/"*"/messages?"* ]] && t=application/octet-stream
  dr_tls "$DR_SERVER_URL" || return 1
  dr_here "$DR_SERVER_URL" localhost && np=(--noproxy '*')      # a server on this machine is called directly, whatever proxy the environment names, as Go's ProxyFromEnvironment never proxies localhost or a loopback address
  rm -f "$DR/error.json" "$DR/error.meta" "$DR/response.body" "$DR/response.meta"
  curl -q -sS "${np[@]}" --max-time 60 --max-filesize 16777216 --fail-with-body -o "$DR/response.body" -w '%{response_code}\n%header{retry-after}\n%header{date}\n%header{deprecation}\n%header{sunset}\n' -X "$m" -H "Dromas-Version: $DR_VERSION" ${f:+-H "Content-Type: $t" --data-binary "@$f"} "$@" "$DR_SERVER_URL$p" > "$DR/response.meta" 2> "$DR/curl.err"; s=$?
  dr_met "$DR/response.meta"
  [ "$s" = 0 ] && [[ $(sed -n 1p "$DR/response.meta") = 2?? ]] && { cat "$DR/response.body"; return 0; }      # -q first, or curl reads the user's .curlrc, where location, insecure or proxy change what is called. Only a 2xx is an answer: curl, which follows no redirect without -L, exits 0 on a 3xx too. The status and the two headers are the final answer's own, as curl read it: never a 1xx's line or a trailer, which the Go client never reads either
  mv "$DR/response.body" "$DR/error.json" 2> /dev/null; mv "$DR/response.meta" "$DR/error.meta" 2> /dev/null
  s=$(dr_status); c=$(dr_code); w=$(dr_wait); q=; u=; v=
  [ "$c" = rate_limited ] && q=$(dr_member quota_id "$DR_QUOTAS") && u=$(dr_member subject '["mailbox","ip"]')
  [ "$c" = version_retired ] && v=$(jq -r '.min_version | strings | select(test("\\A(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(\\.(0|[1-9][0-9]*))?\\z"))' "$DR/error.json" 2> /dev/null)      # a version is shown only once it has a policy version's form
  [ -n "$s" ] || { dr_err "no answer from $DR_SERVER_URL"; return 1; }      # curl's words, which can quote what the server sent (a certificate's name), are not printed
  jq -cn --argjson s "$s" --arg c "$c" --arg w "$w" --arg q "$q" --arg u "$u" --arg v "$v" --arg own "$DR_VERSION" '{type:"error", status:$s} + (if $c != "" then {code:$c} else {} end) + (if $q != "" then {quota_id:$q} else {} end) + (if $u != "" then {subject:$u} else {} end) + (if $v != "" then {min_version:$v} else {} end) + (if $w != "" then {retry_after:($w | tonumber)} else {} end) +
    {detail:("ERROR \($s)" + (if $c != "" then " \($c)" elif $s >= 300 and $s <= 399 then ": a redirect, which this client never follows: the API answers where it is called" else ": an answer this client does not know" end) + (if $c == "version_retired" then ": this server no longer takes this client'"'"'s version, \($own): upgrade this client" + (if $v != "" then "; the oldest it takes is \($v)" else "" end) else "" end) + (if $q != "" then ": the limit \($q)" else "" end) + (if $u == "mailbox" then ", counted against this mailbox" elif $u == "ip" then ", counted against this machine'"'"'s IP address" else "" end) + (if $w != "" then "; the server asks to wait \($w) seconds" else "" end))}' >&2; return 1
}
DR_TYPE='tag:dromas.dev,2026-10-26:errors/'      # an error's type is this and its code, which names the problem and resolves to nothing (PROTOCOL.md §11.3): a code counts only beside its own
DR_CODES='{"bad_request":400,"bad_address":400,"bad_encoding":400,"identity_mismatch":400,"bad_key":400,"prekey_not_new":400,"prekey_time":400,"certificate_too_long":400,"unsupported_key_type":400,"not_age":400,"wrong_recipient_type":400,"bad_revocation":400,"unauthorized":401,"pass_expired":401,"certificate_not_current":401,"certificate_revoked":401,"unknown_sender":403,"sender_revoked":403,"sender_not_allowed":403,"sender_key_type":403,"adopt_key_refused":403,"no_such_mailbox":404,"no_such_message":404,"not_revoked":404,"conflict":409,"mailbox_changed":409,"stale_prekey":409,"identity_mode":409,"prekey_expired":409,"request_timeout":408,"revoked":410,"version_retired":410,"precondition_failed":412,"too_large":413,"rate_limited":429,"fetch_paced":429,"refetch_spent":429,"mailbox_full":429,"mailbox_busy":429,"unavailable":503}'      # every code, and its status (PROTOCOL.md §11.3)
DR_QUOTAS='["polls","pages","calls","sends","renewals","certificates","certificate_revocations","registrations","registrations_range","misses","sends_before_pass","requests"]'      # every limit a rate_limited may name in quota_id (PROTOCOL.md §11.5)
dr_met(){ # <curl meta> → keeps the earliest Deprecation and Sunset an answer of this command carried, as Unix times, in $DR/met.deprecation and $DR/met.sunset, which the command line prints at its end (dr_said): a Deprecation only as a Structured Field Date, @ and an integer of up to 15 digits with an optional - (RFC 9745 §2.1, RFC 9651 §3.3.7), and a Sunset only as an HTTP-date in its preferred form (RFC 8594, RFC 9110 §5.6.7). Any other value is none, and neither is ever printed as it came (PROTOCOL.md §11.17, §11.3)
  local d n t
  d=$(sed -n 4p "$1" 2> /dev/null)
  if [[ $d =~ ^@-?[0-9]{1,15}$ ]]; then n=${d#@}; t=; [[ $n = -* ]] && t=- n=${n#-}; dr_earliest "$DR/met.deprecation" "$t$((10#$n))"; fi
  d=$(sed -n '5{/^[A-Za-z]\{3\}, [0-9]\{2\} [A-Za-z]\{3\} [0-9]\{4\} [0-9:]\{8\} GMT$/p;}' "$1" 2> /dev/null)
  [ -n "$d" ] && t=$(jq -nr --arg d "$d" '$d | strptime("%a, %d %b %Y %H:%M:%S GMT") | mktime' 2> /dev/null) && [[ $t =~ ^[0-9]+$ ]] && dr_earliest "$DR/met.sunset" "$t"
  return 0
}
dr_earliest(){ [ -s "$1" ] && [ "$(cat "$1")" -le "$2" ] || printf '%s\n' "$2" > "$1"; }      # <file> <Unix time> → the file holds the earlier of the two
dr_said(){ # → the lines the Go client prints at a command's end of what its answers said of this client's version (dr_met): a "deprecated" line and a "sunset" line, each with the date, in this script's own words. Neither changes the exit status: this script has no "needs a look" status. It reads no server's document, so it says nothing of an upgrade
  local t at
  if t=$(cat "$DR/met.deprecation" 2> /dev/null) && at=$(jq -nr --argjson t "$t" '$t | todate' 2> /dev/null); then dr_out deprecated --arg version "$DR_VERSION" --arg at "$at" --arg detail "the server deems this client's version, $DR_VERSION, deprecated from $at, by the Deprecation its last answer carried: it still takes it, and an upgrade of this client is due"; fi
  if t=$(cat "$DR/met.sunset" 2> /dev/null) && at=$(jq -nr --argjson t "$t" '$t | todate' 2> /dev/null); then dr_out sunset --arg version "$DR_VERSION" --arg at "$at" --arg detail "the server stops taking this client's version, $DR_VERSION, from $at, by the Sunset its last answer carried: upgrade this client, whose calls it refuses as version_retired from then on"; fi
  rm -f "$DR/met.deprecation" "$DR/met.sunset"
}
dr_member(){ jq -r --arg m "$1" --argjson known "$2" '.[$m] | strings | select(. as $v | $known | index([$v])) ' "$DR/error.json" 2> /dev/null; }      # <member> <known values, a JSON array> → the last API error's string member, only when it is one of them: a client shows no value it does not know (PROTOCOL.md §11.3)
dr_status(){ sed -n '1{/^[0-9][0-9][0-9]$/p;}' "$DR/error.meta" 2> /dev/null | grep -vx 000; }      # the status of the last API error. error.meta is what curl's -w read of the final answer, a line each: its status (000 for none), then its Retry-After and its Date, each the first given, trimmed, as Go's Header.Get reads one
dr_code(){ local s; s=$(dr_status) && [ -n "$s" ] && dr_shape "$DR/error.json" problem && jq -r --argjson codes "$DR_CODES" --argjson s "$s" --arg t "$DR_TYPE" '(.code | strings) as $c | select($codes[$c] == $s and .type == $t + $c) | $c' "$DR/error.json" 2> /dev/null; }   # the code of the last API error: one this client knows, under its own status, beside its own type, from an answer the Go client would read the same. Any other is no code
dr_wait(){ sed -n '2{/^[0-9]\{1,\}$/p;}' "$DR/error.meta" 2> /dev/null | sed 's/^0*\([0-9]\)/\1/' | awk '$1 > 0 { print ($1 > 86400 ? 86400 : $1) }'; }      # the seconds the last API error's Retry-After asks to wait, as a number of at most a day, or nothing. It is delay-seconds, digits alone (PROTOCOL.md §11.3): an HTTP-date asks for no wait
dr_dated(){ local d; d=$(sed -n '3{/^[A-Za-z0-9 ,:]*$/p;}' "$DR/error.meta" 2> /dev/null) && [ -n "$d" ] && jq -nr --arg d "$d" '$d | strptime("%a, %d %b %Y %H:%M:%S GMT") | mktime | todate' 2> /dev/null; }      # the time the last API error's Date header gives, the server's word
dr_shape(){ # <answer> <mailbox|list|record|receipt|problem> → 0 only for one JSON object of that kind, each member this script reads of its type, and null as if the member were left out. An integer is from 0 to 2^53 - 1 and jq gives it back as digits, since bash reads it. A byte member is a string, read by dr_bytes. Members it does not read are ignored
  jq -en --arg k "$2" 'def s: . == null or type == "string"; def n: . == null or (type == "number" and . == floor and . >= 0 and . <= 9007199254740991 and (tostring | test("\\A(0|[1-9][0-9]*)\\z")));
    def record: all(.identity, .revocation_signature, .revoked_certificates, .revoked_certificates_signature; s);
    [inputs] | length == 1 and (.[0] | type == "object" and
    {mailbox: all(.identity, .prekey, .prekey_signature, .revoked_certificates, .revoked_certificates_signature; s),
     list: ((.next_cursor | . == null or (type == "string" and test("\\A[A-Za-z0-9_-]+\\z"))) and (.messages | . == null or (type == "array" and all(.[]; . == null or (type == "object" and (.id | s) and (.size | n and (. // 0) <= 16777216)))))),
     record: record,
     receipt: all(.id, .received_at, .expires_at; s),
     problem: (all(.type, .code; s) and (.record | . == null or (type == "object" and record)))}[$k])' "$1" > /dev/null 2>&1
}
dr_bytes(){ # <answer> <member> <file> → the member's bytes into the file, only for base64 in its one encoding (RFC 4648 §3): padded, nothing outside the alphabet, a line break included, and the unused bits zero, which is what encoding the bytes again gives back. So a field has one text whatever base64 -d takes (GNU's refuses one unpadded, uutils' takes it), and the identity a plain/ vector carries is refused as the Go client refuses it. A member null or left out is no bytes. 1 for anything else
  jq -ejr --arg m "$2" '.[$m] | if . == null then "" else strings end' "$1" > "$3.b64" 2> /dev/null && base64 -d < "$3.b64" > "$3" 2> /dev/null && [ "$(dr_b64 "$3" | sha256sum)" = "$(sha256sum < "$3.b64")" ] || { rm -f "$3.b64"; return 1; }
  rm -f "$3.b64"
}
dr_stamp(){ jq -nr --argjson t "$1" '$t | strftime("%Y%m%d%H%M%SZ")'; }      # <Unix time> → the time as ssh-keygen takes one, in UTC
dr_asc(){ printf %s "$1" | od -An -v -tx1 | tr -d ' \n'; }      # <text> → its bytes in hex
dr_owner(){ # <METHOD> <PATH> [body file] [curl args…] → dr_api as this mailbox: adds its pass. If the server refuses the pass (it ran out sooner by the server's clock, or the server holds its signer revoked), signs another and tries once more. On certificate_revoked it reads its own mailbox first (dr_own), and a revocation there that verifies stops it (PROTOCOL.md §12.5). A pass refused twice for its time is the clock: it says what this one reads, beside the server's words
  local p; p=$(dr_pass) || return 1
  dr_api "$1" "$2" "${3-}" -H "Authorization: $p" "${@:4}" && return 0
  case $(dr_code) in unauthorized | pass_expired | certificate_not_current) ;; certificate_revoked) dr_own; dr_finished || { rm -f "$DR/error.json"; return 1; } ;; *) return 1 ;; esac      # what dr_own read is said: the caller's own dr_own has nothing more to say
  rm -f "$DR/pass"; p=$(dr_pass) && dr_api "$1" "$2" "${3-}" -H "Authorization: $p" "${@:4}" && return 0
  dr_clock; return 1
}
dr_taken(){ # → the reading of this machine's clock a server took, in Unix time: the date of the pass in $DR/pass, which the call dr_owner made, or the renewal dr_renew sent, carried once the server answered it: its not_after less the ten minutes a pass is signed for. Every deletion by the clock is by one, never by a reading of the clock (PROTOCOL.md §12.4): a clock far off is stopped at its pass, and one that jumps or steps back while a call is in flight deletes nothing by where it went
  local na; na=$(dr_time "$(sed -n 's/.* not_after="\([^"]*\)".*/\1/p' "$DR/pass" 2> /dev/null)") && echo $((na - 600))
}
dr_look(){ # <address> → dr_api GET of a mailbox from this mailbox's server (GET /v1/<address>), with no pass: the read is public, and a server reads none on it (PROTOCOL.md §11.8)
  dr_api GET "/v1/$1"
}
dr_clock(){ # after a call the server refused: if it refused the pass, or a prekey statement, for its time, says what the server dates its answer and what this machine's clock reads. A new pass does not cure that, so it is nearly always a clock. The date is the server's word: a clock set by a server's lie makes an ended certificate valid again, so this sends its reader to a time source of their own
  local d; case $(dr_code) in pass_expired | prekey_time) ;; *) return 0 ;; esac
  d=$(dr_dated) && d="the server dates its answer $d, and "
  dr_err "${d}this machine's clock reads $(jq -nr --argjson t "$(dr_now)" '$t | todate'). A server refuses a pass from a clock 10 minutes or more behind its own, or more than 50 ahead, and a prekey statement dated more than an hour ahead of it. Check this machine's clock against a time source you trust, not against the server"
}
dr_server(){ # <URL> → the server's name, as a pass names it: the URL's host, lowercase, and its port only when that is not the scheme's default, as an origin is written (PROTOCOL.md §8): the port as a number, and none for https on 443 or http on 80. A user and an @ before the host are no part of it, as Go's url.Parse has it
  local s=${1%%://*} h=${1#*://} p=
  h=${h%%[/?#]*}; h=${h##*@}; h=${h,,}
  if [[ $h =~ ^(.*):([0-9]*)$ ]]; then h=${BASH_REMATCH[1]}; p=${BASH_REMATCH[2]}; fi      # an IPv6 address ends in ], so a colon there begins no port
  [ -z "$p" ] || { p=$((10#$p)); case ${s,,}:$p in https:443 | http:80) ;; *) h+=:$p ;; esac; }
  echo "$h"
}
dr_here(){ # <URL> [localhost] → 0 when the URL's host is this machine by its address, an IPv4 address in 127.0.0.0/8 or [::1], and with localhost, that name too. Other spellings of an IPv6 loopback address are read as no address of this machine
  local h=${1#*://}; h=${h%%[/?#]*}; h=${h##*@}; h=${h,,}
  [[ $h =~ ^(.*):[0-9]*$ ]] && h=${BASH_REMATCH[1]}      # an IPv6 address ends in ], so a colon there begins no port
  [[ $h = '[::1]' || $h =~ ^127(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$ || ( ${2-} = localhost && $h = localhost ) ]]
}
dr_tls(){ # <URL> → 0 when it is a server this mailbox may call: https, or http only to a server on this machine, by its address: an IPv4 address in 127.0.0.0/8, or [::1]. A name is not, since localhost is what a resolver says it is (RFC 8252 §8.3), so that a pass, or the address a lookup asks about, never crosses a network in the clear (PROTOCOL.md §11.1). Otherwise a refusal, and 1
  [[ ${1,,} = https://?* ]] || { [[ ${1,,} = http://?* ]] && dr_here "$1"; } ||
    dr_refuse "$(printf '%.80s' "$1") is not a server this client calls: one is https, or http only to this machine, by its address (127.0.0.0/8, ::1)"
}
dr_pass(){ # [new] → the Authorization value of a call as this mailbox, signed by its identity, its signer in identity mode (PROTOCOL.md §8), unless it may act as its address no more (dr_finished). Without new: the pass kept in $DR/pass while it has more than 30 seconds left and no more than the ten minutes it was signed for, otherwise a new one, kept. With new: a new pass, for the call that publishes a prekey, left in $DR/pass.new until the server has taken it
  local A na h; A=$(cat "$DR/address") || return 1
  dr_finished || { dr_done $?; return 1; }
  if [ -z "${1-}" ]; then
    na=$(dr_time "$(sed -n 's/.* not_after="\([^"]*\)".*/\1/p' "$DR/pass" 2> /dev/null)") && [ $((na - $(dr_now))) -gt 30 ] && [ $((na - $(dr_now))) -le 600 ] && { cat "$DR/pass"; return; }      # more than ten minutes left: this machine's clock has gone back since it was signed, so a new one, dated by the clock as it is
    [ -s "$DR/serial" ] || dr_refuse "this mailbox has published no prekey: run init, or prekey renew for a mailbox restored from its identity" || return 1
  fi
  h=$(dr_server "$DR_SERVER_URL"); na=$(jq -nr --argjson t "$(dr_now)" '$t + 600 | todate')      # who is calling, which server, and until when: ten minutes
  printf 'dromas-pass-v1\n%s\n%s\n%s\n' "$A" "$h" "$na" | ssh-keygen -q -Y sign -n "dromas-pass-v1:$A" -f "$DR/identity" > "$DR/pass.sig" 2> /dev/null ||
    dr_refuse "this mailbox's identity did not sign a pass" || return 1
  printf 'dromas-pass address="%s", not_after="%s", signature="%s"\n' "$A" "$na" "$(dr_b64 "$DR/pass.sig")" > "$DR/pass.new" || return 1
  [ -n "${1-}" ] || mv "$DR/pass.new" "$DR/pass" || return 1
  cat "$DR/pass${1:+.new}"
}
dr_lock(){ # <command> [args] → runs that dr_ command with $DR/lock, the mailbox's lock, held, once the mailbox's directories and identity files are made (dr_dirs, dr_identity), as the Go client's Open makes them: so a mailbox restored from its identity alone runs. Every command that writes the mailbox runs so, from start to end, so one runs at a time and none reads a file another is writing. While another holds it, says so once and waits up to $DR_LOCK_WAIT seconds. If the command dies, the shell's EXIT trap removes it; a kill -9 leaves it behind
  local end=$((SECONDS + DR_LOCK_WAIT)) said= me=$DR outer=${DR_HELD-} trap rc
  [ -s "$DR/identity" ] || { dr_refuse "no mailbox in $DR: run init first"; return 1; }
  dr_ownmailbox || return 1
  until mkdir "$me/lock" 2> /dev/null; do
    [ -n "$said" ] || { jq -cn '{type:"waiting", for:"lock", detail:"waiting for this mailbox'"'"'s lock: another command of this mailbox is running, and a mailbox'"'"'s commands write its files one at a time"}' >&2; said=1; }
    [ "$SECONDS" -lt "$end" ] || { dr_refuse "another command of this mailbox held its lock, $me/lock, for as long as a command waits for it. If none is running, one that crashed left it behind: remove it"; return 1; }
    sleep 1
  done
  trap=$(trap -p EXIT); DR_HELD=$me; trap 'rmdir "$DR_HELD/lock" 2> /dev/null' EXIT
  dr_dirs && dr_identity && "$@"; rc=$?
  rmdir "$me/lock"; DR_HELD=$outer; eval "${trap:-trap - EXIT}"; return $rc      # and the caller's own EXIT trap back
}
dr_ownmailbox(){ [ ! -e "$DR/state" ] || dr_refuse "$DR holds a state file: it is a mailbox of the Go client, which this script never runs, since the two keep their records apart and would undo each other's: set DR_HOME to a directory of this script's own"; }      # whether $DR is a mailbox of this script's, by the one file only the Go client makes
dr_held(){ [ "${DR_HELD-}" = "$DR" ]; }      # whether this shell holds this mailbox's lock: a command another command runs works under its caller's
dr_dirs(){ mkdir -p "$DR/prekeys" "$DR/peers" "$DR/inbox" "$DR/refused" "$DR/sent"; }      # the mailbox's directories, made where they are missing, as the Go client's Open makes them: by init, and by every command that writes the mailbox (dr_lock)
dr_identity(){ # → identity.pub, identity.doc and address, the identity as the mailbox's other files name it: identity.pub made again from the identity where it is missing or empty, then the document and its address, its SHA-384, each written beside and moved into place only where its bytes differ (dr_put), as the Go client's Open writes them. So a mailbox restored from its identity alone gets all three, init run again rewrites nothing a command beside it reads, and a crash leaves no file empty
  local a
  [ -s "$DR/identity.pub" ] || { ssh-keygen -y -f "$DR/identity" < /dev/null > "$DR/id.pub" && dr_put "$DR/id.pub" "$DR/identity.pub"; } || dr_refuse "ssh-keygen cannot read this mailbox's identity, $DR/identity, to make identity.pub" || return 1
  printf 'dromas-v1\n%s\n' "$(cut -d' ' -f1,2 "$DR/identity.pub")" > "$DR/id.doc" || return 1
  cmp -s "$DR/id.doc" "$DR/identity.doc" || { { dr_idcheck "$DR/id.doc"; [ $? != 1 ]; } || dr_refuse "this mailbox's identity.pub is not a key an identity document holds: $DR/identity.pub" || return 1; dr_put "$DR/id.doc" "$DR/identity.doc" || return 1; }      # checked before it is written: a document out of form, from an identity.pub that is, would give the mailbox another address
  a=$(dr_address "$DR/id.doc") && rm -f "$DR/id.doc" "$DR/id.pub" || return 1
  printf '%s\n' "$a" | cmp -s - "$DR/address" || dr_putline "$DR/address" "$a"
}

# recipe: keys and registration
dr_lifetime(){ # → the seconds each new prekey of this mailbox is valid for: what its prekey-lifetime file names, a number of seconds alone on its line from 97200 (a day and three hours) to 2851200 (33 days), or 2851200 when it has none. A file that names anything else is a refusal, never the default: no prekey is signed until it is put right (PROTOCOL.md §12.4)
  local l; [ -e "$DR/prekey-lifetime" ] || { echo 2851200; return 0; }
  l=$(cat "$DR/prekey-lifetime" 2> /dev/null) && [[ $l =~ ^[1-9][0-9]{0,9}$ ]] && { printf '%s\n' "$l" | cmp -s - "$DR/prekey-lifetime" || printf '%s' "$l" | cmp -s - "$DR/prekey-lifetime"; } && [ "$l" -ge 97200 ] && [ "$l" -le 2851200 ] && echo "$l" ||      # compared with itself rebuilt: $(…) drops line feeds and NULs
    dr_refuse "this mailbox's prekey-lifetime file names no lifetime: one is a number of seconds, alone on its line, from 97200 (a day and three hours) to 2851200 (33 days)"
}
dr_prekey(){ # <serial> → prekeys/<serial>.agekey and its statement, signed by this mailbox's identity: a NEW key, valid for the mailbox's prekey lifetime (dr_lifetime), and prekeys/<serial>.made, when it was signed: a statement an earlier attempt left is sent again only while it was made for no longer than the mailbox's lifetime (dr_renew). A re-run reuses the key a failed attempt left, unless it is empty
  local A p="$DR/prekeys/$1" l t k; A=$(cat "$DR/address") || return 1
  [ -s "$p.txt.sig" ] && return 0
  dr_finished || { dr_done $?; return 1; }      # the one path to this mailbox's statements: a mailbox that may act as its address no more makes none, init and prekey renew alike
  l=$(dr_lifetime) || return 1
  [ -s "$p.agekey" ] || { rm -f "$p.agekey"; age-keygen -pq -o "$p.agekey" 2> /dev/null; } || dr_refuse "age-keygen failed: a post-quantum key needs age >= 1.3" || return 1      # an empty key file, as a crash before the sync below leaves one, is no key, and no statement names it, so it is made again, as the Go client does
  k=$(age-keygen -y "$p.agekey" 2> /dev/null) || dr_refuse "age-keygen cannot read $p.agekey, the key this mailbox began prekey $1 with (a post-quantum one needs age >= 1.3)" || return 1      # never a statement with no key in it, which a server refuses at every try
  t=$(dr_now)
  printf 'dromas-prekey-v1\n%s\n%s\n%s\n%s\n' "$A" "$1" "$k" "$(jq -nr --argjson t "$t" --argjson l "$l" '$t + $l | todate')" > "$p.txt" &&
  jq -nr --argjson t "$t" '$t | todate' > "$p.made" &&      # before the signature: a statement is signed once its record is there
  ssh-keygen -q -Y sign -n "dromas-prekey-v1:$A" -f "$DR/identity" < "$p.txt" > "$p.txt.sig" &&      # stdin to stdout: never a stale .sig
  sync "$p.agekey" "$p.txt" "$p.made" "$p.txt.sig" "$DR/prekeys"      # on disk before any upload publishes the statement: a key lost to a crash after that is a message nobody can read
}
dr_init(){ # → creates this mailbox, or finishes a half-done init, and registers it, in identity mode; prints its address and link. The registration carries a pass its identity signs, so the mailbox is in use at once
  dr_ownmailbox || return 1
  dr_dirs && dr_putline "$DR/.gitignore" '*' || return 1      # the mailbox ignores itself, wherever it is
  [ -s "$DR/identity" ] || { rm -f "$DR/identity" "$DR/identity.pub"; ssh-keygen -q -t ed25519 -N '' -C '' -f "$DR/identity" < /dev/null; } || return 1      # an empty identity, as a crash before the sync below leaves one, is no key, and nothing was registered with it, so it is made again, as the Go client does
  if dr_held; then dr_identity; else dr_lock true; fi && sync "$DR/identity" "$DR/identity.pub" "$DR" || return 1      # identity.doc and address made under the mailbox's lock, as every command that writes the mailbox makes them (dr_lock): a command beside init reads them. The identity on disk before it is registered
  [ ! -s "$DR/serial" ] || { dr_addr; return; }      # registered already
  local A n p h m; A=$(cat "$DR/address")
  n=$(ls "$DR/prekeys" | sed -n 's/\.agekey$//p; s/\.txt\.sig$//p' | sort -n | tail -n 1); [ -n "$n" ] || n=$(dr_now); [ "$n" -ge 1 ] || n=1; p="$DR/prekeys/$n"      # the mailbox's first prekey takes its number as every later one does, from this machine's clock in seconds (dr_renew). An attempt that got as far as a key keeps the number it took, so a registration whose answer was lost is sent again as it was
  if [ -s "$p.txt.sig" ] && ! { m=$(dr_time "$(cat "$p.made" 2> /dev/null)") && [ "$m" -le "$(dr_now)" ]; }; then      # a first statement an earlier attempt left, made while this machine's clock read ahead of where it reads now, or with no record of when: a server may not take it until the clock catches up, as a pass made then is not used either (PROTOCOL.md §12.4). The statement is made again; the prekey's own key stays, since a server may have taken a registration whose answer was lost, and then messages may be waiting that only this key opens
    rm -f "$p.txt" "$p.made" "$p.txt.sig" "$DR/pass.new"
  fi
  dr_prekey "$n" || return 1
  jq -n --arg i "$(dr_b64 "$DR/identity.doc")" --arg p "$(dr_b64 "$p.txt")" --arg s "$(dr_b64 "$p.txt.sig")" --argjson k "$(dr_senders)" '{identity:$i, prekey:$p, prekey_signature:$s, sender_key_types:$k}' > "$DR/register.json"
  h=$(dr_pass new) && { dr_api PUT "/v1/$A" "$DR/register.json" -H "Authorization: $h" > /dev/null || { dr_clock; dr_own; false; }; } && mv "$DR/pass.new" "$DR/pass" && dr_putline "$DR/serial" "$n" && dr_addr
}
dr_addr(){ local a; dr_held || { [ -s "$DR/identity" ] && [ -s "$DR/address" ]; } || { dr_lock dr_addr; return; }; a=$(cat "$DR/address") && dr_out mailbox --arg address "$a" --arg link "$DR_SERVER_URL/to/$a"; }      # the mailbox's address and its link: what to give whoever should write to it. Read with no lock; with no mailbox, dr_lock's refusal, and a mailbox restored from its identity alone has its files made under the lock first (dr_identity), as the Go client's Open makes them
dr_dest(){ # <link or address> → the address: 77 characters of lowercase base32, or taken from a link to this mailbox's server, $DR_SERVER_URL/to/<address>
  local a=${1#"$DR_SERVER_URL/to/"}
  dr_isaddr "$a" && { printf '%s\n' "$a"; return 0; }
  [[ $1 != *://* || $1 = "$DR_SERVER_URL/"* ]] || { dr_refuse "a link to another server: this mailbox's server is $DR_SERVER_URL"; return 1; }
  dr_refuse "not an address or a link to one: $1"
}

# recipe: verify a peer
dr_keycheck(){ # <32 bytes in hex> → 0 only for an Ed25519 key that is a canonical point, not of small order
  [[ $1 =~ ^[0-9a-f]{64}$ && ! $1 =~ ^(e[d-f]|f[0-9a-f])(ff){30}(7f|ff)$ ]] || return 1      # y >= p: not canonical
  case $1 in      # the eight points of small order, and the two with x = 0 marked negative
    0100000000000000000000000000000000000000000000000000000000000000 | 0100000000000000000000000000000000000000000000000000000000000080 | \
    ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f | ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff | \
    0000000000000000000000000000000000000000000000000000000000000000 | 0000000000000000000000000000000000000000000000000000000000000080 | \
    26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05 | 26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85 | \
    c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a | c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa) return 1 ;;
  esac
  age -r "ssh-ed25519 $(printf "$(printf %s "0000000b$(dr_asc ssh-ed25519)00000020$1" | sed 's/../\\x&/g')" | base64 | tr -d '\n')" < /dev/null > /dev/null 2>&1      # a point on the curve: age decodes the key as the Go client's edwards25519 does, and refuses 32 bytes that are no point, which ssh-keygen reads as a key
}
dr_idcheck(){ # <identity document> [address] → 0 only for a two-line document whose key is in its one encoding and passes its type's checks (and hashing to the address, given one). 2 for a well-formed document of a key type this script does not verify: nothing is wrong with it, and nothing it signed can be checked here. 1 for anything else
  local f=$1 l t fp
  l=$(sed -n 2p "$f"); t=${l%% *}
  [ "$(printf 'dromas-v1\n%s\n' "$l" | sha256sum)" = "$(sha256sum < "$f")" ] || return 1      # exactly the tag line and one more, each ending in LF, and not a byte else: the file against itself rebuilt from its second line. A shell variable drops a NUL, so a test of the variable alone would pass a file that holds one
  [ -z "${2-}" ] || [ "$(dr_address "$f")" = "$2" ] || return 1
  # the form every type shares: a key type's name (printable ASCII with no comma, at most 64 characters), one space, and the base64, in its one encoding, of a wire key that begins with that name
  grep -Eqx '[!-+.-~-]{1,64} [A-Za-z0-9+/]+={0,2}' <<< "$l" && [ "$(printf %s "${l#* }" | base64 -d 2> /dev/null | base64 | tr -d '\n')" = "${l#* }" ] &&
    [ "$(printf %s "${l#* }" | base64 -d | head -c $((4 + ${#t})) | od -An -v -tx1 | tr -d ' \n')" = "$(printf %08x "${#t}")$(dr_asc "$t")" ] || return 1
  case $t in ssh-ed25519 | ecdsa-sha2-nistp256) ;; *) return 2 ;; esac
  # the key in its one encoding: ssh-keygen reads it, and its fingerprint, the SHA-256 of the key as OpenSSH writes it back, is the SHA-256 of these bytes. ssh-keygen refuses a P-256 point off the curve, compressed, at infinity or with a coordinate not below the field's size, which is all a P-256 key is held to (PROTOCOL.md §4.1). Up to 10.2p1 it also refuses one with a coordinate of 128 bits or fewer, or of the group's order less one or more, which the protocol takes: a known variance (PROTOCOL.md Appendix A)
  fp=$(ssh-keygen -l -E sha256 -f - <<< "$l" 2> /dev/null | awk '{print $2}') && fp=${fp#SHA256:} && [ -n "$fp" ] &&
    [ "$(printf '%s=' "$fp" | base64 -d | od -An -v -tx1 | tr -d ' \n')" = "$(printf %s "${l#* }" | base64 -d | sha256sum | cut -c1-64)" ] || return 1
  case $t in      # then the type's own checks: an Ed25519 key canonical and not of small order
    ssh-ed25519) dr_keycheck "$(printf %s "${l#* }" | base64 -d | tail -c 32 | od -An -v -tx1 | tr -d ' \n')" ;;
  esac
}
dr_sigmax(){ case $(sed -n 2p "$1" | cut -d' ' -f1) in ssh-ed25519 | ecdsa-sha2-nistp256) echo 4096 ;; *) return 1 ;; esac; }      # <identity document> → the most bytes a signature by a mailbox of its key type may be, every byte of the file (PROTOCOL.md §3.2): each type states its own. Nothing for a type this script does not verify
dr_bound(){ local m; m=$(dr_sigmax "$2") && [ "$(wc -c < "$1")" -le "$m" ]; }      # <signature file> <identity document> → 0 only for a signature no longer than its identity's key type allows
dr_blob(){ # <signature file> → the SSHSIG blob it armors, in hex, read as ssh-keygen -Y verify reads it (OpenSSH's sshsig_dearmor), and only if the file is at most 4096 bytes in all, the most any identity key type allows (dr_sigmax): the BEGIN line first, ending in LF or CRLF; then base64 in its one encoding, with space, tab, LF, VT, FF and CR skipped wherever they are; then LF and the END line, after which nothing is read; one NUL may be the last byte before that LF, as OpenSSH's sshbuf_dup_string takes it. 1 for anything else, any other NUL included. The bytes are read as hex, never through a shell variable, which would drop a NUL
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
dr_s(){ # <an SSH signature in hex: its type as a string, then its bytes as one> → 1 only for an Ed25519 signature that is not 64 bytes, or whose S is not below the group's order L: such a signature is invalid (RFC 8032 §5.1.7), and ssh-keygen before the cut PROTOCOL.md Appendix A gives takes one with L added to S. Its type may end in one NUL, as OpenSSH reads it. 0 for any other, which ssh-keygen judges
  local s="" i a b o= e L=1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
  e=$(dr_asc ssh-ed25519)
  [ "${1:0:30}" = "0000000b$e" ] && o=30; [ "${1:0:32}" = "0000000c${e}00" ] && o=32
  [ -n "$o" ] || return 0
  [ ${#1} -eq $((o + 136)) ] && [ "${1:o:8}" = 00000040 ] || return 1
  for ((i = o + 134; i >= o + 72; i -= 2)); do s+=${1:i:2}; done      # S is the signature's last 32 bytes, little-endian: here it is read the other way round, to compare with L
  for i in 0 8 16 24 32 40 48 56; do a=$((16#${s:i:8})); b=$((16#${L:i:8})); [ "$a" -lt "$b" ] && return 0; [ "$a" -gt "$b" ] && return 1; done
  return 1
}
dr_sshsig(){ # <signature file> → 0 only for a signature dr_blob reads that is an SSHSIG of version 0 or 1 (OpenSSH refuses only a higher one), five fields and nothing after them, whose own signature passes dr_s. It leaves the blob in x and its signing key in k, both in hex, for its caller, whose locals they are. The reserved field is read and skipped, as OpenSSH does: ssh-keygen verifies over an empty one
  local o=20 l v
  x=$(dr_blob "$1") && [[ ${x:0:20} =~ ^5353485349470000000[01]$ ]] || return 1      # "SSHSIG", version 0 or 1
  dr_str && k=$v && dr_str && dr_str && dr_str && dr_str && dr_s "$v" && [ "$o" -eq "${#x}" ]      # the signing key, the namespace, reserved, the hash, the signature: and nothing after
}
dr_cert(){ # <signature> <identity document> <address> → "<serial> <valid after> <valid before>", as Unix times, for the certificate the signature carries, only if it is in its one form (below, PROTOCOL.md §5.2) and names that identity as its signer. Its fields are read from its bytes, in order: ssh-keygen -Y verify takes a certificate with a critical option, or with extensions out of their order, and checks no key id. Whether the identity's signature on it is good, and whether it holds now, are dr_signed's
  local x o=20 l v k n a b      # x: the bytes being read, in hex; o: how far into them; v: the field just read
  dr_sshsig "$1" || return 1; x=$k; o=0      # the signing key: here, the certificate
  dr_str && [ "$v" = "$(dr_asc ssh-ed25519-cert-v01@openssh.com)" ] || return 1      # a certificate for an Ed25519 key
  dr_str || return 1      # the nonce
  dr_str && k=$v && dr_keycheck "$k" || return 1      # the working key, held to the identity's own key checks
  dr_u64 && n=$v && [ "$n" -ge 1 ] && [ "$n" -le 9007199254740991 ] || return 1      # the serial: from 1 to 2^53 - 1, as a prekey's
  [ "${x:o:8}" = 00000001 ] || return 1; o=$((o + 8))      # a user certificate
  dr_str && [ "$v" = "$(dr_asc dromas-cert-v1)" ] || return 1      # the key id
  dr_str && [ "$v" = "$(printf %08x ${#3})$(dr_asc "$3")" ] || return 1      # exactly one principal: the address
  dr_u64 && a=$v && dr_u64 && b=$v && [ "$a" -le 253402300799 ] && [ "$b" -le 253402300799 ] || return 1      # valid after, valid before: each at or before 9999-12-31T23:59:59Z, so forever is refused for its form, never as not begun or not ended
  dr_str && [ -z "$v" ] || return 1      # no critical option: one a verifier does not know is refused, and none is known here
  dr_str && dr_exts "$v" && dr_str || return 1      # the extensions, each ignored, as one a verifier does not know is; then reserved, whatever it holds, ignored too
  dr_str && [ "$v" = "$(dr_idkey "$2")" ] && [ "$v" != "0000000b$(dr_asc ssh-ed25519)00000020$k" ] || return 1      # signed by the identity's key, byte for byte, which is never the key certified: SSHSIG signs no signing key, so the identity's own signature, wrapped in a certificate of the identity's key above the trip, would otherwise be taken where the identity's own is refused (PROTOCOL.md §5.2)
  dr_str && dr_s "$v" && [ "$o" -eq "${#x}" ] || return 1      # the identity's signature on it, and nothing after
  echo "$n $a $b"
}
dr_exts(){ # dr_cert's: <a certificate's extensions, in hex> → 0 only for them in their one encoding, as the Go client's library reads them: each name once, in lexical order, and its value nothing or one string that is not empty. What each says is never read: none is known here
  local x=$1 o=0 l v n p=
  while [ "$o" -lt "${#x}" ]; do
    dr_str && n=$v && { [ -z "$p" ] || [ "$p" \< "$n" ]; } && dr_str || return 1      # the name, after the last; [ compares bytes, as their hex compares
    [ -z "$v" ] || { [[ ${v:0:8} =~ ^[0-9a-f]{8}$ ]] && [ $((16#${v:0:8})) -gt 0 ] && [ $((8 + 2 * 16#${v:0:8})) -eq ${#v} ]; } || return 1      # the value
    p=$n
  done
}
dr_str(){ [[ ${x:o:8} =~ ^[0-9a-f]{8}$ ]] || return 1; l=$((16#${x:o:8} * 2)); [ $((o + 8 + l)) -le ${#x} ] || return 1; v=${x:o+8:l}; o=$((o + 8 + l)); }      # dr_cert's: the next length-prefixed string of x, in hex, into v
dr_u64(){ [[ ${x:o:16} =~ ^[0-7][0-9a-f]{15}$ ]] || return 1; v=$((16#${x:o:16})); o=$((o + 16)); }      # dr_cert's: the next 64-bit number of x into v. One with its top bit set is no time and no serial here
dr_idkey(){ sed -n 2p "$1" | cut -d' ' -f2 | base64 -d | od -An -v -tx1 | tr -d ' \n'; }      # <identity document> → its key as the SSH wire writes it, in hex: what a signature by the identity itself carries as its signing key, byte for byte
dr_rank(){ # <signature> <identity document> <address> → the rank of its signer (PROTOCOL.md §5), read from the SSHSIG blob: 0 for the identity's own key, byte for byte, and the serial of a certificate of that identity in its one form (dr_cert). 1 for a signing key of neither form, a bare working key among them. Whether the signature verifies is dr_signed's
  local x k r
  dr_sshsig "$1" || return 1
  [ "$k" != "$(dr_idkey "$2")" ] || { echo 0; return 0; }
  r=$(dr_cert "$1" "$2" "$3") && echo "${r%% *}"
}
dr_signed(){ # <address> <identity document> <namespace> <signature> <message> [at] → the rank of its signer (dr_rank), only for a signature by that identity's own key, or by a working key under a certificate of it that holds at the time given (now, without one): begun and not ended. 1 otherwise; 2 when all that fails is that the certificate has ended, 3 that it has not begun. Whether the address's mode takes that signer is dr_mode's
  local A=$1 r n a b t=${6:-$(dr_now)}
  dr_bound "$4" "$2" && n=$(dr_rank "$4" "$2" "$A") || return 1
  if [ "$n" = 0 ]; then
    printf '%s %s\n' "$A" "$(sed -n 2p "$2")" > "$DR/signers"      # ONE line, built from checked bytes, chosen by the signing key's form: the identity's own key, with no cert-authority
    ssh-keygen -Y verify -f "$DR/signers" -I "$A" -n "$3" -s "$4" < "$5" > /dev/null 2>&1 && echo 0; return
  fi
  r=$(dr_cert "$4" "$2" "$A") || return 1; read -r n a b <<< "$r"
  printf '%s cert-authority %s\n' "$A" "$(sed -n 2p "$2")" > "$DR/signers"      # ONE line, the other form's: only a certificate this identity signed, for this address
  ssh-keygen -Y verify -f "$DR/signers" -I "$A" -n "$3" -s "$4" -O verify-time="$(dr_stamp $((a > 0 ? a : 1)))" < "$5" > /dev/null 2>&1 || return 1      # the two signatures, the identity's on the certificate and the working key's on the message, judged where the certificate begins (a second in, for one that begins at 0: ssh-keygen takes no verify-time of 0); the time is the next line's. A verifier sets no bound on how long one runs (PROTOCOL.md §5.2)
  [ "$a" -le "$t" ] || return 3; [ "$t" -lt "$b" ] || return 2
  echo "$n"
}
dr_mode(){ # <address> <rank> → 0 when the address's mode, as this mailbox holds it, takes a signer of that rank (PROTOCOL.md §5.1): with no revocation of its certificates held, identity mode, the identity alone, rank 0; with one through N, working-key mode, a rank above N, compared as a number. 1: a rank at or below N, the identity's own among them. 2: a certificate, at an address in identity mode. 3: what is kept does not verify
  local x; x=$(dr_certskept "$1"); case $? in
    0) [ "$2" -gt "$x" ] || return 1 ;;
    1) [ "$2" -eq 0 ] || return 2 ;;
    *) return 3 ;;
  esac
}
dr_bech32(){ # <string> → its human-readable part, only for a Bech32 string (BIP 173) as age writes a recipient: in lowercase, its checksum good, and its data whole bytes, with fewer than five bits left over and those zero. age takes one of any length, where BIP 173 stops at 90, and so does this. 1 for anything else
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
dr_prekeycheck(){ # <statement> <signature> <address> <identity document> → "<serial> <age recipient> <not_after as Unix time> <its signer's rank>" only for five LF-ended lines naming that address, signed by its identity or by a working key its identity certified (dr_signed), holding a key age will encrypt to; otherwise the reason, and 1. Whether the address's mode takes the signer is the caller's (dr_mode). 2, with the reason, for one good in every other way whose key is a well-formed age recipient of a type this script cannot encrypt to: its Bech32 human-readable part begins age and is not the hybrid's age1pq, X25519's age among them. Nothing is wrong with such a statement (PROTOCOL.md §6), so its key's type is the last thing checked
  local p=$1 B=$3 s k na c L
  c=$(dr_signed "$B" "$4" "dromas-prekey-v1:$B" "$2" "$p"); case $? in 0) ;;
    2) echo "$B's prekey: the certificate the prekey is signed under has ended"; return 1 ;;
    3) echo "$B's prekey: the certificate the prekey is signed under has not begun, by the clock that checked it"; return 1 ;;
    *) echo "$B's prekey is not signed by its identity, or by a working key its identity certified under a certificate that holds now"; return 1 ;;
  esac
  mapfile -t L < "$p"
  [ "$(printf '%s\n' "${L[@]}" | sha256sum)" = "$(sha256sum < "$p")" ] && [ ${#L[@]} -eq 5 ] && [ "${L[0]}" = dromas-prekey-v1 ] && [ "${L[1]}" = "$B" ] ||      # the file against itself rebuilt from its lines: every line ends in LF, and nothing is in it that a shell variable drops (a NUL)
    { echo "the prekey statement is not $B's: five lines, each ending in LF"; return 1; }
  s=${L[2]}; [[ $s =~ ^[1-9][0-9]{0,15}$ ]] && [ "$s" -le 9007199254740991 ] || { echo "$B's prekey serial is malformed"; return 1; }      # from 1 to 2^53 - 1, as every serial is written
  na=$(dr_time "${L[4]}") || { echo "$B's prekey has no valid not_after"; return 1; }
  k=${L[3]}
  case $(dr_bech32 "$k") in      # the key's type is its human-readable part, read before age is: age 1.3 encrypts to more types than the protocol defines, and to an SSH key
    age1pq) if ! age -r "$k" < /dev/null > /dev/null 2>&1; then
        echo "$B's prekey is post-quantum, and this age ($(age --version 2> /dev/null)) cannot encrypt to one: that takes age >= 1.3"; return 1
      fi ;;
    age*) echo "$B's prekey is an age recipient of a type this script cannot encrypt to, so nothing is sent"; return 2 ;;
    *) echo "$B's prekey is not an age key that age will encrypt to"; return 1 ;;
  esac
  echo "$s $k $na $c"
}
dr_resolve(){ # <address> [the mailbox dr_lookup read] → prints "<serial> <age recipient> <its signer's rank> <the statement's SHA-256>" only when EVERY check passes; otherwise there is nothing to encrypt to. The identity is the pinned one, or at first contact the served one, kept only once its prekey statement has verified. Without a mailbox read for it, it reads one, and keeps what verifies of the revocation of certificates it carries before the statement is checked against it
  local B=$1 d="$DR/peers/$1" f r s k na c sc h
  dr_isaddr "$B" || dr_refuse "not an address" || return 1
  dr_gone "$B"; case $? in      # a peer this mailbox holds a revocation of is refused before anything is asked, whatever the server now serves for it
    0) dr_err "REVOKED: $B is revoked, for good, and the revocation verifies: ask its owner for their new address"; return 1 ;;
    3) dr_refuse "the revocation kept for $B does not verify"; return 1 ;;
  esac
  if [ -n "${2-}" ] && [ -s "$2" ]; then cp "$2" "$DR/peer.json" || return 1
  else dr_look "$B" > "$DR/peer.json" || return 1
    dr_ismailbox "$DR/peer.json" && jq -c '{identity, revoked_certificates, revoked_certificates_signature}' "$DR/peer.json" > "$DR/rev.json" ||
      dr_refuse "the server's answer for $B is not one this client reads: one JSON object, each byte field base64" || return 1
    dr_take "$B"; [ $? != 3 ] || dr_refuse "what this mailbox keeps about $B does not verify, or could not be written" || return 1
  fi
  dr_shape "$DR/peer.json" mailbox && dr_bytes "$DR/peer.json" identity "$DR/new.doc" && dr_bytes "$DR/peer.json" prekey "$DR/peer.txt" && dr_bytes "$DR/peer.json" prekey_signature "$DR/peer.sig" ||
    dr_refuse "the server's answer for $B is not one this client reads: one JSON object, each byte field base64" || return 1
  f="$d/identity.doc"      # a pin always wins
  [ -e "$f" ] || { f="$DR/new.doc"; [ -s "$f" ] || dr_refuse "no identity for $B in the response" || return 1; }
  [ "$(dr_address "$f")" = "$B" ] || dr_refuse "the identity the server sent does not hash to $B" || return 1
  dr_idcheck "$f"; case $? in 0) ;;
    2) dr_refuse "$B's identity is of a key type this script does not verify, so nothing it signs can be checked here and nothing is sent"; return 1 ;;
    *) dr_refuse "$B's identity is not a two-line identity document in the one form of its key type, with a valid key"; return 1 ;;
  esac
  [ -s "$DR/peer.txt" ] && [ -s "$DR/peer.sig" ] || dr_refuse "no prekey for $B in the response" || return 1
  r=$(dr_prekeycheck "$DR/peer.txt" "$DR/peer.sig" "$B" "$f"); case $? in 0) ;;
    2) jq -cn --arg m "REFUSED: $r" '{type:"error", code:"unsupported_prekey_type", detail:$m}' >&2; return 1 ;;      # a refusal with a code of its own: nothing is wrong with the statement
    *) dr_refuse "$r"; return 1 ;;
  esac
  read -r s k na c <<< "$r"
  sc=$(cat "$d/rank" 2> /dev/null || echo 0)      # a mailbox's statements are ordered by (c, p), their signer's rank first, then their own serial (PROTOCOL.md §5.3): a later signer outranks any serial under an earlier one, so a mailbox that moved to a new certificate is followed whatever serial it publishes
  [ "$c" -ge "$sc" ] || dr_refuse "rollback: $B's prekey is signed by a signer of rank $c, below one already seen" || return 1
  [ "$c" -gt "$sc" ] || [ "$s" -ge "$(cat "$d/serial" 2> /dev/null || echo 0)" ] || dr_refuse "rollback: $B's prekey serial $s is below one already seen" || return 1
  dr_mode "$B" "$c"; case $? in      # by what this mailbox holds, which the read above kept: only the identity's own signature moves an address to working-key mode, or revokes a signer
    1) if [ "$c" = 0 ]; then dr_refuse "$B's prekey is signed by its identity, and $B is in working-key mode, where its identity's own signature is revoked: its owner must publish a new one"; else dr_refuse "$B's prekey is signed under a certificate its identity has revoked: its owner must publish a new one"; fi; return 1 ;;
    2) dr_refuse "$B's prekey is signed under a certificate, and $B is in identity mode, where its identity signs and no certificate is taken"; return 1 ;;
    3) dr_refuse "the revocation of certificates kept for $B does not verify"; return 1 ;;
  esac
  [ "$na" -gt "$(dr_now)" ] || dr_refuse "$B's prekey has expired: its owner must publish a new one" || return 1
  h=$(sha256sum < "$DR/peer.txt" | cut -c1-64) && dr_hex "$h" || return 1      # the statement's bytes as served, never its signature, which another encoding of an ECDSA signature changes (PROTOCOL.md §11.10)
  dr_meet "$B" "$f" && dr_putline "$d/serial" "$s" && dr_putline "$d/rank" "$c" && dr_put "$DR/peer.txt" "$d/prekey.txt" && dr_put "$DR/peer.sig" "$d/prekey.sig" || return 1      # recorded only after every check passed
  echo "$s $k $c $h"
}
dr_put(){ local d; d=$(dirname "$2") && cp "$1" "$2.new" && sync "$2.new" && mv "$2.new" "$2" && sync "$d"; }      # <file> <path> → <path> holds the file's bytes, on disk before this returns: written beside it, synced, moved into place, and its directory synced, as the Go client's writeFile does. A crash leaves the old file or the new one, never an empty one
dr_putline(){ local d; d=$(dirname "$1") && printf '%s\n' "$2" > "$1.new" && sync "$1.new" && mv "$1.new" "$1" && sync "$d"; }      # <path> <value> → dr_put of the value alone on its line
dr_putout(){ local d; d=$(dirname "$1") && "${@:2}" > "$1.new" && sync "$1.new" && mv "$1.new" "$1" && sync "$d" || { rm -f "$1.new"; return 1; }; }      # <path> <command> [args] → dr_put of what the command prints: a command that fails or is stopped midway leaves no file cut short
dr_meet(){ local d="$DR/peers/$1"; mkdir -p "$d" && { [ -e "$d/identity.doc" ] || dr_put "$2" "$d/identity.doc"; }; }      # <address> <its checked identity document> → pinned, unless it is already: called only for an identity that signed something this mailbox verified

# recipe: revocation
dr_revcheck(){ # <address> <identity document> <signature> → 0 only for a revocation of that address: the document hashes to it and is one this script verifies, and the signature is that identity's OWN over the fixed statement. The signers line names the identity's key with no cert-authority, so a working key's signature, which carries a certificate, is not taken: a working key can be stolen without the identity, and must not end the address
  local x k
  dr_idcheck "$2" "$1" && dr_bound "$3" "$2" && dr_sshsig "$3" || return 1
  printf '%s %s\n' "$1" "$(sed -n 2p "$2")" > "$DR/signers"
  printf 'dromas-revoke-v1\n%s\n' "$1" | ssh-keygen -Y verify -f "$DR/signers" -I "$1" -n "dromas-revoke-v1:$1" -s "$3" > /dev/null 2>&1
}
dr_gone(){ # <address> → 0 if this mailbox holds a revocation of it: peers/<address>/revoke.sig beside its pinned identity, or revoked.sig for this mailbox's own. It is checked again each time. 1 if none is kept. 3 if one is kept and does not verify: a fault of this mailbox, never a quiet "not revoked"
  local d="$DR/peers/$1/identity.doc" s="$DR/peers/$1/revoke.sig"
  [ "$1" != "$(cat "$DR/address" 2> /dev/null)" ] || { d="$DR/identity.doc"; s="$DR/revoked.sig"; }
  [ -e "$s" ] || return 1
  dr_revcheck "$1" "$d" "$s" || return 3
}
dr_certscheck(){ # <address> <identity document> <statement> <signature> → the serial it revokes through, only for a revocation of that address's certificates: signed by its identity's OWN key, as a revocation of the address is (no cert-authority, so a certificate cannot revoke another, or itself), and in its one exact form, the tag, the address and a serial, each on a line ending in LF, and nothing else. The serial is from 1 to 2^53 - 1 with no leading zero, compared by bash, whose numbers are exact there where awk's are not
  local L x k
  dr_idcheck "$2" "$1" && dr_bound "$4" "$2" && dr_sshsig "$4" || return 1
  printf '%s %s\n' "$1" "$(sed -n 2p "$2")" > "$DR/signers"
  ssh-keygen -Y verify -f "$DR/signers" -I "$1" -n "dromas-revoke-certs-v1:$1" -s "$4" < "$3" > /dev/null 2>&1 || return 1
  mapfile -t L < "$3"
  [ "$(printf '%s\n' "${L[@]}" | sha256sum)" = "$(sha256sum < "$3")" ] || return 1      # the file against itself rebuilt from its lines: every line ends in LF, and nothing is in it that a shell variable drops (a NUL)
  [ ${#L[@]} -eq 3 ] && [ "${L[0]}" = dromas-revoke-certs-v1 ] && [ "${L[1]}" = "$1" ] && [[ ${L[2]} =~ ^[1-9][0-9]{0,15}$ ]] && [ "${L[2]}" -le 9007199254740991 ] || return 1
  echo "${L[2]}"
}
dr_certskept(){ # <address> → the serial through which this mailbox holds that address's certificates revoked, checked again as it is read. It is kept as the record that carries it, one line of JSON {type, identity, revoked_certificates, revoked_certificates_signature}: peers/<address>/revoked-certs.json beside the pinned identity, or revoked-certs.json for this mailbox's own. 1 if none is kept. 3 if one is kept and does not verify under the identity this mailbox holds for the address: a fault of this mailbox, never a quiet "nothing revoked"
  local d="$DR/peers/$1/identity.doc" f="$DR/peers/$1/revoked-certs.json"
  [ "$1" != "$(cat "$DR/address" 2> /dev/null)" ] || { d="$DR/identity.doc"; f="$DR/revoked-certs.json"; }
  [ -e "$f" ] || return 1
  dr_shape "$f" record && dr_bytes "$f" revoked_certificates "$DR/kept.certs" && dr_bytes "$f" revoked_certificates_signature "$DR/kept.csig" &&
    dr_certscheck "$1" "$d" "$DR/kept.certs" "$DR/kept.csig" || return 3
}
dr_keepcerts(){ # <address> <identity document> <statement> <signature> → keeps the revocation of the address's certificates, if it verifies and runs through a higher serial than the one this mailbox holds: the highest stands, and a certificate once revoked stays so. One that does not verify, or runs no higher, changes nothing. 1 only for a fault of this mailbox
  local f="$DR/peers/$1/revoked-certs.json" v h
  [ "$1" != "$(cat "$DR/address" 2> /dev/null)" ] || f="$DR/revoked-certs.json"
  v=$(dr_certscheck "$1" "$2" "$3" "$4") || return 0
  h=$(dr_certskept "$1"); case $? in 0) [ "$v" -gt "$h" ] || return 0 ;; 1) ;; *) return 1 ;; esac
  [ "$f" = "$DR/revoked-certs.json" ] || dr_meet "$1" "$2" || return 1
  dr_b64 "$2" > "$f.i" && dr_b64 "$3" > "$f.l" && dr_b64 "$4" > "$f.g" && jq -cn --rawfile i "$f.i" --rawfile l "$f.l" --rawfile g "$f.g" '{type:"revocation_record", identity:$i, revoked_certificates:$l, revoked_certificates_signature:$g}' > "$f.new" && sync "$f.new" && mv "$f.new" "$f" && sync "$(dirname "$f")" && rm -f "$f.i" "$f.l" "$f.g"      # one file, moved into place whole and on disk before anything reads it: a statement is never kept without the signature that goes with it
}
dr_keep(){ # <address> <its identity document> <signature> → the revocation, kept for good: called only once dr_revcheck took it. A revoked address stays revoked
  if [ "$1" = "$(cat "$DR/address" 2> /dev/null)" ]; then dr_put "$3" "$DR/revoked.sig"; else dr_meet "$1" "$2" && dr_put "$3" "$DR/peers/$1/revoke.sig"; fi
}
dr_record(){ # <record> → the address it is a revocation of, only if it verifies; its parts are left in $DR/rev.doc and $DR/rev.sig. A record is one line of JSON, {type, identity, revocation_signature}: its type, revocation_record, which this script does not read, then the identity document and the signature, each base64
  local A
  dr_isrecord "$1" && dr_bytes "$1" identity "$DR/rev.doc" && dr_bytes "$1" revocation_signature "$DR/rev.sig" || return 1
  A=$(dr_address "$DR/rev.doc") && dr_revcheck "$A" "$DR/rev.doc" "$DR/rev.sig" && printf '%s\n' "$A"
}
dr_isrecord(){ # <file> → 0 only for a record: an answer dr_shape takes as a record, and each of its four byte members base64, or left out. What it holds is checked by whoever uses it
  local m r=0
  dr_shape "$1" record || return 1
  for m in identity revocation_signature revoked_certificates revoked_certificates_signature; do dr_bytes "$1" $m "$DR/record.part" || { r=1; break; }; done
  rm -f "$DR/record.part"; return $r
}
dr_ismailbox(){ # <file> → 0 only for a mailbox: an answer dr_shape takes as a mailbox, and each of its byte members base64, or left out. What it holds is checked by whoever uses it
  local m r=0
  dr_shape "$1" mailbox || return 1
  for m in identity prekey prekey_signature revoked_certificates revoked_certificates_signature; do dr_bytes "$1" $m "$DR/mailbox.part" || { r=1; break; }; done
  rm -f "$DR/mailbox.part"; return $r
}
dr_take(){ # <address> → keeps what verifies of $DR/rev.json, a server's answer about the address: a revocation of its certificates, of the address, or both. 0: this mailbox now holds a revocation of the address. 1: it does not: what the answer showed of one does not verify, which counts as nothing shown. 3: a fault of this mailbox
  if dr_bytes "$DR/rev.json" identity "$DR/rev.doc" && dr_bytes "$DR/rev.json" revoked_certificates "$DR/rev.certs" && [ -s "$DR/rev.certs" ] &&
    dr_bytes "$DR/rev.json" revoked_certificates_signature "$DR/rev.csig"; then      # a revocation of certificates rides in the same record. It is taken or not on its own: the address may well go on
    dr_keepcerts "$1" "$DR/rev.doc" "$DR/rev.certs" "$DR/rev.csig" || return 3
  fi
  [ "$(dr_record "$DR/rev.json")" = "$1" ] || return 1
  dr_keep "$1" "$DR/rev.doc" "$DR/rev.sig" || return 3
}
dr_lookup(){ # <address> [revocations] → reads the address's mailbox from this mailbox's server (GET /v1/<address>, dr_look), and keeps what verifies of the revocations it carries. A mailbox served carries the revocation of its certificates the server holds, and a revoked address is answered 410 revoked with its record. With revocations, where the server holds no such mailbox, it reads the address's revocations instead (GET /v1/<address>/revocations), which a server keeps with a mailbox there or none (PROTOCOL.md §11.15): a reader's ask at check 7, and a mailbox's of its own (§12.3, §12.5). The mailbox served is left in $DR/mailbox.json, for the seal that follows. 0: this mailbox holds a revocation of the address, and that is final. 1: none: the server served the mailbox, or holds no such mailbox, or said revoked and showed nothing that verifies, which comes to the same: only the identity's own signature revokes. 2: no answer from the mailbox's own server, which is not "none". 3: a fault of this mailbox: what it keeps for the address does not verify, or cannot be written
  local r
  rm -f "$DR/mailbox.json"
  dr_gone "$1"; case $? in 0) return 0 ;; 3) return 3 ;; esac
  if dr_look "$1" > "$DR/look.json" 2> "$DR/read.err"; then dr_ismailbox "$DR/look.json" || return 2; mv "$DR/look.json" "$DR/mailbox.json"      # a 2xx that is no mailbox is no answer, as one that is no JSON is
    jq -c '{identity, revoked_certificates, revoked_certificates_signature}' "$DR/mailbox.json" > "$DR/rev.json" && dr_take "$1"; r=$?; [ $r = 1 ] || return $r
  else case $(dr_code) in
    revoked) dr_takerecord "$1"; r=$?; [ $r = 1 ] || return $r ;;      # the record it carries proves itself, or counts as nothing shown
    no_such_mailbox) [ -z "${2-}" ] || { dr_revocations "$1"; return; } ;;
    *) cat "$DR/read.err" >&2; return 2 ;; esac; fi      # no answer: its error line, the status, the code and the wait, and none of the server's words
  return 1
}
dr_revocations(){ # <address> → reads the address's revocations from this mailbox's server (GET /v1/<address>/revocations) and keeps what verifies: dr_lookup's answer. A record that is no record is no answer; not_revoked, and revoked with nothing that verifies, are none
  local r w=$1; [ "$1" != "$(cat "$DR/address" 2> /dev/null)" ] || w="this mailbox"
  if dr_api GET "/v1/$1/revocations" > "$DR/rev.json" 2> "$DR/read.err"; then dr_isrecord "$DR/rev.json" || { dr_refuse "the server's answer for $w's revocations is not one this client reads: a record, each byte field base64"; return 2; }      # a 2xx that is no record is no answer, as one that is no JSON is
    dr_take "$1"; return
  fi
  case $(dr_code) in
    revoked) dr_takerecord "$1"; r=$?; [ $r = 1 ] || return $r ;;
    not_revoked) ;;
    *) cat "$DR/read.err" >&2; return 2 ;;
  esac
  return 1
}
dr_takerecord(){ # <address> → keeps what verifies of the record a 410 revoked carries, in $DR/error.json: dr_take's answer, or 1 where it carries no record
  jq -ce '.record | objects' "$DR/error.json" > "$DR/rev.json" 2> /dev/null && dr_isrecord "$DR/rev.json" || return 1
  dr_take "$1"
}
dr_finished(){ # → 0 while this mailbox may act as its address. 1: it holds its own revocation, which verifies, and signs nothing more as that address, no pass, no message and no statement, whatever any server answers: a server that never saw the revocation would take it all (PROTOCOL.md §12.5). It still asks and keeps records, which carry no pass. 4: it holds a revocation of its own certificates, a trip, which verifies: its address is in working-key mode, where its identity's own signature is revoked (PROTOCOL.md §5.1), and this script, whose mailbox is in identity mode and makes no trip, signs nothing more. 3: one it keeps does not verify, a fault of this mailbox, which stops the same
  local A; A=$(cat "$DR/address" 2> /dev/null)
  dr_gone "$A"; case $? in 1) ;; 0) return 1 ;; *) return 3 ;; esac
  dr_certskept "$A" > /dev/null; case $? in 1) return 0 ;; 0) return 4 ;; *) return 3 ;; esac
}
dr_done(){ # <what dr_finished returned> → says on stderr why this mailbox acts as its address no more
  case $1 in
    1) dr_err "REVOKED: this mailbox's own address is revoked, for good, and the revocation verifies. It can send and receive nothing more: make a new mailbox and give its address to those who write to this one" ;;
    4) if [ -s "$DR/serial" ]; then      # a mailbox that has published a statement of its own made every one in identity mode, and this script makes no trip: so another did, with its identity (PROTOCOL.md §12.5)
         dr_refuse "this mailbox holds a revocation of its own certificates that its identity signed and this mailbox did not make, so its identity is in other hands: the address is in working-key mode, and this mailbox signs nothing more. Revoke the address (the Go client's dromas revocation publish, with the address in full), which ends it for good, and give those who write to this one a new mailbox's address"
       else      # one that has published none, a mailbox restored from its identity, takes the trip as its mode (PROTOCOL.md §12.5): a mode this script does not sign in
         dr_refuse "this mailbox's address is in working-key mode, by a revocation of its certificates its identity signed, and this script signs in identity mode only: run this mailbox's identity with the Go client"
       fi ;;
    *) dr_refuse "a revocation this mailbox keeps of its own (revoked.sig or revoked-certs.json) does not verify: a fault of this mailbox, which acts as its address no more until it is put right" ;;
  esac
  return 1
}
dr_own(){ # after a call as this mailbox failed: if the server said this mailbox is revoked, asks it for the revocation, and says which it is. If it said its signer is (certificate_revoked), reads its own mailbox, or its revocations where the server holds no mailbox for it, and keeps what verifies, which may stop it (dr_finished, PROTOCOL.md §12.5). A server's word revokes nothing
  case $(dr_code) in
    revoked) ;;
    certificate_revoked) dr_lookup "$(cat "$DR/address")" revocations > /dev/null 2>&1; dr_finished || dr_done $?; return 0 ;;
    *) return 0 ;;
  esac
  if dr_lookup "$(cat "$DR/address")"; then dr_err "REVOKED: this mailbox's own address is revoked, for good, and the revocation verifies. It can send and receive nothing more: make a new mailbox and give its address to those who write to this one"
  else dr_err "the server showed no revocation of this mailbox that verifies, so this mailbox does not take itself as revoked"; fi
}

# recipe: send
dr_uuid(){ local h; h=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n'); printf '%s-%s-4%s-%x%s-%s\n' "${h:0:8}" "${h:8:4}" "${h:13:3}" $(( 0x${h:16:1} & 3 | 8 )) "${h:17:3}" "${h:20:12}"; }
dr_send(){ # <link or address> [body file] → one message, posted now or not at all: its envelope built once, then sealed and posted (dr_post), and nothing kept to post again. A send that fails says so and leaves nothing: run it again, and if the first post's answer was lost its reader gets two messages, under two msg_ids
  dr_held || { dr_lock dr_send "$@"; return; }
  local B f A id
  f=${2-}; A=$(cat "$DR/address") && B=$(dr_dest "${1-}") || return 1
  { if [ -n "$f" ]; then cat < "$f"; else cat; fi; } > "$DR/body.new" 2> /dev/null && mv "$DR/body.new" "$DR/body.txt" || { rm -f "$DR/body.new"; dr_err "the body${f:+ file $f} could not be read: nothing is sent"; return 1; }; f="$DR/body.txt"      # read ONCE, from the file named or stdin, into a new file moved into place: every check below and the envelope read these bytes, so a body from a pipe is sent, one changed after its check is not, and a body named $DR/body.txt is not emptied before it is read
  iconv -f UTF-8 -t UTF-8 < "$f" > /dev/null 2>&1 || { dr_spent; dr_refuse "the body is not UTF-8 text"; return 1; }
  id=$(dr_uuid) || { dr_spent; return 1; }
  jq -cn --arg from "$A" --arg to "$B" --arg id "$id" --argjson t "$(dr_now)" --arg i "$(dr_b64 "$DR/identity.doc")" --rawfile body "$f" \
    '{v:1, from:$from, to:$to, sent_at:($t|todate), msg_id:$id, identity:$i, body:$body}' > "$DR/send.P" 2> /dev/null || { dr_spent; dr_err "the envelope could not be built: nothing is sent"; return 1; }      # ONE line, ending in a line feed: exactly the bytes that are signed. It carries this mailbox's identity document, so its reader need not ask the server who wrote it
  why=$(dr_envcheck "$DR/send.P" "$A" "$B") || { dr_spent; dr_refuse "nothing is sent, since its reader would refuse this message: ${why#*: }"; return 1; }      # read back as its reader will, and as dr_seal does
  dr_post "$B" "$DR/send"; local rc=$?; dr_spent; return $rc
}
dr_spent(){ rm -f "$DR/body.txt" "$DR/send.P" "$DR/seal.P" "$DR/seal.sig" "$DR/seal.age" "$DR/seal.query" "$DR/mailbox.json" "$DR/receipt.json"; }      # what a send wrote to post its message, gone once it is posted or refused: the body, the envelope, its seal, the mailbox it was sealed to and the server's receipt. sent/ is the record of what was sent
dr_agehead(){ echo 1627; }      # <age recipient> → the size of an age file's header for one key of its type, mlkem768x25519, the one a prekey has: its fields are fixed-size, so it never varies
dr_sealed(){ echo $(($(dr_agehead "$2") + 16 + $1 + 16 * ($1 > 65536 ? ($1 + 65535) / 65536 : 1))); }      # <plaintext bytes> <age recipient> → the size of the age file holding them: the header, a 16-byte nonce, and a 16-byte tag after each 64 KiB chunk
dr_blocks(){ # <size> → the size rounded up to a whole number of blocks. A block is 1/16 of the size, rounded up to a power of two, and never under 1 KiB: 1 KiB blocks up to 16 KiB, 2 KiB up to 32 KiB, and on
  local b=1024; while [ $((16 * b)) -lt "$1" ]; do b=$((b * 2)); done; echo $((($1 + b - 1) / b * b))
}
dr_padding(){ # <message bytes: the envelope's line and its signature> <age recipient> → "<padding bytes> <age file size>": the padding after the signature that makes the age file a whole number of blocks, so the server sees a message's size only to within a block. A message already on a block gets none
  local n=$1 s c; s=$(dr_blocks "$(dr_sealed "$n" "$2")"); c=$((s - $(dr_agehead "$2") - 16))      # what a file of that size has for its chunks, each with its tag
  echo "$((c - 16 * (c > 65552 ? (c + 65551) / 65552 : 1) - n)) $s"
}
dr_seal(){ # <address> <envelope stem> [the mailbox dr_lookup read] → what to post: $DR/seal.age, the envelope <stem>.P dated at this post ($DR/seal.P: its sent_at this clock, and nothing else changed, as a signed request's time is when it was signed, made anew for each attempt), signed for that recipient only, by this mailbox's identity, then the line, the signature and the padding encrypted to the recipient's VERIFIED prekey; and $DR/seal.query, the query that names that prekey statement. It is git's layout for a signed tag: the signed bytes as they are, then the signature block. The envelope is read as its recipient will read it first. A seal is made for one post and never kept: dr_post seals the envelope again for its one retry
  local B=$1 o=$2 s="$DR/seal" A r k f t why ps pc ph d; rm -f "$s.P" "$s.sig" "$s.age" "$s.query"; A=$(cat "$DR/address") || return 1
  why=$(dr_envcheck "$o.P" "$A" "$B") && [ "$(wc -l < "$o.P")" -eq 1 ] && [ "$(jq -r .identity "$o.P")" = "$(dr_b64 "$DR/identity.doc")" ] || dr_refuse "the envelope is not one this mailbox made for that address${why:+: $why}" || return 1
  d=$(jq -nr --argjson t "$(dr_now)" '$t | todate') && jq -c --arg d "$d" '.sent_at = $d' "$o.P" > "$s.P" || return 1      # written again by jq, as dr_send wrote it: the script seals only an envelope it has just built
  why=$(dr_envcheck "$s.P" "$A" "$B") && [ "$(wc -l < "$s.P")" -eq 1 ] && jq -e --arg d "$d" --slurpfile w "$o.P" '.sent_at == $d and del(.sent_at) == ($w[0] | del(.sent_at))' "$s.P" > /dev/null 2>&1 ||
    dr_refuse "the envelope does not read back as itself once dated at this post${why:+: $why}" || return 1
  r=$(dr_resolve "$B" "${3-}") && read -r ps k pc ph <<< "$r" && [ -n "$ph" ] || return 1
  dr_finished || { dr_done $?; return 1; }      # at every signature, as at every pass and statement
  ssh-keygen -q -Y sign -n "dromas-msg-v1:$B" -f "$DR/identity" < "$s.P" > "$s.sig" && tail -n 1 "$s.sig" | cmp -s - <(printf -- '-----END SSH SIGNATURE-----\n') ||
    dr_refuse "the identity did not sign the message whole: nothing is sent" || return 1      # ssh-keygen does not check its write to stdout: a full disk leaves the file short and exits 0
  read -r f t <<< "$(dr_padding $(($(wc -c < "$s.P") + $(wc -c < "$s.sig"))) "$k")" && [ -n "$t" ] || return 1
  { cat "$s.P" "$s.sig" && head -c "$f" /dev/zero | tr '\0' .; } | age -r "$k" > "$s.age" || return 1
  [ "$(wc -c < "$s.age")" -eq "$t" ] || { rm -f "$s.age"; dr_refuse "the encrypted message is not the $t bytes its padding was made for: it is not sent at a size that tells its length"; return 1; }
  printf 'statement=%s\n' "$ph" > "$s.query"      # the prekey statement is named by the SHA-256 of its bytes as served, in lowercase hex (dr_resolve; PROTOCOL.md §11.10). The body is the age file as it is, and no signature is beside it: the server knows the sender from the pass the post carries
}
dr_post(){ # <address> <envelope stem> → seals it and POSTs it; on 409 stale_prekey, seals the SAME envelope again, once, to the mailbox read again. Before each seal, the recipient's mailbox is read (dr_lookup), and the seal is made to what this mailbox then holds, dated after that read. A post that fails is told, and nothing is kept
  local B=$1 o=$2 c try
  dr_finished; c=$?; case $c in      # a mailbox that holds its own revocation can never deliver it: every reader that holds the revocation refuses its messages, whenever they were signed
    0) ;;
    1) dr_err "REVOKED: this mailbox's own address is revoked, for good, and the revocation verifies, so its messages can never be delivered: nothing is sent"; return 1 ;;
    *) dr_done $c; return 1 ;;
  esac
  for try in first retry; do
    rm -f "$DR/error.json"
    dr_lookup "$B"; case $? in      # asked before every post, the retry's included: what verifies is kept, and "none held" is the server's word, kept nowhere
      0) dr_err "REVOKED: $B is revoked, for good, and the revocation verifies, so it can never be delivered: nothing is sent"; return 1 ;;
      1) rm -f "$DR/error.json" ;;      # its 404 is an answer, and not one about the message
      2) rm -f "$DR/error.json"; dr_err "the mailbox $B could not be read, so nothing is sent"; return 1 ;;      # no answer is not "none held". Whatever code the failed lookup carried is no answer about the message
      *) dr_refuse "what this mailbox keeps about $B does not verify, or could not be written: nothing is sent"; return 1 ;;
    esac
    dr_seal "$B" "$o" "$DR/mailbox.json" && dr_owner POST "/v1/$B/messages?$(cat "$DR/seal.query")" "$DR/seal.age" > "$DR/receipt.json" && dr_receipt && { dr_sent "$B"; return; }      # sealed to the mailbox the lookup read, and dated once it was read
    [ "$try" = first ] && [ "$(dr_code)" = stale_prekey ] || break      # a newer prekey: the same envelope, sealed again once, to the mailbox read again
  done
  c=$(dr_code)
  case $c in revoked) dr_lookup "$B" ;; sender_revoked) dr_lookup "$(cat "$DR/address")" ;; esac      # a server's "revoked" is checked: with the revocation in hand it is final, and without one it is a call that failed
  if dr_gone "$B" || dr_gone "$(cat "$DR/address")"; then dr_err "REVOKED: the revocation verifies, so it can never be delivered: nothing is sent"; return 1; fi
  case $c in
    revoked | sender_revoked) dr_err "the server showed no revocation that verifies, so this mailbox does not take that address as revoked: nothing is sent" ;;
    *) dr_err "nothing is sent" ;;
  esac
  return 1
}
dr_receipt(){ # → 0 only for a receipt in $DR/receipt.json that names the ciphertext this mailbox posted, $DR/seal.age (its id the SHA-256 of it, PROTOCOL.md §11.10), and whose times are times. Anything else is no receipt, and nothing is recorded as sent
  dr_shape "$DR/receipt.json" receipt && jq -e --arg h "$(sha256sum < "$DR/seal.age" | cut -c1-64)" '.id == $h and all(.received_at, .expires_at; test("\\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\\z"))' "$DR/receipt.json" > /dev/null 2>&1 &&      # compared in jq: $(…) drops trailing LFs and every NUL, so a time is held to its form there before dr_time reads it
    dr_time "$(jq -r '.received_at | strings' "$DR/receipt.json")" > /dev/null && dr_time "$(jq -r '.expires_at | strings' "$DR/receipt.json")" > /dev/null && return 0
  dr_refuse "the server's receipt does not name the ciphertext this mailbox posted, or its times are not times: it is not recorded as sent"
}
dr_sent(){ # <address> → sent/<address>.<msg_id>.json, one line, {"envelope":…,"receipt":…}: the envelope as the post that was taken dated and signed it ($DR/seal.P), as the recipient's inbox/ keeps it, and the server's receipt; and a sent line: the server's id, the msg_id and the address, both from the envelope posted. sent/ is yours to prune
  local m t; m=$(jq -r .msg_id "$DR/seal.P") && t="$DR/sent/$1.$m.json" || return 1
  mkdir -p "$DR/sent" && dr_putout "$t" dr_line "$DR/seal.P" "$DR/receipt.json" || { dr_err "sent, but not recorded in sent/"; return 1; }
  dr_out sent --arg id "$(jq -r .receipt.id "$t")" --arg msg_id "$m" --arg to "$1"
}

# recipe: receive
dr_recv(){ # drains the mailbox, every page up to a drain's limits. ACCEPT → inbox/ and a message line on stdout. REFUSED → refused/, never delivered, and a refused line on stdout. Both are acked
  dr_held || { dr_lock dr_recv "$@"; return; }
  DR_LISTED=; dr_drain; local rc=$?; [ -z "$DR_LISTED" ] || dr_prune "$DR_LISTED"; return $rc      # keys deleted by this clock only once the server has answered the list, so has taken a pass dated by it, and by that pass's date: a clock far ahead is stopped at its pass, one that moves while the list is in flight deletes nothing by where it went, and the keys that messages wait for stay (PROTOCOL.md §12.4)
}
dr_drain(){ # stops at a transient error or a fault of this mailbox, leaving the rest on the server for the next drain. And at a number of messages and of pages (below): a server that lists messages without end costs one run that much
  local B c="" n i id k=0 pages=0; B=$(cat "$DR/address") || return 1
  dr_finished || { dr_done $?; return 1; }
  rm -f "$DR/asked" "$DR/reread"      # the senders this drain has asked the server about, one lookup each, and those it has read again before refusing a certificate (dr_judge)
  while :; do
    [ $((pages += 1)) -le 100 ] || { dr_out more --arg detail "this run stopped at the most one drain takes: run recv again for the rest, which is still on the server"; return 0; }
    dr_owner GET "/v1/$B/messages${c:+?cursor=$c}" > "$DR/list.json" || { dr_own; return 1; }
    [ "$pages" -gt 1 ] || { DR_LISTED=$(dr_taken) && dr_forget "$DR_LISTED"; } || return 1      # the replay set pruned by this clock only once the server has taken a pass dated by it, and by that pass's date (dr_taken): a drain that a clock far off would prune is stopped at its pass first. DR_LISTED tells dr_recv the same reading for the keys
    dr_shape "$DR/list.json" list && n=$(jq -r '.messages | length' "$DR/list.json") || { dr_err "the server's list of messages is not one this client reads: the messages stay on the server"; return 1; }
    for ((i = 0; i < n; i++)); do
      id=$(jq -r --argjson i "$i" '.messages[$i].id | strings | select(test("\\A[0-9a-f]{64}\\z"))' "$DR/list.json") && dr_hex "$id" || continue      # tested in jq: $(…) drops trailing LFs and every NUL
      [ $((k += 1)) -le 1000 ] || { dr_out more --arg detail "this run stopped at the most one drain takes: run recv again for the rest, which is still on the server"; return 0; }
      if ! grep -q "^$id " "$DR/seen" 2> /dev/null; then jq -c --argjson i "$i" '.messages[$i]' "$DR/list.json" > "$DR/entry.json" && dr_one "$B" "$id" "$DR/entry.json" || return 1; fi   # an id already handled is only acked again
      dr_owner DELETE "/v1/$B/messages/$id" > /dev/null || [ "$(dr_code)" = no_such_message ] || return 1
    done
    c=$(jq -r '.next_cursor // empty' "$DR/list.json"); [ -n "$c" ] || return 0      # one or more of A-Z, a-z, 0-9, - and _ (dr_shape), so it goes into the next query as it is
  done
}
dr_one(){ # <me> <id> <its list entry> → 0 once the message is judged and its verdict is on disk; 1 on a transient error or a fault of this mailbox, so it is not acked. The fetch answers the ciphertext alone, of the size the list gives; when it came, on the server's word, is the list entry's, and who sent it is its signature's: a from the entry carries is never read
  local B=$1 id=$2 m="$DR/msg" A why rc h z
  rm -f "$m.json" "$m.age" "$m.sig" "$m.P" "$m.T" "$m.doc"
  cp "$3" "$m.json" && z=$(jq -r '.size // 0' "$m.json") || return 1      # an integer from 0 to 16 MiB, the protocol's largest ciphertext, or null, which is 0 (dr_shape's list; PROTOCOL.md §11.10)
  if dr_owner GET "/v1/$B/messages/$id" "" --max-filesize $((z > 0 ? z : 1)) > "$m.age"; then :      # no more than the list says it holds, and every size up to 16 MiB, the protocol's largest ciphertext, which every reader takes; the list's form holds the size to it (dr_shape; PROTOCOL.md §11.10, §12.3)
  elif [ "$(dr_code)" = no_such_message ]; then return 0      # already gone
  elif [[ $(dr_status) != 2?? ]]; then return 1; fi      # a 2xx that curl cut short is a body past its size
  [ "$(wc -c < "$m.age" 2> /dev/null)" = "$z" ] || { dr_err "the server's answer for message $id is not the $z bytes of ciphertext its list gives: it stays on the server"; return 1; }      # an answer that breaks its form, the server's fault and not the sender's: no verdict, and no ack
  h=$(sha256sum < "$m.age" | cut -c1-64)      # files are named by the hash computed here, never the server's id
  rm -f "$DR/said"; why=$(dr_judge "$B" "$m"); rc=$?; cat "$DR/said" 2> /dev/null; rm -f "$DR/said"      # what the judge met on the way is printed here: its stdout is its verdict
  if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then [ "$h" = "$id" ] || { why="bad_id: the server's id for it is not the SHA-256 of its ciphertext"; rc=1; }; fi
  case $rc in
    0) A=$(jq -r .from "$m.P") && dr_putout "$DR/inbox/$h.json" dr_line "$m.P" && dr_seen "$A" "$m" "$h" || return 1      # stored, then seen, both on disk before the ack: a crash delivers again, never loses
       printf '{"type":"message","id":"%s","envelope":' "$h" && cat "$DR/inbox/$h.json" && echo '}' ;;      # the envelope the line inbox/ keeps, as its bytes are (jq would write the line breaks dr_line escaped), and only inside "envelope", so a member it gains later never meets the line's own (#356)
    2) dr_out duplicate --arg id "$h" --arg detail "a retry of a message already delivered: not delivered again" ;;
    3) dr_err "$why: nothing is judged or acked until this mailbox is fixed"; return 1 ;;
    4) dr_err "$why: the message stays on the server, and the next recv asks again"; return 1 ;;
    *) dr_putout "$DR/refused/$h.json" dr_kept "$m" "$h" && dr_putline "$DR/refused/$h.reason" "$why" || return 1      # what dr_kept keeps of the message, the id this script hashed and the ciphertext in base64, and beside it why: "<code>: <words>", this script's own words, never the message's
       dr_out refused --arg id "$h" --arg code "${why%%: *}" --arg detail "${why#*: }" ;;
  esac
}
dr_kept(){ # <message stem> <id> → the message as refused/ keeps it: the id this script hashed, and the ciphertext its fetch answered, <stem>.age, in base64; none of the server's strings, so nothing the server chose is there to be read
  local rc; dr_b64 "$1.age" > "$1.b64" && jq -cj -n --rawfile c "$1.b64" --arg id "$2" '{id: $id, ciphertext: $c}'; rc=$?; rm -f "$1.b64"; return $rc      # base64 of the bytes, a file of ASCII, which jq carries as it is
}
dr_judge(){ # <me> <message stem> → 0 only if EVERY check passes, in this order; 2 for a resend of an accepted msg_id; 1 refused, with "<code>: <words>" on stdout, the words this script's own and never the message's; 3 a fault of this mailbox, no verdict; 4 no answer from the server on whether the sender is revoked, or on its mode, no verdict. Who the sender is, is never asked of the server, nor read from its list: the message carries what proves it. The one thing asked is whether a revocation of that sender, or of its certificates, exists, and the answer proves itself
  local B=$1 m=$2 ids=() k h A c f r
  for k in "$DR"/prekeys/*.agekey; do [ -e "$k" ] || continue; age-keygen -y "$k" > /dev/null 2>&1 || { echo "cannot read the prekey key $k"; return 3; }; ids+=(-i "$k"); done      # a key file age cannot read is a fault of this mailbox, which stops the drain: never a message refused for it
  [ ${#ids[@]} -gt 0 ] || { echo "this mailbox has no prekeys"; return 3; }
  age -d "${ids[@]}" < "$m.age" > "$m.T" 2> /dev/null || { echo "undecryptable: it does not decrypt with this mailbox's prekeys"; return 1; }
  A=$(dr_open "$B" "$m") || { echo "$A"; return 1; }      # the sender, proved by what was decrypted
  f=$(dr_floor 2> /dev/null) || { echo "$DR/seen-floor names no time"; return 3; }
  [ "$f" -eq 0 ] || [ "$(dr_time "$(jq -r .sent_at "$m.P")")" -ge $((f + 33*86400)) ] || { echo "stale: sent_at is before this mailbox's replay set reaches back to, since its clock once read later than it does now"; return 1; }      # freshness has a floor too: a sent_at before the highest cutoff the replay set was pruned at may be a message whose line went, and so may one up to 33 days above it, a retry of such a message, dated afresh up to 33 days after its first copy (check 9 knows a retry by that copy's line). dr_open checked sent_at's grammar
  if ! grep -qxF -e "$A" "$DR/asked" 2> /dev/null; then      # the server is asked once for each sender in a drain. That it holds none is an answer; no answer is not, and the message then stays where it is
    dr_lookup "$A" revocations >> "$DR/said"; case $? in 0) ;; 1) printf '%s\n' "$A" >> "$DR/asked" ;; 3) echo "what this mailbox keeps of its sender's revocations does not verify, or cannot be written"; return 3 ;; *) echo "whether its sender is revoked could not be asked"; return 4 ;; esac
  fi
  dr_gone "$A"; case $? in      # nobody can vouch for when a signature was made, so a revocation reaches back over everything that address signed
    0) echo "revoked: its sender's address is revoked, and the revocation verifies: nothing signed for that address is taken, whenever it was signed"; return 1 ;;
    3) echo "the revocation kept for $A does not verify"; return 3 ;;
  esac
  c=$(dr_rank "$m.sig" "$m.doc" "$A") || { echo "cannot read the signer of a signature that verified"; return 3; }
  dr_mode "$A" "$c"; r=$?      # the same answer carried the sender's revocation of its certificates, if it has one, which gives its mode (PROTOCOL.md §5.1): the address goes on
  if [ $r = 2 ] && ! grep -qxF -e "$A" "$DR/reread" 2> /dev/null; then      # a certificate from a sender whose trip this mailbox does not hold: read once more, once for each sender in a drain, since the trip may reach the sender's server's store later than its first message under a certificate
    printf '%s\n' "$A" >> "$DR/reread"
    dr_lookup "$A" revocations >> "$DR/said"; case $? in 0 | 1) ;; 3) echo "what this mailbox keeps of its sender's revocations does not verify, or cannot be written"; return 3 ;; *) echo "whether its sender's mode takes its signer could not be asked"; return 4 ;; esac
    dr_gone "$A"; case $? in
      0) echo "revoked: its sender's address is revoked, and the revocation verifies: nothing signed for that address is taken, whenever it was signed"; return 1 ;;
      3) echo "the revocation kept for $A does not verify"; return 3 ;;
    esac
    dr_mode "$A" "$c"; r=$?
  fi
  dr_admitted "$A" "$c" $r || return
  [ ! -e "$DR/seen" ] || [ -r "$DR/seen" ] || { echo "cannot read $DR/seen"; return 3; }
  h=$(sha256sum < "$m.age" | cut -c1-64)
  ! grep -q "^$h " "$DR/seen" 2> /dev/null || { echo "replay: this ciphertext was already received"; return 1; }
  dr_meet "$A" "$m.doc" || { echo "cannot write under $DR/peers"; return 3; }
  ! grep -q " $A $(jq -r .msg_id "$m.P")\$" "$DR/seen" 2> /dev/null || return 2
}
dr_admitted(){ # <sender> <its signer's rank> <what dr_mode returned> → check 7's verdict on the mode (PROTOCOL.md §12.3): 0 for a signer the sender's mode takes; 1, with "<code>: <words>", for one it refuses: certificate_revoked for a rank at or below the sender's revocation of its certificates, the identity's own among them, and bad_signature for a certificate from a sender in identity mode; 3, with words, for what is kept that does not verify
  case $3 in
    0) return 0 ;;
    1) if [ "$2" = 0 ]; then echo "certificate_revoked: it is signed by its sender's identity, and its sender's address is in working-key mode, where its identity's own signature is revoked: nothing it signs is taken, whenever it was signed"
       else echo "certificate_revoked: it is signed under a certificate its sender's identity has revoked: nothing signed under it is taken, whenever it was signed"; fi; return 1 ;;
    2) echo "bad_signature: it is signed under a certificate, and its sender's address is in identity mode, where its identity signs and no certificate is taken"; return 1 ;;
    *) echo "the revocation of certificates kept for $1 does not verify"; return 3 ;;
  esac
}
dr_open(){ # <me> <message stem> → the sender's address, only if what was decrypted, <stem>.T, is a message for this mailbox that its sender signed; otherwise "<code>: <words>", and 1. It leaves the envelope in <stem>.P, its signature in <stem>.sig and the sender's identity document in <stem>.doc
  local B=$1 m=$2 A
  # Line 1 is the envelope, line 2 begins the signature, the first END line ends it, and nothing after that is read. Each part has one place; nothing is searched for. The END line is the first line that begins so, and it must end there, in a line feed
  head -n 1 "$m.T" > "$m.P"; sed -n '2,/^-----END SSH SIGNATURE-----/p' "$m.T" > "$m.sig"
  [ "$(tail -c 1 "$m.P" | od -An -tx1 | tr -d ' \n')" = 0a ] && head -n 1 "$m.sig" | cmp -s - <(printf -- '-----BEGIN SSH SIGNATURE-----\n') && tail -n 1 "$m.sig" | cmp -s - <(printf -- '-----END SSH SIGNATURE-----\n') ||      # each compared as bytes: $(…) drops a NUL
    { echo "bad_message: what was decrypted is not an envelope line and then a signature block"; return 1; }
  dr_envform "$m.P" || return 1
  jq -e '.from | . == null or type == "string"' "$m.P" > /dev/null 2>&1 || { echo "bad_envelope: the envelope is malformed: its from is not what that field holds"; return 1; }
  jq -e 'has("identity")' "$m.P" > /dev/null 2>&1 || { echo "bad_identity: the envelope carries no identity document"; return 1; }
  dr_bytes "$m.P" identity "$m.doc" && [ -s "$m.doc" ] || { echo "bad_identity: the envelope's identity is not base64 of an identity document"; return 1; }      # its bytes, compared as bytes
  dr_idcheck "$m.doc"; case $? in 0) ;;      # a well-formed document of a key type this script does not verify has its own code, once it is known to be the sender's
    2) jq -e --arg a "$(dr_address "$m.doc")" '.from == $a' "$m.P" > /dev/null 2>&1 || { echo "reattributed: the envelope's from is not the address of the identity it carries"; return 1; }
       echo "unsupported_key_type: the sender's identity is of a key type this client does not verify"; return 1 ;;
    *) echo "bad_identity: the envelope's identity document breaks its format or its key checks"; return 1 ;;
  esac
  A=$(dr_address "$m.doc")      # the sender: the hash of the identity document the envelope carries. The document proves itself, and the signature must now verify under it
  jq -e --arg a "$A" '.from == $a' "$m.P" > /dev/null 2>&1 || { echo "reattributed: the envelope's from is not the address of the identity it carries"; return 1; }
  dr_signed "$A" "$m.doc" "dromas-msg-v1:$B" "$m.sig" "$m.P" > /dev/null; case $? in      # over line 1 exactly as decrypted, never over anything rebuilt: either form of signer, whose mode is check 7's (dr_judge)
    0) ;; 2) echo "bad_signature: the certificate of the key that signed it has ended"; return 1 ;;
    3) echo "bad_signature: the certificate of the key that signed it has not begun, by this machine's clock"; return 1 ;;
    *) echo "bad_signature: it is not signed for this mailbox by the sender's identity, or by a working key the sender's identity certified"; return 1 ;;
  esac
  dr_envcheck "$m.P" "$A" "$B" || return 1
  printf '%s\n' "$A"
}
dr_envform(){ # <envelope> → 0 only for one JSON object with no member named twice in any object in it: a name given twice could be read as two values of one signed text. Otherwise the reason, and 1
  local n; n=$(jq -n --stream '[inputs | if length == 2 then .[0] else .[0][:-1] end | select(length > 0 and (.[-1] | type) == "string")] | length' "$1" 2> /dev/null) &&      # every member of every object, as written: one named twice is counted twice here, and once below
    jq -en --argjson n "$n" '[inputs] | length == 1 and (.[0] | type == "object" and ([.. | objects | length] | add) == $n)' "$1" > /dev/null 2>&1 ||
    { echo "bad_envelope: the envelope is not one JSON object with no member named twice"; return 1; }
}
dr_envcheck(){ # <envelope> <signer> <this mailbox> → 0 only for one JSON object, keys exact and none twice, checked in PROTOCOL.md §12.3 check 6's order: a body and fields that are strings, v the number 1, from the signer and to this mailbox, a msg_id, and sent_at no older than 33 days and no more than an hour ahead; otherwise the reason, and 1
  local e=$1 sa
  dr_envform "$e" || return 1
  jq -e 'has("body") and all(.from, .to, .msg_id, .sent_at, .subject, .in_reply_to, .supersedes, .identity; . == null or type == "string") and .v == 1' "$e" > /dev/null 2>&1 ||
    { echo "bad_envelope: the envelope is malformed: a body, fields that are strings, and v the number 1"; return 1; }      # in PROTOCOL.md §12.3 check 6's order: a body and every member of its type, v, to, msg_id, then the time
  jq -e --arg a "$2" --arg b "$3" '.from == $a and .to == $b' "$e" > /dev/null 2>&1 || { echo "reattributed: the inner from/to do not match the signer and this mailbox (re-attribution)"; return 1; }
  jq -e '.msg_id | type == "string" and test("\\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\z")' "$e" > /dev/null 2>&1 || { echo "bad_envelope: the envelope has no valid msg_id"; return 1; }
  jq -e '.sent_at | strings | test("\\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\\z")' "$e" > /dev/null 2>&1 && sa=$(dr_time "$(jq -r .sent_at "$e")") || { echo "bad_envelope: the envelope's sent_at is not a UTC timestamp to the second"; return 1; }      # its grammar tested in jq first: $(…) drops trailing LFs and every NUL
  [ "$sa" -ge $(($(dr_now) - 33*86400)) ] || { echo "stale: sent_at is older than 33 days"; return 1; }
  [ "$sa" -le $(($(dr_now) + 3600)) ] || { echo "future: sent_at is more than 60 minutes ahead of this machine's clock"; return 1; }
}
dr_line(){ # <checked envelope> [receipt] → the one line delivered: built from the checked fields, never the sender's bytes, with U+0085, U+2028 and U+2029 escaped (Python's splitlines and Node's readline end lines there), and every character of Unicode 18.0's Default_Ignorable_Code_Point, which nobody sees and a model reads (tag characters, BiDi controls, zero-width characters, variation selectors): the Go client's escapeUnseen, in its list and its form. With a receipt it is dr_sent's record, the envelope inside "envelope" and the receipt beside it
  jq -j --slurpfile r "${2:-/dev/null}" 'def h4: . as $n | [range(3; -1; -1) | ($n / pow(16; .) | floor) % 16] | map("0123456789abcdef"[.:. + 1]) | add;
    def dr_esc: if . > 65535 then (. - 65536) as $v | "\\u" + ((55296 + ($v / 1024 | floor)) | h4) + "\\u" + ((56320 + $v % 1024) | h4) else "\\u" + h4 end;      # a code point as JSON escapes it, lowercase, as Go writes it: a surrogate pair above U+FFFF
    ({v: 1, from, to, sent_at, msg_id, body} + ([{subject}, {in_reply_to}, {supersedes}] | map(select(.[] | . != null and . != "")) | add // {})) as $e | ($r[0] | if . then {envelope: $e, receipt: {id, received_at, expires_at}} else $e end) | tojson | gsub("(?<c>[\\x{85}\\x{2028}\\x{2029}\\x{AD}\\x{34F}\\x{61C}\\x{115F}-\\x{1160}\\x{17B4}-\\x{17B5}\\x{180B}-\\x{180F}\\x{200B}-\\x{200F}\\x{202A}-\\x{202E}\\x{2060}-\\x{206F}\\x{3164}\\x{FE00}-\\x{FE0F}\\x{FEFF}\\x{FFA0}\\x{FFF0}-\\x{FFF8}\\x{1BCA0}-\\x{1BCA3}\\x{1D173}-\\x{1D17A}\\x{E0000}-\\x{E0FFF}])"; .c | explode[0] | dr_esc)' "$1"
}
dr_forget(){ # <Unix time, one a server took (dr_taken)> → the replay set without the lines past 66 days and an hour from their sent_at by that reading: a retry, dated afresh, may be posted up to 33 days after a first copy that was delivered, and read up to 33 days after that, and an hour covers a clock that steps back as far as two clocks a server takes are apart. When it drops one, the floor rises to the cutoff first, so a clock that later reads further back still takes no message whose line went (dr_floor)
  local c=$(($1 - 66*86400 - 3600)) f; [ -e "$DR/seen" ] || return 0
  awk -v c="$c" '$2 >= c' "$DR/seen" > "$DR/seen.new" || return 1
  cmp -s "$DR/seen" "$DR/seen.new" && { rm -f "$DR/seen.new"; return 0; }      # nothing dropped: nothing written
  f=$(dr_floor) || return 1
  if [ "$f" -lt "$c" ]; then printf '%s\n' "$c" > "$DR/seen-floor.new" && sync "$DR/seen-floor.new" && mv "$DR/seen-floor.new" "$DR/seen-floor" && sync "$DR" || return 1; fi      # on disk before any line goes
  sync "$DR/seen.new" && mv "$DR/seen.new" "$DR/seen" && sync "$DR"      # on disk before it replaces the old one: a crash leaves the old set or the new, never an empty one
}
dr_floor(){ # → the highest cutoff a prune of the replay set has dropped a line at, from seen-floor, or 0 when it has none: a message sent before it, or less than 33 days after it, is stale whatever the clock now reads, since its line, or its first copy's, may be gone, as a Kerberos server that has lost its replay cache refuses until the window has passed (RFC 4120 §3.2.3). A file that names anything else is an error, never the default
  local f; [ -e "$DR/seen-floor" ] || { echo 0; return 0; }
  f=$(cat "$DR/seen-floor" 2> /dev/null) && [[ $f =~ ^(0|[1-9][0-9]{0,17})$ ]] && printf '%s\n' "$f" | cmp -s - "$DR/seen-floor" && echo "$f" ||      # compared with itself rebuilt: $(…) drops line feeds and NULs
    { dr_err "$DR/seen-floor names no time: it is a number of seconds and a line feed, written by recv"; return 1; }
}
dr_seen(){ # <sender> <message stem> <hash> → the message, in the replay set and on disk
  local new=; [ -e "$DR/seen" ] || new=$DR
  printf '%s %s %s %s\n' "$3" "$(dr_time "$(jq -r .sent_at "$2.P")")" "$1" "$(jq -r .msg_id "$2.P")" >> "$DR/seen" && sync "$DR/seen" ${new:+"$new"}
}

# recipe: new prekey (monthly)
dr_rekey(){ # → publishes a new prekey, signed by this mailbox's identity, under the lock: a NEW key at a new number, which this machine's clock gives, or the statement an earlier run signed and the server did not take, sent again as it is. Needs only the identity (dr_lock makes the mailbox's other files from it), so it also recovers a mailbox that lost its prekeys
  dr_held || { dr_lock dr_rekey; return; }
  dr_renew
}
dr_renew(){ # → what dr_rekey does, the lock held. A serial is signed ONCE
  local A r s t na p new gone u w at; A=$(cat "$DR/address") || return 1; mkdir -p "$DR/prekeys"
  dr_finished || { dr_done $?; return 1; }
  dr_api GET "/v1/$A" > "$DR/self.json" 2> "$DR/self.err" || case $(dr_code) in
    no_such_mailbox) gone=1 ;;      # 404: the server holds no mailbox here any more, past its record's expiry (PROTOCOL.md §13), so nothing is served to number above or to hold to its order, and the renewal goes as a registration
    revoked) dr_takerecord "$A"; [ $? != 3 ] || return 1; dr_finished || { dr_done $?; return 1; }; cat "$DR/self.err" >&2; return 1 ;;      # 410: the address's record, kept once it verifies, so the mailbox signs nothing more here or at any server it is pointed at (PROTOCOL.md §12.5; #343)
    *) cat "$DR/self.err" >&2; return 1 ;;
  esac
  if [ -n "$gone" ]; then      # what is held of this mailbox's own revocations, at every renewal: from its server's answer, or for a mailbox it holds no more, which carries none, from its revocations alone
    dr_revocations "$A" > /dev/null; case $? in 2 | 3) return 1 ;; esac
  else
    dr_ismailbox "$DR/self.json" && jq -c '{identity, revoked_certificates, revoked_certificates_signature}' "$DR/self.json" > "$DR/rev.json" ||
      dr_refuse "the server's answer for this mailbox is not one this client reads: one JSON object, each byte field base64" || return 1
    dr_take "$A"; [ $? != 3 ] || return 1
  fi
  dr_finished || { dr_done $?; return 1; }      # a revocation of its own address, or of its certificates, which this script never makes: a trip it was shown stops it here (PROTOCOL.md §12.5)
  p=$(cat "$DR/serial" 2> /dev/null || echo 0); s=$p
  if [ -z "$gone" ]; then
    dr_bytes "$DR/self.json" identity "$DR/self.doc" && dr_bytes "$DR/self.json" prekey "$DR/self.txt" && dr_bytes "$DR/self.json" prekey_signature "$DR/self.sig" ||
      dr_refuse "the server's answer for this mailbox is not one this client reads: one JSON object, each byte field base64" || return 1
    [ -s "$DR/self.txt" ] && [ -s "$DR/self.sig" ] || dr_refuse "the server sent no prekey for this mailbox" || return 1
    r=$(dr_prekeycheck "$DR/self.txt" "$DR/self.sig" "$A" "$DR/identity.doc") || dr_refuse "this mailbox's current prekey, as served: $r" || return 1      # its own record, by every rule but its dates (PROTOCOL.md §12.4): whether its identity signed it, and where it stands in the mailbox's order
    [ "${r##* }" = 0 ] || dr_refuse "this mailbox's current prekey, as served, is signed under a certificate, and this mailbox is in identity mode, where its identity signs and no certificate is taken" || return 1
    s=${r%% *}
    if ! cmp -s "$DR/self.txt" "$DR/prekeys/$s.txt"; then      # signed by this mailbox's identity and not a statement it made: unless it is its owner's own, from a machine this mailbox was restored from, the identity is in other hands. Said, and the renewal goes on: no certificate of its own is in doubt, so nothing waits (PROTOCOL.md §12.4)
      dr_out prekey_not_made --argjson serial "$s" --arg at "$(jq -nr --argjson t "$(dr_now)" '$t | todate')" --arg detail "this mailbox's server served a prekey statement in its name, serial $s, that this mailbox's identity signed and this mailbox did not make: unless it is the owner's own, from the machine this mailbox was restored from, the identity is in other hands, and only revoking the address ends that (the Go client's dromas revocation publish, with the address in full). This renewal goes above it"
    fi
    [ "$s" -ge "$p" ] || dr_refuse "rollback: the server serves this mailbox's prekey serial $s, before serial $p, which this mailbox published" || return 1
  fi
  t=$(ls "$DR/prekeys" | sed -n 's/\.agekey$//p; s/\.txt\.sig$//p' | sort -n | tail -n 1); new=1      # s is the highest number this mailbox knows of, its own and the server's, and the new statement goes above it under the same signer (PROTOCOL.md §5.3). t is the highest number this mailbox began a prekey at
  if [ "${t:-0}" -gt "$s" ]; then s=$t; new=; [ ! -s "$DR/prekeys/$s.txt.sig" ] || { na=$(dr_time "$(sed -n 5p "$DR/prekeys/$s.txt")") && [ "$na" -gt "$(dr_now)" ] && u=$(dr_time "$(cat "$DR/prekeys/$s.made" 2> /dev/null)") && [ "$u" -le "$(dr_now)" ] && w=$(dr_lifetime 2> /dev/null) && [ $((na - u)) -le "$w" ]; } || new=1; fi      # a number an earlier run took, and that nothing has passed since, is kept. Signed and never seen published: sent again AS IT IS until it expires, then a new number, and so is one made while the clock read ahead of where it reads now, which a server may not take until the clock catches up. Signed again, the same key would get 33 more days from a server that keeps what it refuses. Never signed: its key is used
  if [ -n "$new" ]; then [ "$s" -lt 9007199254740991 ] || dr_refuse "this mailbox's prekey serial is the highest there is, so no later statement can be made: the address cannot renew" || return 1; t=$(dr_now); s=$((t > s ? t : s + 1)); fi      # a new number: this machine's clock, in seconds, or one above the highest this mailbox knows of when the clock gives nothing higher. A mailbox restored from its identity knows only what the server shows: by the clock, its statement is above every one made before, on whatever machine
  [ -s "$DR/prekeys/$s.txt.sig" ] || rm -f "$DR/prekeys/$s.txt" "$DR/prekeys/$s.made"; dr_prekey "$s" || return 1
  if [ -n "$gone" ]; then u="/v1/$A"; w='{identity:$i}'; else u="/v1/$A/prekey"; w='{}'; fi      # a registration is the identity document, then what a new prekey carries
  jq -n --arg i "$(dr_b64 "$DR/identity.doc")" --arg p "$(dr_b64 "$DR/prekeys/$s.txt")" --arg g "$(dr_b64 "$DR/prekeys/$s.txt.sig")" --argjson k "$(dr_senders)" "$w"' + {prekey:$p, prekey_signature:$g, sender_key_types:$k}' > "$DR/rekey.json"
  h=$(dr_pass new) && dr_api PUT "$u" "$DR/rekey.json" -H "Authorization: $h" > /dev/null || { dr_clock; dr_own; return 1; }      # a new pass, dated as the renewal is sent
  [ "$s" -le "$(cat "$DR/serial" 2> /dev/null || echo 0)" ] || dr_putline "$DR/serial" "$s" || return 1
  mv "$DR/pass.new" "$DR/pass" || return 1
  at=$(dr_taken) && dr_prune "$at" && dr_out prekey --argjson serial "$s" --arg not_after "$(sed -n 5p "$DR/prekeys/$s.txt")"      # by the reading the server took the renewal at: the date of its pass, now $DR/pass
}
dr_prune(){ # <Unix time, one a server took (dr_taken)> → deletes every retired prekey past its deletion time by that reading of this machine's clock: its not_after + the 33 days a message is kept. dr_recv gives the date of the pass its list carried, dr_renew that of the renewal's: a clock a server took, never a later reading. After that, a message encrypted to it is unrecoverable. (The Go client also deletes them sooner.)
  local f n top na; top=$(ls "$DR/prekeys" | sed -n 's/\.agekey$//p' | sort -n | tail -n 1); [ -n "$top" ] || return 0
  for f in "$DR"/prekeys/*.txt; do
    [ -e "$f" ] || continue
    n=$(basename "$f" .txt); [ "$n" -lt "$top" ] || continue      # never the newest
    na=$(dr_time "$(sed -n 5p "$f")") || continue
    [ "$1" -lt $((na + 33*86400)) ] || rm -f "$DR/prekeys/$n.agekey"
  done
}

# Run as a command, not sourced: the Go client's command line, for the commands this script has.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  dr_usage(){ sed -n '/^#   bash dromas\.sh /,/^#   The README/p' "$0" | sed 's/^#   //'; }      # the usage at the top
  dr_lines(){ dr_usage | awk -v w="bash dromas.sh $* " '/^bash dromas\.sh /{ on = index($0 " ", w) == 1 } /^The README/{ on = 0 } on'; }      # <words> → the usage lines of the commands they start
  dr_wrong(){ jq -cn --arg m "$1" --arg u "${2-}" --arg h "${3:-bash dromas.sh help}" '{type:"usage_error"} + (if $u != "" then {usage:$u} else {} end) + {help:$h, detail:$m}' >&2; exit 2; }      # <words> [usage] [help] → the usage_error line on stderr, as the Go client prints one: what was wrong, the command's usage, and the help to read. Nothing ran
  dr_cmd= dr_n=0 dr_min=0 dr_max=0      # the function the command line runs, how many words name it, and how many arguments it takes, at least and at most
  case ${1-} in init | addr | recv) dr_cmd=dr_$1 dr_n=1 ;; send) dr_cmd=dr_send dr_n=1 dr_min=1 dr_max=2 ;; esac
  case "${1-} ${2-}" in 'prekey renew') dr_cmd=dr_rekey dr_n=2 ;; esac
  dr_help=0
  for a; do case $a in --help) dr_help=1 ;; -h) dr_help=1; echo "Flag shorthand -h has been deprecated, use --help" >&2 ;; esac; done      # anywhere after a command: its help, and nothing runs. -h works too, as in the Go client, and means nothing else
  if [ "${1-}" = help ] || { [ -z "$dr_cmd" ] && [ "${2-}" = help ]; }; then
    dr_help=1; [ "$1" = help ] && shift || set -- "$1"
    [ $# -eq 0 ] || case "${1-} ${2-}" in 'prekey '?*) dr_n=2 ;; ?*) dr_n=1 ;; esac
  fi
  if [ $dr_help = 1 ]; then      # help: the usage, or the lines of the command or group it names
    [ "$dr_n" -gt 0 ] || [ $# -eq 0 ] || [[ $1 = -* ]] || dr_n=1
    [ "$dr_n" -gt 0 ] || { dr_usage; exit 0; }
    out=$(dr_lines "${@:1:dr_n}"); [ -n "$out" ] && { echo "$out"; exit 0; }
    dr_wrong "dromas.sh has no command ${*:1:dr_n}"
  fi
  if [ -z "$dr_cmd" ]; then      # bare, a group alone, or a command it does not have
    if [ $# -eq 0 ]; then dr_wrong "dromas.sh takes a command: bash dromas.sh help lists them"
    elif [ -z "$(dr_lines "$1")" ]; then dr_wrong "dromas.sh has no command $1"
    elif [ -n "${2-}" ]; then dr_wrong "dromas.sh $1 has no command $2" "" "bash dromas.sh help $1"
    else dr_wrong "dromas.sh $1 takes a command: bash dromas.sh help $1 lists them" "" "bash dromas.sh help $1"; fi
  fi
  words=${*:1:dr_n}; shift $dr_n
  dr_use=$(dr_lines "$words" | head -n 1 | sed 's/   .*//')
  if [ $# -lt $dr_min ] || [ $# -gt $dr_max ]; then dr_wrong "dromas.sh $words takes $([ $dr_min = $dr_max ] && echo $dr_min || echo "$dr_min to $dr_max") arguments, and was given $#" "$dr_use" "bash dromas.sh help $words"; fi
  case $dr_cmd in      # every word a command takes, and no other: a word it does not take is a wrong command line, never dropped
    dr_send) for a; do [[ $a != -* ]] || dr_wrong "dromas.sh send takes no option: $a" "$dr_use" "bash dromas.sh help send"; done ;;
  esac
  dr_tls "$DR_SERVER_URL" || exit 1      # refused before anything, as the Go client refuses to open a mailbox whose server it would not call
  rm -f "$DR/met.deprecation" "$DR/met.sunset"
  "$dr_cmd" "$@"; dr_rc=$?
  dr_said; exit $dr_rc
fi
