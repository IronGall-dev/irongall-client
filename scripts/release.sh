#!/usr/bin/env bash
# scripts/release.sh: the next release's tag, signed and pushed, which
# .github/workflows/release.yml then builds and publishes (AGENTS.md §
# Releases).
#
#   scripts/release.sh                   the next patch: what it would tag, and its checks
#   scripts/release.sh v0.<minor>.0      a new minor, the maintainer's choice
#   scripts/release.sh [<tag>] --execute sign the tag and push it
#
# Without --execute it changes nothing, as cargo-release does. It tags
# origin/main, and only a commit with no tag yet, commits since the last
# release, and a CI run that passed; the tag is signed with git's signing
# key (gpg.format ssh, user.signingkey) and verified against
# .github/allowed_signers before it is pushed.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "release: $*" >&2; exit 1; }

want='' execute=''
for a in "$@"; do
  case $a in
    --execute) execute=1 ;;
    v*) [ -z "$want" ] || fail "one tag at most"; want=$a ;;
    *) sed -n '6,8p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
  esac
done

[ -z "$(git status --porcelain)" ] || fail "the working tree is not clean"
git fetch -q --tags origin main
commit=$(git rev-parse origin/main)
repo=$(gh repo view --json nameWithOwner --jq .nameWithOwner)

last=$(git tag -l 'v*' --sort=-v:refname | head -n 1)
[[ $last =~ ^v0\.([0-9]+)\.([0-9]+)$ ]] || fail "the last tag, \"$last\", is not v0.<minor>.<patch>"
minor=${BASH_REMATCH[1]} patch=${BASH_REMATCH[2]}
next=v0.$minor.$((patch + 1))
if [ -n "$want" ]; then
  [[ $want =~ ^v0\.([0-9]+)\.([0-9]+)$ ]] || fail "$want is not v0.<minor>.<patch> (no v1.0.0 until the maintainer says)"
  if [ "$want" != "$next" ] && { [ "${BASH_REMATCH[1]}" -le "$minor" ] || [ "${BASH_REMATCH[2]}" != 0 ]; }; then
    fail "$want is neither the next patch, $next, nor a new minor, v0.<above $minor>.0"
  fi
  next=$want
fi

[ -z "$(git tag --points-at "$commit" -l 'v*')" ] || fail "origin/main, ${commit:0:7}, is released already"
since=$(git rev-list --count "$last..$commit")
[ "$since" -gt 0 ] || fail "nothing on origin/main since $last"
passed=$(gh run list -R "$repo" --workflow ci.yml --commit "$commit" --status success --json databaseId --jq length)
[ "$passed" -gt 0 ] || fail "no CI run of ${commit:0:7} has passed yet: gh run list -R $repo --commit $commit"
[ "$(git config gpg.format || true)" = ssh ] && [ -n "$(git config user.signingkey || true)" ] ||
  fail "git signs no tag here: git config gpg.format ssh, and user.signingkey to the key's .pub"

echo "$next: origin/main ${commit:0:7}, $since commits since $last, CI passed"
git log --oneline "$last..$commit"
if [ -z "$execute" ]; then
  echo "nothing done: run again with --execute to sign $next and push it"
  exit 0
fi

git tag -s "$next" -m "dromas $next" "$commit"
if ! git -c gpg.ssh.allowedSignersFile=.github/allowed_signers verify-tag "$next"; then
  git tag -d "$next" > /dev/null
  fail "$next does not verify against .github/allowed_signers: deleted, nothing pushed"
fi
git push -q origin "refs/tags/$next"
echo "pushed $next: the release runs at https://github.com/$repo/actions/workflows/release.yml"
