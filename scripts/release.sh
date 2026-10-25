#!/usr/bin/env bash
# scripts/release.sh: the next release, end to end. It brings this checkout
# to origin/main, checks what .github/workflows/release.yml would refuse,
# shows what it will tag, and asks; on yes it signs the tag, verifies it
# against .github/allowed_signers, pushes it, and waits for the release
# (AGENTS.md § Releases).
#
#   scripts/release.sh                  the next patch
#   scripts/release.sh v0.<minor>.0     a new minor, the maintainer's choice
#   scripts/release.sh [<tag>] --yes    without asking, where there is no terminal
#
# It tags origin/main, and only a commit with no tag yet, commits since the
# last release, and a CI run that passed. The tag is signed with git's
# signing key (gpg.format ssh, user.signingkey).
set -euo pipefail

fail() { echo "release: $*" >&2; exit 1; }

main() {
  cd "$(dirname "$0")/.."
  local want='' yes='' a
  for a in "$@"; do
    case $a in
      --yes) yes=1 ;;
      v*) [ -z "$want" ] || fail "one tag at most"; want=$a ;;
      *) sed -n '8,10p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
    esac
  done

  [ -z "$(git status --porcelain)" ] || fail "this checkout has changes: commit or stash them first"
  git fetch -q --tags origin main
  local commit
  commit=$(git rev-parse origin/main)
  if [ "$(git rev-parse HEAD)" != "$commit" ]; then
    git merge -q --ff-only origin/main || fail "this checkout has commits origin/main lacks"
    exec "$0" "$@" # the script as it is at origin/main
  fi
  local repo
  repo=$(gh repo view --json nameWithOwner --jq .nameWithOwner)

  local last minor patch next
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
  local since passed
  since=$(git rev-list --count "$last..$commit")
  [ "$since" -gt 0 ] || fail "nothing on origin/main since $last"
  passed=$(gh run list -R "$repo" --workflow ci.yml --commit "$commit" --status success --json databaseId --jq length)
  [ "$passed" -gt 0 ] || fail "no CI run of ${commit:0:7} has passed yet: gh run list -R $repo --commit $commit"
  [ "$(git config gpg.format || true)" = ssh ] && [ -n "$(git config user.signingkey || true)" ] ||
    fail "git signs no tag here: git config gpg.format ssh, and user.signingkey to the key's .pub"

  echo "$next would release origin/main ${commit:0:7}: $since commits since $last, CI passed"
  git log --oneline "$last..$commit" | sed 's/^/  /'
  if [ -z "$yes" ]; then
    local answer
    { exec 3< /dev/tty; } 2> /dev/null || fail "no terminal to ask on: pass --yes"
    read -r -u 3 -p "Sign $next and push it, which publishes the release? [y/N] " answer
    exec 3<&-
    [[ $answer =~ ^[Yy] ]] || fail "nothing done"
  fi

  # The key's passphrase is in the macOS keychain (ssh-add --apple-use-keychain).
  if [ "$(uname -s)" = Darwin ]; then ssh-add -q --apple-load-keychain 2> /dev/null || true; fi
  git tag -s "$next" -m "dromas $next" "$commit"
  if ! scripts/tagcheck.sh "$next"; then
    git tag -d "$next" > /dev/null
    fail "$next is not a tag release.yml would build: deleted, nothing pushed"
  fi
  if ! git push -q origin "refs/tags/$next"; then
    git tag -d "$next" > /dev/null
    fail "the push failed: $next deleted here, nothing published"
  fi
  echo "pushed $next; waiting for the release run"

  local run=''
  for _ in $(seq 30); do
    run=$(gh run list -R "$repo" --workflow release.yml --branch "$next" --limit 1 --json databaseId --jq '.[0].databaseId // empty')
    [ -n "$run" ] && break
    sleep 2
  done
  [ -n "$run" ] || fail "no release run for $next after a minute: https://github.com/$repo/actions/workflows/release.yml"
  gh run watch "$run" -R "$repo" --exit-status > /dev/null ||
    fail "the release run failed: https://github.com/$repo/actions/runs/$run"
  echo "released: $(gh release view "$next" -R "$repo" --json url --jq .url)"
}

main "$@"
