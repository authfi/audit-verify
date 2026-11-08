#!/usr/bin/env bash
# The release gate the Release workflow runs before it builds anything: the tag is a version tag, it points at a
# commit on main, and CHANGELOG.md has a section for it. Run from the repository root.
#
#   scripts/check-release.sh v1.3.0 [commit-sha [notes-file]]
#
# With no commit it skips the "on main" check. With a notes file it writes the changelog section there, for the
# release job to publish, so the rule for "has notes" is written once.
set -euo pipefail

tag="${1:?usage: check-release.sh vMAJOR.MINOR.PATCH [commit]}"
sha="${2:-}"
notes_out="${3:-}"
changelog="${CHANGELOG:-CHANGELOG.md}"

[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "::error::$tag is not a version tag (vMAJOR.MINOR.PATCH)"; exit 1; }

if [[ -n "$sha" ]]; then
  git merge-base --is-ancestor "$sha" origin/main || { echo "::error::$tag is not on main"; exit 1; }
fi

v="${tag#v}"
grep -Eq "^## \[?${v//./[.]}\]?( |$)" "$changelog" || { echo "::error::$changelog has no section for $v"; exit 1; }

# The section must say something: a release with empty notes is refused by the release job, so refuse it here.
body="$(awk -v v="$v" 'BEGIN{a="## "v; b="## ["v"]"} $0==a || index($0,a" ")==1 || $0==b || index($0,b" ")==1 {f=1;next} /^## /{f=0} f' "$changelog")"
[[ -n "${body//[[:space:]]/}" ]] || { echo "::error::$changelog has a section for $v with no notes"; exit 1; }
[[ -z "$notes_out" ]] || printf '%s\n' "$body" > "$notes_out"
echo "release $tag: version tag, changelog section present"
