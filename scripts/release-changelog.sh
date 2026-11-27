#!/usr/bin/env bash
# Prepend a release section to CHANGELOG.md: participants plus one line per commit since the previous tag.
# Usage: release-changelog.sh <new-tag> <previous-tag> [changelog-file]
set -euo pipefail

NEW_TAG=${1:?new tag required}
PREV_TAG=${2:?previous tag required}
FILE=${3:-CHANGELOG.md}
REPO=${REPO:-SUNET/vc}

# noreply emails carry the handle; otherwise ask GitHub for the commit author.
resolve_handle() {
	local sha=$1 email=$2 local_part
	case $email in
	*@users.noreply.github.com)
		local_part=${email%@*}
		echo "${local_part#*+}"
		return
		;;
	esac
	if command -v gh >/dev/null 2>&1; then
		gh api "repos/$REPO/commits/$sha" --jq '.author.login // empty' 2>/dev/null || true
	fi
}

RANGE="$PREV_TAG..HEAD"
git rev-parse -q --verify "refs/tags/$PREV_TAG" >/dev/null || RANGE=HEAD
if [ -z "$(git log --no-merges --format=%h "$RANGE")" ]; then
	echo "No commits since $PREV_TAG, changelog unchanged"
	exit 0
fi

declare -A seen_email seen_handle
participants=()
while IFS='|' read -r sha name email; do
	[ -n "${seen_email[$email]:-}" ] && continue
	seen_email[$email]=1
	handle=$(resolve_handle "$sha" "$email")
	if [ -n "$handle" ]; then
		[ -n "${seen_handle[$handle]:-}" ] && continue
		seen_handle[$handle]=1
		participants+=("$name ($handle)")
	else
		participants+=("$name")
	fi
done < <(git log --no-merges --format='%H|%an|%ae' "$RANGE")

# Not every merge keeps "(#N)" in the subject, so ask GitHub; fall back to commit SHAs.
since=$(git log -1 --format=%cI "$PREV_TAG" 2>/dev/null || true)
prs=
if [ -n "$since" ] && command -v gh >/dev/null 2>&1; then
	prs=$(gh pr list -R "$REPO" --state merged --base main --search "merged:>$since" --limit 1000 --json number,title,mergedAt --jq 'sort_by(.mergedAt) | reverse | .[] | "- #\(.number): \(.title)"' 2>/dev/null || true)
fi
if [ -n "$prs" ]; then
	change_list=$prs
	pr_count=$(printf '%s\n' "$prs" | wc -l | tr -d ' ')
else
	change_list=$(git log --no-merges --format='- %h: %s' "$RANGE")
	pr_count=$(git log --no-merges --format=%s "$RANGE" | grep -oE '\(#[0-9]+\)$' | sort -u | wc -l | tr -d ' ')
fi

closed_issues=
if [ -n "$since" ] && command -v gh >/dev/null 2>&1; then
	closed_issues=$(gh issue list -R "$REPO" --state closed --search "closed:>$since" --limit 1000 --json number,title --jq 'sort_by(.number) | .[] | "- #\(.number): \(.title)"' 2>/dev/null || true)
fi

section=$(mktemp)
trap 'rm -f "$section"' EXIT
{
	echo "## $NEW_TAG - $(date +%Y-%m-%d)"
	echo
	echo "Participants: $(printf '%s, ' "${participants[@]}" | sed 's/, $//')"
	echo
	echo "Pull requests: $pr_count"
	echo
	printf '%s\n' "$change_list"
	echo
	if [ -n "$closed_issues" ]; then
		echo "Closed issues: $(printf '%s\n' "$closed_issues" | wc -l | tr -d ' ')"
		echo
		printf '%s\n' "$closed_issues"
		echo
	fi
} >"$section"

out=$(mktemp)
{
	sed -n '1p' "$FILE"
	echo
	cat "$section"
	sed '1,2d' "$FILE"
} >"$out"
cat "$out" >"$FILE"
rm -f "$out"
echo "==> $FILE updated for $NEW_TAG"
