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
	*) ;;
	esac
	if command -v gh >/dev/null 2>&1; then
		# gh prints the JSON error body to stdout on HTTP errors, so keep output only on success.
		local login
		if login=$(gh api "repos/$REPO/commits/$sha" --jq '.author.login // empty' 2>/dev/null); then
			echo "$login"
		fi
	fi
}

# A PR belongs to the release when its merge commit is in HEAD but not in the previous tag.
in_range() {
	local oid=$1
	git merge-base --is-ancestor "$oid" HEAD 2>/dev/null || return 1
	git rev-parse -q --verify "refs/tags/$PREV_TAG" >/dev/null || return 0
	! git merge-base --is-ancestor "$oid" "$PREV_TAG" 2>/dev/null
}

RANGE="$PREV_TAG..HEAD"
git rev-parse -q --verify "refs/tags/$PREV_TAG" >/dev/null || RANGE=HEAD
# The draft changelog commit of an earlier attempt for this tag is not a change.
DRAFT=(--invert-grep --grep="^chore: changelog for $NEW_TAG\$")
if [[ -z "$(git log --no-merges "${DRAFT[@]}" --format=%h "$RANGE")" ]]; then
	echo "No commits since $PREV_TAG, changelog unchanged"
	exit 0
fi

declare -A seen_email seen_handle
participants=()
while IFS='|' read -r sha name email; do
	[[ -n "${seen_email[$email]:-}" ]] && continue
	seen_email[$email]=1
	handle=$(resolve_handle "$sha" "$email")
	if [[ -n "$handle" ]]; then
		[[ -n "${seen_handle[$handle]:-}" ]] && continue
		seen_handle[$handle]=1
		participants+=("$name ($handle)")
	else
		participants+=("$name")
	fi
done < <(git log --no-merges "${DRAFT[@]}" --format='%H|%an|%ae' "$RANGE")

# Not every merge keeps "(#N)" in the subject, so ask GitHub; fall back to commit SHAs.
since=$(git log -1 --format=%cI "$PREV_TAG" 2>/dev/null || true)
prs=
if [[ -n "$since" ]] && command -v gh >/dev/null 2>&1; then
	candidates=$(gh pr list -R "$REPO" --state merged --base main --search "merged:>$since" --limit 1000 --json number,title,mergedAt,mergeCommit --jq 'sort_by(.mergedAt) | reverse | .[] | select(.mergeCommit != null) | "\(.mergeCommit.oid)\t\(.number)\t\(.title)"' 2>/dev/null || true)
	while IFS=$'\t' read -r oid number title; do
		[[ -n "$oid" ]] || continue
		in_range "$oid" || continue
		prs+="- #$number: $title"$'\n'
	done <<<"$candidates"
	prs=${prs%$'\n'}
fi
if [[ -n "$prs" ]]; then
	change_list=$prs
	pr_count=$(printf '%s\n' "$prs" | wc -l | tr -d ' ')
else
	change_list=$(git log --no-merges "${DRAFT[@]}" --format='- %h: %s' "$RANGE")
	pr_count=$(git log --no-merges "${DRAFT[@]}" --format=%s "$RANGE" | { grep -oE '\(#[0-9]+\)$' || true; } | sort -u | wc -l | tr -d ' ')
fi

closed_issues=
if [[ -n "$since" ]] && command -v gh >/dev/null 2>&1; then
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
	if [[ -n "$closed_issues" ]]; then
		echo "Closed issues: $(printf '%s\n' "$closed_issues" | wc -l | tr -d ' ')"
		echo
		printf '%s\n' "$closed_issues"
		echo
	fi
} >"$section"

# A re-run for the same tag replaces its section, so the notes match the current range.
stripped=$(mktemp)
awk -v tag="## $NEW_TAG" '
	skip && /^## / { skip = 0 }
	$0 == tag || index($0, tag " ") == 1 { skip = 1; next }
	!skip { print }
' "$FILE" >"$stripped"

out=$(mktemp)
{
	sed -n '1p' "$stripped"
	echo
	cat "$section"
	sed '1,2d' "$stripped"
} >"$out"
cat "$out" >"$FILE"
rm -f "$out" "$stripped"
echo "==> $FILE updated for $NEW_TAG"
