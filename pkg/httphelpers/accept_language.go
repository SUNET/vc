package httphelpers

import (
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
)

// AcceptLanguageOf returns the request's Accept-Language field value, with
// repeated field lines joined as one.
//
// A field may be sent as several lines, and RFC 9110 5.3 makes that exactly
// equivalent to one line with the values comma-separated. Reading it with
// Header.Get returns the FIRST line only, so a client sending
//
//	Accept-Language: sv-SE
//	Accept-Language: en;q=0
//
// had its second line discarded - here, a refusal discarded, which is the
// thing this file exists to stop happening.
func AcceptLanguageOf(c *gin.Context) string {
	if c == nil || c.Request == nil {
		return ""
	}

	return strings.Join(c.Request.Header.Values("Accept-Language"), ",")
}

// AcceptedLanguages parses an Accept-Language header into the language tags it
// names as acceptable, most preferred first, lowercased.
//
// The wildcard "*" is dropped: as a preference it says "any language", which
// adds nothing to an ordered list and would otherwise match the first
// candidate it was compared against. Tags given q=0 are dropped too - RFC 9110
// 12.5.4 gives that quality the meaning "not acceptable", so relaying such a
// tag as a preference would invert what the client asked for. Neither is
// merely absent: RejectedLanguages returns the refusals, wildcard included,
// because a range the client ruled out has to keep ruling out what it matches.
//
// Ties keep header order, so a header that states no qualities at all yields
// its tags exactly as written, which is what every browser sends for its
// primary language.
func AcceptedLanguages(header string) []string {
	accepted := make([]string, 0, 4)
	for _, tag := range languageTags(header, func(q float64) bool { return q > 0 }) {
		if tag != wildcardRange {
			accepted = append(accepted, tag)
		}
	}

	return accepted
}

// wildcardRange is the language range that matches every tag. As an
// acceptance it carries no information; as a refusal it is the client saying
// "nothing else", which is why it survives into RejectedLanguages.
const wildcardRange = "*"

// RejectedLanguages returns the ranges an Accept-Language header named with
// q=0, lowercased - what the client has said it will not take.
//
// "*" is one of them. A zero-quality wildcard is the client refusing every
// language it did not name, so "fr, *;q=0" rejects en-US; dropping it left
// that header behaving exactly like a bare "fr", which is the opposite of
// "nothing else". It is kept here and only here: as an acceptance a wildcard
// still carries nothing.
//
// Order carries no meaning here, so the result is sorted, but the ranges do:
// a rejection applies to whatever it matches as precisely as it matches it,
// and the wildcard matches everything at the lowest precision there is.
// LanguageRejects applies that rule.
func RejectedLanguages(header string) []string {
	rejected := languageTags(header, func(q float64) bool { return q <= 0 })
	sort.Strings(rejected)

	return rejected
}

// languageTags parses the header once and returns the tags whose quality
// satisfies keep, most preferred first.
func languageTags(header string, keep func(q float64) bool) []string {
	type weighted struct {
		tag string
		q   float64
	}

	entries := make([]weighted, 0, strings.Count(header, ",")+1)
	for part := range strings.SplitSeq(header, ",") {
		// An Accept-Language entry has the same "value;q=" grammar as the
		// Accept entries parseMediaRange was written for; only the value is a
		// language tag rather than a media range.
		tag, q := parseMediaRange(part)
		if tag == "" || !keep(q) {
			continue
		}
		entries = append(entries, weighted{tag: tag, q: q})
	}

	sort.SliceStable(entries, func(i, j int) bool { return entries[i].q > entries[j].q })

	tags := make([]string, 0, len(entries))
	for _, entry := range entries {
		tags = append(tags, entry.tag)
	}

	return tags
}

// LanguageRejects reports whether a client that accepted the tags in accepted
// and rejected the tags in rejected has ruled out the language tag candidate.
//
// A language range matches a tag as precisely as it shares subtags with it
// (RFC 4647 basic filtering), and the most precise range the client named is
// the one that decides - the same rule prefersHTML applies to Accept, where an
// explicit application/json;q=0 beats a */*;q=1 fallback. So
// "sv-SE;q=0, sv;q=1" rejects sv-SE, whose two-subtag rejection outranks the
// one-subtag acceptance, while leaving sv-FI acceptable on that same "sv".
//
// A candidate no range matches at all is not rejected: the caller is then
// choosing without guidance, not against it.
func LanguageRejects(accepted, rejected []string, candidate string) bool {
	candidate = strings.ToLower(strings.TrimSpace(candidate))
	if candidate == "" {
		return false
	}

	rejectDepth := bestRangeMatch(rejected, candidate)
	if rejectDepth == noRangeMatch {
		return false
	}

	return rejectDepth > bestRangeMatch(accepted, candidate)
}

// noRangeMatch is the precision reported for a candidate no range matches. It
// is below the wildcard's zero, so a candidate named by nothing at all loses
// to one a wildcard reaches - which is what makes "fr, *;q=0" refuse en-US
// while leaving fr-CA, reached by the one-subtag "fr", acceptable.
const noRangeMatch = -1

// bestRangeMatch returns the precision of the most precise range in ranges
// that matches candidate - its subtag count, or zero for the wildcard - and
// noRangeMatch when none does.
func bestRangeMatch(ranges []string, candidate string) int {
	best := noRangeMatch
	for _, r := range ranges {
		if !LanguageRangeMatches(r, candidate) {
			continue
		}

		depth := 0
		if r != wildcardRange {
			depth = strings.Count(r, "-") + 1
		}
		if depth > best {
			best = depth
		}
	}

	return best
}

// LanguageRangeMatches reports whether the language range r matches the tag
// candidate: the wildcard matches any tag, and a named range matches one it
// equals or is a whole-subtag prefix of, so "sv" matches "sv-SE" but "sv" does
// not match "svx" and "sv-SE" does not match "sv".
//
// Exported because selection needs the same notion of "matches" this package
// refuses by, and two definitions of it would drift.
func LanguageRangeMatches(r, candidate string) bool {
	if r == "" {
		return false
	}
	if r == wildcardRange {
		return true
	}
	if r == candidate {
		return true
	}

	return strings.HasPrefix(candidate, r+"-")
}

// TruncateLanguageRange removes the last subtag of a language range, returning
// "" once nothing is left. It is the progressive fallback RFC 4647 3.4 Lookup
// is defined in terms of: "zh-Hans-CN" yields "zh-Hans", then "zh", then "".
//
// A singleton subtag - one character, which introduces an extension - is never
// left stranded at the end, so "en-a-bbb" yields "en" rather than "en-a".
//
// Selection without this step matches a range only exactly or on its primary
// language, and the subtags in between are where a script lives: a reader
// asking for zh-Hans-CN was handed zh-Hant-TW over zh-Hans, which is
// Traditional Chinese for someone who asked for Simplified.
func TruncateLanguageRange(r string) string {
	i := strings.LastIndex(r, "-")
	if i < 0 {
		return ""
	}
	truncated := r[:i]

	// A singleton is "removed at the same time as its closest trailing
	// subtag", and a chain of them goes together: en-a-b-ccc truncates to en,
	// not to en-a, which would be a range ending in a singleton that could
	// match unrelated extensions. Looping rather than checking once is the
	// difference, and it leaves a non-singleton boundary alone -
	// de-DE-u-co-phonebk still truncates to de-DE-u-co, because "co" is two
	// characters and the extension is not finished being read.
	for {
		j := strings.LastIndex(truncated, "-")
		if j < 0 || len(truncated)-j != 2 {
			break
		}
		truncated = truncated[:j]
	}

	// A singleton with nothing in front of it is not a range anyone can mean.
	// Private-use subtags are opaque by definition, so a bare "x" matched
	// every other private-use tag: a holder asking for x-foo - or, through the
	// chained-singleton path above, x-a-foo - was handed x-bar, which has no
	// relationship to it, in preference to the English they also accepted.
	if len(truncated) == 1 {
		return ""
	}

	return truncated
}
