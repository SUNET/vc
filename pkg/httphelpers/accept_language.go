package httphelpers

import (
	"sort"
	"strings"
)

// AcceptedLanguages parses an Accept-Language header into the language tags it
// names as acceptable, most preferred first, lowercased.
//
// The wildcard "*" is dropped: it says "any language", which adds nothing to
// an ordered list of preferences and would otherwise match the first candidate
// it was compared against. Tags given q=0 are dropped too - RFC 9110 12.5.4
// gives that quality the meaning "not acceptable", so relaying such a tag as a
// preference would invert what the client asked for. They are not merely
// absent, though: RejectedLanguages returns them, because a tag the client
// ruled out has to keep ruling out whatever it matches.
//
// Ties keep header order, so a header that states no qualities at all yields
// its tags exactly as written, which is what every browser sends for its
// primary language.
func AcceptedLanguages(header string) []string {
	return languageTags(header, func(q float64) bool { return q > 0 })
}

// RejectedLanguages returns the tags an Accept-Language header named with q=0,
// lowercased - the languages the client has said it will not take.
//
// Order carries no meaning here, so the result is sorted, but the tags do:
// a rejection is a range like any other, and it applies to whatever it matches
// as precisely as it matches it. LanguageRejects applies that rule.
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
		if tag == "" || tag == "*" || !keep(q) {
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
	if rejectDepth == 0 {
		return false
	}

	return rejectDepth > bestRangeMatch(accepted, candidate)
}

// bestRangeMatch returns the subtag count of the most precise range in ranges
// that matches candidate, or 0 when none does.
func bestRangeMatch(ranges []string, candidate string) int {
	best := 0
	for _, r := range ranges {
		if !languageRangeMatches(r, candidate) {
			continue
		}
		if depth := strings.Count(r, "-") + 1; depth > best {
			best = depth
		}
	}

	return best
}

// languageRangeMatches reports whether the language range r matches the tag
// candidate: equal, or r is a whole-subtag prefix of it, so "sv" matches
// "sv-SE" but "sv" does not match "svx" and "sv-SE" does not match "sv".
func languageRangeMatches(r, candidate string) bool {
	if r == "" {
		return false
	}
	if r == candidate {
		return true
	}

	return strings.HasPrefix(candidate, r+"-")
}
