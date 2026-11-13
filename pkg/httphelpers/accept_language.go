package httphelpers

import (
	"sort"
	"strings"
)

// AcceptedLanguages parses an Accept-Language header into the language tags it
// names, most preferred first, lowercased.
//
// Entries with q=0 are dropped: RFC 9110 gives that quality the meaning "not
// acceptable", so passing such a tag on as a preference would invert what the
// client asked for. The wildcard "*" is dropped as well - it says "any
// language", which adds nothing to an ordered list of preferences and would
// otherwise match the first entry of whatever it was compared against.
//
// Ties keep header order, so a header that states no qualities at all yields
// its tags exactly as written, which is what every browser sends for its
// primary language.
func AcceptedLanguages(header string) []string {
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
		if tag == "" || tag == "*" || q <= 0 {
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
