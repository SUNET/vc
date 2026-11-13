package apiv1

import (
	"sort"
	"strings"

	"github.com/SUNET/vc/pkg/httphelpers"
)

// displayForLocales returns the index of the display entry to show to a holder
// whose accepted languages are locales, most preferred first, and whose
// rejected tags are rejected, or -1 when there is nothing to show.
//
// It replaces reading entry 0, which was whichever entry the metadata document
// happened to list first: a VCTM whose first display entry is not English
// showed a non-English credential name to every holder, and a document that
// reordered its entries changed the consent page without changing anything
// else. The consent page is the most end-user-facing surface this service has,
// so the entry it shows should be chosen for the end user.
//
// The preference order below is the one the verifier UI already applies to the
// same metadata client-side (staticembed/locale-helpers.js): an exact locale
// match, then a match on the language alone, then any English entry, then the
// first entry by locale. The last two steps are what make an unmatched holder
// deterministic rather than dependent on document order - the shipped metadata
// populates en-US, so English is the useful fallback, and sorting breaks the
// remaining tie the same way on every request.
//
// A tag the holder ruled out with q=0 is excluded from every one of those
// steps, so "sv-SE;q=0, sv;q=1, en;q=0.8" lands on en-US rather than reaching
// the sv-SE entry through its own "sv" - which is the opposite of what the
// holder said. The exception is a document whose every entry is ruled out:
// the page still has to name the credential, and a name in an unwanted
// language beats no name at all.
func displayForLocales[T any](entries []T, locales, rejected []string, localeOf func(T) string) int {
	if len(entries) == 0 {
		return -1
	}

	// Lowercased once: language tags are case-insensitive, AcceptedLanguages
	// has already lowercased its side, and metadata is written both ways.
	tags := make([]string, len(entries))
	for i, entry := range entries {
		tags[i] = strings.ToLower(strings.TrimSpace(localeOf(entry)))
	}

	// Tracked as its own mask rather than by blanking the tag, so that an
	// entry which legitimately declares no locale - a document's
	// language-independent entry - stays distinguishable from one the holder
	// ruled out.
	excluded := make([]bool, len(entries))
	allExcluded := true
	for i, tag := range tags {
		excluded[i] = httphelpers.LanguageRejects(locales, rejected, tag)
		if !excluded[i] {
			allExcluded = false
		}
	}
	if allExcluded {
		clear(excluded)
	}

	eligible := func(i int) bool { return !excluded[i] }

	for _, locale := range locales {
		for i, tag := range tags {
			if eligible(i) && tag == locale {
				return i
			}
		}
	}

	for _, locale := range locales {
		language := baseLanguage(locale)
		if language == "" {
			continue
		}
		for i, tag := range tags {
			if eligible(i) && tag != "" && baseLanguage(tag) == language {
				return i
			}
		}
	}

	// Deterministic fallbacks, by locale rather than by position: English
	// first, then whatever sorts lowest. An entry that declares no locale
	// sorts lowest of all, which is the right place for the one entry a
	// document means to apply regardless of language.
	ordered := make([]int, 0, len(entries))
	for i := range entries {
		if eligible(i) {
			ordered = append(ordered, i)
		}
	}
	sort.SliceStable(ordered, func(a, b int) bool { return tags[ordered[a]] < tags[ordered[b]] })

	for _, i := range ordered {
		if baseLanguage(tags[i]) == "en" {
			return i
		}
	}

	return ordered[0]
}

// baseLanguage returns the primary language subtag of a language tag, so that
// "en" matches "en-US" and "en-GB" matches "en-US".
func baseLanguage(tag string) string {
	language, _, _ := strings.Cut(tag, "-")

	return language
}
