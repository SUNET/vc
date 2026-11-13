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
// Matching follows RFC 4647 3.4 Lookup: the holder's ranges are tried in
// priority order, and each is truncated from the right until it matches or
// runs out - zh-Hans-CN, then zh-Hans, then zh. Matching only exactly and then
// on the primary language skips every subtag in between, which is where a
// script lives: a reader asking for zh-Hans-CN was handed zh-Hant-TW over an
// available zh-Hans, Traditional Chinese for someone who asked for Simplified.
//
// Lookup also settles which range wins. A holder asking for "en-US, sv-SE;q=0.8"
// against a document offering en-GB and sv-SE gets en-GB: their first choice,
// reached by truncation, outranks an exact match on their second. That is the
// spec's answer and it is the right one - they said English first - though it
// is not what an earlier revision of this function did, which compared every
// range exactly before trying any of them loosely.
//
// Where no range matches at all, the fallbacks keep the choice deterministic
// rather than dependent on document order: any English entry, then the first
// entry by locale. No step in this function reads the entries in document
// order, at any level. The shipped metadata populates en-US, so English is the
// useful one, and sorting breaks the remaining tie the same way on every
// request. The verifier UI applies the same two fallbacks client-side
// (staticembed/locale-helpers.js).
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

	// Every step below walks the entries in locale order, never in document
	// order. That is the whole point of this function: which entry a holder
	// sees must not depend on how the metadata document happens to be
	// arranged. Reading entry 0 was the original bug, and taking the first
	// matching entry at a truncation step was the same bug in miniature -
	// "en" against a document offering en-US and en selected whichever came
	// first.
	byLocale := make([]int, 0, len(entries))
	for i := range entries {
		byLocale = append(byLocale, i)
	}
	sort.SliceStable(byLocale, func(a, b int) bool { return tags[byLocale[a]] < tags[byLocale[b]] })

	firstMatch := func(match func(tag string) bool) int {
		for _, i := range byLocale {
			if eligible(i) && tags[i] != "" && match(tags[i]) {
				return i
			}
		}

		return -1
	}

	for _, locale := range locales {
		for r := locale; r != ""; r = httphelpers.TruncateLanguageRange(r) {
			// Locale order also settles exact-before-extension at each level,
			// without a separate pass: everything matching range r either
			// equals it or begins with r + "-", and a proper prefix sorts
			// first, so an "en" entry is reached before "en-US" and a
			// "zh-Hans" entry before "zh-Hans-CN". Asserted by
			// TestAnExactMatchSortsBeforeAnyExtensionOfIt.
			if i := firstMatch(func(tag string) bool { return httphelpers.LanguageRangeMatches(r, tag) }); i >= 0 {
				return i
			}
		}
	}

	// Deterministic fallbacks, by locale rather than by position: English
	// first, then whatever sorts lowest. An entry that declares no locale
	// sorts lowest of all, which is the right place for the one entry a
	// document means to apply regardless of language.
	ordered := make([]int, 0, len(entries))
	for _, i := range byLocale {
		if eligible(i) {
			ordered = append(ordered, i)
		}
	}

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
