package httphelpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAcceptedLanguages(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
		want   []string
	}{
		{
			name:   "no header at all",
			header: "",
			want:   []string{},
		},
		{
			name:   "a single tag, as every browser sends for its primary language",
			header: "sv-SE",
			want:   []string{"sv-se"},
		},
		{
			name:   "qualities order the list, highest first",
			header: "de;q=0.5, sv-SE;q=0.9, en;q=0.7",
			want:   []string{"sv-se", "en", "de"},
		},
		{
			name:   "equal qualities keep header order",
			header: "sv-SE, da, nb",
			want:   []string{"sv-se", "da", "nb"},
		},
		{
			name:   "an implicit quality of 1 outranks an explicit lower one",
			header: "de;q=0.8, sv-SE",
			want:   []string{"sv-se", "de"},
		},
		{
			name:   "q=0 means not acceptable, so the tag is dropped",
			header: "sv-SE, de;q=0",
			want:   []string{"sv-se"},
		},
		{
			name:   "the wildcard carries no preference and is dropped",
			header: "sv-SE, *;q=0.1",
			want:   []string{"sv-se"},
		},
		{
			name:   "a refusing wildcard is no more of a preference",
			header: "fr, *;q=0",
			want:   []string{"fr"},
		},
		{
			name:   "a header of nothing but a wildcard yields nothing",
			header: "*",
			want:   []string{},
		},
		{
			name:   "surrounding whitespace and case do not matter",
			header: "  SV-se ,  EN-GB ",
			want:   []string{"sv-se", "en-gb"},
		},
		{
			name:   "an unparsable quality falls back to 1 rather than dropping the tag",
			header: "sv-SE;q=high",
			want:   []string{"sv-se"},
		},
		{
			// A quality outside 0..1 is malformed, so it falls back to 1 like
			// any other malformed value. Read literally, q=-1 was a refusal
			// and q=5 outranked every well-formed preference beside it.
			name:   "a quality below the range is malformed, not a refusal",
			header: "sv-SE;q=-1, en;q=0.8",
			want:   []string{"sv-se", "en"},
		},
		{
			name:   "a quality above the range does not outrank a well-formed one",
			header: "de;q=5, sv-SE;q=1, en;q=0.8",
			want:   []string{"de", "sv-se", "en"},
		},
		{
			// Parameter names are case-insensitive (RFC 9110 5.6.6), and an
			// unrecognised name left the entry at the default quality of 1 -
			// so an uppercase refusal read as a preference.
			name:   "an uppercase Q is the same parameter",
			header: "sv-SE;Q=0, en;Q=0.8, de;Q=0.9",
			want:   []string{"de", "en"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, AcceptedLanguages(tc.header))
		})
	}
}

func TestRejectedLanguages(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
		want   []string
	}{
		{
			name:   "nothing rejected",
			header: "sv-SE, en;q=0.8",
			want:   []string{},
		},
		{
			name:   "a tag the client will not take",
			header: "sv-SE;q=0, sv;q=1, en;q=0.8",
			want:   []string{"sv-se"},
		},
		{
			name:   "several, sorted, since their order carries no meaning",
			header: "sv;q=0, en;q=0, de",
			want:   []string{"en", "sv"},
		},
		{
			name:   "a zero written long-hand is still zero",
			header: "sv-SE;q=0.000, en",
			want:   []string{"sv-se"},
		},
		{
			// A zero-quality wildcard is the client refusing every language
			// it did not name, so it has to survive as a rejection even
			// though it is worthless as a preference.
			name:   "a refusing wildcard is kept, unlike an accepting one",
			header: "*;q=0, en",
			want:   []string{"*"},
		},
		{
			name:   "a wildcard with a usable quality carries no refusal",
			header: "en-US,en;q=0.9,*;q=0.5",
			want:   []string{},
		},
		{
			name:   "nothing but a refusing wildcard",
			header: "*;q=0",
			want:   []string{"*"},
		},
		{
			name:   "a malformed negative quality is not a refusal",
			header: "sv-SE;q=-1, en",
			want:   []string{},
		},
		{
			name:   "an uppercase Q refuses just as a lowercase one does",
			header: "sv-SE;Q=0, en",
			want:   []string{"sv-se"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, RejectedLanguages(tc.header))
		})
	}
}

// A header that both refuses and accepts the same range is ill-defined, and
// the parser reports it in both lists rather than picking for the client.
// LanguageRejects then settles it, and settles it towards acceptance: a
// refusal has to be more precise than the acceptance to win, and an equally
// precise one is not.
func TestARangeBothRefusedAndAccepted(t *testing.T) {
	const header = "en;q=0, en;q=1"

	assert.Equal(t, []string{"en"}, AcceptedLanguages(header))
	assert.Equal(t, []string{"en"}, RejectedLanguages(header))
	assert.False(t, LanguageRejects(AcceptedLanguages(header), RejectedLanguages(header), "en-US"))
}

// The most precise range the client named decides, which is the rule
// prefersHTML already applies to Accept: an explicit application/json;q=0
// beats a */*;q=1 fallback.
func TestLanguageRejects(t *testing.T) {
	for _, tc := range []struct {
		name      string
		header    string
		candidate string
		want      bool
	}{
		{
			name:      "a two-subtag rejection beats a one-subtag acceptance",
			header:    "sv-SE;q=0, sv;q=1, en;q=0.8",
			candidate: "sv-SE",
			want:      true,
		},
		{
			name:      "and leaves a sibling region it does not match alone",
			header:    "sv-SE;q=0, sv;q=1",
			candidate: "sv-FI",
			want:      false,
		},
		{
			name:      "a one-subtag rejection loses to a two-subtag acceptance",
			header:    "sv;q=0, sv-SE;q=1",
			candidate: "sv-SE",
			want:      false,
		},
		{
			name:      "but still rejects what only it matches",
			header:    "sv;q=0, sv-SE;q=1",
			candidate: "sv-FI",
			want:      true,
		},
		{
			name:      "a language rejection reaches its regions",
			header:    "en;q=0, sv",
			candidate: "en-US",
			want:      true,
		},
		{
			name:      "a region rejection does not reach the bare language",
			header:    "en-US;q=0, sv",
			candidate: "en",
			want:      false,
		},
		{
			name:      "a prefix that is not a whole subtag is not a match",
			header:    "sv;q=0",
			candidate: "svx",
			want:      false,
		},
		{
			name:      "a candidate no range mentions is unguided, not rejected",
			header:    "sv;q=0",
			candidate: "de-DE",
			want:      false,
		},
		{
			name:      "a refusing wildcard reaches a language nobody named",
			header:    "fr, *;q=0",
			candidate: "en-US",
			want:      true,
		},
		{
			name:      "a named acceptance outranks the refusing wildcard",
			header:    "fr, *;q=0",
			candidate: "fr-CA",
			want:      false,
		},
		{
			name:      "the wildcard is the least precise range there is",
			header:    "en;q=0, *;q=1",
			candidate: "en-US",
			want:      true,
		},
		{
			name:      "an entry with no locale escapes even the wildcard",
			header:    "fr, *;q=0",
			candidate: "",
			want:      false,
		},
		{
			name:      "an entry with no locale is never rejected",
			header:    "sv;q=0, en;q=0",
			candidate: "",
			want:      false,
		},
		{
			name:      "case does not matter on either side",
			header:    "SV-se;q=0, sv",
			candidate: "sv-SE",
			want:      true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := LanguageRejects(AcceptedLanguages(tc.header), RejectedLanguages(tc.header), tc.candidate)
			assert.Equal(t, tc.want, got)
		})
	}
}

// RFC 4647 3.4 defines lookup as progressive truncation of the range, which is
// how a script subtag gets its own chance to match before the primary language
// does.
func TestTruncateLanguageRange(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{in: "zh-Hans-CN", want: "zh-Hans"},
		{in: "zh-Hans", want: "zh"},
		{in: "zh", want: ""},
		{in: "", want: ""},
		{in: "sr-Latn-RS", want: "sr-Latn"},
		// A singleton subtag introduces an extension and is never left
		// stranded at the end of a range.
		{in: "en-a-bbb", want: "en"},
		{in: "de-DE-u-co-phonebk", want: "de-DE-u-co"},
		{in: "en-GB-oed", want: "en-GB"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, TruncateLanguageRange(tc.in))
		})
	}
}

// Truncating all the way down terminates, for every range shape, which the
// selection loop depends on - it truncates until the range is empty.
func TestTruncateLanguageRangeTerminates(t *testing.T) {
	for _, start := range []string{"zh-Hans-CN", "en-a-bbb", "de-DE-u-co-phonebk", "x", "a-b-c-d-e"} {
		steps := 0
		for r := start; r != ""; r = TruncateLanguageRange(r) {
			steps++
			require.Less(t, steps, 20, "truncating %q from %q did not terminate", r, start)
		}
	}
}
