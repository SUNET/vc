package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// localeEntry stands in for the two display types, which share only the field
// displayForLocales reads.
type localeEntry struct {
	locale string
}

func localeEntries(locales ...string) []localeEntry {
	entries := make([]localeEntry, 0, len(locales))
	for _, locale := range locales {
		entries = append(entries, localeEntry{locale: locale})
	}

	return entries
}

// Driven by the header rather than by a hand-derived (locales, rejected) pair,
// because that pair is only ever derived from a header - and because three of
// the bugs this test now covers lived in the seam between the two, where a
// refusal the parser dropped could not be honoured by the selection no matter
// how either behaved alone.
func TestDisplayForLocales(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []localeEntry
		header  string
		want    int
	}{
		{name: "nothing to show", entries: nil, header: "sv-SE", want: -1},
		{name: "an exact match wins", entries: localeEntries("en-US", "sv-SE", "de-DE"), header: "sv-SE", want: 1},
		{name: "the holder's order decides between two they accept", entries: localeEntries("en-US", "sv-SE"), header: "sv-SE,en-US;q=0.8", want: 1},
		{name: "a region-less preference matches a regional entry", entries: localeEntries("en-US", "sv-SE"), header: "sv", want: 1},
		{name: "a different region of the same language still matches", entries: localeEntries("de-DE", "en-US"), header: "en-GB", want: 1},
		// RFC 4647 3.4 tries the ranges in priority order, so the holder's
		// first choice reached by truncation (en-US -> en, matching en-GB)
		// outranks an exact match on their second. They said English first.
		{name: "the top range, truncated, beats an exact match on a weaker one", entries: localeEntries("en-GB", "sv-SE"), header: "en-US,sv-SE;q=0.8", want: 0},
		{name: "an exact match on the top range still wins outright", entries: localeEntries("en-GB", "en-US"), header: "en-US,sv-SE;q=0.8", want: 1},
		{name: "an unmatched holder gets English, not entry zero", entries: localeEntries("de-DE", "en-US", "sv-SE"), header: "fr-FR", want: 1},
		{name: "English is picked deterministically when there are two", entries: localeEntries("en-US", "en-GB"), header: "fr-FR", want: 1},
		{name: "with no English the lowest locale wins, not the first listed", entries: localeEntries("sv-SE", "de-DE"), header: "fr-FR", want: 1},
		{name: "an entry declaring no locale is the catch-all", entries: localeEntries("sv-SE", ""), header: "fr-FR", want: 1},
		{name: "no header at all still answers, and still prefers English", entries: localeEntries("de-DE", "en-US"), header: "", want: 1},
		{name: "metadata case does not matter", entries: localeEntries("DE-de", "SV-SE"), header: "sv-SE", want: 1},

		// Script subtags. Truncating a range one subtag at a time is what
		// keeps these apart; matching only exactly and then on the primary
		// language collapses zh-Hans and zh-Hant to "zh" and hands a
		// Simplified reader Traditional text.
		{name: "a script is matched before falling back to the language", entries: localeEntries("zh-Hant-TW", "zh-Hans"), header: "zh-Hans-CN", want: 1},
		{name: "a script range reaches a more specific entry", entries: localeEntries("zh-Hant-TW", "zh-Hans-CN"), header: "zh-Hans", want: 1},
		{name: "an exact script-and-region match still wins", entries: localeEntries("zh-Hant-TW", "zh-Hans-CN"), header: "zh-Hans-CN", want: 1},
		{name: "a script that is published nowhere falls back to the language", entries: localeEntries("de-DE", "zh-Hant-TW"), header: "zh-Hans-CN", want: 1},
		{name: "the same rule holds for a Latin and Cyrillic pair", entries: localeEntries("sr-Cyrl-RS", "sr-Latn-RS"), header: "sr-Latn", want: 1},
		{name: "an extension subtag is not left stranded by truncation", entries: localeEntries("de-DE", "en-GB"), header: "en-a-bbb", want: 1},

		// Refusals. The holder names a language they will not take, and the
		// selection has to keep honouring that through every step - which is
		// what it did not do: a tag refused with q=0 was reached anyway by the
		// language-only step, and a refusing wildcard was discarded outright.
		{name: "a refused tag is not reached through its own language", entries: localeEntries("sv-SE", "en-US"), header: "sv-SE;q=0, sv;q=1, en;q=0.8", want: 1},
		{name: "a refusal spares a sibling region it does not match", entries: localeEntries("sv-SE", "sv-FI"), header: "sv-SE;q=0, sv", want: 1},
		{name: "a refusal outranks only a less specific acceptance", entries: localeEntries("de-DE", "sv-SE"), header: "sv;q=0, sv-SE", want: 1},
		{name: "a refused tag is kept out of the English fallback too", entries: localeEntries("en-US", "sv-SE"), header: "en;q=0, fr", want: 1},
		{name: "a refused region yields the sibling region", entries: localeEntries("en-US", "en-GB"), header: "en;q=1, en-US;q=0", want: 1},
		{name: "an entry with no locale is not mistaken for a refused one", entries: localeEntries("sv-SE", ""), header: "sv-SE;q=0, sv", want: 1},
		{name: "a refusing wildcard leaves the language-independent entry", entries: localeEntries("en-US", ""), header: "fr, *;q=0", want: 1},
		{name: "an uppercase Q refuses just as a lowercase one does", entries: localeEntries("sv-SE", "en-US"), header: "sv-SE;Q=0, sv;Q=1, en;Q=0.8", want: 1},

		// Every entry refused. The page still has to name the credential, so
		// the refusals give way rather than the name disappearing.
		{name: "all refused by name still yields an entry", entries: localeEntries("en-US", "sv-SE"), header: "en;q=0, sv;q=0", want: 0},
		{name: "all refused by wildcard still yields an entry", entries: localeEntries("de-DE", "en-US"), header: "fr, *;q=0", want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := displayForLocales(
				tc.entries,
				httphelpers.AcceptedLanguages(tc.header),
				httphelpers.RejectedLanguages(tc.header),
				func(e localeEntry) string { return e.locale },
			)
			assert.Equal(t, tc.want, got)
		})
	}
}

// The regression this exists for: the Swedish holder of a credential whose
// metadata lists Swedish second used to be shown the German name.
func TestVCTMCredentialDisplayFollowsTheHolderLanguage(t *testing.T) {
	vctm := &sdjwtvc.VCTM{
		VCT:         "https://credential.example/pid",
		Name:        "PID (developer name)",
		Description: "developer description",
		Display: []sdjwtvc.VCTMDisplay{
			{Locale: "de-DE", Name: "Personalausweis", Description: "Deutsche Beschreibung"},
			{Locale: "sv-SE", Name: "Identitetshandling", Description: "Svensk beskrivning"},
			{Locale: "en-US", Name: "Identity document", Description: "English description"},
		},
	}

	display := vctmCredentialDisplay(vctm, "https://issuer.example", []string{"sv-se"}, nil)
	require.NotNil(t, display)
	assert.Equal(t, "Identitetshandling", display.Name)
	assert.Equal(t, "Svensk beskrivning", display.Description)
	assert.Equal(t, "https://credential.example/pid", display.VCT)
	assert.Equal(t, "https://issuer.example", display.Issuer)

	// A language nobody published falls back to English, not to the first
	// entry, which here is German.
	display = vctmCredentialDisplay(vctm, "https://issuer.example", []string{"fr-fr"}, nil)
	require.NotNil(t, display)
	assert.Equal(t, "Identity document", display.Name)
}

func TestMDDLCredentialDisplayFollowsTheHolderLanguage(t *testing.T) {
	mddl := &mdoc.MDDLSchema{
		DocType: "org.iso.18013.5.1.mDL",
		Display: []mdoc.DisplayProperties{
			{Locale: "de-DE", Name: "Führerschein", Description: "Deutsche Beschreibung"},
			{Locale: "sv-SE", Name: "Körkort", Description: "Svensk beskrivning"},
			{Locale: "en-US", Name: "Driving licence", Description: "English description"},
		},
	}

	display := mddlCredentialDisplay(mddl, "https://issuer.example", []string{"sv"}, nil)
	require.NotNil(t, display)
	assert.Equal(t, "Körkort", display.Name)
	assert.Equal(t, "Svensk beskrivning", display.Description)
	assert.Equal(t, "org.iso.18013.5.1.mDL", display.VCT)

	display = mddlCredentialDisplay(mddl, "https://issuer.example", nil, nil)
	require.NotNil(t, display)
	assert.Equal(t, "Driving licence", display.Name)
}

// End to end from the raw header to the name the consent page shows, over real
// VCTM metadata - the index-level semantics are TestDisplayForLocales's job,
// so this keeps only what is about resolving a name.
func TestConsentNameFromAcceptLanguageHeader(t *testing.T) {
	vctm := &sdjwtvc.VCTM{
		VCT:  "https://credential.example/pid",
		Name: "pid-v2-internal",
		Display: []sdjwtvc.VCTMDisplay{
			{Locale: "sv-SE", Name: "Identitetshandling"},
			{Locale: "en-US", Name: "Identity document"},
			{Locale: "de-DE", Name: "Personalausweis"},
		},
	}

	for _, tc := range []struct {
		name   string
		header string
		want   string
	}{
		{name: "the holder's language", header: "sv-SE,sv;q=0.9,en-US;q=0.8", want: "Identitetshandling"},
		{name: "Swedish, but not this Swedish, with English on offer", header: "sv-SE;q=0, sv;q=1, en;q=0.8", want: "Identity document"},
		{name: "a language nobody published falls back to English", header: "fr-FR,fr;q=0.9", want: "Identity document"},
		{name: "English refused, so the next deterministic choice", header: "en;q=0, fr", want: "Personalausweis"},
		{name: "nothing else, over a document that has nothing else", header: "fr, *;q=0", want: "Identity document"},
		{name: "no header at all", header: "", want: "Identity document"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			display := vctmCredentialDisplay(
				vctm,
				"https://issuer.example",
				httphelpers.AcceptedLanguages(tc.header),
				httphelpers.RejectedLanguages(tc.header),
			)
			require.NotNil(t, display)
			assert.Equal(t, tc.want, display.Name)
		})
	}
}
