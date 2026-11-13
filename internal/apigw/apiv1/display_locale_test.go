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

func TestDisplayForLocales(t *testing.T) {
	for _, tc := range []struct {
		name     string
		entries  []localeEntry
		locales  []string
		rejected []string
		want     int
	}{
		{
			name:    "nothing to show",
			entries: nil,
			locales: []string{"sv-se"},
			want:    -1,
		},
		{
			name:    "an exact match wins",
			entries: localeEntries("en-US", "sv-SE", "de-DE"),
			locales: []string{"sv-se"},
			want:    1,
		},
		{
			name:    "the holder's order decides between two entries they both accept",
			entries: localeEntries("en-US", "sv-SE"),
			locales: []string{"sv-se", "en-us"},
			want:    1,
		},
		{
			name:    "a region-less preference matches a regional entry",
			entries: localeEntries("en-US", "sv-SE"),
			locales: []string{"sv"},
			want:    1,
		},
		{
			name:    "a different region of the same language still matches",
			entries: localeEntries("de-DE", "en-US"),
			locales: []string{"en-gb"},
			want:    1,
		},
		{
			name:    "an exact match is preferred over a language match from a stronger tag",
			entries: localeEntries("en-GB", "sv-SE"),
			locales: []string{"en-us", "sv-se"},
			want:    1,
		},
		{
			name:    "an unmatched holder gets English rather than entry zero",
			entries: localeEntries("de-DE", "en-US", "sv-SE"),
			locales: []string{"fr-fr"},
			want:    1,
		},
		{
			name:    "English is picked deterministically when there is more than one",
			entries: localeEntries("en-US", "en-GB"),
			locales: []string{"fr-fr"},
			want:    1,
		},
		{
			name:    "with no English at all the lowest locale wins, not the first listed",
			entries: localeEntries("sv-SE", "de-DE"),
			locales: []string{"fr-fr"},
			want:    1,
		},
		{
			name:    "an entry declaring no locale is the catch-all",
			entries: localeEntries("sv-SE", ""),
			locales: []string{"fr-fr"},
			want:    1,
		},
		{
			name:    "no Accept-Language still answers, and still prefers English",
			entries: localeEntries("de-DE", "en-US"),
			locales: nil,
			want:    1,
		},
		{
			name:    "metadata case does not matter",
			entries: localeEntries("DE-de", "SV-SE"),
			locales: []string{"sv-se"},
			want:    1,
		},
		{
			// Accept-Language: sv-SE;q=0, sv;q=1, en;q=0.8 - the holder wants
			// Swedish but not this Swedish. The language-only step must not
			// hand them the entry they ruled out while English is on offer.
			name:     "a rejected tag is not reached through its own language",
			entries:  localeEntries("sv-SE", "en-US"),
			locales:  []string{"sv", "en"},
			rejected: []string{"sv-se"},
			want:     1,
		},
		{
			name:     "a rejection does not exclude a sibling region it does not match",
			entries:  localeEntries("sv-SE", "sv-FI"),
			locales:  []string{"sv"},
			rejected: []string{"sv-se"},
			want:     1,
		},
		{
			name:     "a rejection outranks only a less specific acceptance",
			entries:  localeEntries("de-DE", "sv-SE"),
			locales:  []string{"sv-se"},
			rejected: []string{"sv"},
			want:     1,
		},
		{
			name:     "a rejected tag is kept out of the English fallback too",
			entries:  localeEntries("en-US", "sv-SE"),
			locales:  []string{"fr"},
			rejected: []string{"en"},
			want:     1,
		},
		{
			// Nothing acceptable is left, and the page still has to name the
			// credential, so the rejections are ignored rather than answering
			// with nothing.
			name:     "every entry ruled out still yields an entry",
			entries:  localeEntries("en-US", "sv-SE"),
			locales:  nil,
			rejected: []string{"en", "sv"},
			want:     0,
		},
		{
			name:     "an entry declaring no locale is not mistaken for a rejected one",
			entries:  localeEntries("sv-SE", ""),
			locales:  []string{"sv"},
			rejected: []string{"sv-se"},
			want:     1,
		},
		{
			// Accept-Language: en;q=1,en-US;q=0 - the holder takes English
			// but not the US variant, and the document offers both.
			name:     "a refused region yields the sibling region of the same language",
			entries:  localeEntries("en-US", "en-GB"),
			locales:  []string{"en"},
			rejected: []string{"en-us"},
			want:     1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := displayForLocales(tc.entries, tc.locales, tc.rejected, func(e localeEntry) string { return e.locale })
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

// End to end from the raw header to the name the consent page shows, which is
// the pairing that matters: the parser drops a q=0 tag from the preferences,
// and the selection has to keep honouring it anyway or the holder is handed
// the one entry they ruled out.
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
		{
			name:   "the holder's language",
			header: "sv-SE,sv;q=0.9,en-US;q=0.8",
			want:   "Identitetshandling",
		},
		{
			name:   "Swedish, but not this Swedish, with English on offer",
			header: "sv-SE;q=0, sv;q=1, en;q=0.8",
			want:   "Identity document",
		},
		{
			name:   "Swedish of another region is still Swedish",
			header: "sv-FI",
			want:   "Identitetshandling",
		},
		{
			name:   "a language nobody published falls back to English",
			header: "fr-FR,fr;q=0.9",
			want:   "Identity document",
		},
		{
			name:   "English refused, so the next deterministic choice",
			header: "en;q=0, fr",
			want:   "Personalausweis",
		},
		{
			name:   "no header at all",
			header: "",
			want:   "Identity document",
		},
		{
			name:   "an uppercase Q refuses the same language a lowercase one would",
			header: "sv-SE;Q=0, sv;Q=1, en;Q=0.8",
			want:   "Identity document",
		},
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
