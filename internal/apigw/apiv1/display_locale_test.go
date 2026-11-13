package apiv1

import (
	"testing"

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
		name    string
		entries []localeEntry
		locales []string
		want    int
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := displayForLocales(tc.entries, tc.locales, func(e localeEntry) string { return e.locale })
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

	display := vctmCredentialDisplay(vctm, "https://issuer.example", []string{"sv-se"})
	require.NotNil(t, display)
	assert.Equal(t, "Identitetshandling", display.Name)
	assert.Equal(t, "Svensk beskrivning", display.Description)
	assert.Equal(t, "https://credential.example/pid", display.VCT)
	assert.Equal(t, "https://issuer.example", display.Issuer)

	// A language nobody published falls back to English, not to the first
	// entry, which here is German.
	display = vctmCredentialDisplay(vctm, "https://issuer.example", []string{"fr-fr"})
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

	display := mddlCredentialDisplay(mddl, "https://issuer.example", []string{"sv"})
	require.NotNil(t, display)
	assert.Equal(t, "Körkort", display.Name)
	assert.Equal(t, "Svensk beskrivning", display.Description)
	assert.Equal(t, "org.iso.18013.5.1.mDL", display.VCT)

	display = mddlCredentialDisplay(mddl, "https://issuer.example", nil)
	require.NotNil(t, display)
	assert.Equal(t, "Driving licence", display.Name)
}
