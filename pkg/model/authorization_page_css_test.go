package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The documented example sets theme: "blue" and primary_color together. Before
// the colors were resolved here, the template emitted the configured pair and
// then the theme's, two :root rules of equal specificity, so the theme won and
// the operator's color never reached the page.
func TestThemeColors(t *testing.T) {
	for _, tc := range []struct {
		name          string
		cfg           AuthorizationPageCSSConfig
		wantPrimary   string
		wantSecondary string
	}{
		{
			name:          "the default theme",
			cfg:           AuthorizationPageCSSConfig{Theme: "light"},
			wantPrimary:   "#3182ce",
			wantSecondary: "#2c5282",
		},
		{
			name:          "dark keeps the brand colors and changes only surfaces",
			cfg:           AuthorizationPageCSSConfig{Theme: "dark"},
			wantPrimary:   "#3182ce",
			wantSecondary: "#2c5282",
		},
		{
			name:          "blue",
			cfg:           AuthorizationPageCSSConfig{Theme: "blue"},
			wantPrimary:   "#3182ce",
			wantSecondary: "#2c5282",
		},
		{
			name:          "purple is the one theme with its own pair",
			cfg:           AuthorizationPageCSSConfig{Theme: "purple"},
			wantPrimary:   "#805ad5",
			wantSecondary: "#553c9a",
		},
		{
			name:          "an explicit color overrides the theme that would have chosen it",
			cfg:           AuthorizationPageCSSConfig{Theme: "blue", PrimaryColor: "#1e40af", SecondaryColor: "#1e3a8a"},
			wantPrimary:   "#1e40af",
			wantSecondary: "#1e3a8a",
		},
		{
			name:          "overriding one color leaves the theme's other one alone",
			cfg:           AuthorizationPageCSSConfig{Theme: "purple", PrimaryColor: "#1e40af"},
			wantPrimary:   "#1e40af",
			wantSecondary: "#553c9a",
		},
		{
			name:          "no theme at all answers as light rather than as empty",
			cfg:           AuthorizationPageCSSConfig{},
			wantPrimary:   "#3182ce",
			wantSecondary: "#2c5282",
		},
		{
			name:          "colors alone, with no theme, are still the answer",
			cfg:           AuthorizationPageCSSConfig{PrimaryColor: "#1e40af", SecondaryColor: "#1e3a8a"},
			wantPrimary:   "#1e40af",
			wantSecondary: "#1e3a8a",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			primary, secondary := tc.cfg.ThemeColors()
			assert.Equal(t, tc.wantPrimary, primary, "primary")
			assert.Equal(t, tc.wantSecondary, secondary, "secondary")
		})
	}
}
