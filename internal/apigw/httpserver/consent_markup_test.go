package httpserver

import (
	"strings"
	"testing"

	"github.com/SUNET/vc/internal/apigw/staticembed"

	"github.com/stretchr/testify/require"
)

// These assert on the SHIPPED markup and stylesheet rather than on a
// helper, because that is where each of these three defects actually
// lived: the logic was fine, the template and the stylesheet were not.
// Testing the helpers would have passed with every one of them present.
func TestConsentMarkupFixes(t *testing.T) {
	consent, err := staticembed.FS.ReadFile("consent.html")
	require.NoError(t, err)
	html := string(consent)

	t.Run("the radio follows the component's selection", func(t *testing.T) {
		// Per-row `x-data="{ checked: false }"` could not be preselected,
		// and `checked = !checked` toggled rather than assigned, so with
		// more than one credential every row the holder had touched kept
		// its highlight.
		require.Contains(t, html, `:checked="selectedCredential === index"`)
		require.NotContains(t, html, `x-data="{ checked: false }"`)
		require.NotContains(t, html, "console.log(checked)")
	})

	t.Run("a single credential does not require a click", func(t *testing.T) {
		// A hard `required` on a control that is hidden for the
		// one-credential case blocks submit with a validation message the
		// browser has nowhere to show, so it has to be conditional too.
		require.Contains(t, html, `:required="credentials.length > 1"`)
		require.NotContains(t, html, ` required class="peer`)
	})

	t.Run("the claim table sits behind a disclosure", func(t *testing.T) {
		require.Contains(t, html, `class="vc-claim-details`)
		require.Contains(t, html, "Show details")
		require.Contains(t, html, `class="vc-claims-table`)
	})

	t.Run("the claim cells can break anywhere", func(t *testing.T) {
		// `table-auto` takes its width from the columns' min-content
		// width, and Tailwind's `break-words` is `overflow-wrap:
		// break-word`, which by specification does not reduce min-content
		// size. One vct URN or issuer URL therefore pinned the table
		// wider than the panel and it spilled over the card's border at
		// every phone width. `anywhere` is the variant that shrinks it.
		styles, err := staticembed.FS.ReadFile("styles.css")
		require.NoError(t, err)
		css := strings.Join(strings.Fields(string(styles)), " ")

		require.Contains(t, css, ".vc-claims-table th, .vc-claims-table td, .vc-wrap-anywhere { overflow-wrap: anywhere; }")

		// ...and the old rule is gone from the cells it was on, or the
		// table would still size to its longest unbreakable token.
		require.NotContains(t, html, `align-top break-words min-w-0`)
	})
}
