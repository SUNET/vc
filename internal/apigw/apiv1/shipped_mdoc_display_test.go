package apiv1

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/mdoc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadShippedMDoc(t *testing.T, name string) *mdoc.MDDLSchema {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "metadata", name))
	require.NoError(t, err)
	schema, err := mdoc.LoadMDDLSchema(raw)
	require.NoError(t, err)
	return schema
}

var shippedMDocSchemas = []string{"mdl.mdoc.json", "pid_mdoc.mdoc.json"}

// SUNET/vc#605: the issuer metadata carries localized claim display for
// SD-JWT credentials and not for mdoc ones. The mapping code was already
// there (pkg/model/config.go copies meta.Display into ClaimDescription);
// what was missing is the data - no claim in either shipped schema had a
// display block, so there was nothing to copy.
func TestShippedMDocClaimsHaveDisplay(t *testing.T) {
	for _, name := range shippedMDocSchemas {
		t.Run(name, func(t *testing.T) {
			schema := loadShippedMDoc(t, name)
			require.NotEmpty(t, schema.Claims)

			for namespace, elements := range schema.Claims {
				require.NotEmpty(t, elements, "namespace %s has no elements", namespace)
				for elementID, meta := range elements {
					require.NotEmpty(t, meta.Display,
						"%s/%s has no display, so the issuer metadata carries none", namespace, elementID)

					display := meta.Display[0]
					assert.NotEmpty(t, display.Locale, "%s: display needs a locale to be localizable", elementID)
					assert.NotEmpty(t, display.Label, "%s: display needs a human label", elementID)
					assert.Equal(t, elementID, display.Name,
						"%s: name should be the element id, as the SD-JWT VC schemas do it", elementID)
				}
			}
		})
	}
}

// Every placeholder the card draws must be backed by a claim carrying that
// svg_id, or the card renders with a literal {{given_name}} in it. The two
// halves live in the same file and drifted apart is exactly how that
// happens, so they are compared rather than eyeballed.
func TestShippedMDocCardPlaceholdersAreBackedByClaims(t *testing.T) {
	placeholder := regexp.MustCompile(`{{(\w+)}}`)

	for _, name := range shippedMDocSchemas {
		t.Run(name, func(t *testing.T) {
			schema := loadShippedMDoc(t, name)

			uri := mddlCardURI(schema)
			require.NotEmpty(t, uri)
			_, encoded, found := strings.Cut(uri, "base64,")
			require.True(t, found, "the card is not a base64 data URI")
			svg, err := base64.StdEncoding.DecodeString(encoded)
			require.NoError(t, err)

			svgIDs := map[string]bool{}
			for _, elements := range schema.Claims {
				for _, meta := range elements {
					if meta.SVGID != "" {
						svgIDs[meta.SVGID] = true
					}
				}
			}

			matches := placeholder.FindAllStringSubmatch(string(svg), -1)
			require.NotEmpty(t, matches, "the card draws no claim values")

			for _, m := range matches {
				assert.True(t, svgIDs[m[1]],
					"the card draws {{%s}} but no claim carries that svg_id", m[1])
			}
		})
	}
}

// SVGValues is what turns those svg_ids into the values the consent page
// substitutes; it needs both an svg_id and a display on the claim, so this
// checks the two shipped schemas actually satisfy it.
func TestShippedMDocSchemasProduceSVGValues(t *testing.T) {
	for _, name := range shippedMDocSchemas {
		t.Run(name, func(t *testing.T) {
			schema := loadShippedMDoc(t, name)

			values := schema.SVGValues(map[string]any{
				"given_name":      "Ada",
				"family_name":     "Lovelace",
				"birth_date":      "1815-12-10",
				"document_number": "ABC-123",
				"expiry_date":     "2030-01-01",
				"issuing_country": "SE",
			})

			require.NotEmpty(t, values, "the consent card would render with empty slots")
			assert.Equal(t, "Ada", values["given_name"].Value)
			assert.Equal(t, "First name", values["given_name"].Label)
			assert.Equal(t, "Lovelace", values["family_name"].Value)
		})
	}
}
