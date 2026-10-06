package apiv1

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SUNET/vc/pkg/mdoc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The report (SUNET/vc#737) names mDL and PID (mdoc) specifically, and those
// are exactly the two shipped schemas that carried no image at all: every
// VCTM has rendering.svg_templates, both mdoc schemas had neither a template
// nor a logo, so the consent page had nothing to draw.
func TestShippedMDocSchemasOfferACardImage(t *testing.T) {
	for _, name := range []string{"mdl.mdoc.json", "pid_mdoc.mdoc.json"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", "..", "metadata", name))
			require.NoError(t, err)

			schema, err := mdoc.LoadMDDLSchema(raw)
			require.NoError(t, err)

			uri := mddlCardURI(schema)
			require.NotEmpty(t, uri, "the consent page would render no card for this credential")
			assert.True(t, len(uri) > len("data:image/svg+xml;base64,"),
				"the data URI carries no payload")
			assert.Contains(t, uri, "data:image/svg+xml;base64,",
				"an https template URI would be fetched at consent time; a data URI is served from the schema")
		})
	}
}
