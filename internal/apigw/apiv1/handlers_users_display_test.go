package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testIssuerURL = "https://issuer.example.com"

// The consent page used to open on a flattened claim table with no heading,
// because the lookup resolved the scope's type metadata and then discarded
// everything but the claims. These are the four strings it needs to say
// what the holder is about to receive and from whom.
func TestVCTMCredentialDisplay(t *testing.T) {
	t.Run("prefers the end-user Display wording over the developer pair", func(t *testing.T) {
		// SD-JWT VC is explicit that the top-level Name/Description are for
		// developers and the Display entry is what an end user should see.
		// Showing "PID test credential, do not use in production" to a
		// holder is the failure this ordering prevents.
		got := vctmCredentialDisplay(&sdjwtvc.VCTM{
			VCT:         "https://credentials.example.com/pid",
			Name:        "pid-v2-internal",
			Description: "PID test credential, do not use in production",
			Display: []sdjwtvc.VCTMDisplay{{
				Locale:      "en-US",
				Name:        "Personal ID",
				Description: "Your identity, issued by Example University",
			}},
		}, testIssuerURL)

		require.NotNil(t, got)
		assert.Equal(t, "Personal ID", got.Name)
		assert.Equal(t, "Your identity, issued by Example University", got.Description)
		assert.Equal(t, "https://credentials.example.com/pid", got.VCT)
		assert.Equal(t, testIssuerURL, got.Issuer)
	})

	t.Run("falls back per field, not all or nothing", func(t *testing.T) {
		// A Display entry with a name and no description must not blank
		// out a description the top-level metadata does have.
		got := vctmCredentialDisplay(&sdjwtvc.VCTM{
			Name:        "pid-v2-internal",
			Description: "The holder's identity attributes",
			Display:     []sdjwtvc.VCTMDisplay{{Locale: "en-US", Name: "Personal ID"}},
		}, testIssuerURL)

		require.NotNil(t, got)
		assert.Equal(t, "Personal ID", got.Name)
		assert.Equal(t, "The holder's identity attributes", got.Description)
	})

	t.Run("uses the top-level pair when there is no Display entry", func(t *testing.T) {
		got := vctmCredentialDisplay(&sdjwtvc.VCTM{
			VCT:  "https://credentials.example.com/pid",
			Name: "Personal ID",
		}, testIssuerURL)

		require.NotNil(t, got)
		assert.Equal(t, "Personal ID", got.Name)
	})

	t.Run("no metadata, no display block", func(t *testing.T) {
		// The page then falls back to a generic heading. A missing name is
		// a worse page, never a broken one.
		assert.Nil(t, vctmCredentialDisplay(nil, testIssuerURL))
	})
}

// An MDDL schema has no top-level name, so Display is the only source and
// the doctype stands in for the vct.
func TestMDDLCredentialDisplay(t *testing.T) {
	t.Run("takes name and description from Display", func(t *testing.T) {
		got := mddlCredentialDisplay(&mdoc.MDDLSchema{
			DocType: "org.iso.18013.5.1.mDL",
			Display: []mdoc.DisplayProperties{{
				Locale:      "en-US",
				Name:        "Driving Licence",
				Description: "Your driving entitlements",
			}},
		}, testIssuerURL)

		require.NotNil(t, got)
		assert.Equal(t, "Driving Licence", got.Name)
		assert.Equal(t, "Your driving entitlements", got.Description)
		assert.Equal(t, "org.iso.18013.5.1.mDL", got.VCT)
		assert.Equal(t, testIssuerURL, got.Issuer)
	})

	t.Run("a schema with no Display still names its doctype and issuer", func(t *testing.T) {
		got := mddlCredentialDisplay(&mdoc.MDDLSchema{DocType: "org.iso.18013.5.1.mDL"}, testIssuerURL)

		require.NotNil(t, got)
		assert.Empty(t, got.Name)
		assert.Equal(t, "org.iso.18013.5.1.mDL", got.VCT)
		assert.Equal(t, testIssuerURL, got.Issuer)
	})

	t.Run("no schema, no display block", func(t *testing.T) {
		assert.Nil(t, mddlCredentialDisplay(nil, testIssuerURL))
	})
}
