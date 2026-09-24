package configuration

import (
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCheckCredentialMetadataEntries pins the refusal of a scope written with
// nothing under it.
//
// Skipping such an entry only moves the failure: the verifier's Client.New
// iterates the map and dereferences it at startup. The check has to sit where
// every credential-using service reaches it - ResolveVCTUrls is gated on an
// APIGW stanza, so a verifier-only config file never runs it.
func TestCheckCredentialMetadataEntries(t *testing.T) {
	t.Run("a fully configured map passes", func(t *testing.T) {
		assert.NoError(t, checkCredentialMetadataEntries(&model.Cfg{Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"pid": {Format: "dc+sd-jwt", VCTM: &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"}},
			},
		}}))
	})

	t.Run("an empty entry is named", func(t *testing.T) {
		err := checkCredentialMetadataEntries(&model.Cfg{Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"pid":    {Format: "dc+sd-jwt", VCTM: &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"}},
				"broken": nil,
			},
		}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "broken")
		assert.NotContains(t, err.Error(), "pid")
	})

	t.Run("every empty entry is reported at once, in order", func(t *testing.T) {
		err := checkCredentialMetadataEntries(&model.Cfg{Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"zeta": nil, "alpha": nil,
			},
		}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "alpha, zeta")
	})

	t.Run("no common stanza is not this check's problem", func(t *testing.T) {
		assert.NoError(t, checkCredentialMetadataEntries(&model.Cfg{}))
	})
}
