package configuration

import (
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCheckW3CTypeConsistency pins the three fields as a set.
//
// credential_type_values is what a verifier constrains by, credential_types is
// what gets minted, credential_contexts is what gives a custom term meaning.
// Narrow the constraint without the other two and the deployment issues
// credentials its own verifier refuses - which is only discoverable by trying
// a presentation, so it belongs at config load.
func TestCheckW3CTypeConsistency(t *testing.T) {
	const diplomaIRI = "https://example.org/diploma#DiplomaCredential"

	cfgWith := func(cm *model.CredentialMetadata) *model.Cfg {
		return &model.Cfg{Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{"diploma": cm},
		}}
	}

	t.Run("all three configured", func(t *testing.T) {
		assert.NoError(t, checkW3CTypeConsistency(cfgWith(&model.CredentialMetadata{
			Format:               openid4vp.FormatLdpVCDCQL,
			CredentialTypes:      []string{"DiplomaCredential"},
			CredentialContexts:   []string{"https://example.org/diploma"},
			CredentialTypeValues: [][]string{{openid4vp.BaseVCTypeIRI, diplomaIRI}},
		})))
	})

	t.Run("narrowing constraint without credential_types", func(t *testing.T) {
		err := checkW3CTypeConsistency(cfgWith(&model.CredentialMetadata{
			Format:               openid4vp.FormatLdpVCDCQL,
			CredentialTypeValues: [][]string{{openid4vp.BaseVCTypeIRI, diplomaIRI}},
		}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no type beyond VerifiableCredential")
	})

	t.Run("narrowing constraint without credential_contexts", func(t *testing.T) {
		err := checkW3CTypeConsistency(cfgWith(&model.CredentialMetadata{
			Format:               openid4vp.FormatLdpVCDCQL,
			CredentialTypes:      []string{"DiplomaCredential"},
			CredentialTypeValues: [][]string{{openid4vp.BaseVCTypeIRI, diplomaIRI}},
		}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "credential_contexts")
	})

	t.Run("base-only credential_types cannot answer a narrowing constraint", func(t *testing.T) {
		err := checkW3CTypeConsistency(cfgWith(&model.CredentialMetadata{
			Format:               openid4vp.FormatLdpVCDCQL,
			CredentialTypes:      []string{"VerifiableCredential"},
			CredentialTypeValues: [][]string{{openid4vp.BaseVCTypeIRI, diplomaIRI}},
		}))
		require.Error(t, err, "base-only is as broken as unset")
		assert.Contains(t, err.Error(), "no type beyond VerifiableCredential")
	})

	t.Run("no constraint configured is not a W3C request at all", func(t *testing.T) {
		assert.NoError(t, checkW3CTypeConsistency(cfgWith(&model.CredentialMetadata{
			Format: openid4vp.FormatLdpVCDCQL,
		})))
	})

	t.Run("a base-only constraint narrows nothing, so nothing is required", func(t *testing.T) {
		assert.NoError(t, checkW3CTypeConsistency(cfgWith(&model.CredentialMetadata{
			Format:               openid4vp.FormatLdpVCDCQL,
			CredentialTypeValues: [][]string{{openid4vp.BaseVCTypeIRI}},
		})))
	})

	t.Run("other formats are untouched", func(t *testing.T) {
		assert.NoError(t, checkW3CTypeConsistency(cfgWith(&model.CredentialMetadata{
			Format: openid4vp.FormatSDJWTVC,
		})))
	})

	t.Run("no common stanza", func(t *testing.T) {
		assert.NoError(t, checkW3CTypeConsistency(&model.Cfg{}))
	})

	t.Run("a minted custom term needs a context even if nothing requests it", func(t *testing.T) {
		// No credential_type_values at all: this deployment issues but does
		// not request. The credential is still malformed without a context -
		// its type expands to a relative IRI.
		err := checkW3CTypeConsistency(cfgWith(&model.CredentialMetadata{
			Format:          openid4vp.FormatLdpVCDCQL,
			CredentialTypes: []string{"VerifiableCredential", "DiplomaCredential"},
		}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "DiplomaCredential")
		assert.Contains(t, err.Error(), "relative IRI")
	})

	t.Run("the base type alone needs no context", func(t *testing.T) {
		assert.NoError(t, checkW3CTypeConsistency(cfgWith(&model.CredentialMetadata{
			Format:          openid4vp.FormatLdpVCDCQL,
			CredentialTypes: []string{"VerifiableCredential"},
		})))
	})

	t.Run("a relative IRI in credential_type_values is refused", func(t *testing.T) {
		// This is what a compact term looks like in the wrong field. It would
		// go out in meta.type_values and match nothing, because the verifier
		// drops relative IRIs from the credential side too.
		err := checkW3CTypeConsistency(cfgWith(&model.CredentialMetadata{
			Format:               openid4vp.FormatLdpVCDCQL,
			CredentialTypes:      []string{"DiplomaCredential"},
			CredentialContexts:   []string{"https://example.org/diploma"},
			CredentialTypeValues: [][]string{{openid4vp.BaseVCTypeIRI, "DiplomaCredential"}},
		}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "relative IRI")
	})
}
