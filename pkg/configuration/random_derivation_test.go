package configuration

import (
	"testing"

	"github.com/SUNET/vc/pkg/credential/primitives"
	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func presentationCfg(derivations ...primitives.Derivation) *model.Cfg {
	return &model.Cfg{APIGW: &model.APIGW{DataSources: model.DataSources{
		Presentation: model.PresentationConfig{Scopes: map[string]model.PresentationScope{
			"diploma": {FromScope: "eduid", Derivations: derivations},
		}},
	}}}
}

// Derivations run twice on a presentation source - once for the consent
// preview, once for issuance - from the same verified claims with nothing
// carried between them. Every other primitive is a function of its input, so
// both runs agree; random is not, so the identifier the holder approves is
// not the one they receive. That failure is invisible at runtime: nothing
// errors, the two values simply differ.
func TestCheckRandomDerivations_RefusesOnAPresentationSource(t *testing.T) {
	err := checkRandomDerivations(presentationCfg(
		primitives.Derivation{Trim: &primitives.TrimArgs{Input: "name"}},
		primitives.Derivation{Random: &primitives.RandomArgs{Output: "document_id"}},
	))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "derivations[1]", "the error must name the entry to remove")
	assert.Contains(t, err.Error(), "diploma", "and the scope it is on")
	assert.Contains(t, err.Error(), "presentation")
}

func TestCheckRandomDerivations_Accepts(t *testing.T) {
	t.Run("a presentation scope with other primitives", func(t *testing.T) {
		assert.NoError(t, checkRandomDerivations(presentationCfg(
			primitives.Derivation{Trim: &primitives.TrimArgs{Input: "name"}},
			primitives.Derivation{Lowercase: &primitives.LowercaseArgs{Input: "email"}},
		)))
	})

	t.Run("a presentation scope with no derivations", func(t *testing.T) {
		assert.NoError(t, checkRandomDerivations(presentationCfg()))
	})

	t.Run("a service that is not the apigw", func(t *testing.T) {
		assert.NoError(t, checkRandomDerivations(&model.Cfg{}))
	})

	// The sources the feature is actually for. Assertion sources run
	// derivations once, before the document is cached, so one value covers
	// consent and every credential issued from that session.
	t.Run("an assertion source", func(t *testing.T) {
		cfg := &model.Cfg{APIGW: &model.APIGW{DataSources: model.DataSources{
			Assertion: model.AssertionConfig{Scopes: map[string]model.AssertionScope{
				"diploma": {Derivations: []primitives.Derivation{
					{Random: &primitives.RandomArgs{Output: "document_id"}},
				}},
			}},
		}}}
		assert.NoError(t, checkRandomDerivations(cfg))
	})
}
