package openid4vp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateCredentialQueryRejectsRelativeTypeValueMembers: MatchTypeValues
// requires a credential to carry ALL of an alternative's types, and the
// verifier drops relative IRIs from the credential's expanded types - so an
// alternative holding one good IRI and one compact term validated, was sent,
// and could never match. A query that cannot be satisfied is not a
// constraint; it is an outage wearing a constraint's shape.
func TestValidateCredentialQueryRejectsRelativeTypeValueMembers(t *testing.T) {
	const diploma = "https://example.org/Diploma"

	query := func(alternative []string) CredentialQuery {
		return CredentialQuery{
			ID:     "eudi_pid",
			Format: FormatLdpVCDCQL,
			Meta:   MetaQuery{TypeValues: [][]string{alternative}},
		}
	}

	require.NoError(t, ValidateCredentialQuery(query([]string{BaseVCTypeIRI, diploma})))

	for name, alternative := range map[string][]string{
		"a compact term alongside a good IRI": {BaseVCTypeIRI, diploma, "DiplomaCredential"},
		"an empty member":                     {BaseVCTypeIRI, diploma, ""},
		"a relative reference with a colon":   {BaseVCTypeIRI, diploma, "/relative:Type"},
		"a scheme that is not one":            {BaseVCTypeIRI, diploma, "1:Type"},
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidateCredentialQuery(query(alternative))
			require.Error(t, err, "every member is matched as a fully expanded IRI")
			assert.Contains(t, err.Error(), "can never match a credential")
		})
	}

	// The base-only rule still stands on its own: every member is absolute
	// and the alternative still constrains nothing.
	err := ValidateCredentialQuery(query([]string{BaseVCTypeIRI}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "beyond "+BaseVCTypeIRI)
}
