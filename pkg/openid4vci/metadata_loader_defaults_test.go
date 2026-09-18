package openid4vci

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MetadataConfig's issuer-level CryptographicBindingMethodsSupported and
// CredentialSigningAlgValuesSupported were accepted and ignored, which made
// them a trap: a caller setting them got metadata without them.
//
// The binding methods matter most. That field is how a Wallet knows whether to
// bind the holder key by value (`jwk`, which HAIP expects) or by a DID
// (`did:jwk`, which DIIP expects), and OID4VCI allows only one of `jwk` and
// `kid` in a proof header - so a Wallet that cannot read it has to guess.

func TestIssuerLevelDefaultsReachEveryConfiguration(t *testing.T) {
	cfg := &MetadataConfig{
		CredentialIssuer:                     "https://issuer.example",
		CredentialEndpoint:                   "https://issuer.example/credential",
		CryptographicBindingMethodsSupported: []string{"jwk"},
		CredentialSigningAlgValuesSupported:  []string{"ES256"},
		CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
			"pid": {Format: "dc+sd-jwt"},
			"mdl": {Format: "mso_mdoc"},
		},
	}

	metadata := cfg.GenerateIssuerMetadata(context.Background())

	require.Len(t, metadata.CredentialConfigurationsSupported, 2)
	for id, config := range metadata.CredentialConfigurationsSupported {
		assert.Equal(t, []string{"jwk"}, config.CryptographicBindingMethodsSupported,
			"configuration %s should have inherited the issuer-level binding methods", id)
		assert.Equal(t, []any{"ES256"}, config.CredentialSigningAlgValuesSupported,
			"configuration %s should have inherited the issuer-level signing algorithms", id)
	}
}

func TestAConfigurationKeepsItsOwnValues(t *testing.T) {
	// The issuer-level value is a default, not an override. An mdoc device key
	// is a cose_key whatever the issuer's default says.
	cfg := &MetadataConfig{
		CredentialIssuer:                     "https://issuer.example",
		CredentialEndpoint:                   "https://issuer.example/credential",
		CryptographicBindingMethodsSupported: []string{"jwk"},
		CredentialSigningAlgValuesSupported:  []string{"ES256"},
		CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
			"pid": {Format: "dc+sd-jwt"},
			"mdl": {
				Format:                               "mso_mdoc",
				CryptographicBindingMethodsSupported: []string{"cose_key"},
				CredentialSigningAlgValuesSupported:  []any{"ES384"},
			},
		},
	}

	metadata := cfg.GenerateIssuerMetadata(context.Background())

	assert.Equal(t, []string{"jwk"},
		metadata.CredentialConfigurationsSupported["pid"].CryptographicBindingMethodsSupported)
	assert.Equal(t, []string{"cose_key"},
		metadata.CredentialConfigurationsSupported["mdl"].CryptographicBindingMethodsSupported)
	assert.Equal(t, []any{"ES384"},
		metadata.CredentialConfigurationsSupported["mdl"].CredentialSigningAlgValuesSupported)
}

func TestNoIssuerLevelDefaultsPublishesNothing(t *testing.T) {
	// Both fields are OPTIONAL in OID4VCI. An issuer that configures nothing
	// publishes nothing; inventing a value would claim something the
	// deployment never said.
	cfg := &MetadataConfig{
		CredentialIssuer:   "https://issuer.example",
		CredentialEndpoint: "https://issuer.example/credential",
		CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
			"pid": {Format: "dc+sd-jwt"},
		},
	}

	metadata := cfg.GenerateIssuerMetadata(context.Background())

	assert.Empty(t, metadata.CredentialConfigurationsSupported["pid"].CryptographicBindingMethodsSupported)
	assert.Empty(t, metadata.CredentialConfigurationsSupported["pid"].CredentialSigningAlgValuesSupported)
}

func TestADidBindingMethodSurvivesToTheMetadata(t *testing.T) {
	// A DIIP deployment advertises did:jwk, and a Wallet reading this is how
	// it knows to name the holder key by DID rather than carry it.
	cfg := &MetadataConfig{
		CredentialIssuer:                     "https://issuer.example",
		CredentialEndpoint:                   "https://issuer.example/credential",
		CryptographicBindingMethodsSupported: []string{"did:jwk", "jwk"},
		CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
			"pid": {Format: "dc+sd-jwt"},
		},
	}

	metadata := cfg.GenerateIssuerMetadata(context.Background())

	assert.Equal(t, []string{"did:jwk", "jwk"},
		metadata.CredentialConfigurationsSupported["pid"].CryptographicBindingMethodsSupported)
}
