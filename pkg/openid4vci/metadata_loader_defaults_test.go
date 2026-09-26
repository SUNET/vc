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
	}
	assert.Equal(t, []any{"ES256"},
		metadata.CredentialConfigurationsSupported["pid"].CredentialSigningAlgValuesSupported)
}

func TestAnMdocGetsNoStringTypedSigningAlgDefault(t *testing.T) {
	// mso_mdoc identifies signing algorithms by COSE integer (-7 for ES256),
	// not by JOSE name, and the issuer-level default is []string - so it
	// cannot say what such a configuration needs. Publishing "ES256" where -7
	// is meant would be worse than publishing nothing, and the field is
	// OPTIONAL.
	cfg := &MetadataConfig{
		CredentialIssuer:                    "https://issuer.example",
		CredentialEndpoint:                  "https://issuer.example/credential",
		CredentialSigningAlgValuesSupported: []string{"ES256"},
		CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
			"mdl": {Format: "mso_mdoc"},
			"mdl-cose": {
				Format:                              "mso_mdoc",
				CredentialSigningAlgValuesSupported: []any{-7},
			},
		},
	}

	metadata := cfg.GenerateIssuerMetadata(context.Background())

	assert.Empty(t, metadata.CredentialConfigurationsSupported["mdl"].CredentialSigningAlgValuesSupported)
	// And a configuration that states its own COSE identifiers keeps them.
	assert.Equal(t, []any{-7},
		metadata.CredentialConfigurationsSupported["mdl-cose"].CredentialSigningAlgValuesSupported)
}

func TestGeneratingMetadataDoesNotMutateTheCallersConfiguration(t *testing.T) {
	// A "generate" helper that writes back into what it was handed leaks the
	// defaults into a caller that reuses cfg - and then a later change to the
	// issuer-level default silently does nothing, because the configuration
	// now "states its own".
	cfg := &MetadataConfig{
		CredentialIssuer:                     "https://issuer.example",
		CredentialEndpoint:                   "https://issuer.example/credential",
		CryptographicBindingMethodsSupported: []string{"jwk"},
		CredentialSigningAlgValuesSupported:  []string{"ES256"},
		CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
			"pid": {Format: "dc+sd-jwt"},
		},
	}

	metadata := cfg.GenerateIssuerMetadata(context.Background())
	require.Equal(t, []string{"jwk"},
		metadata.CredentialConfigurationsSupported["pid"].CryptographicBindingMethodsSupported)

	assert.Empty(t, cfg.CredentialConfigurationsSupported["pid"].CryptographicBindingMethodsSupported,
		"the caller's configuration must be untouched")
	assert.Empty(t, cfg.CredentialConfigurationsSupported["pid"].CredentialSigningAlgValuesSupported,
		"the caller's configuration must be untouched")

	// The returned metadata must not alias the issuer-level slice either.
	metadata.CredentialConfigurationsSupported["pid"].CryptographicBindingMethodsSupported[0] = "did:jwk"
	assert.Equal(t, []string{"jwk"}, cfg.CryptographicBindingMethodsSupported)
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
