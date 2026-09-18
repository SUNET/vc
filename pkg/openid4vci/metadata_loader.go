package openid4vci

import (
	"context"

	"github.com/SUNET/vc/pkg/pki"
)

// MetadataConfig holds the configuration parameters needed to generate and sign issuer metadata
type MetadataConfig struct {
	// KeyConfig is not read by GenerateIssuerMetadata: it returns unsigned
	// metadata, and the endpoint handler signs on demand so the JWS is fresh
	// (see the method's doc comment). Kept because callers hold the key
	// configuration alongside the rest of this, and signing needs it.
	KeyConfig                  *pki.KeyConfig
	CredentialIssuer           string
	CredentialEndpoint         string
	NonceEndpoint              string
	AuthorizationServers       []string
	DeferredCredentialEndpoint string
	NotificationEndpoint       string
	// CryptographicBindingMethodsSupported and
	// CredentialSigningAlgValuesSupported are issuer-level DEFAULTS: OID4VCI
	// puts both on the credential configuration, not on the issuer, so
	// GenerateIssuerMetadata applies them to every configuration that does not
	// state its own. A configuration's own value always wins.
	//
	// CredentialSigningAlgValuesSupported is []string, while the published
	// field is []any because mso_mdoc identifies algorithms by COSE integer
	// (-7 for ES256) rather than by JOSE name. An issuer-level default
	// therefore cannot express what an mso_mdoc configuration needs, so it is
	// not applied to one - see applyDefaults.
	CryptographicBindingMethodsSupported []string
	CredentialSigningAlgValuesSupported  []string
	// ProofSigningAlgValuesSupported is NOT applied here, unlike the two
	// above. In the published metadata these algorithms live inside
	// ProofTypesSupported, keyed by proof type, and which proof types an
	// issuer advertises - and for which configurations - is deployment policy
	// rather than a flat default: see model.IssuerMetadata's
	// applyCommonCredentialConfig, where declaring `attestation` uniformly
	// across every configuration is a deliberate workaround for a wallet
	// library that validates proof_types_supported document-wide. Composing
	// that map here would duplicate the policy in the place least able to see
	// it, so callers populate ProofTypesSupported themselves.
	ProofSigningAlgValuesSupported    []string
	CredentialResponseEncryption      *MetadataCredentialResponseEncryption
	BatchCredentialIssuance           *BatchCredentialIssuance
	Display                           []MetadataDisplay
	Claims                            []ClaimDescription
	CredentialConfigurationsSupported map[string]CredentialConfigurationsSupported
	MdocIacasURI                      string
}

// GenerateIssuerMetadata creates issuer metadata from configuration.
// Returns unsigned metadata that should be signed on-demand in the endpoint handler for freshness.
func (cfg *MetadataConfig) GenerateIssuerMetadata(ctx context.Context) *CredentialIssuerMetadataParameters {
	metadata := &CredentialIssuerMetadataParameters{
		CredentialIssuer:                  cfg.CredentialIssuer,
		CredentialEndpoint:                cfg.CredentialEndpoint,
		CredentialConfigurationsSupported: make(map[string]CredentialConfigurationsSupported),
	}

	if cfg.NonceEndpoint != "" {
		metadata.NonceEndpoint = cfg.NonceEndpoint
	}

	if len(cfg.AuthorizationServers) > 0 {
		metadata.AuthorizationServers = cfg.AuthorizationServers
	}

	if cfg.DeferredCredentialEndpoint != "" {
		metadata.DeferredCredentialEndpoint = cfg.DeferredCredentialEndpoint
	}

	if cfg.NotificationEndpoint != "" {
		metadata.NotificationEndpoint = cfg.NotificationEndpoint
	}

	// Copy the caller's configurations rather than aliasing them: the
	// defaults below are written back into this map, and a "generate" helper
	// that mutates what it was handed would leak them into a caller that
	// reuses cfg.
	for id, config := range cfg.CredentialConfigurationsSupported {
		metadata.CredentialConfigurationsSupported[id] = cfg.applyDefaults(config)
	}

	// Set credential response encryption if provided
	if cfg.CredentialResponseEncryption != nil {
		metadata.CredentialResponseEncryption = cfg.CredentialResponseEncryption
	}

	// Set batch credential issuance if provided
	if cfg.BatchCredentialIssuance != nil {
		metadata.BatchCredentialIssuance = cfg.BatchCredentialIssuance
	}

	// Set display information if provided
	if len(cfg.Display) > 0 {
		metadata.Display = cfg.Display
	}

	// Set claims if provided
	if len(cfg.Claims) > 0 {
		metadata.Claims = cfg.Claims
	}

	// Set mdoc IACA endpoint if provided
	if cfg.MdocIacasURI != "" {
		metadata.MdocIacasURI = cfg.MdocIacasURI
	}

	return metadata
}

// applyDefaults returns config with the issuer-level defaults filled in for
// whatever it does not state itself. Both fields belong to the credential
// configuration in OID4VCI, so an issuer-level setting can only be a default,
// and a configuration's own value always wins.
//
// These were previously accepted and ignored, which made them a trap: a caller
// setting CryptographicBindingMethodsSupported got metadata without it, and
// that field is how a Wallet knows whether to bind the holder key by value
// (`jwk`) or by a DID (`did:jwk`). OID4VCI allows only one of `jwk` and `kid`
// in a proof header, so a Wallet that cannot read it has to guess.
//
// vc's own path is unaffected: model.IssuerMetadata's
// applyCommonCredentialConfig already fills both in per configuration before
// they reach here, so every value is already set and nothing is overwritten.
func (cfg *MetadataConfig) applyDefaults(
	config CredentialConfigurationsSupported,
) CredentialConfigurationsSupported {
	if len(config.CryptographicBindingMethodsSupported) == 0 &&
		len(cfg.CryptographicBindingMethodsSupported) > 0 {
		methods := make([]string, len(cfg.CryptographicBindingMethodsSupported))
		copy(methods, cfg.CryptographicBindingMethodsSupported)
		config.CryptographicBindingMethodsSupported = methods
	}

	// mso_mdoc identifies signing algorithms by COSE integer (-7 for ES256),
	// not by JOSE name, and the issuer-level default is []string - so it
	// cannot say what such a configuration needs. Publishing "ES256" where -7
	// is meant would be worse than publishing nothing, and the field is
	// OPTIONAL, so an mso_mdoc configuration states its own or goes without.
	if len(config.CredentialSigningAlgValuesSupported) == 0 &&
		len(cfg.CredentialSigningAlgValuesSupported) > 0 &&
		config.Format != "mso_mdoc" {
		algs := make([]any, len(cfg.CredentialSigningAlgValuesSupported))
		for i, alg := range cfg.CredentialSigningAlgValuesSupported {
			algs[i] = alg
		}
		config.CredentialSigningAlgValuesSupported = algs
	}

	return config
}
