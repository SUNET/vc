package openid4vci

import (
	"context"

	"github.com/SUNET/vc/pkg/pki"
)

// MetadataConfig holds the configuration parameters needed to generate and sign issuer metadata
type MetadataConfig struct {
	KeyConfig                            *pki.KeyConfig
	CredentialIssuer                     string
	CredentialEndpoint                   string
	NonceEndpoint                        string
	AuthorizationServers                 []string
	DeferredCredentialEndpoint           string
	NotificationEndpoint                 string
	CryptographicBindingMethodsSupported []string
	CredentialSigningAlgValuesSupported  []string
	ProofSigningAlgValuesSupported       []string
	CredentialResponseEncryption         *MetadataCredentialResponseEncryption
	BatchCredentialIssuance              *BatchCredentialIssuance
	Display                              []MetadataDisplay
	CredentialConfigurationsSupported    map[string]CredentialConfigurationsSupported
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

	// Use provided CredentialConfigurationsSupported directly
	if cfg.CredentialConfigurationsSupported != nil {
		metadata.CredentialConfigurationsSupported = cfg.CredentialConfigurationsSupported
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

	return metadata
}
