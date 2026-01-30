package openid4vci

import (
	"context"
	"crypto/x509"
	"vc/pkg/pki"
)

// MetadataConfig holds the configuration parameters needed to generate and sign issuer metadata
type MetadataConfig struct {
	KeyConfig                            *pki.KeyConfig
	CredentialIssuer                     string
	CredentialEndpoint                   string
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

// GenerateMetadata creates issuer metadata from configuration including credential configurations.
func GenerateMetadata(cfg *MetadataConfig) *CredentialIssuerMetadataParameters {
	metadata := &CredentialIssuerMetadataParameters{
		CredentialIssuer:                  cfg.CredentialIssuer,
		CredentialEndpoint:                cfg.CredentialEndpoint,
		CredentialConfigurationsSupported: make(map[string]CredentialConfigurationsSupported),
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

// LoadAndSign generates issuer metadata at runtime and signs it.
// Returns the metadata, signing key, signing certificate, and certificate chain.
func LoadAndSign(ctx context.Context, cfg *MetadataConfig) (*CredentialIssuerMetadataParameters, any, *x509.Certificate, []string, error) {
	// Generate metadata at runtime
	metadata := GenerateMetadata(cfg)

	// Ensure signed_metadata is empty before signing
	metadata.SignedMetadata = ""

	// Use centralized KeyLoader
	keyLoader := pki.NewKeyLoader()
	km, err := keyLoader.LoadKeyMaterial(cfg.KeyConfig)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Sign the metadata
	signedMetadata, err := metadata.Sign(km.SigningMethod, km.PrivateKey, km.Chain)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return signedMetadata, km.PrivateKey, km.Cert, km.Chain, nil
}
