package openid4vci

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"vc/pkg/pki"

	"github.com/golang-jwt/jwt/v5"
)

// MetadataConfig holds the configuration parameters needed to generate and sign issuer metadata
type MetadataConfig struct {
	SigningKeyPath                       string
	SigningChainPath                     string
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

	// Load signing key
	privateKey, err := pki.ParseKeyFromFile(cfg.SigningKeyPath)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Load certificate chain
	cert, chain, err := pki.ParseX509CertificateFromFile(cfg.SigningChainPath)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Encode chain to base64
	chainBase64Encoded := []string{}
	for _, c := range chain {
		chainBase64Encoded = append(chainBase64Encoded, pki.Base64EncodeCertificate(c))
	}

	// Determine signing method from key type
	var signingMethod jwt.SigningMethod
	switch privateKey.(type) {
	case *ecdsa.PrivateKey:
		signingMethod = jwt.SigningMethodES256
	case *rsa.PrivateKey:
		signingMethod = jwt.SigningMethodRS256
	default:
		signingMethod = jwt.SigningMethodRS256
	}

	// Sign the metadata
	signedMetadata, err := metadata.Sign(signingMethod, privateKey, chainBase64Encoded)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return signedMetadata, privateKey, cert, chainBase64Encoded, nil
}
