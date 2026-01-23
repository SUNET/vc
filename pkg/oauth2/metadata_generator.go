package oauth2

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"vc/pkg/pki"

	"github.com/golang-jwt/jwt/v5"
)

// MetadataConfig holds the configuration parameters needed to generate OAuth2 Authorization Server Metadata
type MetadataConfig struct {
	IssuerURL        string
	TokenEndpoint    string
	SigningKeyPath   string
	SigningChainPath string
}

// GenerateMetadata creates OAuth2 Authorization Server Metadata from configuration.
// This eliminates the need for separate JSON files and ensures all options are derived from configuration.
func GenerateMetadata(cfg *MetadataConfig) *AuthorizationServerMetadata {
	return &AuthorizationServerMetadata{
		Issuer:                              cfg.IssuerURL,
		AuthorizationEndpoint:               cfg.IssuerURL + "/authorize",
		TokenEndpoint:                       cfg.TokenEndpoint,
		PushedAuthorizationRequestEndpoint:  cfg.IssuerURL + "/op/par",
		RequiredPushedAuthorizationRequests: true,
		TokenEndpointAuthMethodsSupported:   []string{"none"},
		ResponseTypesSupported:              []string{"code"},
		CodeChallengeMethodsSupported:       []string{"S256"},
		DPOPSigningALGValuesSupported:       []string{"ES256"},
	}
}

// GenerateAndSign generates OAuth2 Authorization Server Metadata from configuration and signs it.
// Returns the metadata, signing key, and certificate chain for further use.
func GenerateAndSign(cfg *MetadataConfig) (*AuthorizationServerMetadata, any, []string, error) {
	// Generate metadata
	metadata := GenerateMetadata(cfg)

	// Load signing key
	privateKey, err := pki.ParseKeyFromFile(cfg.SigningKeyPath)
	if err != nil {
		return nil, nil, nil, err
	}

	// Load certificate chain
	_, chain, err := pki.ParseX509CertificateFromFile(cfg.SigningChainPath)
	if err != nil {
		return nil, nil, nil, err
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
		return nil, nil, nil, err
	}

	return signedMetadata, privateKey, chainBase64Encoded, nil
}
