package oauth2

import (
	"vc/pkg/pki"
)

// MetadataConfig holds the configuration parameters needed to generate OAuth2 Authorization Server Metadata
type MetadataConfig struct {
	IssuerURL     string
	TokenEndpoint string
	KeyConfig     *pki.KeyConfig
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

	// Use centralized KeyLoader
	keyLoader := pki.NewKeyLoader()
	km, err := keyLoader.LoadKeyMaterial(cfg.KeyConfig)
	if err != nil {
		return nil, nil, nil, err
	}

	// Sign the metadata
	signedMetadata, err := metadata.Sign(km.SigningMethod, km.PrivateKey, km.Chain)
	if err != nil {
		return nil, nil, nil, err
	}

	return signedMetadata, km.PrivateKey, km.Chain, nil
}
