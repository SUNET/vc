package oauth2

// MetadataConfig holds the configuration parameters needed to generate OAuth2 Authorization Server Metadata
type MetadataConfig struct {
	IssuerURL     string
	TokenEndpoint string
}

// GenerateMetadata creates OAuth2 Authorization Server Metadata from configuration.
// This eliminates the need for separate JSON files and ensures all options are derived from configuration.
func GenerateMetadata(cfg *MetadataConfig) *AuthorizationServerMetadata {
	return &AuthorizationServerMetadata{
		Issuer:                              cfg.IssuerURL,
		AuthorizationEndpoint:               cfg.IssuerURL + "/authorize",
		TokenEndpoint:                       cfg.TokenEndpoint,
		JWKSURI:                             cfg.IssuerURL + "/jwks",
		PushedAuthorizationRequestEndpoint:  cfg.IssuerURL + "/op/par",
		RequiredPushedAuthorizationRequests: true,
		TokenEndpointAuthMethodsSupported:   []string{"none"},
		ResponseTypesSupported:              []string{"code"},
		CodeChallengeMethodsSupported:       []string{"S256"},
		DPOPSigningALGValuesSupported:       []string{"ES256"},
	}
}
