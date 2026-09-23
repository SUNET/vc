package oauth2

// MetadataConfig holds the configuration parameters needed to generate OAuth2 Authorization Server Metadata
type MetadataConfig struct {
	IssuerURL     string
	TokenEndpoint string
	GrantTypes    []string // If empty, defaults to authorization_code + pre-authorized_code
}

// GenerateMetadata creates OAuth2 Authorization Server Metadata from configuration.
// This eliminates the need for separate JSON files and ensures all options are derived from configuration.
func GenerateMetadata(cfg *MetadataConfig) *AuthorizationServerMetadata {
	grantTypes := cfg.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{
			"authorization_code",
			"urn:ietf:params:oauth:grant-type:pre-authorized_code",
		}
	}

	return &AuthorizationServerMetadata{
		Issuer:                              cfg.IssuerURL,
		AuthorizationEndpoint:               cfg.IssuerURL + "/authorize",
		TokenEndpoint:                       cfg.TokenEndpoint,
		JWKSURI:                             cfg.IssuerURL + "/jwks",
		PushedAuthorizationRequestEndpoint:  cfg.IssuerURL + "/op/par",
		RequiredPushedAuthorizationRequests: true,
		GrantTypesSupported:                 grantTypes,
		// "attest_jwt_client_auth" per draft-ietf-oauth-attestation-based-client-auth-07 §10.1; "none" kept for pre-authorized_code anonymous access.
		TokenEndpointAuthMethodsSupported:             []string{"attest_jwt_client_auth", "none"},
		ClientAttestationSigningALGValuesSupported:    []string{"ES256", "ES384", "ES512"},
		ClientAttestationPoPSigningALGValuesSupported: []string{"ES256", "ES384", "ES512"},
		ResponseTypesSupported:                        []string{"code"},
		CodeChallengeMethodsSupported:                 []string{"S256"},
		DPOPSigningALGValuesSupported:                 []string{"ES256"},
	}
}
