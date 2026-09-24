package oauth2

// MetadataConfig holds the configuration parameters needed to generate OAuth2 Authorization Server Metadata
type MetadataConfig struct {
	IssuerURL     string
	TokenEndpoint string
	GrantTypes    []string // If empty, defaults to authorization_code + pre-authorized_code
	// WalletAttestationEnabled controls advertisement of
	// "attest_jwt_client_auth" (draft-ietf-oauth-attestation-based-client-auth-07 §10.1).
	// Only deployments that have wired up a wallet-attestation evaluator can
	// accept it; verifier and pre-auth-only apigw setups must leave it off.
	WalletAttestationEnabled bool
	// AllowedSignatureAlgorithms narrows the advertised
	// client_attestation_signing_alg_values_supported /
	// client_attestation_pop_signing_alg_values_supported lists to the
	// intersection with the deployment's Trust.AllowedSignatureAlgorithms.
	// Empty means: advertise the full built-in set.
	AllowedSignatureAlgorithms []string
}

// walletAttestationBaseALGs is the built-in set supported by the evaluator;
// AllowedSignatureAlgorithms may only narrow it, never widen.
var walletAttestationBaseALGs = []string{"ES256", "ES384", "ES512"}

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

	// "none" is always advertised for pre-authorized_code anonymous access.
	authMethods := []string{"none"}
	var attestationALGs, attestationPoPALGs []string
	if cfg.WalletAttestationEnabled {
		authMethods = append([]string{"attest_jwt_client_auth"}, authMethods...)
		attestationALGs = intersectALGs(walletAttestationBaseALGs, cfg.AllowedSignatureAlgorithms)
		attestationPoPALGs = intersectALGs(walletAttestationBaseALGs, cfg.AllowedSignatureAlgorithms)
	}

	return &AuthorizationServerMetadata{
		Issuer:                                        cfg.IssuerURL,
		AuthorizationEndpoint:                         cfg.IssuerURL + "/authorize",
		TokenEndpoint:                                 cfg.TokenEndpoint,
		JWKSURI:                                       cfg.IssuerURL + "/jwks",
		PushedAuthorizationRequestEndpoint:            cfg.IssuerURL + "/op/par",
		RequiredPushedAuthorizationRequests:           true,
		GrantTypesSupported:                           grantTypes,
		TokenEndpointAuthMethodsSupported:             authMethods,
		ClientAttestationSigningALGValuesSupported:    attestationALGs,
		ClientAttestationPoPSigningALGValuesSupported: attestationPoPALGs,
		ResponseTypesSupported:                        []string{"code"},
		CodeChallengeMethodsSupported:                 []string{"S256"},
		DPOPSigningALGValuesSupported:                 []string{"ES256"},
	}
}

// intersectALGs returns the members of base that also appear in allowed. If
// allowed is empty, the full base is returned unchanged.
func intersectALGs(base, allowed []string) []string {
	if len(allowed) == 0 {
		out := make([]string, len(base))
		copy(out, base)
		return out
	}
	set := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		set[a] = struct{}{}
	}
	out := make([]string, 0, len(base))
	for _, a := range base {
		if _, ok := set[a]; ok {
			out = append(out, a)
		}
	}
	return out
}
