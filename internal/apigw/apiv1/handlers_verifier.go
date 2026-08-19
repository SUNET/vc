package apiv1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/issuance"
	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type VerificationRequestObjectRequest struct {
	ID string `form:"id" uri:"id" validate:"required,max=128,printascii"`
}

func (c *Client) VerificationRequestObject(ctx context.Context, req *VerificationRequestObjectRequest) (string, error) {
	c.log.Debug("Verification request object", "req", req)

	authorizationContext, err := c.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{
		VerifierResponseCode: req.ID,
	})
	if err != nil {
		c.log.Error(err, "failed to get authorization context")
		return "", err
	}

	// Match a scope from the authorization context to a known credential constructor
	scope, _, err := c.matchScope(authorizationContext.Scopes)
	if err != nil {
		c.log.Error(err, "no matching scope in authorization context")
		return "", err
	}

	// Get OpenID4VP auth config for this credential type
	vpAuth := c.cfg.GetOpenID4VPAuth(scope)
	if vpAuth == nil {
		return "", fmt.Errorf("scope %q is not configured for openid4vp authentication", scope)
	}

	// Build one CredentialQuery per auth scope so the wallet can authenticate
	// with any of the acceptable credential types (e.g. pid OR eduid).
	// Each scope has its own claim queries derived from its per-scope auth_claims.
	credentialQueries := make([]openid4vp.CredentialQuery, 0, len(vpAuth.AuthScopes))
	options := make([][]string, 0, len(vpAuth.AuthScopes))
	for _, authScope := range slices.Sorted(maps.Keys(vpAuth.AuthScopes)) {
		entry := vpAuth.AuthScopes[authScope]
		scopeClaimQueries := make([]openid4vp.ClaimQuery, 0, len(entry.AuthClaims))
		for _, claim := range entry.AuthClaims {
			scopeClaimQueries = append(scopeClaimQueries, openid4vp.ClaimQuery{
				Path: openid4vp.StringPath(claim),
			})
		}
		credentialQueries = append(credentialQueries, openid4vp.CredentialQuery{
			ID:       authScope,
			Format:   c.cfg.GetFormatForScope(authScope),
			Multiple: false,
			Meta: openid4vp.MetaQuery{
				VCTValues: c.cfg.VCTIdentifiersForScopes([]string{authScope}),
			},
			RequireCryptographicHolderBinding: false,
			Claims:                            scopeClaimQueries,
		})
		options = append(options, []string{authScope})
	}

	dcql := &openid4vp.DCQL{
		Credentials: credentialQueries,
		CredentialSets: []openid4vp.CredentialSetQuery{
			{
				Options:  options,
				Required: false,
				Purpose:  "authenticate for " + scope,
			},
		},
	}

	// Persist the DCQL query in the auth context so VerificationDirectPost
	// can use it for VP Token validation later.
	authorizationContext.DCQLQuery = dcql
	if err := c.cacheService.AuthContext.Update(ctx, authorizationContext); err != nil {
		c.log.Error(err, "failed to update authorization context with DCQL query")
		return "", fmt.Errorf("failed to update authorization context: %w", err)
	}

	// Derive VP formats from issuer metadata
	vf := deriveVPFormatsFromMetadata(c.issuerMetadata)

	_, ephemeralPublicJWK, err := c.EphemeralEncryptionKey(ctx, authorizationContext.EphemeralEncryptionKeyID)
	if err != nil {
		return "", err
	}

	responseURI, err := url.JoinPath(c.cfg.APIGW.PublicURL, "/verification/direct_post")
	if err != nil {
		return "", fmt.Errorf("failed to construct response URI: %w", err)
	}
	authorizationRequest := openid4vp.RequestObject{
		ResponseURI:  responseURI,
		AUD:          "https://self-issued.me/v2",
		ISS:          authorizationContext.ClientID,
		ClientID:     authorizationContext.ClientID,
		ResponseType: "vp_token",
		ResponseMode: "direct_post.jwt",
		State:        authorizationContext.State,
		Nonce:        authorizationContext.Nonce,
		DCQLQuery:    dcql,
		ClientMetadata: &openid4vp.ClientMetadata{
			VPFormatsSupported: vf,
			JWKS: &openid4vp.Keys{
				Keys: []jwk.Key{ephemeralPublicJWK},
			},
			AuthorizationEncryptedResponseALG: "ECDH-ES",
			AuthorizationEncryptedResponseENC: "A256GCM",
		},
		IAT: time.Now().UTC().Unix(),
	}

	c.log.Debug("Authorization request", "request", authorizationRequest)

	reply, err := authorizationRequest.Sign(ctx, c.pkiSigner, c.pkiSignerChain)
	if err != nil {
		c.log.Error(err, "failed to sign authorization request")
		return "", err
	}

	c.log.Debug("Signed JWT", "jwt", reply)

	return reply, nil
}

type VerificationDirectPostRequest struct {
	Response string `json:"response" form:"response"`
}

func (v *VerificationDirectPostRequest) GetKID() (string, error) {
	return jose.ExtractKIDFromCompactJWT(v.Response)
}

type VerificationDirectPostResponse struct {
	PresentationDuringIssuanceSession string `json:"presentation_during_issuance_session"`
	RedirectURI                       string `json:"redirect_uri"`
}

func (c *Client) VerificationDirectPost(ctx context.Context, req *VerificationDirectPostRequest) (*VerificationDirectPostResponse, error) {
	c.log.Debug("Verification direct-post")

	// Extract KID from JWE header
	kid, err := req.GetKID()
	if err != nil {
		c.log.Error(err, "failed to get KID from request")
		return nil, err
	}

	// Get ephemeral private key from cache
	privateEphemeralJWK, ok := c.cacheService.EphemeralEncryptionKey.Get(ctx, kid)
	if !ok {
		c.log.Debug("No ephemeral key found in cache", "kid", kid)
		return nil, errors.New("ephemeral key not found in cache")
	}

	c.log.Debug("Found ephemeral key in cache", "kid", kid)

	// Decrypt JWE response
	decryptedJWE, err := jwe.Decrypt([]byte(req.Response), jwe.WithKey(jwa.ECDH_ES(), privateEphemeralJWK))
	if err != nil {
		c.log.Error(err, "failed to decrypt JWE")
		return nil, err
	}

	// Parse response parameters using openid4vp
	vpResponse := openid4vp.VPResponse{}
	if err := json.Unmarshal(decryptedJWE, &vpResponse); err != nil {
		c.log.Error(err, "failed to unmarshal decrypted JWE")
		return nil, err
	}

	// Get authorization context
	authCtx, err := c.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{EphemeralEncryptionKeyID: kid})
	if err != nil {
		c.log.Error(err, "failed to get authorization context")
		return nil, err
	}

	c.log.Debug("VP Response received", "vp_token_keys", vpResponse.VPToken, "scope", authCtx.Scopes)

	// Match a scope from the authorization context to a known credential constructor
	scope, credMetaCfg, err := c.matchScope(authCtx.Scopes)
	if err != nil {
		c.log.Error(err, "no matching scope in authorization context")
		return nil, err
	}

	// Extract the credential query ID from the persisted DCQL query.
	// The VP Token map is keyed by credential query ID (the auth scope),
	// not by the issuing scope. The wallet may have responded with any of
	// the acceptable credential types, so try all DCQL credential query IDs.
	var vpToken string
	var matchedAuthScope string
	if authCtx.DCQLQuery == nil || len(authCtx.DCQLQuery.Credentials) == 0 {
		c.log.Error(nil, "DCQL query has no credential queries", "scope", scope)
		return nil, errors.New("DCQL query has no credential queries")
	}
	for _, cq := range authCtx.DCQLQuery.Credentials {
		if tokens, ok := vpResponse.VPToken[cq.ID]; ok && len(tokens) > 0 {
			if len(tokens) > 1 {
				c.log.Info("multiple VP tokens received for credential query, using first", "credential_query_id", cq.ID, "count", len(tokens))
			}
			vpToken = tokens[0]
			matchedAuthScope = cq.ID
			c.log.Info("VP token matched credential query", "matched_auth_scope", matchedAuthScope, "scope", scope)
			break
		}
	}
	if vpToken == "" {
		c.log.Error(nil, "VP Token not found for any credential query", "available_keys", vpResponse.VPToken)
		return nil, errors.New("VP Token not found for any configured credential query")
	}

	// Prepare response parameters
	responseParams := &openid4vp.ResponseParameters{
		State:   vpResponse.State,
		VPToken: vpToken,
	}

	c.log.Debug("Response parameters prepared", "has_vp_token", responseParams.VPToken != "", "state", responseParams.State)

	// Validate response parameters
	if err := responseParams.Validate(); err != nil {
		c.log.Error(err, "response parameters validation failed")
		return nil, fmt.Errorf("invalid response: %w", err)
	}

	// Validate VP Token using VPTokenValidator
	validator := &openid4vp.VPTokenValidator{
		Nonce:           authCtx.Nonce,
		ClientID:        authCtx.ClientID,
		ValidateFormat:  true,
		CheckRevocation: false,
		DCQLQuery:       authCtx.DCQLQuery,
	}

	if err := validator.Validate(responseParams.VPToken); err != nil {
		c.log.Error(err, "VP Token validation failed")
		return nil, fmt.Errorf("VP Token validation failed: %w", err)
	}

	c.log.Debug("VP Token validated successfully")

	// Evaluate issuer trust before accepting the credential
	if err := c.jwtTrustVerifier.EvaluateIssuerTrust(ctx, vpToken, scope); err != nil {
		c.log.Error(err, "Issuer trust evaluation failed", "scope", scope)
		return nil, fmt.Errorf("issuer trust evaluation failed: %w", err)
	}

	// Build credential from validated VP Token
	credential, err := responseParams.BuildCredential()
	if err != nil {
		c.log.Error(err, "failed to build credential from response parameters")
		return nil, err
	}

	c.log.Debug("Found credential metadata", "scope", scope, "vct", credMetaCfg.GetVCTURL())

	// LOCAL PATCH (lpidportal): evaluate SPOCP issuance policy (if configured
	// for this scope) against the presented credential's own claims. Upstream
	// only wires issuance.GetPolicyEngine/Evaluate into the OIDC-RP callback
	// (handlers_oidcrp.go) — this is the openid4vp equivalent, added because
	// PolicyEngine.Evaluate is claims-source-agnostic (it takes a plain
	// map[string]any and doesn't care whether it came from an OIDC token or a
	// presented credential). This gates on PID *attributes* only — it is not
	// a substitute for the identity-binding lookup below (ResolveIdentifier /
	// GetByIdentity), which still does the actual wallet-to-applicant match.
	// See vc-deploy/patches/README.md.
	if scopeCfg := c.cfg.APIGW.DataSources.LookupScopePolicyConfig(scope); scopeCfg != nil && scopeCfg.IssuancePolicy != nil {
		policyEngine, policyErr := issuance.GetPolicyEngine(scopeCfg.IssuancePolicy)
		if policyErr != nil {
			return nil, fmt.Errorf("failed to initialize issuance policy engine: %w", policyErr)
		}
		if policyEngine != nil {
			// Evaluate the full presented-credential claims map, not just the
			// identity subset extracted below — a policy rule may reference
			// attributes (e.g. an age predicate) that aren't part of the
			// identity-matching claim set at all.
			policyClaims := maps.Clone(credential)
			if policyErr := policyEngine.Evaluate(scope, policyClaims, scopeCfg.IssuancePolicy.QueryTemplate); policyErr != nil {
				c.log.Warn("Issuance policy denied credential",
					"scope", scope,
					"matched_auth_scope", matchedAuthScope,
					"error", policyErr)
				return nil, fmt.Errorf("credential issuance denied: %w", policyErr)
			}
			c.log.Info("Issuance policy evaluation passed", "scope", scope)
		}
	}

	// Extract identity from validated credential using the matched auth scope's claims.
	// The vpAuth config tells us which claims to extract based on which credential was presented.
	vpAuth2 := c.cfg.GetOpenID4VPAuth(scope)
	if vpAuth2 == nil {
		return nil, fmt.Errorf("scope %q lost openid4vp configuration", scope)
	}
	authScopeEntry, ok := vpAuth2.AuthScopes[matchedAuthScope]
	if !ok {
		return nil, fmt.Errorf("matched auth scope %q not found in config for scope %q", matchedAuthScope, scope)
	}
	identityClaims, err := model.ExtractIdentityClaims(credential, authScopeEntry.AuthClaims)
	if err != nil {
		c.log.Error(err, "required identity claims missing from presented credential", "matched_auth_scope", matchedAuthScope, "scope", scope)
		return nil, fmt.Errorf("identity extraction failed: %w", err)
	}

	// Resolve the person identifier — uses authentic_source_person_id directly
	// when present in the extracted claims, otherwise falls back to identity
	// mapping (given_name, family_name, birth_date → authentic_source_person_id).
	claimsAny := make(map[string]any, len(identityClaims))
	for k, v := range identityClaims {
		claimsAny[k] = v
	}
	identityMappingID, err := c.ResolveIdentifier(ctx, authCtx.AuthenticSource, claimsAny)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve identity from VP claims: %w", err)
	}

	// Persist the resolved identifier on the authorization context so that
	// downstream credential issuance (VCICredential) can find it.
	if err := c.cacheService.AuthContext.SetIdentifier(ctx, &cache.AuthorizationContext{SessionID: authCtx.SessionID}, identityMappingID); err != nil {
		c.log.Error(err, "failed to persist identifier on auth context")
		return nil, fmt.Errorf("failed to persist identifier: %w", err)
	}

	// Retrieve documents matching the identity by scope
	c.log.Debug("Querying documents", "scope", scope, "identity_mapping_id", identityMappingID)
	documents, err := c.datastoreStore.GetByIdentity(ctx, scope, identityMappingID)
	if err != nil {
		c.log.Debug("failed to get document", "error", err)
		return nil, err
	}

	c.log.Debug("Retrieved documents", "count", len(documents))

	if len(documents) == 0 {
		c.log.Error(nil, "no documents found for identity", "identity_claims", identityClaims)
		return nil, errors.New("no documents found for the provided identity")
	}

	// Cache PID documents for session
	c.cacheService.Document.Set(ctx, authCtx.SessionID, documents)

	c.log.Debug("Documents cached for session", "session_id", authCtx.SessionID)

	callbackURL, err := url.JoinPath(c.cfg.APIGW.PublicURL, "/authorization/consent/callback/")
	if err != nil {
		c.log.Error(nil, "Failed to construct callback URL", "error", err)
		return nil, errors.New("failed to construct callback URL")
	}
	u, err := url.Parse(callbackURL)
	if err != nil {
		c.log.Error(nil, "Failed to parse callback URL", "error", err)
		return nil, errors.New("failed to parse callback URL")
	}
	q := u.Query()
	q.Set("response_code", authCtx.VerifierResponseCode)
	u.RawQuery = q.Encode()

	reply := &VerificationDirectPostResponse{
		RedirectURI: u.String(),
	}
	return reply, nil
}
