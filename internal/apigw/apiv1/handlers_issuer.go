package apiv1

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/SUNET/vc/internal/apigw/cache"
	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/internal/gen/registry/apiv1_registry"
	"github.com/SUNET/vc/pkg/crypto"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vci"
)

// ResolveIdentifier resolves an identifier string from authentication claims.
// It first checks for an explicit authentic_source_person_id claim.
// If none is found, it attempts an identity mapping lookup using the available
// attributes against the configured authentic source.
func (c *Client) ResolveIdentifier(ctx context.Context, authenticSource string, claims map[string]any) (string, error) {
	// Path 1: explicit identifier from claims
	if v, ok := claims["authentic_source_person_id"].(string); ok && v != "" {
		c.log.Debug("ResolveIdentifier: direct identifier found", "value", v)
		return v, nil
	}

	// Path 2: resolve from attributes via identity mapping
	attrs := make(map[string]string)
	for _, key := range []string{"family_name", "given_name", "birth_date"} {
		if v, ok := claims[key].(string); ok && v != "" {
			attrs[key] = v
		}
	}
	if len(attrs) == 0 {
		return "", errors.New("no identifier claim or identity attributes found in claims")
	}

	personID, err := c.identityMappingStore.ResolveMapping(ctx, &db.ResolveMappingQuery{
		AuthenticSource: authenticSource,
		Attributes:      attrs,
	})
	if err != nil {
		return "", fmt.Errorf("identity mapping resolution failed: %w", err)
	}
	c.log.Debug("ResolveIdentifier: resolved via identity mapping", "identifier", personID)
	return personID, nil
}

// requireIdentifier validates that a non-empty identifier exists for data sources
// that require it. Assertion-based and datastore-based issuance allow an empty
// identifier because the data comes from trusted sources (IdP claims or
// pre-uploaded documents) rather than identity-mapped lookups.
func requireIdentifier(identifier string, dataSource model.DataSourceType) (string, error) {
	if identifier == "" && dataSource != model.DataSourceAssertion && dataSource != model.DataSourceDatastore {
		return "", errors.New("no identifier in auth context")
	}
	return identifier, nil
}

// ResolveVCIIdentifier resolves an identifier for a VCI session based on the
// data source. For assertion data source, it derives the identifier directly
// from claims and optional pre-transform fallback values (no identity mapping
// lookup is performed — the issuer trusts the IdP). For other data sources, it
// delegates to ResolveIdentifier which may perform identity mapping lookups.
//
// The fallbacks parameter allows callers to supply pre-transform identifiers
// (e.g., authResp.IDToken.Subject for OIDC, assertion.NameID for SAML) that
// should be tried when the transformed claims don't contain the expected keys.
func (c *Client) ResolveVCIIdentifier(ctx context.Context, authCtx *cache.AuthorizationContext, claims map[string]any, fallbacks ...string) (string, error) {
	if authCtx.Identifier != "" {
		return authCtx.Identifier, nil
	}

	if authCtx.DataSource == string(model.DataSourceAssertion) {
		// Assertion: derive identifier from claims, no identity mapping lookup.
		if v, ok := claims["authentic_source_person_id"].(string); ok && v != "" {
			return v, nil
		}
		if v, ok := claims["sub"].(string); ok && v != "" {
			return v, nil
		}
		// Try caller-provided pre-transform fallbacks.
		for _, fb := range fallbacks {
			if fb != "" {
				return fb, nil
			}
		}
		// Best-effort: identifier may remain empty for assertion.
		return "", nil
	}

	// Non-assertion: perform full identity resolution (may include mapping lookup).
	identifier, err := c.ResolveIdentifier(ctx, authCtx.AuthenticSource, claims)
	if err != nil {
		return "", err
	}
	return identifier, nil
}

// StoreVCIDocuments stores transformed credential documents in the VCI session cache.
// This is used by external auth flows (SAML/OIDC) that are integrated into the
// OpenID4VCI pipeline. The documents are stored keyed by the VCI session ID so they
// can be retrieved during credential issuance (same as pid_auth flow).
func (c *Client) StoreVCIDocuments(ctx context.Context, sessionID string, docs map[string]*model.CompleteDocument) error {
	c.cacheService.Document.Set(ctx, sessionID, docs)
	c.log.Debug("VCI documents stored from external auth", "session_id", sessionID, "doc_count", len(docs))
	return nil
}

// LookupDatastoreByIdentity queries the datastore for documents matching the
// given identity claims and scope, then stores them in the VCI session cache.
// Used when a datastore credential is authenticated via SAML/OIDC — the
// identity extracted from the assertion is used to find the pre-loaded document.
func (c *Client) LookupDatastoreByIdentity(ctx context.Context, sessionID, scope, authenticSource string, claims map[string]any, dsCred *model.DatastoreScope) error {
	identityClaims, err := model.ExtractIdentityClaims(claims, dsCred.AuthClaims)
	if err != nil {
		return fmt.Errorf("identity extraction failed for scope %q: %w", scope, err)
	}

	// Resolve the person identifier — uses authentic_source_person_id directly
	// when present in the extracted claims, otherwise falls back to identity
	// mapping (given_name, family_name, birth_date → authentic_source_person_id).
	claimsAny := make(map[string]any, len(identityClaims))
	for k, v := range identityClaims {
		claimsAny[k] = v
	}
	identityMappingID, err := c.ResolveIdentifier(ctx, authenticSource, claimsAny)
	if err != nil {
		return fmt.Errorf("failed to resolve identity for scope %q: %w", scope, err)
	}

	c.log.Debug("LookupDatastoreByIdentity", "scope", scope, "identity_mapping_id", identityMappingID)

	docs, err := c.datastoreStore.GetByIdentity(ctx, scope, identityMappingID)
	if err != nil {
		return fmt.Errorf("datastore lookup failed for scope %q: %w", scope, err)
	}
	if len(docs) == 0 {
		return fmt.Errorf("no documents found in datastore for scope %q with the provided identity", scope)
	}

	// Filter out expired documents
	now := time.Now().UTC()
	for key, doc := range docs {
		if doc.Meta.ValidNotAfter != nil && now.After(*doc.Meta.ValidNotAfter) {
			c.log.Info("Skipping expired document", "document_id", doc.Meta.DocumentID, "valid_not_after", doc.Meta.ValidNotAfter)
			delete(docs, key)
		}
	}

	// If all documents are expired, return an error to avoid caching and issuing from expired data
	if len(docs) == 0 {
		return fmt.Errorf("all documents expired for scope %q", scope)
	}

	c.cacheService.Document.Set(ctx, sessionID, docs)
	c.log.Info("Datastore documents cached for VCI session",
		"session_id", sessionID, "scope", scope, "doc_count", len(docs))
	return nil
}

// HasVCIDocuments checks whether documents have already been stored for the given VCI session.
// Used by the consent endpoint to avoid re-initiating external auth when documents are already cached.
func (c *Client) HasVCIDocuments(ctx context.Context, sessionID string) bool {
	docs, ok := c.cacheService.Document.Get(ctx, sessionID)
	return ok && len(docs) > 0
}

// VCICredentialOffer implements OpenID4VCI credential offer endpoint
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-endpoint
func (c *Client) VCICredentialOffer(ctx context.Context, req *openid4vci.CredentialOfferParameters) (*openid4vci.CredentialOfferParameters, error) {
	c.log.Debug("credential offer")
	return nil, nil
}

// VCINonce implements OpenID4VCI nonce endpoint for DPoP proof freshness
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-nonce-endpoint
func (c *Client) VCINonce(ctx context.Context) (*openid4vci.NonceResponse, error) {
	nonce, err := crypto.GenerateSecureToken(0, 43)
	if err != nil {
		return nil, err
	}
	// Store the nonce in cache so the credential endpoint can validate proofs
	if c.cacheService != nil && c.cacheService.VCINonce != nil {
		c.cacheService.VCINonce.Set(ctx, nonce, true)
	}
	reply := &openid4vci.NonceResponse{
		CNonce: nonce,
	}
	return reply, nil
}

// VCICredential implements OpenID4VCI credential issuance endpoint
//
//	@Summary		VCICredential
//	@ID				create-credential
//	@Description	Create credential endpoint
//	@Tags			vc-platform
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	apiv1_issuer.MakeSDJWTReply		"Success"
//	@Failure		400	{object}	helpers.ErrorResponse			"Bad Request"
//	@Param			req	body		openid4vci.CredentialRequest	true	" "
//	@Router			/credential [post]
func (c *Client) VCICredential(ctx context.Context, req *openid4vci.CredentialRequest) (*openid4vci.CredentialResponse, error) {
	c.log.Debug("VCICredential request", "credential_identifier", req.CredentialIdentifier, "credential_configuration_id", req.CredentialConfigurationID)
	// Validate DPoP JWT signature and claims first, before checking JTI replay.
	// This prevents attackers from poisoning the JTI cache with forged tokens.
	dpop, err := oauth2.ValidateAndParseDPoPJWT(req.DPoP)
	if err != nil {
		c.log.Error(err, "failed to validate DPoP JWT")
		return nil, err
	}

	unique, err := c.cacheService.DPopJTI.SetNX(ctx, dpop.JTI, true)
	if err != nil {
		c.log.Error(err, "DPoP JTI cache error", "jti", dpop.JTI)
		return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeServerError,
			"internal error checking DPoP proof", 500, err)
	}
	if !unique {
		c.log.Error(nil, "DPoP JTI replay detected", "jti", dpop.JTI)
		return nil, oauth2.OAuthErrJTIReplay
	}

	// Validate HTU matches credential endpoint
	if dpop.HTU != c.issuerMetadata.CredentialEndpoint {
		return nil, fmt.Errorf("invalid HTU in DPoP claims: expected %s, got %s", c.issuerMetadata.CredentialEndpoint, dpop.HTU)
	}

	// Validate HTM is POST (credential endpoint only accepts POST)
	if dpop.HTM != "POST" {
		return nil, fmt.Errorf("invalid HTM in DPoP claims: expected POST, got %s", dpop.HTM)
	}

	accessToken := strings.TrimPrefix(req.Authorization, "DPoP ")

	if !dpop.IsAccessTokenDPoP(accessToken) {
		return nil, errors.New("invalid DPoP token")
	}

	authContext, err := c.cacheService.AuthContext.GetWithAccessToken(ctx, accessToken)
	if err != nil {
		c.log.Error(err, "failed to get authorization")
		return nil, err
	}

	// Verify DPoP key binding: the proof's public key must match the one used
	// at token issuance (RFC 9449 §4.3).
	if err := verifyDPoPKeyBinding(dpop.Thumbprint, authContext.Token); err != nil {
		return nil, err
	}

	// Validate credential request against authorization details per OID4VCI 1.0 Section 7.1
	if err := req.Validate(ctx, authContext.AuthorizationDetails); err != nil {
		c.log.Error(err, "credential request validation failed")
		return nil, err
	}

	// Match a scope from the authorization context to a known credential constructor
	scope, _, err := c.matchScope(authContext.Scopes)
	if err != nil {
		c.log.Error(err, "no matching scope in auth context")
		return nil, err
	}

	document := &model.CompleteDocument{}

	// For child sessions created in the pre-auth multi-client flow, use the
	// source session ID (the original pre-auth code) for document lookup.
	docSessionID := docLookupSessionID(authContext)

	c.log.Debug("VCICredential: retrieving credential data", "auth_provider", authContext.AuthProvider, "scope", scope, "session_id", authContext.SessionID, "doc_session_id", docSessionID)
	// Retrieve credential data based on the auth provider used during authorization
	switch authContext.AuthProvider {
	case model.AuthProviderOpenID4VP, model.AuthProviderSAML, model.AuthProviderOIDC, model.AuthProviderDatastore:
		// Session-based auth providers: retrieve from session cache
		docs, ok := c.cacheService.Document.Get(ctx, docSessionID)
		if !ok || len(docs) == 0 {
			c.log.Error(nil, "no documents found in cache for session", "session_id", docSessionID)
			return nil, errors.New("no documents found for session " + docSessionID)
		}
		if len(docs) > 1 {
			c.log.Info("multiple documents in cache for session, using first", "session_id", docSessionID, "count", len(docs))
		}
		for _, doc := range docs {
			document = doc
			break
		}
		if document == nil || document.DocumentData == nil {
			return nil, errors.New("cached document is empty for session " + docSessionID)
		}
	default:
		return nil, fmt.Errorf("unsupported or missing auth provider: %q", authContext.AuthProvider)
	}

	documentData, err := json.Marshal(document.DocumentData)
	if err != nil {
		return nil, err
	}

	// Extract JWK from proof (singular) or proofs (plural/batch)
	var jwk *apiv1_issuer.Jwk
	if req.Proof != nil {
		jwk, err = req.Proof.ExtractJWK()
		if err != nil {
			c.log.Error(err, "failed to extract JWK from proof")
			return nil, &openid4vci.Error{Err: openid4vci.ErrInvalidProof, ErrorDescription: err.Error()}
		}
	} else if req.Proofs != nil {
		jwk, err = req.Proofs.ExtractJWK()
		if err != nil {
			c.log.Error(err, "failed to extract JWK from proofs")
			return nil, &openid4vci.Error{Err: openid4vci.ErrInvalidProof, ErrorDescription: err.Error()}
		}
	} else {
		return nil, &openid4vci.Error{Err: openid4vci.ErrInvalidProof, ErrorDescription: "proof or proofs parameter is required"}
	}

	// Verify proof of possession per OID4VCI Appendix F.4
	pubKey, err := jwkProtoToPublicKey(jwk)
	if err != nil {
		desc := "invalid key in proof"
		// Detect kid-only references that lack embedded key material
		if jwk.X == "" && jwk.Y == "" && jwk.N == "" && jwk.E == "" && jwk.Kid != "" {
			desc = "proof contains only a key reference (kid) without embedded key material; key resolution is not supported"
		}
		c.log.Error(err, "failed to convert proof JWK to public key")
		return nil, &openid4vci.Error{Err: openid4vci.ErrInvalidProof, ErrorDescription: desc}
	}

	// Resolve the expected c_nonce: extract nonce from the proof and check if
	// it was issued by us (via token response or nonce endpoint).
	var proofNonce string
	if req.Proof != nil && req.Proof.ProofType == "jwt" {
		proofNonce = openid4vci.ProofJWTToken(req.Proof.JWT).ExtractNonce()
	} else if req.Proofs != nil && len(req.Proofs.JWT) > 0 {
		proofNonce = req.Proofs.JWT[0].ExtractNonce()
	}

	// Determine which nonce to validate against.
	// Non-destructive lookup (Get) finds the expected nonce without consuming it.
	// The nonce is consumed (GetAndDelete) only after successful proof verification
	// to enforce one-time use while avoiding false rejections on verification failure.
	expectedNonce := ""
	if c.cacheService.VCINonce != nil {
		// First try the nonce from the proof JWT (non-destructive lookup)
		if proofNonce != "" {
			if _, ok := c.cacheService.VCINonce.Get(ctx, proofNonce); ok {
				expectedNonce = proofNonce
			}
		}
		// Fall back to the nonce stored in the auth context
		if expectedNonce == "" && authContext.Nonce != "" {
			if _, ok := c.cacheService.VCINonce.Get(ctx, authContext.Nonce); ok {
				expectedNonce = authContext.Nonce
			}
		}
	}
	if expectedNonce == "" {
		return nil, &openid4vci.Error{Err: openid4vci.ErrInvalidNonce, ErrorDescription: "nonce is missing or already consumed"}
	}

	verifyOpts := &openid4vci.VerifyProofOptions{
		CNonce:   expectedNonce,
		Audience: c.issuerMetadata.CredentialIssuer,
	}
	if req.Proof != nil && req.Proof.ProofType == "jwt" {
		proofJWT := openid4vci.ProofJWTToken(req.Proof.JWT)
		if verifyErr := proofJWT.Verify(pubKey, verifyOpts); verifyErr != nil {
			c.log.Error(verifyErr, "proof JWT verification failed")
			return nil, verifyErr
		}
	} else if req.Proofs != nil {
		if err := req.VerifyProofWithOptions(pubKey, verifyOpts); err != nil {
			c.log.Error(err, "proofs verification failed")
			return nil, err
		}
	}

	// Consume nonce atomically after successful proof verification.
	// If another request consumed it concurrently, fail with invalid_nonce.
	if c.cacheService.VCINonce != nil {
		if _, ok := c.cacheService.VCINonce.GetAndDelete(ctx, expectedNonce); !ok {
			return nil, &openid4vci.Error{Err: openid4vci.ErrInvalidNonce, ErrorDescription: "nonce was consumed concurrently"}
		}
	}

	// Determine credential format from credential_configuration_id or credential_identifier
	format, err := req.ResolveCredentialFormatWithAuthDetails(c.issuerMetadata, authContext.AuthorizationDetails)
	if err != nil {
		c.log.Error(err, "failed to resolve credential format")
		return nil, err
	}

	// The authenticated identifier is used for registry; for assertion-based
	// issuance the identifier is best-effort (all data comes from trusted IdP claims).
	identifier, err := requireIdentifier(authContext.Identifier, model.DataSourceType(authContext.DataSource))
	if err != nil {
		return nil, err
	}

	// Branch based on requested credential format
	switch format {
	case "mso_mdoc":
		return c.issueMDoc(ctx, scope, documentData, jwk, identifier)

	case "vc+sd-jwt", "dc+sd-jwt":
		return c.issueSDJWT(ctx, scope, documentData, jwk, identifier)

	case "ldp_vc", "vc+ld+json":
		// W3C VC 2.0 Data Integrity credential
		return c.issueVC20(ctx, scope, documentData, identifier, req)

	default:
		c.log.Error(nil, "unsupported or missing credential format", "format", format)
		return nil, errors.New("unsupported or missing credential format: " + format)
	}
}

// issueSDJWT issues an SD-JWT credential
func (c *Client) issueSDJWT(ctx context.Context, scope string, documentData []byte, jwk *apiv1_issuer.Jwk, identifier string) (*openid4vci.CredentialResponse, error) {
	credMeta := c.cfg.GetCredentialMetadata(scope)
	if credMeta == nil {
		return nil, fmt.Errorf("unsupported scope: %s", scope)
	}

	issuerReply, err := c.issuerClient.MakeSDJWT(ctx, &apiv1_issuer.MakeSDJWTRequest{
		Scope:        scope,
		DocumentData: documentData,
		Jwk:          jwk,
		Integrity:    credMeta.GetIntegrity(),
		Vctm:         credMeta.GetVCTMRaw(),
	})
	if err != nil {
		c.log.Error(err, "failed to call MakeSDJWT")
		return nil, err
	}

	if issuerReply == nil {
		return nil, errors.New("MakeSDJWT reply is nil")
	}

	// Save credential subject info to registry for status management
	if identifier != "" {
		_, err = c.registryClient.SaveCredentialSubject(ctx, &apiv1_registry.SaveCredentialSubjectRequest{
			Identifier: identifier,
			Section:    issuerReply.TokenStatusListSection,
			Index:      issuerReply.TokenStatusListIndex,
		})
		if err != nil {
			c.log.Error(err, "failed to save credential subject to registry")
			return nil, fmt.Errorf("failed to save credential subject: %w", err)
		}
	}

	reply := &openid4vci.CredentialResponse{}
	switch len(issuerReply.Credentials) {
	case 0:
		return nil, helpers.ErrNoDocumentFound
	case 1:
		reply.Credentials = []openid4vci.Credential{
			{
				Credential: issuerReply.Credentials[0].Credential,
			},
		}
		return reply, nil
	default:
		return nil, errors.New("multiple credentials returned from issuer, not supported")
	}
}

// issueMDoc issues an mDoc credential
func (c *Client) issueMDoc(ctx context.Context, scope string, documentData []byte, jwk *apiv1_issuer.Jwk, identifier string) (*openid4vci.CredentialResponse, error) {
	// Convert JWK to COSE key bytes for mDoc
	deviceKeyBytes, err := convertJWKToCOSEKey(jwk)
	if err != nil {
		c.log.Error(err, "failed to convert JWK to COSE key")
		return nil, err
	}
	credentialMetadata := c.cfg.GetCredentialMetadata(scope)
	if credentialMetadata == nil {
		return nil, fmt.Errorf("unsupported scope: %s", scope)
	}
	var docType string
	if len(credentialMetadata.Attributes) == 0 {
		return nil, fmt.Errorf("no claims found in credential metadata")
	}
	for _, attrs := range credentialMetadata.Attributes {
		for _, path := range attrs {
			if len(path) > 0 && path[0] != nil {
				docType = mdoc.DocTypes[*path[0]]
				break
			}
		}
		if docType != "" {
			break
		}
	}
	if docType == "" {
		return nil, fmt.Errorf("unable to determine document type from claims")
	}

	issuerReply, err := c.issuerClient.MakeMDoc(ctx, &apiv1_issuer.MakeMDocRequest{
		Scope:           scope,
		DocType:         docType,
		DocumentData:    documentData,
		DevicePublicKey: deviceKeyBytes,
		DeviceKeyFormat: "cose",
	})
	if err != nil {
		c.log.Error(err, "failed to call MakeMDoc")
		return nil, err
	}

	if issuerReply == nil {
		return nil, errors.New("MakeMDoc reply is nil")
	}

	// Save credential subject info to registry for status management
	if identifier != "" && issuerReply.StatusListSection > 0 {
		_, err = c.registryClient.SaveCredentialSubject(ctx, &apiv1_registry.SaveCredentialSubjectRequest{
			Identifier: identifier,
			Section:    issuerReply.StatusListSection,
			Index:      issuerReply.StatusListIndex,
		})
		if err != nil {
			c.log.Error(err, "failed to save credential subject to registry")
			return nil, fmt.Errorf("failed to save credential subject: %w", err)
		}
	}

	// For mDoc, the credential is CBOR bytes - encode as base64 for JSON response
	mdocBase64 := base64.StdEncoding.EncodeToString(issuerReply.Mdoc)

	reply := &openid4vci.CredentialResponse{
		Credentials: []openid4vci.Credential{
			{
				Credential: mdocBase64,
			},
		},
	}

	return reply, nil
}

// issueVC20 issues a W3C VC 2.0 Data Integrity credential
func (c *Client) issueVC20(ctx context.Context, scope string, documentData []byte, identifier string, req *openid4vci.CredentialRequest) (*openid4vci.CredentialResponse, error) {
	// Extract cryptosuite from credential configuration
	var cryptosuite string
	var mandatoryPointers []string
	var credentialTypes []string

	if req.CredentialConfigurationID != "" && c.issuerMetadata != nil {
		if config, ok := c.issuerMetadata.CredentialConfigurationsSupported[req.CredentialConfigurationID]; ok {
			cryptosuite = config.Cryptosuite
			if config.CredentialDefinition != nil {
				credentialTypes = config.CredentialDefinition.Type
			}
			// Mandatory pointers could be specified in config in future
		}
	}

	// Default cryptosuite if not specified
	if cryptosuite == "" {
		cryptosuite = "ecdsa-rdfc-2019"
	}

	// Default credential types
	if len(credentialTypes) == 0 {
		credentialTypes = []string{"VerifiableCredential"}
	}

	// Extract subject DID from proof if available
	var subjectDID string
	if req.Proof != nil {
		subjectDID = req.Proof.ExtractSubjectDID()
	}

	issuerReply, err := c.issuerClient.MakeVC20(ctx, &apiv1_issuer.MakeVC20Request{
		Scope:             scope,
		DocumentData:      documentData,
		CredentialTypes:   credentialTypes,
		SubjectDid:        subjectDID,
		Cryptosuite:       cryptosuite,
		MandatoryPointers: mandatoryPointers,
	})
	if err != nil {
		c.log.Error(err, "failed to call MakeVC20")
		return nil, err
	}

	if issuerReply == nil {
		return nil, errors.New("MakeVC20 reply is nil")
	}

	// Save credential subject info to registry for status management
	if identifier != "" && issuerReply.StatusListSection > 0 {
		_, err = c.registryClient.SaveCredentialSubject(ctx, &apiv1_registry.SaveCredentialSubjectRequest{
			Identifier: identifier,
			Section:    issuerReply.StatusListSection,
			Index:      issuerReply.StatusListIndex,
		})
		if err != nil {
			c.log.Error(err, "failed to save credential subject to registry")
			return nil, fmt.Errorf("failed to save credential subject: %w", err)
		}
	}

	reply := &openid4vci.CredentialResponse{
		Credentials: []openid4vci.Credential{
			{
				// VC20 Data Integrity credentials are JSON-LD, return as-is
				Credential: string(issuerReply.Credential),
			},
		},
	}

	return reply, nil
}

// convertJWKToCOSEKey converts a JWK to CBOR-encoded COSE_Key bytes
func convertJWKToCOSEKey(jwk *apiv1_issuer.Jwk) ([]byte, error) {
	if jwk == nil {
		return nil, errors.New("JWK is nil")
	}

	// Decode the X and Y coordinates from base64url
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, errors.New("failed to decode JWK X coordinate")
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, errors.New("failed to decode JWK Y coordinate")
	}

	// Create COSE_Key from JWK
	coseKey, err := mdoc.NewCOSEKeyFromCoordinates(jwk.Kty, jwk.Crv, xBytes, yBytes)
	if err != nil {
		return nil, err
	}

	return coseKey.Bytes()
}

// VCIDeferredCredential implements OpenID4VCI deferred credential endpoint
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-deferred-credential-endpoin
func (c *Client) VCIDeferredCredential(ctx context.Context, req *openid4vci.DeferredCredentialRequest) (*openid4vci.CredentialResponse, error) {
	c.log.Debug("deferred credential", "req", req)
	// run the same code as VCICredential
	return nil, nil
}

// VCICredentialOfferURI implements OpenID4VCI credential offer URI endpoint
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-14.html#name-sending-credential-offer-by-
func (c *Client) VCICredentialOfferURI(ctx context.Context, req *openid4vci.CredentialOfferURIRequest) (*openid4vci.CredentialOfferParameters, error) {
	c.log.Debug("credential offer uri", "req", req.CredentialOfferUUID)
	doc, err := c.credentialOfferStore.Get(ctx, req.CredentialOfferUUID)
	if err != nil {
		c.log.Debug("failed to marshal document data", "error", err)
		return nil, err
	}

	reply := &doc.CredentialOfferParameters

	return reply, nil
}

// VCINotification implements OpenID4VCI notification endpoint
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-notification-endpoint
func (c *Client) VCINotification(ctx context.Context, req *openid4vci.NotificationRequest) error {
	c.log.Debug("notification", "req", req)
	return nil
}

// VCIMetadata https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata-p
func (c *Client) VCIMetadata(ctx context.Context) (*openid4vci.CredentialIssuerMetadataParameters, error) {
	if err := helpers.Check(ctx, c.cfg, c.issuerMetadata, c.log); err != nil {
		c.log.Error(err, "failed to check metadata")
		return nil, err
	}

	// Shallow-copy to avoid mutating the shared struct concurrently.
	metadata := *c.issuerMetadata

	// Use cached signed metadata (refreshed by background ticker every 55 min).
	// signed_metadata is OPTIONAL per OID4VCI §12.2.4 — if signing fails
	// (issuer unreachable, not configured, etc.) return unsigned metadata.
	signedMetadata, err := c.getOrSignMetadata(ctx, signedMetadataKeyVCI, c.issuerMetadata, "vci-issuer", c.issuerMetadata.CredentialIssuer)
	if err != nil {
		c.log.Error(err, "signed_metadata unavailable, serving unsigned metadata")
		metadata.SignedMetadata = ""
	} else {
		metadata.SignedMetadata = signedMetadata
	}

	return &metadata, nil
}

// GetIACAsResponse is the HTTP response for the /iacas endpoint.
type GetIACAsResponse struct {
	Iacas []IACACertificate `json:"iacas"`
}

// IACACertificate is a single IACA certificate in the response.
type IACACertificate struct {
	Certificate string `json:"certificate"` // Base64 DER-encoded X.509 certificate
}

// GetIACAs returns the IACA certificates from the mDOC issuer via gRPC.
func (c *Client) GetIACAs(ctx context.Context) (*GetIACAsResponse, error) {
	reply, err := c.issuerClient.GetIACAs(ctx, &apiv1_issuer.Empty{})
	if err != nil {
		return nil, fmt.Errorf("failed to get IACAs from issuer: %w", err)
	}

	resp := &GetIACAsResponse{
		Iacas: make([]IACACertificate, 0, len(reply.Certificates)),
	}
	for _, certDER := range reply.Certificates {
		resp.Iacas = append(resp.Iacas, IACACertificate{
			Certificate: base64.StdEncoding.EncodeToString(certDER),
		})
	}

	return resp, nil
}

// jwkProtoToPublicKey converts a protobuf Jwk to a crypto.PublicKey for proof verification.
func jwkProtoToPublicKey(jwk *apiv1_issuer.Jwk) (any, error) {
	// Build a standard JWK map and use jose.ParseJWKToPublicKey
	jwkMap := map[string]any{
		"kty": jwk.Kty,
	}
	if jwk.Crv != "" {
		jwkMap["crv"] = jwk.Crv
	}
	if jwk.X != "" {
		jwkMap["x"] = jwk.X
	}
	if jwk.Y != "" {
		jwkMap["y"] = jwk.Y
	}
	if jwk.N != "" {
		jwkMap["n"] = jwk.N
	}
	if jwk.E != "" {
		jwkMap["e"] = jwk.E
	}
	if jwk.Kid != "" {
		jwkMap["kid"] = jwk.Kid
	}
	return jose.ParseJWKToPublicKey(jwkMap)
}

// verifyDPoPKeyBinding checks that the DPoP proof's JWK thumbprint matches the
// thumbprint bound to the access token at issuance time (RFC 9449 §4.3).
// When the token was issued without DPoP binding (e.g. pre-authorized_code flow
// where the client did not present DPoP), the stored thumbprint is empty and the
// check is skipped — the token was not bound to a specific key.
func verifyDPoPKeyBinding(proofThumbprint string, token *cache.Token) error {
	if token == nil || token.DPoPThumbprint == "" {
		return nil
	}
	if proofThumbprint != token.DPoPThumbprint {
		return oauth2.NewOAuthError(
			oauth2.ErrCodeInvalidDPoPProof,
			"DPoP key does not match the key bound to the access token",
			400,
		)
	}
	return nil
}

// docLookupSessionID returns the session ID to use for document lookup.
// For child sessions created in the pre-auth multi-client flow, the source
// session ID (original pre-auth code) is used instead of the child's own ID.
func docLookupSessionID(authContext *cache.AuthorizationContext) string {
	if authContext.SourceSessionID != "" {
		return authContext.SourceSessionID
	}
	return authContext.SessionID
}
