package apiv1

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/revocation"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
)

type VerificationRequestObjectRequest struct {
	ID string `json:"-" form:"id" uri:"id" validate:"required,max=128,printascii"`
	// SessionID string `json:"-"`
}

func (c *Client) VerificationRequestObject(ctx context.Context, req *VerificationRequestObjectRequest) (string, error) {
	c.log.Debug("Verification request object", "id", req.ID)

	// Query by RequestObjectID since that's what the wallet sends via ?id= parameter
	authorizationContext, err := c.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{
		RequestObjectID: req.ID,
	})
	if err != nil {
		c.log.Error(err, "failed to get authorization context")
		return "", err
	}

	// TODO(masv): should requestObjectCache be using cache lib
	requestObject, found := c.openid4vp.RequestObjectCache.Get(authorizationContext.RequestObjectID)
	if !found {
		c.log.Error(nil, "request object not found in cache", "requestObjectID", authorizationContext.RequestObjectID)
		return "", errors.New("request object not found")
	}

	signedJWT, err := requestObject.Sign(ctx, c.pkiSigner, c.pkiSignerChain)
	if err != nil {
		c.log.Error(err, "failed to sign authorization request")
		return "", err
	}

	c.log.Debug("Signed JWT created", "requestObjectID", authorizationContext.RequestObjectID)

	return signedJWT, nil
}

type VerificationDirectPostRequest struct {
	Response  string `json:"response"  form:"response"`
	SessionID string `json:"-"` // Set by HTTP layer if same-device flow
}

func (v *VerificationDirectPostRequest) GetKID() (string, error) {
	return jose.ExtractKIDFromCompactJWT(v.Response)
}

type VerificationDirectPostResponse struct {
	// RedirectURI is optional - only included for same-device flows
	// For cross-device flows, the browser is notified via SSE instead
	RedirectURI string `json:"redirect_uri,omitempty"`
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
	privateEphemeralJWK, found := c.openid4vp.EphemeralKeyCache.Get(kid)
	if !found {
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

	c.log.Debug("directPost", "state", vpResponse.State, "credential_count", len(vpResponse.VPToken))

	// Get authorization context by state
	authCtx, err := c.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{State: vpResponse.State})
	if err != nil {
		c.log.Error(err, "failed to get authorization context")
		return nil, err
	}

	// Generate response code
	responseCode := uuid.NewString()
	callbackURL, err := url.JoinPath(c.cfg.Verifier.PublicURL, "/verification/callback")
	if err != nil {
		c.log.Error(err, "Failed to construct callback URL")
		return nil, fmt.Errorf("failed to construct callback URL: %w", err)
	}
	u, err := url.Parse(callbackURL)
	if err != nil {
		c.log.Error(err, "Failed to parse callback URL")
		return nil, fmt.Errorf("failed to parse callback URL: %w", err)
	}
	q := u.Query()
	q.Set("response_code", responseCode)
	u.RawQuery = q.Encode()
	redirectURI := u.String()

	// Process all VP tokens for the requested scopes
	scopeCredentials := make(map[string][]sdjwtvc.CredentialCache, len(authCtx.Scopes))

	for _, scope := range authCtx.Scopes {
		vpTokens, ok := vpResponse.VPToken[scope]
		if !ok || len(vpTokens) == 0 {
			// Fallback: wallet sent vp_token as a plain string (single credential).
			// Only allow this when exactly one scope was requested; otherwise
			// the same credential would be reused for every scope with potentially
			// wrong validations.
			if len(authCtx.Scopes) != 1 {
				c.log.Error(nil, "VP token not found for scope and multiple scopes requested", "scope", scope)
				return nil, fmt.Errorf("VP token not found for scope %s: _default fallback is only allowed when a single scope is requested", scope)
			}
			vpTokens, ok = vpResponse.VPToken["_default"]
			if !ok || len(vpTokens) == 0 {
				c.log.Error(nil, "VP token not found for scope", "scope", scope)
				return nil, fmt.Errorf("VP token not found for scope: %s", scope)
			}
		}
		if len(vpTokens) > 1 {
			c.log.Info("multiple VP tokens received for scope, using first", "scope", scope, "count", len(vpTokens))
		}
		vpToken := vpTokens[0]

		responseParams := &openid4vp.ResponseParameters{}
		responseParams.State = vpResponse.State
		responseParams.VPToken = vpToken

		// Validate response parameters
		if err := responseParams.Validate(); err != nil {
			c.log.Error(err, "response parameters validation failed", "scope", scope)
			return nil, fmt.Errorf("invalid response for scope %s: %w", scope, err)
		}

		// Detect credential format and process accordingly
		format := detectCredentialFormat(vpToken)
		c.log.Debug("Detected credential format", "scope", scope, "format", format)

		switch format {
		case FormatSDJWT:
			// SD-JWT: Use VPTokenValidator for format validation, then evaluateIssuerTrust for sig+trust
			validator := &openid4vp.VPTokenValidator{
				Nonce:           authCtx.Nonce,
				ClientID:        authCtx.ClientID,
				ValidateFormat:  false, // We do real signature verification in evaluateIssuerTrust
				CheckRevocation: false,
			}

			if err := validator.Validate(responseParams.VPToken); err != nil {
				c.log.Error(err, "VP Token validation failed", "scope", scope)
				return nil, fmt.Errorf("VP Token validation failed for scope %s: %w", scope, err)
			}

			c.log.Debug("VP Token format validated successfully", "scope", scope)

			// Evaluate trust (includes signature verification) via JWTTrustVerifier
			if err := c.jwtTrustVerifier.EvaluateIssuerTrust(ctx, responseParams.VPToken, scope); err != nil {
				c.log.Error(err, "issuer trust evaluation failed", "scope", scope)
				return nil, fmt.Errorf("issuer trust evaluation failed for scope %s: %w", scope, err)
			}

			// Parse SD-JWT credential
			// Parse credential claims (recursively resolves nested _sd disclosures)
			parsed, err := sdjwtvc.Token(responseParams.VPToken).Parse()
			if err != nil {
				c.log.Error(err, "failed to parse sd-jwt credential", "scope", scope)
				return nil, err
			}

			c.log.Debug("Parsed SD-JWT credential",
				"scope", scope,
				"disclosures_count", len(parsed.Disclosures),
				"claims_keys", claimKeys(parsed.Claims),
			)

			// Build display claims from the resolved credential map.
			// This ensures nested disclosures (place_of_birth, address, etc.)
			// are shown with their resolved values rather than raw _sd hashes.
			displayClaims := credentialToDisclosers(parsed.Claims)

			// Add to per-scope credential cache
			scopeCredentials[scope] = append(scopeCredentials[scope], sdjwtvc.CredentialCache{
				Scope:      scope,
				Credential: parsed.Claims,
				Claims:     displayClaims,
			})

		case FormatMDoc:
			// mDOC: Use MDocHandler which delegates to TrustEvaluator
			if c.trustEvaluator == nil {
				c.log.Error(nil, "TrustEvaluator required for mDOC verification", "scope", scope)
				return nil, fmt.Errorf("TrustEvaluator not configured for mDOC verification")
			}

			mdocHandler, err := mdoc.NewMDocHandler(
				mdoc.WithMDocTrustEvaluator(c.trustEvaluator),
			)
			if err != nil {
				c.log.Error(err, "failed to create mDOC handler", "scope", scope)
				return nil, fmt.Errorf("failed to create mDOC handler for scope %s: %w", scope, err)
			}

			mdocResult, err := mdocHandler.VerifyAndExtract(ctx, vpToken)
			if err != nil {
				c.log.Error(err, "mDOC verification failed", "scope", scope)
				return nil, fmt.Errorf("mDOC verification failed for scope %s: %w", scope, err)
			}

			c.log.Debug("mDOC verified successfully", "scope", scope, "doc_count", len(mdocResult.Documents))

			// Convert mDOC claims to credential cache format
			for docType, docClaims := range mdocResult.Documents {
				// Reuse a single GetClaims() result for consistency
				verifiedClaims := docClaims.GetClaims()
				// Convert map claims to []Discloser format
				disclosers := mapToDisclosers(verifiedClaims)
				// Augment verified claims map for validation and caching
				verifiedClaims["docType"] = docType
				// Convert map[string]map[string]any to map[string]any so resolvePath can traverse it
				nsMap := make(map[string]any, len(docClaims.Namespaces))
				for ns, items := range docClaims.Namespaces {
					nsMap[ns] = items
				}
				verifiedClaims["namespaces"] = nsMap
				scopeCredentials[scope] = append(scopeCredentials[scope], sdjwtvc.CredentialCache{
					Scope:      scope,
					Credential: verifiedClaims,
					Claims:     disclosers,
				})
			}

		case FormatMDocZK:
			// ZK mDOC: zero-knowledge proof of possession (+ optional
			// pairwise pseudonym) over an mdoc credential. Native proof
			// verification (nativeVerifyZkProofWithPPID) is real when
			// vc-verifier is built with the "zknative" Go build tag (see
			// pkg/mdoc/zk_native_cgo.go); the default build returns a
			// specific ErrNativeZkVerifyNotImplemented-derived error past
			// the trust/matching checks below. See
			// docs/ZK_PPID_VERIFICATION_PLAN.md.
			if c.trustEvaluator == nil {
				c.log.Error(nil, "TrustEvaluator required for ZK mDOC verification", "scope", scope)
				return nil, fmt.Errorf("TrustEvaluator not configured for ZK mDOC verification")
			}

			zkHandler, err := mdoc.NewZkHandler(mdoc.ZkVerifierConfig{
				TrustEvaluator:   c.trustEvaluator,
				ZkCircuitSources: c.cfg.Verifier.ZkCircuits.Sources,
			})
			if err != nil {
				c.log.Error(err, "failed to create ZK mDOC handler", "scope", scope)
				return nil, fmt.Errorf("failed to create ZK mDOC handler for scope %s: %w", scope, err)
			}

			// Find this scope's CredentialQuery (by the "scope == query ID"
			// convention this codebase's own DCQL builders use - see
			// buildDCQLQueryFromConfig in client.go) to recover
			// zk_system_type/ppid_context, and the requested claims in their
			// original request order - see ZkPresentationContext.
			// RequestedClaimIDs's doc comment for why order matters here.
			// Best-effort: if no DCQL query was cached for this session (or
			// none matches), RequestedZkSystems/RequestedClaimIDs are both
			// empty and verification correctly fails (zk_system_type
			// matching, then buildZkAttributes' own empty-order guard)
			// rather than silently skipping either check.
			var zkMeta openid4vp.MetaQuery
			var requestedClaimIDs []string
			if authCtx.DCQLQuery != nil {
				for _, cq := range authCtx.DCQLQuery.Credentials {
					if cq.ID == scope && openid4vp.IsMdocZkFormat(cq.Format) {
						zkMeta = cq.Meta
						for _, claim := range cq.Claims {
							if len(claim.Path) == 0 || claim.Path[len(claim.Path)-1] == nil {
								continue
							}
							requestedClaimIDs = append(requestedClaimIDs, *claim.Path[len(claim.Path)-1])
						}
						break
					}
				}
			}

			// SessionTranscript for the OpenID4VP redirect flow. Its wire
			// format is cross-checked against an independent CBOR library
			// (see pkg/mdoc.TestBuildOID4VPSessionTranscript_MatchesIndependentKotlinCBORLibraryCrossCheck),
			// but is STILL NOT confirmed against a real wallet's own
			// transcript bytes from a live session - no such fixture could
			// be found (checked siros-sdk-kotlin, siros-sdk-swift,
			// go-wallet-backend, multipaz). TRACKED GAP: if native ZK
			// verification of a real presentation fails in a way that looks
			// like a transcript/binding mismatch, treat
			// BuildOID4VPSessionTranscript's exact byte layout as a prime
			// suspect and get a real captured transcript to compare against.
			responseURI, err := url.JoinPath(c.cfg.Verifier.PublicURL, "/verification/oidc-direct_post")
			if err != nil {
				c.log.Error(err, "failed to construct response URI for ZK session transcript", "scope", scope)
				return nil, fmt.Errorf("failed to construct response URI for scope %s: %w", scope, err)
			}
			sessionTranscript, err := mdoc.BuildOID4VPSessionTranscript(authCtx.ClientID, authCtx.Nonce, responseURI, nil)
			if err != nil {
				c.log.Error(err, "failed to build ZK session transcript", "scope", scope)
				return nil, fmt.Errorf("failed to build ZK session transcript for scope %s: %w", scope, err)
			}

			zkResult, err := zkHandler.VerifyAndExtract(ctx, vpToken, mdoc.ZkPresentationContext{
				SessionID:          authCtx.SessionID,
				ClientID:           authCtx.ClientID,
				PPIDContext:        zkMeta.PPIDContext,
				RequestedZkSystems: zkMeta.ZKSystemType,
				RequestedClaimIDs:  requestedClaimIDs,
				SessionTranscript:  sessionTranscript,
			})
			if err != nil {
				c.log.Error(err, "ZK mDOC verification failed", "scope", scope)
				return nil, fmt.Errorf("ZK mDOC verification failed for scope %s: %w", scope, err)
			}

			c.log.Debug("ZK mDOC verified successfully", "scope", scope, "doc_count", len(zkResult.Documents))

			for docType, docResult := range zkResult.Documents {
				verifiedClaims := docResult.GetClaims()
				disclosers := mapToDisclosers(verifiedClaims)
				verifiedClaims["docType"] = docType
				nsMap := make(map[string]any, len(docResult.Claims))
				for ns, items := range docResult.Claims {
					nsMap[ns] = items
				}
				verifiedClaims["namespaces"] = nsMap
				scopeCredentials[scope] = append(scopeCredentials[scope], sdjwtvc.CredentialCache{
					Scope:      scope,
					Credential: verifiedClaims,
					Claims:     disclosers,
				})
			}

		default:
			c.log.Error(nil, "Unknown credential format", "scope", scope, "format", format)
			return nil, fmt.Errorf("unknown credential format for scope %s", scope)
		}
	}

	// Apply claim validations if configured (e.g., age_over checks)
	if len(authCtx.Validations) > 0 {
		for _, scope := range authCtx.Scopes {
			scopeValidations := authCtx.Validations[scope]
			if len(scopeValidations) == 0 {
				continue
			}
			entries := scopeCredentials[scope]
			if len(entries) == 0 {
				c.log.Error(nil, "validations configured but no credentials extracted", "scope", scope)
				return nil, fmt.Errorf("validations configured for scope %s but no credentials were extracted", scope)
			}
			for _, cc := range entries {
				// Validate against the verified credential claims (only disclosures
				// referenced by _sd are included), not raw disclosures which may
				// contain unbound/decoy entries.
				if err := openid4vp.ValidateClaims(cc.Credential, scopeValidations); err != nil {
					c.log.Error(err, "claim validation failed", "scope", scope)
					return nil, fmt.Errorf("claim validation failed for scope %s: %w", scope, err)
				}
			}
		}
	}

	// Revocation status verification (ARF 3.0 §6.6.3.7)
	if c.revocationRegistry != nil && c.cfg.Verifier.Revocation != nil && c.cfg.Verifier.Revocation.Enabled {
		skipScopes := c.cfg.Verifier.Revocation.SkipScopes
		for _, scope := range authCtx.Scopes {
			if slices.Contains(skipScopes, scope) {
				c.log.Debug("Skipping revocation check for exempt scope", "scope", scope)
				continue
			}
			for _, cc := range scopeCredentials[scope] {
				result, err := c.revocationRegistry.Validate(ctx, cc.Credential)
				if err != nil {
					// Transient error (network, malformed token) — fail_open controls behavior
					if c.cfg.Verifier.Revocation.FailOpen {
						c.log.Info("Revocation check failed (fail-open: allowing)", "scope", scope, "err", err)
					} else {
						c.log.Error(err, "revocation check failed", "scope", scope)
						return nil, fmt.Errorf("revocation check failed for scope %s: %w", scope, err)
					}
				} else if result != nil && result.Status != revocation.StatusValid {
					// Authoritative revocation/suspension — always reject regardless of fail_open
					c.log.Error(nil, "credential has been revoked or suspended", "scope", scope, "status", result.Status.String(), "uri", result.URI, "index", result.Index)
					return nil, fmt.Errorf("credential for scope %s has been %s", scope, result.Status.String())
				}
			}
		}
	}

	// Combined presentation binding verification (ARF 3.0 §6.6.3.10)
	if len(authCtx.Scopes) > 1 && c.cfg.Verifier.CombinedPresentation != nil && c.cfg.Verifier.CombinedPresentation.Enabled {
		bindingCredentials := make([]openid4vp.VerifiedCredentialBinding, 0, len(authCtx.Scopes))
		for _, scope := range authCtx.Scopes {
			for _, cc := range scopeCredentials[scope] {
				tp, err := openid4vp.ExtractHolderKeyThumbprint(cc.Credential)
				if err != nil {
					c.log.Error(err, "failed to extract holder key thumbprint", "scope", scope)
					return nil, fmt.Errorf("failed to extract holder key for scope %s: %w", scope, err)
				}
				bindingCredentials = append(bindingCredentials, openid4vp.VerifiedCredentialBinding{
					Scope:               scope,
					HolderKeyThumbprint: tp,
					Claims:              cc.Credential,
				})
			}
		}

		verifier := &openid4vp.CombinedBindingVerifier{Config: *c.cfg.Verifier.CombinedPresentation}
		bindingResult, err := verifier.Verify(bindingCredentials)
		if err != nil {
			c.log.Error(err, "combined presentation binding verification error")
			return nil, fmt.Errorf("combined presentation binding verification failed: %w", err)
		}
		if bindingResult != nil {
			c.log.Debug("Combined presentation binding result",
				"bound", bindingResult.Bound,
				"valid", bindingResult.Valid(),
				"confidence", bindingResult.HighestConfidence,
				"results", bindingResult.Results,
			)
			if !bindingResult.Valid() {
				switch c.cfg.Verifier.CombinedPresentation.Enforcement {
				case openid4vp.BindingEnforcementEnforce:
					c.log.Error(bindingResult.Err(), "combined presentation binding verification failed")
					return nil, fmt.Errorf("combined presentation binding verification failed: credentials not bound to same holder")
				case openid4vp.BindingEnforcementWarn:
					c.log.Info("combined presentation binding issues detected (warn mode)", "confidence", bindingResult.HighestConfidence, "err", bindingResult.Err())
				}
			}
		}
	}

	// Flatten per-scope credentials into ordered slice for caching
	credentialCaches := make([]sdjwtvc.CredentialCache, 0, len(authCtx.Scopes))
	for _, scope := range authCtx.Scopes {
		credentialCaches = append(credentialCaches, scopeCredentials[scope]...)
	}

	// Cache validated credentials
	c.cacheService.Credential.Set(ctx, responseCode, credentialCaches)

	c.log.Debug("Credentials cached", "response_code", responseCode, "count", len(credentialCaches))

	// Notify AFTER credentials are cached so the browser can fetch them
	c.notify.Submit(authCtx.SessionID, map[string]string{"redirect_uri": redirectURI})

	reply := &VerificationDirectPostResponse{}

	// Check if there's an active SSE listener for this session
	// If yes -> cross-device flow: browser is listening, notify via SSE, don't include redirect_uri
	// If no -> same-device flow: no browser listening, include redirect_uri for wallet to follow
	if c.notify.HasListener(authCtx.SessionID) {
		// Cross-device flow: browser is waiting on SSE
		c.log.Debug("Cross-device flow detected (SSE listener active)", "session_id", authCtx.SessionID)
		// Don't include redirect_uri - wallet shows success, browser gets SSE notification
	} else {
		// Same-device flow: no SSE listener, wallet should redirect
		c.log.Debug("Same-device flow detected (no SSE listener)", "session_id", authCtx.SessionID)
		reply.RedirectURI = redirectURI
	}

	return reply, nil
}

type VerificationCallbackRequest struct {
	ResponseCode string `form:"response_code" uri:"response_code"`
}

type VerificationCallbackResponse struct {
	CredentialData []sdjwtvc.CredentialCache `json:"credential_data"`
}

func (c *Client) VerificationCallback(ctx context.Context, req *VerificationCallbackRequest) (*VerificationCallbackResponse, error) {
	c.log.Debug("verificationCallback", "req", req)

	credential, ok := c.cacheService.Credential.Get(ctx, req.ResponseCode)
	if !ok {
		return nil, fmt.Errorf("no item in credential cache matching id %s", req.ResponseCode)
	}

	reply := &VerificationCallbackResponse{
		CredentialData: credential,
	}

	return reply, nil
}

// CredentialFormat represents the format of a verifiable credential.
type CredentialFormat string

const (
	// FormatSDJWT represents SD-JWT Verifiable Credentials (vc+sd-jwt, dc+sd-jwt)
	FormatSDJWT CredentialFormat = "vc+sd-jwt"
	// FormatMDoc represents ISO/IEC 18013-5 mDOC credentials (mso_mdoc)
	FormatMDoc CredentialFormat = "mso_mdoc"
	// FormatMDocZK represents a zero-knowledge-proof presentation of an
	// ISO/IEC 18013-5 mDOC credential (mso_mdoc_zk) - see pkg/mdoc/zk*.go.
	FormatMDocZK CredentialFormat = "mso_mdoc_zk"
	// FormatUnknown represents an unrecognized format
	FormatUnknown CredentialFormat = "unknown"
)

// detectCredentialFormat determines the credential format from the VP token.
// SD-JWT: contains ~ separators (disclosure markers) and JWT dots
// mDOC: base64url-encoded CBOR (doesn't look like JWT - no dots, or random data without ~)
func detectCredentialFormat(vpToken string) CredentialFormat {
	// SD-JWT format: <issuer-jwt>~<disclosure1>~<disclosure2>~...[~<kb-jwt>]
	// Must contain at least one ~ and the first part must look like a JWT (has 2 dots)
	if strings.Contains(vpToken, "~") {
		parts := strings.Split(vpToken, "~")
		if len(parts) > 0 && strings.Count(parts[0], ".") == 2 {
			return FormatSDJWT
		}
	}

	// Plain JWT without SD (still vc+sd-jwt format per spec, but no disclosures)
	if strings.Count(vpToken, ".") == 2 && !strings.Contains(vpToken, "~") {
		// Could be a plain JWT - check if it's valid base64url
		headerPart := strings.Split(vpToken, ".")[0]
		if _, err := base64.RawURLEncoding.DecodeString(headerPart); err == nil {
			return FormatSDJWT
		}
	}

	// mDOC / ZK-mDOC: base64url-encoded CBOR DeviceResponse. Both
	// "mso_mdoc" and "mso_mdoc_zk" are wire-compatible CBOR at this
	// byte-sniffing level (a DeviceResponse is a DeviceResponse either way -
	// only the presence of a non-empty "zkDocuments" array distinguishes
	// them), so a successful decode needs one more peek to tell them apart.
	if !strings.Contains(vpToken, ".") && !strings.Contains(vpToken, "~") {
		data, err := base64.RawURLEncoding.DecodeString(vpToken)
		if err != nil {
			// Also try standard base64 (some implementations use this)
			data, err = base64.StdEncoding.DecodeString(vpToken)
		}
		if err == nil {
			if isZK, zkErr := mdoc.PeekIsZkDeviceResponse(data); zkErr == nil && isZK {
				return FormatMDocZK
			}
			return FormatMDoc
		}
	}

	return FormatUnknown
}

// mapToDisclosers converts a map of claims to []sdjwtvc.Discloser format.
// This is used for mDOC credentials where claims are extracted as a map.
func mapToDisclosers(claims map[string]any) []sdjwtvc.Discloser {
	disclosers := make([]sdjwtvc.Discloser, 0, len(claims))
	for name, value := range claims {
		disclosers = append(disclosers, sdjwtvc.Discloser{
			ClaimName: name,
			Value:     value,
		})
	}
	return disclosers
}

// credentialToDisclosers converts a resolved credential claims map into a flat
// []Discloser suitable for display. Nested maps are flattened using dot notation
// (e.g., "address.street_address"). JWT metadata claims (iss, iat, exp, etc.) are
// excluded since they are not user-facing credential attributes.
func credentialToDisclosers(claims map[string]any) []sdjwtvc.Discloser {
	result := make([]sdjwtvc.Discloser, 0)
	flattenCredentialClaims(&result, "", claims)
	return result
}

// jwtMetadataClaims contains claim names that are JWT/SD-JWT infrastructure
// and should not be displayed as credential attributes.
var jwtMetadataClaims = map[string]bool{
	"iss":           true,
	"sub":           true,
	"iat":           true,
	"exp":           true,
	"nbf":           true,
	"jti":           true,
	"cnf":           true,
	"vct":           true,
	"vct#integrity": true,
	"status":        true,
	"_sd":           true,
	"_sd_alg":       true,
}

func flattenCredentialClaims(result *[]sdjwtvc.Discloser, prefix string, m map[string]any) {
	for key, value := range m {
		// Skip JWT metadata at top level
		if prefix == "" && jwtMetadataClaims[key] {
			continue
		}

		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		switch v := value.(type) {
		case map[string]any:
			// Recurse into nested objects
			flattenCredentialClaims(result, fullKey, v)
		default:
			*result = append(*result, sdjwtvc.Discloser{
				ClaimName: fullKey,
				Value:     value,
			})
		}
	}
}

func claimKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
