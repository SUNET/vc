package apiv1

import (
	"bytes"
	"context"
	"crypto"
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
	"github.com/SUNET/vc/pkg/trust"

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

	// Resolve the supplied id directly from the request object cache. A
	// single authorization context can produce two ids (the QR / request_uri
	// id and a separate DC API id), only the first of which is persisted on
	// the auth context - looking up by RequestObjectID would therefore 404
	// every DC API fetch. The cache is written only from authenticated
	// /ui/interaction paths, so a cache hit is itself sufficient proof the
	// id names a request we minted.
	//
	// cacheService.RequestObject is HA-backed (Mongo in HA mode), so the
	// wallet's request_uri resolves even when it lands on a different
	// verifier node from the one that minted it.
	requestObject, found := c.cacheService.RequestObject.Get(ctx, req.ID)
	if !found {
		c.log.Error(nil, "request object not found in cache", "requestObjectID", req.ID)
		return "", errors.New("request object not found")
	}

	// A cache hit proves we minted this request; it does not prove the
	// session is still open. The request-object cache outlives the
	// presentation window by its own floor, and UIResume can mint a DC API
	// object moments before the deadline - which then stays fetchable long
	// after the direct-post handlers would refuse its response. Handing a
	// wallet a request it can no longer answer is worse than a 404.
	if authCtx := c.authContextFor(ctx, requestObject.State); sessionExpired(authCtx) {
		c.log.Info("Request object fetched for an expired session", "state", requestObject.State)
		return "", ErrSessionExpired
	}

	signedJWT, err := requestObject.Sign(ctx, c.pkiSigner, c.pkiSignerChain)
	if err != nil {
		c.log.Error(err, "failed to sign authorization request")
		return "", err
	}

	c.log.Debug("Signed JWT created", "requestObjectID", req.ID)

	return signedJWT, nil
}

type VerificationDirectPostRequest struct {
	Response string `json:"response"  form:"response"`
	// DCAPI marks a response returned inside a navigator.credentials.get
	// call and forwarded here by the verifier's own page, rather than POSTed
	// by a wallet reached through request_uri. The two bind their mdoc
	// session transcripts to different handovers, so this selects which one
	// the verifier recomputes - see mdoc.BuildOID4VPDCAPISessionTranscript.
	//
	// Client-supplied and not trusted as an assertion: the origin bound into
	// the transcript comes from configuration, never from the caller, so a
	// caller that sets this wrongly only fails its own verification. It
	// cannot choose what the presentation is checked against.
	DCAPI     bool   `json:"dc_api" form:"dc_api"`
	SessionID string `json:"-"` // Set by HTTP layer if same-device flow
}

func (v *VerificationDirectPostRequest) GetKID() (string, error) {
	return jose.ExtractKIDFromCompactJWT(v.Response)
}

type VerificationDirectPostResponse struct {
	// RedirectURI is present for same-device flows so the wallet can send
	// the browser back to the verifier. Cross-device flows omit it: the
	// still-open verifier tab is nudged over SSE instead.
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
	privateEphemeralJWK, found := c.cacheService.EphemeralEncryptionKey.Get(ctx, kid)
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

	// The presentation deadline. Nothing on this path checked it: the
	// standalone flow accepted a wallet response for as long as the
	// auth-context cache kept the session, whatever openid4vp
	// presentation_timeout said.
	if sessionExpired(authCtx) {
		c.log.Info("Verification direct post for an expired session", "state", vpResponse.State)
		return nil, ErrSessionExpired
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
	// Only the scopes a credential query actually stands for. authCtx.Scopes is
	// the raw OIDC scope list, which carries "openid" (always, per OIDC Core)
	// and whatever else the RP asked for - the shipped eudi_pid_basic template
	// is selected by "pid profile". Requiring a VP token for those meant any
	// request naming more than one scope failed here, since no wallet returns a
	// credential for "profile".
	// A session created before ScopeQueryIDs existed has a cached DCQLQuery and
	// no mapping, so a template-built query's response would not resolve. The
	// mapping is a pure function of the request, so rebuild it rather than fail
	// a presentation the user has already completed mid rolling deploy.
	//
	// Held locally, never written back: MemoryStore.Get returns the cached
	// *AuthorizationContext itself, so assigning here would mutate an object
	// concurrent direct-post requests are reading.
	scopeQueryIDs := authCtx.ScopeQueryIDs
	if scopeQueryIDs == nil && authCtx.DCQLQuery != nil {
		if rebuilt := c.ScopeQueryIDs(ctx, authCtx.DCQLQuery, authCtx.Scopes); len(rebuilt) > 0 {
			c.log.Info("rebuilt the scope-to-query mapping for a session that predates it", "scopes", authCtx.Scopes)
			scopeQueryIDs = rebuilt
		}
	}

	// A query that asked for nothing cannot be satisfied by anything.
	if authCtx.DCQLQuery != nil && len(authCtx.DCQLQuery.Credentials) == 0 {
		c.log.Error(nil, "DCQL query requests no credentials", "scopes", authCtx.Scopes)
		return nil, fmt.Errorf("DCQL query requests no credentials")
	}
	// Unconditional: with no credential scope the loop below runs zero times
	// and caches a successful presentation having validated no VP token. The
	// check used to fire only when the query had credentials, so a query with
	// none skipped it.
	credentialScopes := c.credentialScopes(authCtx, scopeQueryIDs)
	if len(credentialScopes) == 0 {
		c.log.Error(nil, "no requested scope corresponds to a requested credential", "scopes", authCtx.Scopes)
		return nil, fmt.Errorf("no requested scope corresponds to a requested credential")
	}
	// Two scopes must not resolve to one vp_token key. resolveScopeQueries
	// refuses to build such a mapping, but a session cached before it existed
	// reaches here with only its persisted pairs - and a scope that IS a query
	// id resolves to itself, so it can collide with another scope mapped onto
	// it. Both would then read the same credential and validate it twice,
	// under each scope's rules.
	claimedBy := make(map[string]string, len(credentialScopes))
	for _, scope := range credentialScopes {
		key := queryIDForScopeIn(scopeQueryIDs, scope)
		if owner, taken := claimedBy[key]; taken {
			c.log.Error(nil, "two scopes resolve to the same DCQL query id", "query_id", key, "scopes", []string{owner, scope})
			return nil, fmt.Errorf("scopes %q and %q both resolve to DCQL query id %q; the response cannot be attributed", owner, scope, key)
		}
		claimedBy[key] = scope
	}

	defaultAllowed := c.defaultTokenAllowed(authCtx, scopeQueryIDs, credentialScopes)

	scopeCredentials := make(map[string][]sdjwtvc.CredentialCache, len(credentialScopes))

	for _, scope := range credentialScopes {
		vpTokens, err := c.vpTokensForScope(authCtx, scopeQueryIDs, defaultAllowed, vpResponse, scope)
		if err != nil {
			return nil, err
		}
		if len(vpTokens) > 1 {
			c.log.Info("multiple VP tokens received for scope, using first", "scope", scope, "count", len(vpTokens))
		}
		vpToken := vpTokens[0]

		responseParams := &openid4vp.ResponseParameters{}
		responseParams.State = vpResponse.State
		responseParams.VPToken = vpToken

		// Detect credential format and process accordingly
		format := detectCredentialFormat(vpToken)
		c.log.Debug("Detected credential format", "scope", scope, "format", format)

		// The wallet does not get to choose which format answers a scope.
		// Detection reads the token; the request said what was asked for.
		// The wallet does not get to choose which format answers a scope.
		// Detection reads the token; the request said what was asked for.
		//
		// The wallet does not get to choose which format answers a scope.
		// Detection reads the token; the request said what was asked for.
		//
		// Conditional, and the condition now means something narrower than
		// it used to. requestedQuery could not resolve a multi-credential
		// template whose query ids differ from the scope - which is most of
		// the shipped ones - so every such response took the log-and-continue
		// path and was never checked. It consults the session's
		// scope-to-query mapping now, so those resolve.
		//
		// What is left unresolvable is a session whose DCQL query is not
		// available here at all: the persisted one comes back nil from Mongo
		// and the request-object cache is per-process unless
		// common.ha.enable is on, so a response landing on a replica that
		// never saw the request is an ordinary deployment shape rather than
		// an attack, and nothing downstream could check a constraint for it
		// either. Refusing that is a deployment decision (it would require HA
		// caching), not one to take inside a format check.
		//
		// A scope the request does NOT ask for never reaches here:
		// vpTokensForScope refuses it above, because its key names no
		// credential query. So this is not the gap it looks like.
		if requested, ok := c.requestedQuery(authCtx, scopeQueryIDs, scope); ok {
			if !formatMatchesRequest(format, requested.Format) {
				c.log.Error(nil, "returned credential format does not answer the request",
					"scope", scope, "detected", format, "requested", requested.Format)
				return nil, fmt.Errorf("scope %s was requested as %q but the response is %q", scope, requested.Format, format)
			}
		} else {
			c.log.Warn("cannot check the returned format against the request: this session's DCQL query is not available on this replica",
				"scope", scope, "detected", format)
		}

		// ResponseParameters.Validate parses the token as an SD-JWT, so it can
		// only speak for that format - it rejected a perfectly good mdoc or
		// JSON-LD token as "invalid JWT format". Each format's own branch
		// below validates it properly; this stays as the SD-JWT shape check
		// it always was.
		if format == FormatSDJWT {
			if err := responseParams.Validate(); err != nil {
				c.log.Error(err, "response parameters validation failed", "scope", scope)
				return nil, fmt.Errorf("invalid response for scope %s: %w", scope, err)
			}
		}

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
			// authCtx.DCQLQuery is the Mongo-persisted copy - confirmed live
			// (via a temporary debug log, since removed) that it comes back
			// nil here even for a session whose consent screen the wallet
			// just correctly rendered from the SAME original DCQL query,
			// meaning the query itself was never lost, only this particular
			// round-trip through AuthContext's Mongo store. Fall back to
			// RequestObjectCache (the HA-backed cache keyed by
			// RequestObjectID; backed by Mongo when cfg.Common.HA.Enable is
			// set, in-memory otherwise) - it holds the exact RequestObject
			// that was signed and served to the wallet at
			// /verification/request-object (see VerificationRequestObject),
			// which necessarily carries the same DCQLQuery the wallet just
			// demonstrably parsed correctly.
			dcqlQuery := authCtx.DCQLQuery
			if dcqlQuery == nil {
				if requestObject, found := c.cacheService.RequestObject.Get(ctx, authCtx.RequestObjectID); found {
					dcqlQuery = requestObject.DCQLQuery
				}
			}
			if dcqlQuery != nil {
				// By the scope's QUERY ID, not the scope: a template names its
				// queries whatever its author chose, so matching on the scope
				// found nothing for a template-built request and left zkMeta
				// empty - the ZK verification then failed for want of a
				// zk_system_type that was in the query all along.
				queryID := queryIDForScopeIn(scopeQueryIDs, scope)
				for _, cq := range dcqlQuery.Credentials {
					if cq.ID == queryID && openid4vp.IsMdocZkFormat(cq.Format) {
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

			// SessionTranscript for the OpenID4VP redirect flow. CONFIRMED
			// LIVE as the exact cause of a real "InvalidSumcheckProof"
			// rejection of a genuinely valid proof: this endpoint path MUST
			// match the responseURI actually sent to the wallet as
			// requestObject.ResponseURI (see UIInteraction/CreateRequestObject,
			// which use "direct_post", not "oidc-direct_post" - the latter
			// belongs to a wholly separate OIDC RP flow with its own
			// session/state cache namespace, see _submitDCAPIResponse's
			// identical distinction in presentation-definition.js). Any
			// difference here changes handoverInfo's encoded bytes, which
			// changes its SHA-256 digest, which changes the whole
			// SessionTranscript the ZK proof's Fiat-Shamir transcript was
			// built against - a wallet-side proof built over the real
			// "direct_post" responseURI can never verify against a
			// recomputed transcript using a different one, regardless of
			// whether the underlying disclosed claims are correct.
			responseURI, err := url.JoinPath(c.cfg.Verifier.PublicURL, "verification", "direct_post")
			if err != nil {
				c.log.Error(err, "failed to construct response URI for ZK session transcript", "scope", scope)
				return nil, fmt.Errorf("failed to construct response URI for scope %s: %w", scope, err)
			}
			// BuildOID4VPSessionTranscript's own doc comment: the JWK
			// thumbprint is nil "unless the request advertised an
			// encryption key for the response". Every request that reaches
			// this handler advertised one, so passing nil unconditionally
			// contradicted the documented condition and silently left the ZK
			// proof's Fiat-Shamir transcript unbound from the encryption key
			// the wallet actually saw and included in its own transcript.
			//
			// The writer is UIInteraction: it sets EphemeralEncryptionKeyID
			// for every session and caches the key under it, and both request
			// objects it builds carry a ".jwt" response mode, so the key is
			// advertised on both delivery channels.
			//
			// Not CreateRequestObject, which an earlier version of this
			// comment cited as the proof - it attaches ClientMetadata.JWKS
			// only when its response mode requires encryption, and
			// OIDCRelyingPartyResponseMode can return plain direct_post. It
			// also serves a different flow, which answers on
			// oidc-direct_post and never arrives here, so it could not have
			// established anything about this request either way. The guard
			// below is still on the key ID rather than on the response mode,
			// so a future caller that leaves it unset gets a nil thumbprint
			// rather than a wrong one.
			var readerPubKeyThumbprint []byte
			if authCtx.EphemeralEncryptionKeyID != "" {
				if privKey, found := c.cacheService.EphemeralEncryptionKey.Get(ctx, authCtx.EphemeralEncryptionKeyID); found {
					pubKeyIface, err := privKey.PublicKey()
					if err != nil {
						c.log.Error(err, "failed to derive public key for ZK session transcript", "scope", scope)
						return nil, fmt.Errorf("failed to derive public key for scope %s: %w", scope, err)
					}
					tp, err := pubKeyIface.Thumbprint(crypto.SHA256)
					if err != nil {
						c.log.Error(err, "failed to compute JWK thumbprint for ZK session transcript", "scope", scope)
						return nil, fmt.Errorf("failed to compute JWK thumbprint for scope %s: %w", scope, err)
					}
					readerPubKeyThumbprint = tp
				} else {
					// A miss means the key expired or was evicted between
					// issuing the request and the wallet answering it. The
					// wallet built ITS transcript with that key, so carrying
					// on with a nil thumbprint guarantees a mismatch - and
					// one that surfaces as an opaque proof failure rather
					// than as the cache miss it actually is.
					c.log.Error(nil, "ephemeral encryption key missing from cache for ZK session transcript", "scope", scope, "key_id", authCtx.EphemeralEncryptionKeyID)
					return nil, fmt.Errorf("ephemeral encryption key %q is no longer cached, cannot rebuild the session transcript the wallet used for scope %s", authCtx.EphemeralEncryptionKeyID, scope)
				}
			}
			// The handover follows how the response arrived, because the two
			// hash different things and a wallet only ever produced one of
			// them (SUNET/vc#652, SUNET/vc#655). A request_uri response binds
			// to the response URI and client_id; a DC API response binds to
			// the calling origin instead.
			//
			// Both carry the reader-key thumbprint, for the reason given
			// above: a dc_api.jwt response is always encrypted, so leaving it
			// out of that branch would reintroduce exactly the unbinding the
			// block above fixes.
			var origin string
			if req.DCAPI {
				origin, err = c.dcAPIOrigin()
				if err != nil {
					c.log.Error(err, "cannot determine the DC API origin for the session transcript", "scope", scope)
					return nil, err
				}
			}
			sessionTranscript, err := zkSessionTranscript(req.DCAPI, origin, authCtx.ClientID, authCtx.Nonce, responseURI, readerPubKeyThumbprint)
			if err != nil {
				c.log.Error(err, "failed to build ZK session transcript", "scope", scope, "dc_api", req.DCAPI)
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

		case FormatVC20:
			// W3C VC 2.0 Data Integrity. The cryptosuites, RDF canonicalization
			// and JSON-LD handling live in openid4vp.VC20Handler; what the
			// verifier supplies is key resolution, which is the same trust
			// evaluator the other formats use - trust.KeyResolver and
			// openid4vp.VC20KeyResolver declare the same method, and both
			// configured evaluators implement it.
			resolver, ok := c.trustEvaluator.(trust.KeyResolver)
			if !ok {
				c.log.Error(nil, "trust evaluator cannot resolve verification methods", "scope", scope)
				return nil, fmt.Errorf("W3C VC verification for scope %s needs a key-resolving trust evaluator", scope)
			}

			vc20Opts := []openid4vp.VC20HandlerOption{openid4vp.WithVC20KeyResolver(resolver)}

			// Holder binding, when the request asked for it (the OpenID4VP
			// default). The credential's issuer proof says it was issued; only
			// a proof over the PRESENTATION, carrying this session's nonce and
			// naming this verifier, says the holder is presenting it now.
			requested, haveQuery := c.requestedQuery(authCtx, scopeQueryIDs, scope)
			if !haveQuery || requested.RequiresCryptographicHolderBinding() {
				vc20Opts = append(vc20Opts, openid4vp.WithVC20PresentationBinding(authCtx.Nonce, authCtx.ClientID))
			}

			vc20Handler, err := openid4vp.NewVC20Handler(vc20Opts...)
			if err != nil {
				c.log.Error(err, "failed to create W3C VC handler", "scope", scope)
				return nil, fmt.Errorf("failed to create W3C VC handler for scope %s: %w", scope, err)
			}

			vc20Result, err := vc20Handler.VerifyAndExtract(ctx, vpToken)
			if err != nil {
				c.log.Error(err, "W3C VC verification failed", "scope", scope)
				return nil, fmt.Errorf("W3C VC verification failed for scope %s: %w", scope, err)
			}

			// Resolving the issuer's key says who signed it, not whether we
			// trust them. The SD-JWT and mdoc branches both put that decision
			// to the evaluator, and a PDP configured to deny an issuer has to
			// deny it here too.
			//
			// The key the signature was VERIFIED with, not a fresh resolution
			// of the same verification method: a rotating or remote resolver
			// can answer differently the second time, and then the key trusted
			// is not the key that signed.
			if vc20Result.IssuerKey == nil {
				c.log.Error(nil, "W3C verification returned no issuer key to evaluate", "scope", scope)
				return nil, fmt.Errorf("W3C verification for scope %s produced no issuer key to evaluate", scope)
			}
			decision, err := c.trustEvaluator.Evaluate(ctx, &trust.EvaluationRequest{
				SubjectID:      vc20Result.Issuer,
				KeyType:        trust.KeyTypeJWK,
				Key:            vc20Result.IssuerKey,
				Role:           trust.RoleCredentialIssuer,
				CredentialType: scope,
			})
			if err != nil {
				c.log.Error(err, "W3C issuer trust evaluation failed", "scope", scope, "issuer", vc20Result.Issuer)
				return nil, fmt.Errorf("W3C issuer trust evaluation failed for scope %s: %w", scope, err)
			}
			if !decision.Trusted {
				c.log.Warn("W3C issuer not trusted", "scope", scope,
					"issuer", vc20Result.Issuer, "reason", decision.Reason)
				return nil, fmt.Errorf("W3C issuer not trusted for scope %s: %s", scope, decision.Reason)
			}

			// The type constraint the request carried, enforced on what came
			// back. Without this the wallet chooses which credential answers
			// the scope and meta.type_values is decoration.
			// Fail closed. Skipping the constraint because the query could
			// not be recovered would let any valid W3C credential answer the
			// scope, which is the failure this check exists to prevent.
			if !haveQuery {
				c.log.Error(nil, "cannot recover the query this scope was requested under", "scope", scope)
				return nil, fmt.Errorf("cannot verify the constraint for scope %s: the request it was made under is no longer available", scope)
			}
			// Validate the query before trusting it as a constraint. Only
			// UIInteraction validates the DCQL it is handed; a template-built
			// query reaches here unchecked, and a length test is not enough -
			// [[]] and [[VerifiableCredential]] both have length but match
			// every W3C credential. ValidateCredentialQuery already encodes
			// what counts as narrowing, so use it rather than restate it, and
			// pick up anything added to it later for free.
			if err := openid4vp.ValidateCredentialQuery(requested); err != nil {
				c.log.Error(err, "the query this scope was requested under does not constrain it", "scope", scope)
				return nil, fmt.Errorf("the query for scope %s cannot constrain a credential: %w", scope, err)
			}
			if !openid4vp.MatchTypeValues(vc20Result.TypeIRIs, requested.Meta.TypeValues) {
				c.log.Error(nil, "returned W3C credential does not carry the requested types",
					"scope", scope, "got", vc20Result.TypeIRIs, "want", requested.Meta.TypeValues)
				return nil, fmt.Errorf("the credential returned for scope %s does not carry the requested types", scope)
			}

			c.log.Debug("W3C VC verified successfully", "scope", scope,
				"issuer", vc20Result.Issuer, "cryptosuite", vc20Result.Cryptosuite,
				"selective_disclosure", vc20Result.IsSelectiveDisclosure)

			// The whole credential map, so a configured validation can address
			// credentialSubject.* the way the document is actually shaped;
			// display flattens the subject alone, which is the user-facing part.
			scopeCredentials[scope] = append(scopeCredentials[scope], sdjwtvc.CredentialCache{
				Scope:      scope,
				Credential: vc20Result.Claims,
				Claims:     credentialToDisclosers(vc20Result.CredentialSubject),
			})

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

	// Cache validated credentials. responseCode is a fresh UUID, so SetNX
	// cannot lose to a collision; it exists here only to surface a Mongo /
	// Redis write failure that Set would silently swallow - otherwise the
	// completion marker below gets persisted, SSE fires, and /ui/result
	// 404s the one key the browser can use to recover.
	if ok, err := c.cacheService.Credential.SetNX(ctx, responseCode, credentialCaches); err != nil {
		c.log.Error(err, "failed to persist credential cache", "response_code", responseCode)
		return nil, fmt.Errorf("credential cache persist: %w", err)
	} else if !ok {
		return nil, fmt.Errorf("credential cache persist: unexpected id collision for %s", responseCode)
	}

	c.log.Debug("Credentials cached", "response_code", responseCode, "count", len(credentialCaches))

	// Persist the completion marker BEFORE broadcasting the redirect. A tab
	// that reloads after Submit has fired but before it was observed must
	// mint a fresh session rather than resubscribe to this now-consumed
	// context (otherwise isReusableAuthContext would let the reload sit on
	// an SSE stream whose only message has already been delivered). The
	// VerifierResponseCode is already a per-completion value and is also
	// what identifies the cached credentials for the callback.
	authCtx.VerifierResponseCode = responseCode
	if err := c.cacheService.AuthContext.Save(ctx, authCtx); err != nil {
		c.log.Error(err, "failed to persist completion marker on authorization context", "session_id", authCtx.SessionID)
		return nil, err
	}

	// Notify AFTER credentials are cached so the browser can fetch them
	c.notify.Submit(authCtx.SessionID, map[string]string{"redirect_uri": redirectURI})

	reply := &VerificationDirectPostResponse{}

	// WalletFollowsRedirect is committed by the browser tab BEFORE it leaves
	// for the wallet (see /verification/session-preference callers), so it
	// survives native wallets and web wallets alike; DC API responses arrive
	// from in-tab JS, so they are same-device by construction.
	sameDevice := authCtx.WalletFollowsRedirect || req.DCAPI
	if sameDevice {
		c.log.Debug("Same-device flow", "session_id", authCtx.SessionID, "wallet_follows_redirect", authCtx.WalletFollowsRedirect, "dc_api", req.DCAPI)
		reply.RedirectURI = redirectURI
	} else {
		c.log.Debug("Cross-device flow", "session_id", authCtx.SessionID)
	}

	return reply, nil
}

type VerificationCallbackRequest struct {
	ResponseCode string `form:"response_code" uri:"response_code"`
}

type VerificationCallbackResponse struct {
	CredentialData []sdjwtvc.CredentialCache `json:"credential_data"`
}

// credentialScopes returns the requested scopes that are part of the
// presentation, in request order.
//
// A non-standard scope is always kept: dropping on uncertainty would remove it
// from the validation loop rather than fail in it.
//
// A standard OIDC scope is kept only when it really is a credential - named by
// a query, paired with one, or configured in credential_metadata. "openid" is
// always present and the shipped template is selected by "pid profile", so
// requiring a VP token for those failed every multi-scope request. The test is
// that narrow because a standard scope CAN be a credential: a template may be
// selected by one, and nothing stops credential_metadata configuring one.
//
// No cached query means every scope is returned, as before.
func (c *Client) credentialScopes(authCtx *cache.AuthorizationContext, scopeQueryIDs map[string]string) []string {
	if authCtx.DCQLQuery == nil {
		return authCtx.Scopes
	}
	scopes := make([]string, 0, len(authCtx.Scopes))
	for _, scope := range authCtx.Scopes {
		if openid4vp.StandardOIDCScopes[scope] && !c.isCredentialScope(authCtx, scopeQueryIDs, scope) {
			continue
		}
		scopes = append(scopes, scope)
	}
	return scopes
}

// isCredentialScope reports whether a scope names a credential this request
// actually asked for.
func (c *Client) isCredentialScope(authCtx *cache.AuthorizationContext, scopeQueryIDs map[string]string, scope string) bool {
	if _, mapped := scopeQueryIDs[scope]; mapped {
		return true
	}
	if c.cfg.Common != nil {
		if _, configured := c.cfg.Common.CredentialMetadata[scope]; configured {
			return true
		}
	}
	return slices.ContainsFunc(authCtx.DCQLQuery.Credentials, func(cred openid4vp.CredentialQuery) bool {
		return cred.ID == scope
	})
}

// vpTokensForScope finds the VP tokens a wallet returned for one scope, in the
// three ways a response can name them:
//
//   - the scope's own key, which config-built queries use;
//   - its DCQL query id, since a wallet keys vp_token by query id and a
//     template names its queries whatever its author chose;
//   - "_default", for a wallet that sent a plain string. Single-scope requests
//     only: otherwise one credential would answer every scope, carrying the
//     others' validations.
//
// queryIDForScopeIn returns the DCQL credential query id that stands for scope
// in this session, which is the scope itself unless ScopeQueryIDs says
// otherwise. Only differing pairs are persisted, so an absent entry means the
// two already agree.
func queryIDForScopeIn(scopeQueryIDs map[string]string, scope string) string {
	if queryID, mapped := scopeQueryIDs[scope]; mapped {
		return queryID
	}
	return scope
}

// scopeNamedByQuery reports whether the request's DCQL actually asks for this
// scope: a credential query carries its id, either directly or through the
// scope-to-query mapping.
func scopeNamedByQuery(authCtx *cache.AuthorizationContext, scopeQueryIDs map[string]string, scope string) bool {
	if authCtx == nil || authCtx.DCQLQuery == nil {
		return false
	}
	queryID := queryIDForScopeIn(scopeQueryIDs, scope)
	return slices.ContainsFunc(authCtx.DCQLQuery.Credentials, func(cred openid4vp.CredentialQuery) bool {
		return cred.ID == queryID
	})
}

// defaultTokenAllowed reports whether a plain-string vp_token, which the
// wallet keys as "_default", can be attributed to a scope at all.
//
// "_default" names no query, so it is only unambiguous when the request can
// come back with exactly one credential AND the one scope left really is that
// credential.
//
// Neither count alone is that test. A template author writes the queries and
// there can be more of them than the scopes mapped onto them; and
// credentialScopes keeps an unclaimed non-standard scope on purpose, so that
// it fails in the validation loop rather than vanishing from it - "openid
// profile custom_claim" selects the PID template through profile and leaves
// custom_claim alone in the list, where a length check reads as "one
// credential".
//
// A session with no cached query has only the scope count to go on, as before.
func (c *Client) defaultTokenAllowed(authCtx *cache.AuthorizationContext, scopeQueryIDs map[string]string, credentialScopes []string) bool {
	if len(credentialScopes) != 1 {
		return false
	}
	if authCtx.DCQLQuery == nil {
		return true
	}
	// Named by the query, not merely configured. isCredentialScope accepts a
	// scope that credential_metadata configures, which is the right test for
	// deciding whether to VALIDATE a scope - but not for attributing an
	// unlabelled credential to it. A template selected by an unrelated scope
	// can leave a configured-but-unrequested scope as the only entry in
	// credentialScopes, and "_default" would then cache that template's
	// credential under a scope the request never asked for.
	return len(authCtx.DCQLQuery.Credentials) <= 1 &&
		scopeNamedByQuery(authCtx, scopeQueryIDs, credentialScopes[0])
}

func (c *Client) vpTokensForScope(authCtx *cache.AuthorizationContext, scopeQueryIDs map[string]string, defaultAllowed bool, vpResponse openid4vp.VPResponse, scope string) ([]string, error) {
	// One key per scope: its DCQL query id when the mapping names one,
	// otherwise its own name (which is what a config-built query uses).
	//
	// A mapped scope must NOT also be read under its own name. With scope A
	// mapped to query id B and scope B mapped to query id C, a wallet keying
	// by query id returns A's credential under "B" - and a scope-name lookup
	// would hand it to scope B, which would then validate A's credential
	// under B's rules and never look at C. The collision guard above does not
	// see it, because the two resolved ids differ.
	key := queryIDForScopeIn(scopeQueryIDs, scope)

	// The key has to name a credential the request actually asked for.
	// Scopes are kept in the loop even when no query obviously stands for
	// them - dropping one would let it vanish instead of failing here - but
	// keeping it must not mean accepting whatever the wallet chose to key by
	// that name. For "openid pid custom_claim" the template is selected by
	// pid, nothing claims custom_claim, and without this a token keyed
	// "custom_claim" would be validated and cached as though the request had
	// asked for it, while the template's own query went unprocessed.
	if !knownQueryKey(authCtx, key) {
		c.log.Error(nil, "VP token key names no credential this request asked for", "scope", scope, "key", key)
		return nil, fmt.Errorf("scope %s resolves to key %q, which names no credential query in this request", scope, key)
	}

	if tokens, ok := vpResponse.VPToken[key]; ok && len(tokens) > 0 {
		if key != scope {
			c.log.Debug("resolved VP token through the scope's DCQL query id", "scope", scope, "query_id", key)
		}
		return tokens, nil
	}

	// See defaultAllowed at the call site for what makes _default ambiguous.
	if !defaultAllowed {
		c.log.Error(nil, "VP token not found for scope and _default cannot be attributed", "scope", scope)
		return nil, fmt.Errorf("VP token not found for scope %s: the _default fallback is only allowed when the request asks for exactly one credential and that scope is it", scope)
	}
	if tokens, ok := vpResponse.VPToken["_default"]; ok && len(tokens) > 0 {
		return tokens, nil
	}

	c.log.Error(nil, "VP token not found for scope", "scope", scope)
	return nil, fmt.Errorf("VP token not found for scope: %s", scope)
}

// knownQueryKey reports whether key names a credential query in the DCQL
// this request was built from.
//
// A session with no cached DCQL predates the mapping and is accepted as
// before - there is nothing to check against, and refusing would break
// sessions mid rolling deploy.
func knownQueryKey(authCtx *cache.AuthorizationContext, key string) bool {
	if authCtx == nil || authCtx.DCQLQuery == nil {
		return true
	}
	return slices.ContainsFunc(authCtx.DCQLQuery.Credentials, func(cred openid4vp.CredentialQuery) bool {
		return cred.ID == key
	})
}

func (c *Client) VerificationCallback(ctx context.Context, req *VerificationCallbackRequest) (*VerificationCallbackResponse, error) {
	c.log.Debug("verificationCallback", "req", req)

	credential, err := c.cacheService.Credential.GetErr(ctx, req.ResponseCode)
	if err != nil {
		if errors.Is(err, cache.ErrNoDocuments) {
			return nil, fmt.Errorf("no item in credential cache matching id %s: %w", req.ResponseCode, err)
		}
		return nil, err
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
	// FormatVC20 represents a W3C VC 2.0 Data Integrity credential or
	// presentation (ldp_vc / vc+ld+json), carried as JSON-LD.
	FormatVC20 CredentialFormat = "ldp_vc"
	// FormatUnknown represents an unrecognized format
	FormatUnknown CredentialFormat = "unknown"
)

// detectCredentialFormat determines the credential format from the VP token.
// SD-JWT: contains ~ separators (disclosure markers) and JWT dots
// mDOC: base64url-encoded CBOR (doesn't look like JWT - no dots, or random data without ~)
func detectCredentialFormat(vpToken string) CredentialFormat {
	// W3C VC 2.0 is JSON-LD, and a JSON document is unambiguous - so test it
	// first. The mdoc branch below base64-decodes and would otherwise claim a
	// wrapped JSON body before anything looked at it.
	if looksLikeJSONDocument(vpToken) {
		return FormatVC20
	}

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
		headerPart, _, _ := strings.Cut(vpToken, ".")
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

// requestedQuery returns the DCQL credential query this scope was requested
// under. Config-built queries use the scope as the query id.
//
// Falls back to RequestObjectCache exactly as the ZK path does: authCtx's
// Mongo-persisted DCQLQuery has been observed coming back nil for a session
// whose wallet had just rendered a consent screen from that very query, so the
// persisted field alone is not a reliable source. The request object cache
// holds the query that was signed and served to the wallet.
// sessionDCQL returns the DCQL query this session's request was built from,
// or nil when it cannot be recovered.
//
// The persisted DCQLQuery comes back nil from Mongo (see the field's own
// documentation), so the request-object cache is the fallback - and with
// common.ha.enable off that cache is per-process, so on a multi-replica
// deployment a response can land on a replica that never saw the request.
// Nil therefore means "this session's request is not available here", which
// is a different thing from "the request did not ask for that".
func (c *Client) sessionDCQL(authCtx *cache.AuthorizationContext) *openid4vp.DCQL {
	if authCtx == nil {
		return nil
	}
	if authCtx.DCQLQuery != nil {
		return authCtx.DCQLQuery
	}
	if c.openid4vp != nil && c.openid4vp.RequestObjectCache != nil {
		if requestObject, found := c.openid4vp.RequestObjectCache.Get(authCtx.RequestObjectID); found {
			return requestObject.DCQLQuery
		}
	}
	return nil
}

// requestedQueryExact is requestedQuery WITHOUT the single-query fallback:
// the query has to be named by this scope, through the session's mapping or
// its own id.
//
// The fallback is right for applying a CONSTRAINT - with one credential
// query there is no ambiguity about which credential was asked for, and
// using its type_values narrows rather than widens. It is wrong for reading
// a RELAXATION off the same query. "The mapping is gone, so take the only
// query's settings" turns require_cryptographic_holder_binding=false or
// multiple=true into the answer for a scope nobody established that query
// belongs to, and a guard that is meant to fail closed then fails open
// whenever a request happens to carry exactly one query.
func (c *Client) requestedQueryExact(authCtx *cache.AuthorizationContext, scopeQueryIDs map[string]string, scope string) (openid4vp.CredentialQuery, bool) {
	dcqlQuery := c.sessionDCQL(authCtx)
	if dcqlQuery == nil || scope == "" {
		return openid4vp.CredentialQuery{}, false
	}
	queryID := queryIDForScopeIn(scopeQueryIDs, scope)
	for _, q := range dcqlQuery.Credentials {
		if q.ID == queryID {
			return q, true
		}
	}
	return openid4vp.CredentialQuery{}, false
}

func (c *Client) requestedQuery(authCtx *cache.AuthorizationContext, scopeQueryIDs map[string]string, scope string) (openid4vp.CredentialQuery, bool) {
	if authCtx == nil {
		return openid4vp.CredentialQuery{}, false
	}
	dcqlQuery := c.sessionDCQL(authCtx)
	if dcqlQuery == nil {
		return openid4vp.CredentialQuery{}, false
	}
	// The session's own scope-to-query mapping decides, the same way every
	// other lookup in this handler does. A template names its queries
	// whatever its author chose, and the shipped ones nearly all differ from
	// the scope that selects them - "pid" selects a query with id "eudi_pid",
	// "ehic" one with id "eudi_ehic" - so matching the scope against query
	// ids alone finds nothing for a template-built request.
	//
	// queryIDForScopeIn returns the scope itself when nothing is mapped, so
	// this subsumes the plain id match it replaced.
	queryID := queryIDForScopeIn(scopeQueryIDs, scope)
	for _, q := range dcqlQuery.Credentials {
		if q.ID == queryID {
			return q, true
		}
	}

	// No mapping and no matching id: a session cached before #683 persisted
	// the mapping, and one the rebuild could not reconstruct. With exactly
	// one credential query there is no ambiguity about which one the scope
	// was requested under. With more than one there is, and this returns
	// nothing so the caller refuses - guessing would attribute a constraint
	// to the wrong credential.
	if len(dcqlQuery.Credentials) == 1 {
		return dcqlQuery.Credentials[0], true
	}
	return openid4vp.CredentialQuery{}, false
}

// formatMatchesRequest reports whether a sniffed format answers the format the
// request asked for. Detection reads the token, not the request, so without
// this a valid credential of one format satisfies a scope that asked for
// another as long as its signature resolves.
func formatMatchesRequest(detected CredentialFormat, requested string) bool {
	switch requested {
	case openid4vp.FormatMsoMdoc:
		return detected == FormatMDoc
	case openid4vp.FormatMsoMdocZk:
		return detected == FormatMDocZK
	case openid4vp.FormatSDJWTVC, "vc+sd-jwt", "":
		return detected == FormatSDJWT
	case openid4vp.FormatLdpVCDCQL, openid4vp.FormatVCLDJSON:
		return detected == FormatVC20
	default:
		return false
	}
}

// looksLikeJSONDocument reports whether the token is a JSON-LD document in any
// shape VC20Handler.decodeVPToken accepts: an object or an expanded-form
// array, plain or wrapped in base64url or standard base64.
//
// It has to accept exactly what the handler does. Anything narrower sends a
// token the handler could verify down another format's branch instead.
func looksLikeJSONDocument(vpToken string) bool {
	if isJSONDocument([]byte(vpToken)) {
		return true
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(vpToken); err == nil {
		return isJSONDocument(decoded)
	}
	if decoded, err := base64.StdEncoding.DecodeString(vpToken); err == nil {
		return isJSONDocument(decoded)
	}
	return false
}

func isJSONDocument(b []byte) bool {
	trimmed := bytes.TrimSpace(b)
	return bytes.HasPrefix(trimmed, []byte("{")) || bytes.HasPrefix(trimmed, []byte("["))
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
