package apiv1

import (
	"context"
	"fmt"
	"slices"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/trust"
)

// verifyVC20ForOIDC verifies every W3C VC 2.0 document a direct-post
// response carries, before any claim in it is read.
//
// ProcessDirectPost extracts claims without verifying anything, for any
// format - a gap of its own, older and wider than W3C. That is not a licence
// to add another unverified format: making a W3C response usable here means
// an arbitrary JSON-LD document would otherwise have its credentialSubject
// mapped into an OIDC session, with nothing checking who signed it or
// whether the holder was present.
//
// Same machinery the UI direct-post path uses: the trust evaluator resolves
// the verification method, VC20Handler checks the Data Integrity proof, the
// key the signature VERIFIED with goes back to the evaluator - resolving
// again could answer differently, and then the key trusted is not the key
// that signed - and the request's own type constraint is enforced on what
// came back.
func (c *Client) verifyVC20ForOIDC(ctx context.Context, session *cache.AuthorizationContext, vpToken string) error {
	if session == nil {
		return fmt.Errorf("no session to verify a W3C presentation against")
	}

	// A DCQL response is a JSON object too, so "looks like JSON" cannot
	// tell a W3C document from the envelope around one. Asking which
	// documents are actually in there means a conformant DCQL response is
	// unwrapped rather than failed as a malformed credential.
	//
	// The other half of the partition matters as much: this gate verifies
	// W3C documents and nothing else, so what ELSE arrived decides whether
	// verifying the W3C half means anything.
	documents, others := openid4vp.PartitionTokens(vpToken)

	// A response carrying no W3C document still has to answer the request.
	// Returning early here let a wallet answer an ldp_vc query with an
	// SD-JWT or an mdoc: nothing else on this path compares the returned
	// format against the requested one, so the W3C constraint was simply
	// skipped.
	if err := c.refuseAResponseThisPathCannotCheck(session, documents, others); err != nil {
		return err
	}
	if len(documents) == 0 {
		return nil
	}

	resolver, ok := c.trustEvaluator.(trust.KeyResolver)
	if !ok {
		return fmt.Errorf("W3C verification needs a key-resolving trust evaluator")
	}

	for queryID, tokens := range documents {
		// One credential per query unless the query said otherwise.
		// CredentialQuery.Multiple defaults to false, and the claim
		// extraction that follows MERGES every token returned under a query
		// - so a wallet appending a second credential could overwrite the
		// first one's claims in the session even though the request never
		// permitted more than one. Each of them verifies; that is not the
		// question.
		if len(tokens) > 1 {
			// requestedQueryExact, not requestedQuery: permission to
			// return several credentials is a relaxation, and must not be
			// read off a query the single-query fallback guessed at.
			scope := c.oidcScopeFor(session, queryID)
			requested, ok := c.requestedQueryExact(session, session.ScopeQueryIDs, scope)
			if !ok || !requested.Multiple {
				return fmt.Errorf("the response carries %d credentials for one query, which the request did not permit; their claims would be merged", len(tokens))
			}
		}
		for _, token := range tokens {
			if err := c.verifyOneVC20ForOIDC(ctx, resolver, session, queryID, token); err != nil {
				return err
			}
		}
	}
	return nil
}

// sessionCouldAskForW3C reports whether any scope this session carries is
// CONFIGURED as a W3C format.
//
// Asked only when the request itself cannot be recovered, so it reads the
// configuration - the one description of the session still available. A
// deployment with no credential metadata to consult cannot tell, and this
// decides whether to fail closed, so it answers yes.
func (c *Client) sessionCouldAskForW3C(session *cache.AuthorizationContext) bool {
	if session == nil || c.cfg == nil || c.cfg.Common == nil || len(c.cfg.Common.CredentialMetadata) == 0 {
		return true
	}
	for _, scope := range c.credentialScopes(session, session.ScopeQueryIDs) {
		cm := c.cfg.Common.CredentialMetadata[scope]
		if cm != nil && openid4vp.IsW3CVCFormatIdentifier(cm.Format) {
			return true
		}
	}
	return false
}

// refuseAResponseThisPathCannotCheck rejects a direct-post response whose
// claims could not all be accounted for.
//
// Three refusals, all for the same reason: extractAndMapClaims runs straight
// after this and merges EVERY token in the response into the session. What
// this gate does not verify, nothing does.
//
//  1. The request cannot be recovered. createDCQLQuery builds one for every
//     session this flow creates, so a nil query means the persisted request
//     is gone - a replica that cannot read it, most plainly. Returning
//     success there bypassed the gate in exactly the failure mode it exists
//     for, since no scope could then be found to check a format against.
//
//  2. The response mixes a W3C document with something else. Only the W3C
//     half is verified here, so an SD-JWT or an mdoc riding alongside one
//     has its claims merged unverified - and the presence of a verified
//     credential is what makes that look safe.
//
//  3. A scope asking for a W3C format was not answered with a W3C document.
//     The format check on the other path runs per scope inside the dispatch
//     loop; this flow has no such loop, so the comparison has to be made
//     here or not at all. "Cannot tell" is not a reason to accept: the type
//     constraint that scope carries could never be applied to whatever did
//     arrive.
func (c *Client) refuseAResponseThisPathCannotCheck(session *cache.AuthorizationContext, documents, others map[string][]string) error {
	// sessionDCQL, not session.DCQLQuery: a request object may carry the
	// query the session does not, and requestedQuery resolves it that way
	// too. Reading only the session field left a template-driven request
	// with no format check at all.
	if c.sessionDCQL(session) == nil {
		// Fail closed where it matters, and ONLY there.
		//
		// A missing query is a normal cross-replica condition - the
		// persisted request is gone, or this process never had the request
		// object - and refusing every response for it turned a cache miss
		// into an outage for flows that need nothing from this path at all.
		// An SD-JWT-only OIDC response carries no W3C document and asks no
		// W3C scope; there is nothing here to check and nothing downstream
		// relying on this having checked it.
		//
		// Two things still force the refusal, and either alone is enough: a
		// W3C document actually arrived, or the session's scopes are
		// CONFIGURED as a W3C format and so could have asked for one. The
		// second is read from configuration rather than from the request,
		// because this is asked exactly when the request cannot be read.
		if len(documents) > 0 || c.sessionCouldAskForW3C(session) {
			return fmt.Errorf("the request this response answers is no longer available, so nothing in it can be checked against what was asked for")
		}
		return nil
	}

	// A query that asks for NOTHING tells this gate as little as a missing
	// one, and every check below is driven by the session's credential
	// scopes - of which there are none - so each passes vacuously and the
	// response is accepted whatever it carried.
	//
	// New sessions cannot reach this: UIInteraction refuses an empty
	// dcql_query. This covers the ones already persisted, and anything that
	// reaches the cache by another route. Refused outright rather than
	// under the nil case's carve-out, because an empty query is not the
	// normal cross-replica condition that carve-out exists for - no flow
	// legitimately asks for zero credentials and then reads the answer.
	if len(c.sessionDCQL(session).Credentials) == 0 {
		return fmt.Errorf("the request this response answers asks for no credential, so nothing in the response can be checked against it")
	}

	if len(documents) > 0 && len(others) > 0 {
		return fmt.Errorf("the response mixes W3C credentials with %d token(s) this path does not verify, whose claims would be merged unverified", countTokens(others))
	}

	credentialScopes := c.credentialScopes(session, session.ScopeQueryIDs)
	for _, scope := range credentialScopes {
		requested, ok := c.requestedQuery(session, session.ScopeQueryIDs, scope)
		if !ok {
			continue
		}
		isW3C := openid4vp.IsW3CVCFormatIdentifier(requested.Format)

		// Every credential scope has to be answered once ANY W3C document
		// is in the response, not only the W3C ones. A request for a W3C
		// credential and an SD-JWT, answered with the W3C half alone, has
		// no unverified token to refuse above - and the session then
		// completes with nothing for the scope that asked for the other
		// one. Refusing here is the only place that can see it, since
		// nothing downstream compares the response against the request.
		if !isW3C && len(documents) == 0 {
			continue
		}

		// A W3C format this stack cannot verify - jwt_vc_json is advertised
		// and deliberately not requestable - is refused by its own name
		// rather than as a missing document.
		if isW3C {
			if err := openid4vp.ValidateCredentialQuery(requested); err != nil {
				return fmt.Errorf("the query for scope %s cannot constrain a credential: %w", scope, err)
			}
		}
		if len(documents[queryIDForScopeIn(session.ScopeQueryIDs, scope)]) > 0 {
			continue
		}
		// A bare document answers a single-scope request.
		if len(documents[""]) > 0 && len(credentialScopes) == 1 {
			continue
		}
		return fmt.Errorf("scope %s was requested as %q but the response carries no W3C credential for it", scope, requested.Format)
	}
	return nil
}

func countTokens(tokens map[string][]string) int {
	total := 0
	for _, list := range tokens {
		total += len(list)
	}
	return total
}

func (c *Client) verifyOneVC20ForOIDC(ctx context.Context, resolver trust.KeyResolver, session *cache.AuthorizationContext, queryID, token string) error {
	scope := c.oidcScopeFor(session, queryID)

	// VerifyAndExtract verifies the FIRST embedded credential of a
	// presentation, while the claim extraction that follows merges every
	// one of them. A presentation carrying a valid first credential and an
	// unverified second would therefore have the second's subject claims
	// injected into the OIDC session.
	//
	// Refused rather than partially verified. Verifying each one needs the
	// handler to report per-credential results, which is a change to its
	// contract rather than to this guard - and a presentation answering one
	// credential query with several credentials is not a shape this flow
	// asks for.
	count, err := openid4vp.EmbeddedCredentialCount(token)
	if err != nil {
		return fmt.Errorf("cannot tell how many credentials this presentation carries: %w", err)
	}
	if count > 1 {
		return fmt.Errorf("presentation carries %d credentials; only the first is verified, so none of its claims can be trusted", count)
	}

	handler, err := c.vc20HandlerForOIDC(resolver, session, scope)
	if err != nil {
		return err
	}

	result, err := handler.VerifyAndExtract(ctx, token)
	if err != nil {
		return fmt.Errorf("W3C VC verification failed: %w", err)
	}

	// Resolving the issuer's key says who signed it, not whether we trust
	// them.
	if result.IssuerKey == nil {
		return fmt.Errorf("W3C verification produced no issuer key to evaluate")
	}
	decision, err := c.trustEvaluator.Evaluate(ctx, &trust.EvaluationRequest{
		SubjectID:      result.Issuer,
		KeyType:        trust.KeyTypeJWK,
		Key:            result.IssuerKey,
		Role:           trust.RoleCredentialIssuer,
		CredentialType: scope,
	})
	if err != nil {
		return fmt.Errorf("W3C issuer trust evaluation failed: %w", err)
	}
	if !decision.Trusted {
		return fmt.Errorf("W3C issuer not trusted: %s", decision.Reason)
	}

	return c.checkVC20AnswersTheRequest(session, scope, result.TypeIRIs)
}

// vc20HandlerForOIDC builds the handler for one returned document, with the
// binding this session and this scope actually call for.
//
// The nonce is the REQUEST OBJECT's, not session.Nonce. session.Nonce is the
// client's optional OIDC nonce - it may be empty, and it is not what the
// wallet was asked to put in the proof. GetOIDCRequestObject generates the
// challenge and stores it as RequestObjectNonce, and that is what a holder
// proof binds to; binding against the other one rejected every valid
// presentation.
//
// The domain is the client id the request object carried - the verifier's
// own identifier - not session.ClientID, which is the relying party's OAuth
// client id.
//
// Holder binding follows the scope's own query, the way the UI path does,
// so a query that explicitly sets require_cryptographic_holder_binding to
// false is honoured here too. A scope whose query cannot be recovered fails
// closed: binding is REQUIRED, which is the OpenID4VP default.
func (c *Client) vc20HandlerForOIDC(resolver trust.KeyResolver, session *cache.AuthorizationContext, scope string) (*openid4vp.VC20Handler, error) {
	opts := []openid4vp.VC20HandlerOption{openid4vp.WithVC20KeyResolver(resolver)}

	// requestedQueryExact, not requestedQuery. Turning binding OFF is a
	// relaxation, so the query has to be one this scope actually names -
	// the single-query fallback would otherwise hand a scope nobody mapped
	// the settings of whichever query happened to be the only one, and
	// this guard is meant to fail closed.
	requireBinding := true
	if requested, ok := c.requestedQueryExact(session, session.ScopeQueryIDs, scope); ok {
		requireBinding = requested.RequiresCryptographicHolderBinding()
	}

	if requireBinding {
		verifierClientID, err := c.cfg.Verifier.VerifierClientID(c.pkiSigningCert)
		if err != nil {
			return nil, fmt.Errorf("cannot determine this verifier's client id to bind against: %w", err)
		}
		if session.RequestObjectNonce == "" {
			return nil, fmt.Errorf("holder binding is required but this session has no request-object nonce to bind to")
		}
		opts = append(opts, openid4vp.WithVC20PresentationBinding(session.RequestObjectNonce, verifierClientID))
	}

	handler, err := openid4vp.NewVC20Handler(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create W3C VC handler: %w", err)
	}
	return handler, nil
}

// checkVC20AnswersTheRequest enforces, on what came back, the constraint the
// request carried.
//
// The session persists both the DCQL query and the scope-to-query mapping,
// so this path has the same constraint the UI path applies - without it the
// wallet chooses which credential answers a scope and meta.type_values is
// decoration.
//
// Fail closed throughout: a scope that cannot be named, or a query that
// cannot be recovered, is refused rather than accepted unconstrained.
func (c *Client) checkVC20AnswersTheRequest(session *cache.AuthorizationContext, scope string, typeIRIs []string) error {
	if scope == "" {
		return fmt.Errorf("cannot tell which scope this credential answers, so its type constraint cannot be checked")
	}
	requested, ok := c.requestedQuery(session, session.ScopeQueryIDs, scope)
	if !ok {
		return fmt.Errorf("the request for scope %s is no longer available, so the returned credential cannot be checked against it", scope)
	}

	// The query has to be ASKING for a W3C credential. MatchTypeValues is
	// satisfied by an empty TypeValues, and an mdoc or SD-JWT query has
	// none - so without this a signed W3C credential answers a query that
	// asked for something else entirely and its claims are accepted.
	if !openid4vp.IsW3CVCFormatIdentifier(requested.Format) {
		return fmt.Errorf("scope %s was requested as %q, so a W3C credential does not answer it", scope, requested.Format)
	}
	if err := openid4vp.ValidateCredentialQuery(requested); err != nil {
		return fmt.Errorf("the query for scope %s cannot constrain a credential: %w", scope, err)
	}
	if !openid4vp.MatchTypeValues(typeIRIs, requested.Meta.TypeValues) {
		return fmt.Errorf("the credential returned for scope %s does not have a type the request asked for", scope)
	}
	return nil
}

// oidcScopeFor names the scope a returned document answers.
//
// A DCQL response keys by credential query id, so the scope is whichever one
// maps to it. A bare document carries no key, and is only unambiguous when
// the request asked for exactly one credential scope - otherwise this
// returns "" and the caller refuses rather than guessing which constraint
// applies.
func (c *Client) oidcScopeFor(session *cache.AuthorizationContext, queryID string) string {
	credentialScopes := c.credentialScopes(session, session.ScopeQueryIDs)
	if queryID == "" {
		if len(credentialScopes) == 1 {
			return credentialScopes[0]
		}
		return ""
	}
	for _, scope := range credentialScopes {
		if queryIDForScopeIn(session.ScopeQueryIDs, scope) == queryID {
			return scope
		}
	}
	// The key is a query id the request does not carry, or names no scope.
	if slices.Contains(credentialScopes, queryID) {
		return queryID
	}
	return ""
}
