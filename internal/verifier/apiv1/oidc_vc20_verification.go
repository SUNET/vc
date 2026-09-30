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
	documents := openid4vp.W3CDocumentsIn(vpToken)
	if len(documents) == 0 {
		return nil
	}

	resolver, ok := c.trustEvaluator.(trust.KeyResolver)
	if !ok {
		return fmt.Errorf("W3C verification needs a key-resolving trust evaluator")
	}

	// The domain a holder proof binds to is the client id the REQUEST
	// OBJECT carried, which is the verifier's own identifier - not
	// session.ClientID, which is the OAuth client id of the relying party
	// that started the flow. Binding against the wrong one rejects every
	// valid presentation whenever the two differ.
	verifierClientID, err := c.cfg.Verifier.VerifierClientID(c.pkiSigningCert)
	if err != nil {
		return fmt.Errorf("cannot determine this verifier's client id to bind against: %w", err)
	}

	// HOLDER BINDING IS ALWAYS REQUIRED. The UI path lets the DCQL query
	// say otherwise; this one has no per-credential answer to consult for a
	// bare document, and the OpenID4VP default is to require it, so "cannot
	// tell" must not become "not required".
	handler, err := openid4vp.NewVC20Handler(
		openid4vp.WithVC20KeyResolver(resolver),
		openid4vp.WithVC20PresentationBinding(session.Nonce, verifierClientID),
	)
	if err != nil {
		return fmt.Errorf("failed to create W3C VC handler: %w", err)
	}

	for queryID, tokens := range documents {
		for _, token := range tokens {
			if err := c.verifyOneVC20ForOIDC(ctx, handler, session, queryID, token); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Client) verifyOneVC20ForOIDC(ctx context.Context, handler *openid4vp.VC20Handler, session *cache.AuthorizationContext, queryID, token string) error {
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

	result, err := handler.VerifyAndExtract(ctx, token)
	if err != nil {
		return fmt.Errorf("W3C VC verification failed: %w", err)
	}

	// Resolving the issuer's key says who signed it, not whether we trust
	// them.
	if result.IssuerKey == nil {
		return fmt.Errorf("W3C verification produced no issuer key to evaluate")
	}
	scope := c.oidcScopeFor(session, queryID)
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
