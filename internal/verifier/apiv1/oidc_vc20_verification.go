package apiv1

import (
	"context"
	"fmt"
	"strings"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/trust"
)

// verifyVC20ForOIDC verifies a W3C VC 2.0 presentation arriving on the OIDC
// direct-post path, before any claim in it is read.
//
// ProcessDirectPost extracts claims without verifying anything, for any
// format - a gap of its own, older and wider than W3C. That is not a licence
// to add another unverified format: making a W3C response usable here means
// an arbitrary JSON-LD document would otherwise have its credentialSubject
// mapped into an OIDC session, with nothing checking who signed it or
// whether the holder was present.
//
// So W3C is verified here even though its neighbours are not. Same machinery
// the UI direct-post path uses: the trust evaluator resolves the
// verification method, VC20Handler checks the Data Integrity proof, and the
// key the signature VERIFIED with goes back to the evaluator - resolving
// again could answer differently and then the key trusted is not the key
// that signed.
//
// HOLDER BINDING IS ALWAYS REQUIRED here, unlike the UI path where the DCQL
// query may say otherwise. This flow has no query to ask, and the OpenID4VP
// default is to require it; "no query" must not become "no binding".
//
// What this cannot do is the type constraint. That lives in the DCQL query
// the request carried, and the OIDC flow has none - so a verified credential
// of some other W3C type still answers the scope here. The scopes are
// advertised through the same builder on both paths, so that is worth
// knowing rather than assuming; it needs the OIDC flow to carry a query,
// which is a larger change than verification.
func (c *Client) verifyVC20ForOIDC(ctx context.Context, session *cache.AuthorizationContext, vpToken string) error {
	if session == nil {
		return fmt.Errorf("no session to verify a W3C presentation against")
	}

	resolver, ok := c.trustEvaluator.(trust.KeyResolver)
	if !ok {
		return fmt.Errorf("W3C verification needs a key-resolving trust evaluator")
	}

	handler, err := openid4vp.NewVC20Handler(
		openid4vp.WithVC20KeyResolver(resolver),
		openid4vp.WithVC20PresentationBinding(session.Nonce, session.ClientID),
	)
	if err != nil {
		return fmt.Errorf("failed to create W3C VC handler: %w", err)
	}

	result, err := handler.VerifyAndExtract(ctx, vpToken)
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
		CredentialType: strings.Join(session.Scopes, " "),
	})
	if err != nil {
		return fmt.Errorf("W3C issuer trust evaluation failed: %w", err)
	}
	if !decision.Trusted {
		return fmt.Errorf("W3C issuer not trusted: %s", decision.Reason)
	}
	return nil
}
