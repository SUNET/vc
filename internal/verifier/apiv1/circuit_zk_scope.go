package apiv1

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"

	"github.com/SUNET/vc/internal/verifier/cache"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"
)

// verifyCircuitZkScope verifies one scope answered in the circuit_zk
// format, and returns it as a credential for the scope cache.
//
// It is a separate path from the format switch below rather than a
// case in it, for a concrete reason: every other format's
// presentation is a STRING, and the shared extraction takes
// vpTokens[0] accordingly. A circuit_zk presentation is an object, and
// its validation needs the raw bytes - a repeated member or handle
// cannot be seen after decoding. Routing it through the string path
// would mean re-encoding the object, and re-encoded bytes are exactly
// the ones a duplicate check can no longer see.
//
// The REQUEST decides that this path is taken, never the response:
// the DCQL credential query says the format is circuit_zk. A wallet
// does not get to choose which format answers a scope.
func (c *Client) verifyCircuitZkScope(
	ctx context.Context,
	authCtx *cache.AuthorizationContext,
	vpResponse openid4vp.VPResponse,
	scope string,
	query openid4vp.CredentialQuery,
	dcAPI bool,
	responseURI string,
	issuerKey *ecdsa.PublicKey,
) ([]sdjwtvc.CredentialCache, error) {
	if c.nymAuthCircuits == nil {
		// Advertised as a circuit_zk verifier by its own request and
		// unable to check one. Refused rather than passed, because
		// everything upstream is real and returning no error would
		// hand it back as a verified presentation.
		return nil, fmt.Errorf("scope %s was requested as circuit_zk but verifier.nym_auth is not enabled", scope)
	}

	raw, err := circuitZkRawToken(vpResponse, query.ID)
	if err != nil {
		c.log.Error(err, "no circuit_zk presentation for scope", "scope", scope, "query_id", query.ID)
		return nil, err
	}

	// Shape, and binding to what THIS request offered. Nothing here
	// is a verified fact yet; a pseudonym is the holder's claim.
	presentations, err := openid4vp.ValidateCircuitZkResponse(raw, c.circuitZkRequestFor(query))
	if err != nil {
		c.log.Error(err, "circuit_zk presentation refused", "scope", scope, "query_id", query.ID)
		return nil, fmt.Errorf("scope %s: %w", scope, err)
	}

	thumbprint, err := c.readerKeyThumbprint(ctx, authCtx, scope)
	if err != nil {
		return nil, err
	}
	origin := ""
	if dcAPI {
		if origin, err = c.dcAPIOrigin(); err != nil {
			c.log.Error(err, "cannot determine the DC API origin for the circuit_zk session transcript", "scope", scope)
			return nil, err
		}
	}

	session, err := c.circuitZkSessionFor(circuitZkChannelFor(dcAPI), origin, authCtx.ClientID, authCtx.Nonce,
		responseURI, query.Meta.DoctypeValue, thumbprint)
	if err != nil {
		c.log.Error(err, "cannot build the circuit_zk session transcript", "scope", scope, "dc_api", dcAPI)
		return nil, fmt.Errorf("scope %s: %w", scope, err)
	}

	if issuerKey == nil {
		// NOT YET RESOLVED, and refused rather than attempted.
		//
		// Q - the key the credential was signed with - is a public
		// input to the circuit, and it has to come from the issuer
		// chain this verifier resolved and trusted. For every other
		// format the presentation carries the chain; a circuit_zk
		// presentation carries no credential at all, so there is
		// nothing in it to resolve, and taking a key named by the
		// response would let the holder choose which issuer it is
		// measured against.
		//
		// Resolving it by docType through the trust evaluator is the
		// shape that fits - trust and resolution live in go-trust,
		// not here - but which keys a docType resolves to, and what
		// happens when it resolves to several, is a decision that has
		// not been taken. Until it is, this refuses: a verifier that
		// guessed would be reporting a proof as checked against an
		// issuer nobody chose.
		return nil, fmt.Errorf("scope %s: no trusted issuer key is resolved for circuit_zk presentations yet; "+
			"the circuit takes the issuer key as a public input and this verifier has no way to obtain it for %q",
			scope, session.DocType)
	}

	credentials := make([]sdjwtvc.CredentialCache, 0, len(presentations))
	for _, presentation := range presentations {
		verified, err := c.verifyCircuitZkPresentation(ctx, presentation, session, query.Req, issuerKey)
		if err != nil {
			c.log.Error(err, "circuit_zk proof verification failed", "scope", scope,
				"circuit_id", presentation.CircuitID, "proof_system", presentation.ProofSystem)
			return nil, fmt.Errorf("scope %s: %w", scope, err)
		}
		credentials = append(credentials, circuitZkCredential(scope, presentation, verified))
	}

	c.log.Info("circuit_zk presentation verified", "scope", scope,
		"presentations", len(presentations), "doc_type", session.DocType)
	return credentials, nil
}

// circuitZkCredential renders a verified presentation as claims.
//
// Only the pseudonyms the native verifier RETURNED, keyed by the
// handle the request chose, plus the handles whose predicate the
// proof asserts. The claimed values from the response are not here:
// they were the input to the check and mean nothing on their own.
//
// base64url because a pseudonym is 32 opaque bytes and every other
// binary value we publish is spelled that way.
func circuitZkCredential(scope string, presentation openid4vp.CircuitZkPresentation, verified map[string][]byte) sdjwtvc.CredentialCache {
	claims := map[string]any{
		"circuit_id":   presentation.CircuitID,
		"proof_system": presentation.ProofSystem,
	}
	for handle, pseudonym := range verified {
		claims[handle] = base64.RawURLEncoding.EncodeToString(pseudonym)
	}
	for _, handle := range presentation.Satisfied {
		claims[handle] = true
	}
	return sdjwtvc.CredentialCache{
		Scope:      scope,
		Credential: claims,
		Claims:     mapToDisclosers(claims),
	}
}
