package apiv1

import (
	"context"
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

	candidates, err := c.circuitZkIssuerCandidates(ctx, session.DocType, nil)
	if err != nil {
		c.log.Error(err, "cannot resolve a trusted issuer key for circuit_zk", "scope", scope, "doc_type", session.DocType)
		return nil, fmt.Errorf("scope %s: %w", scope, err)
	}

	credentials := make([]sdjwtvc.CredentialCache, 0, len(presentations))
	for _, presentation := range presentations {
		// Each candidate in turn, accepting the FIRST that verifies.
		//
		// A proof is checked against one key; the verifier does not
		// know which of its trusted issuers signed the credential,
		// because the presentation carries nothing that says so. The
		// pseudonym published is the one returned by the verification
		// that succeeded, and never one from an attempt that did not.
		var verified map[string][]byte
		var lastErr error
		for _, candidate := range candidates {
			verified, lastErr = c.verifyCircuitZkPresentation(ctx, presentation, session, query.Req, candidate)
			if lastErr == nil {
				c.log.Info("circuit_zk proof verified", "scope", scope,
					"circuit_id", presentation.CircuitID, "issuer_key", issuerKeyThumbprint(candidate))
				break
			}
		}
		if lastErr != nil {
			// Reported against the whole candidate set, not against
			// the last one tried: "it did not verify against any key
			// we trust" is the true statement, and naming one key
			// would invite chasing the wrong issuer.
			c.log.Error(lastErr, "circuit_zk proof verified against no trusted issuer key", "scope", scope,
				"circuit_id", presentation.CircuitID, "candidates", len(candidates))
			return nil, fmt.Errorf("scope %s: the proof verified against none of the %d trusted issuer keys for %q: %w",
				scope, len(candidates), session.DocType, lastErr)
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
