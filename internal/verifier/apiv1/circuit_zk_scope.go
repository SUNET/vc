package apiv1

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

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
// zkpReqError renders what verifyCircuitZkScope returns for the HTTP
// layer, and logs it at the level it deserves.
//
// A REFUSAL is the wallet's business: a 4xx carrying a stable code, at
// WARN. Anything else is this verifier failing to do its job - a missing
// build tag, an absent trust evaluator, a circuit that will not load -
// and stays an unclassified 5xx at ERROR, because a wallet author told
// "your presentation is bad" would go looking for a defect that is not
// theirs.
//
// A shape refusal keeps the shared validator's own reason code rather
// than being renamed here, so the vocabulary a wallet sees is the one
// the matcher vectors publish.
func (c *Client) zkpReqError(scope string, what string, err error, fields ...any) error {
	refusal, isRefusal := zkpReqRefusalFrom(err)
	if !isRefusal {
		if shape, isShape := zkpReqShapeRefusal(err); isShape {
			refusal, isRefusal = shape, true
		}
	}
	if !isRefusal {
		c.log.Error(err, what, append([]any{"scope", scope}, fields...)...)
		return fmt.Errorf("scope %s: %w", scope, err)
	}
	c.log.Warn(what, append([]any{"scope", scope, "code", refusal.Code, "detail", refusal.Detail}, fields...)...)
	return refusal.HTTPError()
}

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
		return nil, fmt.Errorf("scope %s was requested as zkp_req but verifier.nym_auth is not enabled", scope)
	}

	raw, err := circuitZkRawToken(vpResponse, query.ID)
	if err != nil {
		return nil, c.zkpReqError(scope, "no zkp_req presentation for scope", err, "query_id", query.ID)
	}

	// Shape, and binding to what THIS request offered. Nothing here
	// is a verified fact yet; a pseudonym is the holder's claim.
	presentations, err := openid4vp.ValidateZkpReqResponse(raw, c.circuitZkRequestFor(query))
	if err != nil {
		return nil, c.zkpReqError(scope, "zkp_req presentation refused", err, "query_id", query.ID)
	}

	thumbprint, err := c.readerKeyThumbprint(ctx, authCtx, scope)
	if err != nil {
		return nil, err
	}
	origin := ""
	if dcAPI {
		if origin, err = c.dcAPIOrigin(); err != nil {
			c.log.Error(err, "cannot determine the DC API origin for the zkp_req session transcript", "scope", scope)
			return nil, err
		}
	}

	session, err := c.circuitZkSessionFor(authCtx, circuitZkChannelFor(dcAPI), origin, authCtx.ClientID, authCtx.Nonce,
		responseURI, query.Meta.DoctypeValue, thumbprint)
	if err != nil {
		return nil, c.zkpReqError(scope, "cannot build the zkp_req session transcript", err, "dc_api", dcAPI)
	}

	// T and where it came from, before any proof is checked. A
	// time-binding mismatch is otherwise indistinguishable from a bad
	// proof, and this line is what tells the two apart in a log.
	c.log.Debug("zkp_req proof time", "scope", scope,
		"t", session.Now.UTC().Format("2006-01-02T15:04:05Z"), "t_source", session.NowSource)

	credentials := make([]sdjwtvc.CredentialCache, 0, len(presentations))
	for _, presentation := range presentations {
		// Q comes from the presentation's own issuer chain, and the
		// chain is evaluated by the trust layer before the key is
		// looked at. The circuit proves the credential was signed by
		// Q; the PDP vouches that Q belongs to a trusted issuer.
		// See circuitZkIssuerKey for why neither half is enough.
		//
		// Per presentation, not once per response: a response may
		// carry presentations from different issuers, and verifying
		// the second against the first's key would be verifying it
		// against a key its issuer never held.
		//
		// session.DocType is the REQUEST's docType - the response
		// does not get to choose the trust policy it is judged under.
		// T first: it is the prover's, and a presentation whose T is
		// outside this verifier's window is refused before any work
		// is done on its behalf.
		proofTime, err := c.circuitZkProofTime(presentation, time.Now())
		if err != nil {
			return nil, c.zkpReqError(scope, "zkp_req proof_time refused", err,
				"system_id", presentation.SystemID, "proof_time", presentation.ProofTimeText)
		}
		presentationSession := session
		presentationSession.Now = proofTime
		presentationSession.NowSource = proofTimeSource

		issuerKey, err := c.circuitZkIssuerKey(ctx, presentation, presentationSession.DocType, time.Now())
		if err != nil {
			return nil, c.zkpReqError(scope, "no trusted issuer key for the zkp_req presentation", err,
				"doc_type", session.DocType, "system_id", presentation.SystemID)
		}

		verified, err := c.verifyCircuitZkPresentation(ctx, presentation, presentationSession, query.Req, issuerKey)
		if err != nil {
			return nil, c.zkpReqError(scope, "zkp_req proof did not verify", err,
				"system_id", presentation.SystemID, "issuer_key", issuerKeyThumbprint(issuerKey),
				"t", presentationSession.Now.UTC().Format("2006-01-02T15:04:05Z"), "t_source", presentationSession.NowSource)
		}
		c.log.Info("zkp_req proof verified", "scope", scope,
			"circuit_id", presentation.SystemID, "issuer_key", issuerKeyThumbprint(issuerKey))

		credentials = append(credentials, circuitZkCredential(scope, presentation, verified))
	}

	c.log.Info("zkp_req presentation verified", "scope", scope,
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
func circuitZkCredential(scope string, presentation openid4vp.ZkpPresentation, verified map[string][]byte) sdjwtvc.CredentialCache {
	claims := map[string]any{
		"circuit_id":   presentation.SystemID,
		"proof_system": presentation.SystemID,
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
