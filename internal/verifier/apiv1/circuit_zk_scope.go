package apiv1

import (
	"context"
	"encoding/base64"
	"errors"
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
	presentations, err := openid4vp.ValidateZkpReqResponse(raw, c.circuitZkRequestFor(query))
	if err != nil {
		c.log.Error(err, "circuit_zk presentation refused", "scope", scope, "query_id", query.ID)
		return nil, fmt.Errorf("scope %s: %w", scope, err)
	}

	channel := circuitZkChannelFor(dcAPI)
	if err := checkCircuitZkResponseMode(channel, authCtx); err != nil {
		c.log.Error(err, "circuit_zk response mode refused", "scope", scope, "channel", channel)
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

	session, err := c.circuitZkSessionFor(authCtx, channel, origin, authCtx.ClientID, authCtx.Nonce,
		responseURI, query.Meta.DoctypeValue, thumbprint)
	if err != nil {
		c.log.Error(err, "cannot build the circuit_zk session transcript", "scope", scope, "dc_api", dcAPI)
		return nil, fmt.Errorf("scope %s: %w", scope, err)
	}

	// T and where it came from, before any proof is checked. A
	// time-binding mismatch is otherwise indistinguishable from a bad
	// proof, and this line is what tells the two apart in a log.
	c.log.Debug("circuit_zk proof time", "scope", scope,
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
			c.log.Error(err, "zkp_req proof_time refused", "scope", scope,
				"system_id", presentation.SystemID, "proof_time", presentation.ProofTimeText)
			return nil, fmt.Errorf("scope %s: %w", scope, err)
		}
		presentationSession := session
		presentationSession.Now = proofTime
		presentationSession.NowSource = proofTimeSource

		issuerKey, err := c.circuitZkIssuerKey(ctx, presentation, presentationSession.DocType, time.Now())
		if err != nil {
			c.log.Error(err, "no trusted issuer key for the circuit_zk presentation",
				"scope", scope, "doc_type", session.DocType, "system_id", presentation.SystemID)
			return nil, fmt.Errorf("scope %s: %w", scope, err)
		}

		verified, err := c.verifyCircuitZkPresentation(ctx, presentation, presentationSession, query.Req, issuerKey)
		if err != nil {
			c.log.Error(err, "circuit_zk proof did not verify", "scope", scope,
				"system_id", presentation.SystemID, "issuer_key", issuerKeyThumbprint(issuerKey),
				"t", session.Now.UTC().Format("2006-01-02T15:04:05Z"), "t_source", session.NowSource)
			return nil, fmt.Errorf("scope %s: the proof did not verify against the issuer key the key set established: %w",
				scope, err)
		}
		c.log.Info("circuit_zk proof verified", "scope", scope,
			"system_id", presentation.SystemID, "issuer_key", issuerKeyThumbprint(issuerKey))

		credentials = append(credentials, circuitZkCredential(scope, presentation, verified))
	}

	c.log.Info("circuit_zk presentation verified", "scope", scope,
		"presentations", len(presentations), "doc_type", session.DocType)
	return credentials, nil
}

// checkCircuitZkResponseMode refuses a redirect presentation whose
// response was not encrypted.
//
// Over a redirect the response travels to response_uri through
// whatever the holder's browser and network are, so nym_auth requires
// direct_post.jwt: the pseudonym is a stable identifier for a person
// across that verifier's sessions, and sending one in the clear hands
// it to anything on the path.
//
// The transcript builder refuses this too - its thumbprint is
// required, and an unencrypted response has none - but it refuses it
// as "the reader key thumbprint is 0 bytes", which reads as a
// plumbing failure rather than as the configuration mistake it is.
// Checked here so the message names the actual problem.
//
// The DC API channel is deliberately not checked: a response returned
// inside navigator.credentials.get never crosses the network, and its
// handover takes a null thumbprint for exactly that case.
//
// Drafted against nym_auth_rulebook#9, which is an UNMERGED draft -
// cited for where the reasoning is written down, not as text that
// must exist. The enforceable part of it is in the shared vectors: a
// null thumbprint is in rejects_redirect.
func checkCircuitZkResponseMode(channel circuitZkChannel, authCtx *cache.AuthorizationContext) error {
	if channel != channelOpenID4VP {
		return nil
	}
	if authCtx == nil {
		return errors.New("circuit_zk: no session for this presentation, so its response mode cannot be established")
	}
	if authCtx.ResponseMode != openid4vp.ResponseModeDirectPostJWT {
		return fmt.Errorf("circuit_zk: this presentation arrived by redirect with response_mode %q; nym_auth requires %q there, "+
			"because a pseudonym sent to response_uri in the clear is readable by anything on the path",
			authCtx.ResponseMode, openid4vp.ResponseModeDirectPostJWT)
	}
	return nil
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
		// system_id alone. A v0.4 presentation carries no proof
		// system and no circuit id: the system is named by system_id,
		// and the verifier's registry maps it to a proof system.
		"system_id": presentation.SystemID,
	}
	if presentation.HasProofTime {
		// The T the proof was checked against, as the prover spelled
		// it. Published because a consumer comparing two pseudonyms
		// may need to know how old each one's proof is.
		claims["proof_time"] = presentation.ProofTimeText
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
