package apiv1

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/SUNET/vc/internal/verifier/cache"
	"github.com/SUNET/vc/pkg/nymauth/verifier"
	"github.com/SUNET/vc/pkg/openid4vp"
)

// ErrCircuitZkNotBuilt is what every build without the "zknative" tag
// returns for a circuit_zk presentation.
//
// A refusal and not a pass. Everything upstream - the request's own
// checks, the response's shape, its binding to the offer - is real and
// has already run by the time this is reached, so returning nil would
// hand all of that back as a verified proof that nothing looked at.
var ErrCircuitZkNotBuilt = errors.New("circuit_zk: this verifier was built without the zknative tag, so no nym_auth proof can be checked")

// circuitZkSession is everything the verification needs that comes
// from THIS VERIFIER's own session, resolved before any part of the
// response is read.
//
// Gathered into one value so that the native half receives no raw
// response bytes at all beyond the proof and the claimed pseudonym:
// every public input it passes to the circuit is one of these.
type circuitZkSession struct {
	// Transcript is the SessionTranscript the proof is bound to.
	Transcript []byte
	// DocType is the credential type the challenge binds to.
	DocType string
	// VerifierInput is SHA-256 of the configured BARE verifier_id.
	VerifierInput [32]byte

	// Now is T, the timestamp bound into the proof's public inputs.
	//
	// NOT a free-running clock reading, despite the name. The circuit
	// binds all 20 bytes of YYYY-MM-DDThh:mm:ssZ bit by bit
	// (hash_public_base in zk-cred-longfellow's src/nymauth/mod.rs),
	// so the prover and this verifier must use the SAME second or the
	// public inputs differ and the proof cannot verify.
	Now time.Time

	// NowSource records where Now came from, for the log line.
	NowSource string
}

// proofTimeSource names T's origin in a log line. There is one: the
// prover supplies it in the presentation.
const proofTimeSource = "presentation proof_time"

// circuitZkProofTime takes T from the presentation and checks it
// against this verifier's clock.
//
// T is the PROVER'S, per rulebook v0.4. That is not a weakening: the
// circuit binds all 20 bytes of T into its public inputs, so prover
// and verifier must use the same second, and only the prover knows
// which second it proved at. What makes a prover-supplied value safe
// is the window - without one a holder could replay a proof made long
// ago, against a credential since revoked, or one made with a clock
// set forward.
//
// REFUSED rather than clamped. Clamping would verify against a T the
// prover did not use, which cannot succeed and would then report the
// wrong reason for the failure.
func (c *Client) circuitZkProofTime(presentation openid4vp.ZkpPresentation, now time.Time) (time.Time, error) {
	if !presentation.HasProofTime {
		// Unreachable for mso_mdoc, which the response validator
		// makes it required for. Kept because a proof checked against
		// a guessed T is not checked.
		return time.Time{}, errors.New("zkp_req: the presentation carries no proof_time, so there is no T to verify against")
	}
	skew, maxAge := c.circuitZkTolerance()
	if err := openid4vp.CheckProofTimeTolerance(presentation.ProofTime, now, skew, maxAge); err != nil {
		return time.Time{}, fmt.Errorf("zkp_req: %w", err)
	}
	return presentation.ProofTime, nil
}

// circuitZkTolerance is the configured window, or the shared
// recommendation when a deployment has not chosen.
//
// The recommendation rather than something invented here: a verifier
// that has not thought about it should behave the way every other
// implementation assumes it does.
func (c *Client) circuitZkTolerance() (skew, maxAge time.Duration) {
	skew, maxAge = openid4vp.RecommendedSkew, openid4vp.RecommendedMaxAge
	if c.cfg == nil || c.cfg.Verifier == nil {
		return skew, maxAge
	}
	if configured := c.cfg.Verifier.NymAuth.ProofTimeSkewSeconds; configured > 0 {
		skew = time.Duration(configured) * time.Second
	}
	if configured := c.cfg.Verifier.NymAuth.ProofTimeMaxAgeSeconds; configured > 0 {
		maxAge = time.Duration(configured) * time.Second
	}
	return skew, maxAge
}

// circuitZkRequestFor builds the response-side request from the
// verifier's own DCQL query and its own offered formats.
//
// The offered circuit ids and proof systems come from
// verifier.preferred_vp_formats.circuit_zk - the verifier's
// configuration - and not from anything in the response. A request
// that offered neither list offered nothing, and
// ValidateCircuitZkResponse then refuses every response, which is the
// intended reading: a circuit this verifier never named is not one it
// can decide it trusts after seeing a proof from it.
func (c *Client) circuitZkRequestFor(query openid4vp.CredentialQuery) openid4vp.ZkpReqRequest {
	request := openid4vp.ZkpReqRequest{
		QueryID:  query.ID,
		Items:    query.Req,
		Multiple: query.AllowsMultiple(),
		// From the REQUEST's own meta: proof_time is required for
		// mso_mdoc, because every approved circuit there checks the
		// MSO validity period.
		SourceFormat: query.Meta.SourceFormat,
	}
	if formats := c.cfg.Verifier.PreferredVPFormats; formats != nil && formats.ZkpReq != nil {
		request.OfferedSystemIDs = formats.ZkpReq.SystemIDValues
	}
	return request
}

// circuitZkRawToken returns the whole vp_token ENVELOPE, as it
// arrived, having checked that it carries an entry for this query.
//
// The envelope and not the entry, because the validator checks the
// envelope too - its shape, and a repeated query id - and handing it
// one entry would drop those checks and give it an array where it
// expects a map.
//
// Raw, because the validation has to run on the text: a repeated
// member or a repeated result handle cannot be seen after decoding,
// since Go keeps the last of a repeated key and discards the other
// without a word.
func circuitZkRawToken(vpResponse openid4vp.VPResponse, queryID string) (json.RawMessage, error) {
	if entry, found := vpResponse.VPTokenRaw[queryID]; !found || len(entry) == 0 {
		return nil, fmt.Errorf("circuit_zk: the response carries no presentation for credential query %q", queryID)
	}
	if len(vpResponse.VPTokenEnvelope) == 0 {
		return nil, fmt.Errorf("circuit_zk: the response carries no vp_token to validate")
	}
	return vpResponse.VPTokenEnvelope, nil
}

// circuitZkChannel names how a presentation reached this verifier.
//
// The channel decides the SessionTranscript, and the transcript is
// what the proof is bound to - so this is not a detail. A wallet only
// ever built one of them, and verifying against the other produces an
// opaque proof failure rather than a legible wiring error (the same
// trap as SUNET/vc#652 and #655 on the mdoc ZK path).
type circuitZkChannel string

const (
	// channelDCAPI is a response returned inside a
	// navigator.credentials.get call.
	channelDCAPI circuitZkChannel = "dc_api"
	// channelOpenID4VP is a response POSTed to response_uri by a
	// wallet reached through request_uri - a scanned QR, typically.
	channelOpenID4VP circuitZkChannel = "openid4vp"
)

// circuitZkTranscriptBuilder builds the SessionTranscript for one
// channel.
type circuitZkTranscriptBuilder func(origin, clientID, nonce, responseURI string, readerThumbprint []byte) ([]byte, error)

// circuitZkTranscripts is the per-channel transcript builder, and a
// deliberately extensible one.
//
// Only the DC API handover is here TODAY, because the nym_auth
// circuits define only that one: SPEC section 3, and the shared
// challenge vectors cover it alone. Link-delivered (QR) presentations
// are wanted and are coming - the OpenID4VPHandover variant is pending
// a SPEC patch and shared vectors for it, which is circuit-authoring
// work rather than something this verifier can settle by building a
// transcript of its own and hoping a prover agrees.
//
// When those vectors exist, adding the channel is adding an entry
// here. Nothing else in this file knows which channels exist.
var circuitZkTranscripts = map[circuitZkChannel]circuitZkTranscriptBuilder{
	channelDCAPI: func(origin, _, nonce, _ string, readerThumbprint []byte) ([]byte, error) {
		return verifier.MdocSessionTranscript(origin, nonce, readerThumbprint)
	},
}

// circuitZkChannelFor names the channel a response arrived through.
func circuitZkChannelFor(dcAPI bool) circuitZkChannel {
	if dcAPI {
		return channelDCAPI
	}
	return channelOpenID4VP
}

// circuitZkSessionFor resolves the verifier's own inputs.
//
// A channel with no transcript builder is refused, which is the
// fail-closed half of the table above: verifying it would mean
// constructing a transcript nothing signed, and reporting the
// inevitable mismatch as a bad proof rather than as the wrong channel.
func (c *Client) circuitZkSessionFor(authCtx *cache.AuthorizationContext, channel circuitZkChannel, origin, clientID, nonce, responseURI, docType string, readerThumbprint []byte) (circuitZkSession, error) {
	build, supported := circuitZkTranscripts[channel]
	if !supported {
		return circuitZkSession{}, fmt.Errorf("circuit_zk: this presentation arrived over the %q channel, and the nym_auth "+
			"circuits define a session transcript only for %q; the handover for this channel is pending shared vectors",
			channel, channelDCAPI)
	}

	transcript, err := build(origin, clientID, nonce, responseURI, readerThumbprint)
	if err != nil {
		return circuitZkSession{}, fmt.Errorf("circuit_zk: %w", err)
	}

	verifierInput, err := verifier.VerifierInput(c.cfg.Verifier.NymAuth.VerifierID)
	if err != nil {
		return circuitZkSession{}, fmt.Errorf("circuit_zk: verifier.nym_auth.verifier_id: %w", err)
	}

	// Now is deliberately NOT set here. T is the prover's, carried in
	// each presentation, so it belongs to the presentation and not to
	// the session - a response may legally carry several, and one
	// session-wide T would be the first presentation's imposed on the
	// rest.
	return circuitZkSession{
		Transcript:    transcript,
		DocType:       docType,
		VerifierInput: verifierInput,
	}, nil
}

// circuitZkVerifierRequest assembles the request a circuit is checked
// against, from the session and the verifier's own policy.
//
// issuerKey comes from the resolved and trusted issuer chain. Every
// other field is the verifier's. Request.Check refuses anything taken
// from the response, which is most of why it exists.
func circuitZkVerifierRequest(session circuitZkSession, issuerKey *ecdsa.PublicKey, items []openid4vp.ReqItem) (verifier.Request, error) {
	if issuerKey == nil {
		return verifier.Request{}, errors.New("circuit_zk: no issuer key resolved for this presentation")
	}

	inputs := make([]verifier.CircuitInput, 0, len(items))
	for _, item := range items {
		if item.FnID != verifier.FunctionAgeCheck {
			// Only the predicates this build can map. A pseudonym
			// function contributes no circuit input of its own - it
			// names the configuration, which selects the build.
			continue
		}
		bounds, err := circuitZkAgeBounds(item)
		if err != nil {
			return verifier.Request{}, err
		}
		inputs = append(inputs, bounds.CircuitInput())
	}

	return verifier.Request{
		IssuerKey:          issuerKey,
		Now:                session.Now,
		Inputs:             inputs,
		SupportedFunctions: []string{verifier.FunctionAgeCheck},
		SessionTranscript:  session.Transcript,
		DocType:            session.DocType,
		VerifierInput:      session.VerifierInput,
	}, nil
}

// circuitZkAgeBounds maps an age_check req item's parameters to the
// circuits' inclusive bounds.
//
// From the REQUEST's own parameters, which this verifier sent. Taking
// them from the response would be verifying a statement the holder
// chose.
func circuitZkAgeBounds(item openid4vp.ReqItem) (verifier.AgeBounds, error) {
	check := verifier.AgeCheck{}
	for name, target := range map[string]*string{
		"ge": &check.GE,
		"gt": &check.GT,
		"le": &check.LE,
		"lt": &check.LT,
	} {
		value, present := item.Params[name]
		if !present {
			continue
		}
		text, ok := value.(string)
		if !ok {
			return verifier.AgeBounds{}, fmt.Errorf("circuit_zk: the %q parameter of %q is not a string", name, item.Return)
		}
		*target = text
	}
	return check.Bounds()
}
