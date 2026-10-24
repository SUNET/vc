//go:build zknative

package apiv1

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"sync"

	"github.com/SUNET/vc/pkg/nymauth"
	"github.com/SUNET/vc/pkg/nymauth/circuits"
	"github.com/SUNET/vc/pkg/nymauth/verifier"
	"github.com/SUNET/vc/pkg/openid4vp"
)

// verifyCircuitZkPresentation checks one validated presentation's
// proof, and returns the pseudonyms the caller may act on.
//
// The returned map is the ONLY source of a verified pseudonym. The
// values in the presentation are what the holder sent; they become
// identifiers this verifier may use only once a proof has been
// checked against them, and that happens here.
//
// issuerKey must come from the resolved and trusted issuer chain.
// Everything else comes from session and items, which are this
// verifier's own - Request.Check refuses a request built any other
// way.
func (c *Client) verifyCircuitZkPresentation(
	ctx context.Context,
	presentation openid4vp.ZkpPresentation,
	session circuitZkSession,
	items []openid4vp.ReqItem,
	issuerKey any,
) (map[string][]byte, error) {
	key, ok := issuerKey.(*ecdsa.PublicKey)
	if !ok || key == nil {
		return nil, fmt.Errorf("zkp_req: no issuer key resolved for this presentation")
	}

	request, err := circuitZkVerifierRequest(session, key, items)
	if err != nil {
		return nil, err
	}

	// checked counts the items whose proof was ACTUALLY verified.
	//
	// The loop below calls the native verifier once per pseudonym
	// item and not at all for anything else, so a request carrying
	// only predicates - an age_check with no pseudonym - would run it
	// zero times and return an empty map and a nil error. The caller
	// reads nil as "verified" and caches the presentation's
	// "satisfied": true as a checked fact. It is not: in that path
	// nothing looked at the proof at all, so any base64url bytes
	// would do, and the predicate would be asserted by the holder and
	// believed by the verifier.
	//
	// Counted rather than special-cased on item.FnID, because the
	// invariant is "something was checked", not "a pseudonym was
	// asked for" - a function added later that this loop skips would
	// otherwise reopen exactly this hole, silently.
	checked := 0
	verified := map[string][]byte{}
	for _, item := range items {
		if item.FnID != openid4vp.FunctionPseudonym {
			continue
		}
		claimed, present := presentation.Pseudonyms[item.Return]
		if !present {
			// Unreachable after validation, which requires exactly
			// the request's handles - and checked anyway, because
			// the alternative is verifying against a zero pseudonym.
			return nil, refuseZkpReq(CodeZkpReqNoPseudonym,
				fmt.Sprintf("no pseudonym for handle %q", item.Return), nil)
		}

		config, err := circuitZkConfigOf(item)
		if err != nil {
			return nil, err
		}
		backend, err := c.circuitZkVerifier(ctx, presentation.SystemID, config)
		if err != nil {
			return nil, err
		}

		var claimedArray [32]byte
		copy(claimedArray[:], claimed)
		pseudonym, err := backend.Verify(request, claimedArray, presentation.Proof)
		if err != nil {
			// The proof did not verify against the issuer key the key
			// set established. Which handle it was is the useful part
			// for a prover; WHY is deliberately not elaborated, since
			// the only honest answer is "the proof is not valid for
			// these public inputs".
			return nil, refuseZkpReq(CodeZkpReqProofDidNotVerify,
				fmt.Sprintf("the proof did not verify for handle %q", item.Return), err)
		}
		// The RETURNED value, never the claimed one.
		verified[item.Return] = pseudonym[:]
		checked++
	}

	if checked == 0 {
		// Fail closed. The proof is one proof over the whole request,
		// and the only way this build has to check it is a pseudonym
		// item's Verify - so with none, there is no verification to
		// do and no way to say the predicates hold.
		//
		// A predicate-only request is therefore one this verifier
		// must not send; refused here rather than only where requests
		// are built, because this is the point that cannot be
		// bypassed.
		return nil, refuseZkpReq(CodeZkpReqNothingChecked,
			fmt.Sprintf("this request asks only for predicates, and the proof is checked by verifying a pseudonym; "+
				"a predicate-only request has no verification path in this build, so its %d result(s) cannot be accepted", len(items)), nil)
	}
	return verified, nil
}

// circuitZkConfigOf reads the pseudonym configuration a req item asked
// for.
//
// From the REQUEST, which this verifier sent. The configuration
// selects the circuit build, and the build decides the pseudonym's
// domain separator - so taking it from the response would let the
// holder choose which pseudonym function it is measured by.
func circuitZkConfigOf(item openid4vp.ReqItem) (string, error) {
	value, present := item.Params["config"]
	if !present {
		return "", fmt.Errorf("zkp_req: the %q request item names no pseudonym configuration", item.Return)
	}
	config, ok := value.(string)
	if !ok || config == "" {
		return "", fmt.Errorf("zkp_req: the %q request item's configuration is not a string", item.Return)
	}
	return config, nil
}

// circuitZkVerifier returns a loaded verifier for a proof system and
// configuration, loading it once.
//
// Loading is the expensive step - about 0.15 s and a megabyte of
// artifact for Longfellow, and for Vega roughly 12.5 MB of verifier key
// derived from the shapes - and neither handle holds any interior
// mutability, so one per build is reused across presentations and
// goroutines.
//
// systemID is the system the PRESENTATION states, already checked
// against the ones this request offered. It selects the build beside
// the configuration, and the two together are what the allowlist is
// keyed by - a verifier may allow both Longfellow and Vega for one
// configuration, and they are different artifacts.
func (c *Client) circuitZkVerifier(ctx context.Context, systemID, config string) (verifier.Backend, error) {
	c.nymAuthMu.Lock()
	defer c.nymAuthMu.Unlock()

	key := nymAuthVerifierKey{systemID: systemID, config: config}
	if loaded, ok := c.nymAuthVerifiers[key]; ok {
		return loaded, nil
	}
	if c.nymAuthCircuits == nil {
		return nil, fmt.Errorf("zkp_req: verifier.nym_auth is not enabled")
	}

	entry, err := c.nymAuthCircuits.Entry(systemID, config)
	if err != nil {
		return nil, err
	}
	artifact, err := c.nymAuthCircuits.Artifact(ctx, systemID, config)
	if err != nil {
		return nil, err
	}

	backend, err := newNymAuthBackend(entry, artifact)
	if err != nil {
		return nil, fmt.Errorf("zkp_req: loading the %q %q circuit: %w", systemID, config, err)
	}

	if c.nymAuthVerifiers == nil {
		c.nymAuthVerifiers = map[nymAuthVerifierKey]verifier.Backend{}
	}
	c.nymAuthVerifiers[key] = backend
	c.log.Info("Loaded a nym_auth circuit", "system_id", systemID, "config", config,
		"artifact_bytes", entry.Bytes, "artifact_sha256", entry.SHA256)
	return backend, nil
}

// newNymAuthBackend builds the verifier that belongs to an allowed
// entry's proof system.
//
// The system decides what loading means, and the two are not alike.
// Longfellow loads a circuit artifact together with the four Ligero
// parameters the entry carries. Vega loads R1CS SHAPES and takes no
// parameters at all: it derives the verifier key from them, so the
// artifact digest the allowlist already pins is the circuit's whole
// identity, and there is nothing else for an entry to name. That is
// why pkg/nymauth/circuits REFUSES a Vega entry that carries Ligero
// parameters - they would be configuration nothing ever reads.
//
// Taken from the ENTRY rather than from the presented system_id. The
// two are equal here by construction, since the entry was looked up by
// that key, but the entry is the operator's statement about which
// library may open this artifact, and that is the right thing to
// dispatch on.
func newNymAuthBackend(entry circuits.Entry, artifact []byte) (verifier.Backend, error) {
	switch entry.SystemID {
	case nymauth.SystemLongfellowNymAuth:
		return verifier.NewNativeVerifier(artifact, verifier.CircuitParams{
			BlockEncHash:  entry.BlockEncHash,
			BlockEncSig:   entry.BlockEncSig,
			HashCircuitID: entry.HashCircuitID,
			SigCircuitID:  entry.SigCircuitID,
		})
	case nymauth.SystemVegaNymAuth:
		return verifier.NewVegaVerifier(artifact)
	default:
		// Unreachable: nymauth.CheckSystemID runs when the allowlist is
		// built, so an entry with any other system never reaches a
		// loaded Allowlist. Refused rather than left to fall through,
		// because the alternative to a backend is no verification.
		return nil, fmt.Errorf("no nym_auth verifier for proof system %q; this build knows %v",
			entry.SystemID, nymauth.Systems())
	}
}

// Compile-time assertion that the allowlist type is the one the
// client holds, so the stub build and this one cannot drift.
var _ = (*circuits.Allowlist)(nil)

var _ sync.Locker = (*sync.Mutex)(nil)
