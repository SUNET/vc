//go:build zknative

package apiv1

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"sync"

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
	presentation openid4vp.CircuitZkPresentation,
	session circuitZkSession,
	items []openid4vp.ReqItem,
	issuerKey any,
) (map[string][]byte, error) {
	key, ok := issuerKey.(*ecdsa.PublicKey)
	if !ok || key == nil {
		return nil, fmt.Errorf("circuit_zk: no issuer key resolved for this presentation")
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
	// Counted rather than special-cased on item.ID, because the
	// invariant is "something was checked", not "a pseudonym was
	// asked for" - a function added later that this loop skips would
	// otherwise reopen exactly this hole, silently.
	checked := 0
	verified := map[string][]byte{}
	for _, item := range items {
		if item.ID != openid4vp.CircuitZkFunctionPseudonym {
			continue
		}
		claimed, present := presentation.Pseudonyms[item.Return]
		if !present {
			// Unreachable after validation, which requires exactly
			// the request's handles - and checked anyway, because
			// the alternative is verifying against a zero pseudonym.
			return nil, fmt.Errorf("circuit_zk: no pseudonym for handle %q", item.Return)
		}

		config, err := circuitZkConfigOf(item)
		if err != nil {
			return nil, err
		}
		native, err := c.circuitZkVerifier(ctx, config)
		if err != nil {
			return nil, err
		}

		var claimedArray [32]byte
		copy(claimedArray[:], claimed)
		pseudonym, err := native.Verify(request, claimedArray, presentation.Proof)
		if err != nil {
			return nil, fmt.Errorf("circuit_zk: handle %q: %w", item.Return, err)
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
		return nil, fmt.Errorf("circuit_zk: this request asks only for predicates, and the proof is checked by verifying a pseudonym; "+
			"a predicate-only request has no verification path in this build, so its %d result(s) cannot be accepted", len(items))
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
		return "", fmt.Errorf("circuit_zk: the %q request item names no pseudonym configuration", item.Return)
	}
	config, ok := value.(string)
	if !ok || config == "" {
		return "", fmt.Errorf("circuit_zk: the %q request item's configuration is not a string", item.Return)
	}
	return config, nil
}

// circuitZkVerifier returns a loaded verifier for a configuration,
// loading it once.
//
// Loading is the expensive step - about 0.15 s and a megabyte of
// artifact - and the handle holds no interior mutability, so one per
// configuration is reused across presentations and goroutines.
func (c *Client) circuitZkVerifier(ctx context.Context, config string) (*verifier.NativeVerifier, error) {
	c.nymAuthMu.Lock()
	defer c.nymAuthMu.Unlock()

	if loaded, ok := c.nymAuthVerifiers[config]; ok {
		return loaded, nil
	}
	if c.nymAuthCircuits == nil {
		return nil, fmt.Errorf("circuit_zk: verifier.nym_auth is not enabled")
	}

	entry, err := c.nymAuthCircuits.Entry(config)
	if err != nil {
		return nil, err
	}
	artifact, err := c.nymAuthCircuits.Artifact(ctx, config)
	if err != nil {
		return nil, err
	}

	native, err := verifier.NewNativeVerifier(artifact, verifier.CircuitParams{
		BlockEncHash:  entry.BlockEncHash,
		BlockEncSig:   entry.BlockEncSig,
		HashCircuitID: entry.HashCircuitID,
		SigCircuitID:  entry.SigCircuitID,
	})
	if err != nil {
		return nil, fmt.Errorf("circuit_zk: loading the %q circuit: %w", config, err)
	}

	if c.nymAuthVerifiers == nil {
		c.nymAuthVerifiers = map[string]*verifier.NativeVerifier{}
	}
	c.nymAuthVerifiers[config] = native
	c.log.Info("Loaded a nym_auth circuit", "config", config,
		"hash_circuit_id", entry.HashCircuitID, "artifact_bytes", entry.Bytes)
	return native, nil
}

// Compile-time assertion that the allowlist type is the one the
// client holds, so the stub build and this one cannot drift.
var _ = (*circuits.Allowlist)(nil)

var _ sync.Locker = (*sync.Mutex)(nil)
