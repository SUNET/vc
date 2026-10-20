package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// CircuitZkIssuerKeys resolves the issuer public keys a circuit_zk
// proof may be verified against.
//
// Q - the key the credential was signed with - is a PUBLIC INPUT to
// the circuit, so the verifier has to know it before it can check
// anything. Every other format carries the issuer's chain in the
// presentation; a circuit_zk presentation carries no credential at
// all, so there is nothing in it to resolve.
//
// It therefore comes from the trust layer and never from the
// response, and the response has no member for it. A key the holder
// named would let the holder choose which issuer it is measured
// against, which is the whole property a pseudonym scheme rests on.
//
// An interface because the resolution itself belongs in go-trust, not
// here, and because what go-trust can answer today is not this
// question - see the default below.
type CircuitZkIssuerKeys interface {
	// TrustedIssuerKeys returns the keys this verifier trusts to have
	// signed a credential of this docType, for this request.
	//
	// issuers, when non-empty, is the issuer set the request named,
	// and narrows the answer. An empty result is not an error: it
	// means nothing is trusted, and the caller refuses.
	TrustedIssuerKeys(ctx context.Context, docType string, issuers []string) ([]*ecdsa.PublicKey, error)
}

// ErrNoIssuerKeyResolver is the default answer: refuse.
var ErrNoIssuerKeyResolver = errors.New("circuit_zk: no trusted issuer key resolver is configured")

// refusingIssuerKeys is the resolver a verifier has until one is
// wired, and it refuses.
//
// Fail closed, and deliberately not "no keys, carry on": a verifier
// with no way to learn Q cannot check a proof, and the two failures
// an empty answer could be confused with - "nothing is trusted for
// this docType" and "this build cannot answer the question" - want
// different things done about them.
type refusingIssuerKeys struct{}

func (refusingIssuerKeys) TrustedIssuerKeys(context.Context, string, []string) ([]*ecdsa.PublicKey, error) {
	return nil, ErrNoIssuerKeyResolver
}

// DefaultMaxIssuerKeyCandidates bounds how many keys a proof may be
// tried against.
//
// Verification is the expensive step, and the candidate set comes
// from outside this process, so an unbounded one is an unbounded
// amount of work per presentation. Eight is far beyond any real
// issuer's key set including rotation overlap.
const DefaultMaxIssuerKeyCandidates = 8

// circuitZkIssuerCandidates resolves the bounded candidate set.
//
// Over the limit is REFUSED rather than truncated. Truncating would
// mean verifying against an arbitrary subset chosen by whatever order
// the trust layer happened to return, and reporting a proof as
// unverifiable when the key that signed it was simply past the cut.
func (c *Client) circuitZkIssuerCandidates(ctx context.Context, docType string, issuers []string) ([]*ecdsa.PublicKey, error) {
	resolver := c.nymAuthIssuerKeys
	if resolver == nil {
		resolver = refusingIssuerKeys{}
	}

	keys, err := resolver.TrustedIssuerKeys(ctx, docType, issuers)
	if err != nil {
		return nil, fmt.Errorf("circuit_zk: resolving trusted issuer keys for %q: %w", docType, err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("circuit_zk: no trusted issuer key for docType %q", docType)
	}

	limit := c.cfg.Verifier.NymAuth.MaxIssuerKeyCandidates
	if limit <= 0 {
		limit = DefaultMaxIssuerKeyCandidates
	}
	if len(keys) > limit {
		return nil, fmt.Errorf("circuit_zk: %d trusted issuer keys for docType %q exceeds the limit of %d; "+
			"raise verifier.nym_auth.max_issuer_key_candidates deliberately rather than verifying against a subset",
			len(keys), docType, limit)
	}
	return keys, nil
}

// issuerKeyThumbprint identifies a candidate in a log line without
// putting a key in it.
//
// SHA-256 over the uncompressed point, base64url. A thumbprint is
// enough to say WHICH candidate verified, which is the only thing an
// operator needs from the line.
func issuerKeyThumbprint(key *ecdsa.PublicKey) string {
	if key == nil || key.X == nil || key.Y == nil {
		return ""
	}
	const coordinate = 32
	point := make([]byte, 1+2*coordinate)
	point[0] = 4
	key.X.FillBytes(point[1 : 1+coordinate])
	key.Y.FillBytes(point[1+coordinate:])
	sum := sha256.Sum256(point)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
