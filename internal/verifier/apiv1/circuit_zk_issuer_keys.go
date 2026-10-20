package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/trust"
)

// Q - the key the credential was signed with - is a PUBLIC INPUT to
// the circuit, so the verifier has to know it before it can check
// anything.
//
// WHY THE HOLDER MAY SEND IT. At first reading, taking the key from
// the response looks like letting the holder choose what it is
// measured against. It is not, because the two things are checked
// separately:
//
//   - The CIRCUIT proves "this credential was signed by Q", for the
//     Q given to it. A holder who substitutes a key it controls gets
//     a proof about a credential that key signed - which is a
//     credential it issued to itself.
//   - The TRUST LAYER then says whether Q belongs to an issuer this
//     verifier accepts. That is what the holder cannot forge: the
//     chain is evaluated by the same go-trust PDP, under the same
//     mdoc-issuer-auth role, as a plain mdoc presentation's DS
//     certificate. A self-signed key does not get a decision.
//
// So the holder supplies a candidate and the PDP vouches for it.
// Neither half is sufficient alone, and refusing either one refuses
// the presentation.
//
// It is also the only design that works. A circuit_zk presentation
// carries no credential, and go-trust cannot answer "which keys may
// sign this docType" - its question is "is THIS name bound to THIS
// key". The IACA root cannot stand in for Q either: one IACA signs
// many DS certificates, and the circuit needs the exact signing key.
//
// The wire shape is normative in the matcher repository's
// docs/circuit_zk_response.md rule 5a; pkg/openid4vp checks the
// encoding and the limits, and this is where the X.509 is parsed.
//
// PRIVACY. The chain is issuer-level, not holder-level: a DS
// certificate identifies the issuer and says nothing about which
// credential or which subject. It carries no more than the issuer
// identity a plain mdoc presentation already reveals.
//
// The docType the chain is evaluated for comes from the REQUEST, not
// from the response. A holder choosing the docType would be choosing
// which trust policy it is judged under.

// ErrNoTrustEvaluator is the refusal a verifier with no PDP gives.
//
// Fail closed, and deliberately not "nothing is trusted, carry on": a
// verifier that cannot ask whether an issuer is trusted must not read
// its own silence as a yes.
var ErrNoTrustEvaluator = errors.New("circuit_zk: no trust evaluator is configured, so no issuer key can be trusted")

// ErrAllowAllTrustEvaluator is the refusal for a deployment whose trust
// configuration trusts everything.
//
// A nil evaluator is not the only way to have no trust decision.
// NewTrustEvaluatorFromConfig returns an AllowAllEvaluator when
// verifier.trust.pdp_url is empty, and that evaluator answers
// Trusted=true to every question - which for this path means a chain
// the HOLDER minted is accepted as a trusted issuer.
//
// That breaks the whole construction rather than weakening it. The
// circuit proves "this credential was signed by Q" for the Q it is
// given; the only thing standing between that and a holder issuing a
// credential to itself is the trust layer saying Q belongs to a real
// issuer. With allow-all there is nothing on that side, so a holder
// can self-sign, choose its own issuer key, and so choose its own
// pseudonym - which for known-offender matching means a flagged
// person presents a value that matches nothing and reads as innocent.
//
// Allow-all is a legitimate mode for other formats, where a holder
// cannot supply the key it is measured against. It is not legitimate
// here, so this refuses rather than inheriting it.
var ErrAllowAllTrustEvaluator = errors.New("circuit_zk: verifier.trust.pdp_url is not set, so every issuer is trusted; " +
	"nym_auth takes the issuer key from the holder's own certificate chain and cannot be used without a PDP")

// circuitZkIssuerKey validates the presentation's issuer chain and
// returns the leaf's public key as Q.
//
// docType is the REQUEST's. now is passed in so a test can state the
// moment a certificate is judged at.
func (c *Client) circuitZkIssuerKey(
	ctx context.Context,
	presentation openid4vp.CircuitZkPresentation,
	docType string,
	now time.Time,
) (*ecdsa.PublicKey, error) {
	if c.trustEvaluator == nil {
		return nil, ErrNoTrustEvaluator
	}
	if _, allowAll := c.trustEvaluator.(*trust.AllowAllEvaluator); allowAll {
		// Defence in depth: configuration validation refuses this at
		// startup. Checked here too because the consequence of being
		// wrong is a holder-chosen pseudonym, and this is the point
		// that cannot be bypassed.
		return nil, ErrAllowAllTrustEvaluator
	}
	if len(presentation.X5Chain) == 0 {
		// Unreachable through ValidateCircuitZkResponse, which makes
		// x5chain a required non-empty member. Kept because the
		// consequence of being wrong about that is verifying a proof
		// against no key, which is not verifying it - a belief worth
		// one comparison.
		return nil, errors.New("circuit_zk: the presentation carries no issuer certificate chain")
	}

	chain := make([]*x509.Certificate, 0, len(presentation.X5Chain))
	for i, der := range presentation.X5Chain {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("circuit_zk: certificate %d in the issuer chain does not parse: %w", i, err)
		}
		chain = append(chain, cert)
	}

	// Exactly the plain-mdoc issuer check, through the same function:
	// one implementation, so a policy change reaches both paths and
	// the two cannot drift into trusting different things.
	//
	// The issuer URL is left empty on purpose - it is taken from the
	// leaf's SAN, as the SDKs and the deployed PDP request shape
	// expect - and the docType is the request's.
	if err := mdoc.VerifyIssuerChain(ctx, c.trustEvaluator, chain, docType, "", now); err != nil {
		return nil, fmt.Errorf("circuit_zk: the issuer chain is not trusted for docType %q: %w", docType, err)
	}

	// Only after the chain is trusted: an untrusted chain's key is
	// not a key this verifier has any business looking at.
	key, isECDSA := chain[0].PublicKey.(*ecdsa.PublicKey)
	if !isECDSA {
		return nil, fmt.Errorf("circuit_zk: the issuer certificate holds a %T, and the circuit takes a P-256 key",
			chain[0].PublicKey)
	}
	if key.Curve != elliptic.P256() {
		// Not a limitation to be lifted quietly: the circuit's field
		// arithmetic is over P-256. A key on another curve cannot be
		// a public input to it, so accepting one would mean verifying
		// against something the circuit never saw.
		return nil, fmt.Errorf("circuit_zk: the issuer key is on %s, and the circuit takes P-256",
			key.Curve.Params().Name)
	}
	return key, nil
}

// issuerKeyThumbprint identifies a key in a log line without putting
// one in it.
//
// SHA-256 over the uncompressed point, base64url. A thumbprint is
// enough to say WHICH issuer key verified, which is the only thing an
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
