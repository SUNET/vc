package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"slices"
	"time"

	"github.com/SUNET/vc/pkg/nymauth"
)

// Request is what a nym_auth circuit is verified against.
//
// Every field is the VERIFIER'S: Q comes from the issuer chain the
// verifier resolved and trusted, T from its own clock, E and C from its
// own policy, E2 and VerifierInput from its own session and identity.
// None of them is read from the holder's response, and the pseudonym is
// an OUTPUT. A verifier that took any of these from the response would
// be checking a statement the holder chose.
type Request struct {
	// IssuerKey is Q, the P-256 key the credential was signed with,
	// resolved through the ordinary trust path (go-trust/PDP) and never
	// taken from the proof.
	IssuerKey *ecdsa.PublicKey

	// Now is T, the verifier's own clock reading. The circuits take it
	// as 20 ASCII bytes, YYYY-MM-DDThh:mm:ssZ.
	Now time.Time

	// Inputs are the predicate contributions to this request, each
	// naming the function it comes from.
	//
	// A LIST keyed by function id rather than a field per predicate,
	// because predicates in circuit_zk apply to any claim and the set
	// of functions is open-ended. The age check is the first registered
	// one; a second needs no change here. See functions.go.
	Inputs []CircuitInput

	// SupportedFunctions are the function ids the selected circuit
	// build supports, from the catalog's capabilities and the
	// operator's allowlist.
	//
	// Data-driven on purpose: which circuit supports which predicate is
	// not knowledge this package should carry, and new circuits are
	// created elsewhere. Empty means none, so a request carrying a
	// predicate is refused rather than passed to a circuit that cannot
	// evaluate it - fail closed, because the alternative is a proof
	// that verifies against a statement nobody checked.
	SupportedFunctions []string

	// SessionTranscript is the ISO 18013-5 SessionTranscript this
	// presentation is bound to, built from the verifier's own origin
	// and nonce. The circuits take it whole, as the transcript seed.
	//
	// Checked here for SHAPE only - one three-item CBOR array, which
	// the e2 derivation enforces. Length limits belong to a BACKEND:
	// Longfellow's C ABI takes 32 to 65536 bytes, and the shared
	// digest vector's 12-byte transcript derives a correct e2 and must
	// stay usable here. A backend bound applied in this package would
	// refuse a request some other circuit accepts.
	//
	// e2 is DERIVED from it (see E2) rather than carried beside it.
	// The circuits take both, and a request that carried them as two
	// independent fields could name one session in the seed and
	// another in the digest - a proof that verifies against a
	// transcript nobody in this session built.
	SessionTranscript []byte

	// DocType is the credential's mdoc document type, which the
	// device-authentication message binds the proof to. Not a circuit
	// input of its own: it is what makes e2 this credential type's.
	DocType string

	// VerifierInput is SHA-256 of the BARE verifier_id - never the
	// prefixed Client Identifier, never client_id as it appears in the
	// request. See VerifierInput.
	VerifierInput [32]byte
}

// TimeLayout is how the circuits take T for an mdoc: 20 ASCII bytes.
const TimeLayout = "2006-01-02T15:04:05Z"

// E2 is the challenge digest this request binds the proof to: SHA-256
// of the device-authentication message over SessionTranscript and
// DocType.
//
// Derived, never a field. See SessionTranscript.
func (r Request) E2() ([32]byte, error) {
	return MdocChallengeDigest(r.SessionTranscript, r.DocType)
}

// VerifierInput returns SHA-256 of the bare verifier_id.
//
// The BARE identifier - "verifier.example" - per nym_auth_rulebook PR
// #7. verifier_id_type is agreed out of band between wallet and verifier
// and is not hashed, and the prefixed Client Identifier is the form that
// rulebook marks MUST NOT. A prefixed value is refused rather than
// stripped, for the reason in pkg/nymauth.checkVerifierID: hashing it
// yields a pseudonym no Verifier reports, so a comparison simply never
// matches and the subject looks innocent.
func VerifierInput(verifierID string) ([32]byte, error) {
	if err := nymauth.CheckVerifierID(verifierID); err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256([]byte(verifierID)), nil
}

// Check refuses a request a circuit cannot be verified against, or that
// would be verified against the wrong thing.
func (r Request) Check() error {
	if r.IssuerKey == nil {
		return fmt.Errorf("nymauth: no issuer key; Q must come from the resolved issuer chain, never from the proof")
	}
	if r.IssuerKey.Curve == nil {
		// Checked before the comparison below, which would otherwise
		// dereference it to name the curve in the error: a zero
		// ecdsa.PublicKey fails the P-256 test and then panics while
		// explaining why. A caller handed an incomplete key needs an
		// error, not a crash.
		return fmt.Errorf("nymauth: the issuer key names no curve")
	}
	if r.IssuerKey.Curve != elliptic.P256() {
		return fmt.Errorf("nymauth: the issuer key is on %s; the circuits are built for P-256", r.IssuerKey.Curve.Params().Name)
	}
	if r.IssuerKey.X == nil || r.IssuerKey.Y == nil {
		return fmt.Errorf("nymauth: the issuer key has no coordinates")
	}
	if r.Now.IsZero() {
		return fmt.Errorf("nymauth: no verification time; T is the verifier's own clock reading, and a zero value would check validity against the year 1")
	}
	if err := r.checkInputs(); err != nil {
		return err
	}
	if _, err := r.E2(); err != nil {
		// Derivation is the only check of the transcript's shape and
		// of the docType, so a request is not checked until it has
		// run.
		return err
	}
	if r.VerifierInput == ([32]byte{}) {
		return fmt.Errorf("nymauth: verifier_input is zero; the pseudonym would not be scoped to this verifier")
	}
	return nil
}

// checkInputs refuses predicates this request cannot honour.
//
// Generic: it asks the registry what a function fills and the request
// what the circuit supports. It knows nothing about ages, dates or
// claims, which is what lets a new predicate be added by registering
// it.
func (r Request) checkInputs() error {
	seen := make(map[string]bool, len(r.Inputs))
	for _, input := range r.Inputs {
		if seen[input.FunctionID] {
			// Two contributions from one function would fill the same
			// circuit inputs twice, and the second would silently win.
			return fmt.Errorf("nymauth: function %q contributes twice", input.FunctionID)
		}
		seen[input.FunctionID] = true

		if err := input.check(); err != nil {
			return err
		}
		if !slices.Contains(r.SupportedFunctions, input.FunctionID) {
			// Fail closed. Passing it anyway would hand the circuit
			// inputs it does not read, and the proof would verify
			// against a statement nobody checked.
			return fmt.Errorf("nymauth: the selected circuit does not support function %q; it supports %v",
				input.FunctionID, r.SupportedFunctions)
		}
	}
	return nil
}

// TimeString renders T the way the circuits take it.
//
// In UTC, and refusing a year the layout cannot express. The layout
// writes a literal "Z", so a non-UTC time would render its own wall
// clock under a UTC marker - a different instant, asserted as this one.
func (r Request) TimeString() (string, error) {
	t := r.Now.UTC()
	if year := t.Year(); year < 1 || year > 9999 {
		return "", fmt.Errorf("nymauth: year %d cannot be written in the circuits' 20-byte time format", year)
	}
	return t.Format(TimeLayout), nil
}
