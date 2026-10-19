package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
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

	// Bounds are E and C, from the verifier's policy.
	Bounds AgeBounds

	// E2 binds the proof to this session: SHA-256 of the device
	// authentication message. See MdocE2.
	E2 [32]byte

	// VerifierInput is SHA-256 of the BARE verifier_id - never the
	// prefixed Client Identifier, never client_id as it appears in the
	// request. See VerifierInput.
	VerifierInput [32]byte
}

// TimeLayout is how the circuits take T for an mdoc: 20 ASCII bytes.
const TimeLayout = "2006-01-02T15:04:05Z"

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
	if r.IssuerKey.Curve != elliptic.P256() {
		return fmt.Errorf("nymauth: the issuer key is on %s; the circuits are built for P-256", r.IssuerKey.Curve.Params().Name)
	}
	if r.IssuerKey.X == nil || r.IssuerKey.Y == nil {
		return fmt.Errorf("nymauth: the issuer key has no coordinates")
	}
	if r.Now.IsZero() {
		return fmt.Errorf("nymauth: no verification time; T is the verifier's own clock reading, and a zero value would check validity against the year 1")
	}
	if r.Bounds.Earliest == "" || r.Bounds.Cutoff == "" {
		return fmt.Errorf("nymauth: the age bounds are unset; use AgeCheck.Bounds, which fills the disabling sentinels rather than leaving them empty")
	}
	if err := r.Bounds.checkRange(); err != nil {
		return err
	}
	if r.E2 == ([32]byte{}) {
		return fmt.Errorf("nymauth: e2 is zero; without it the proof is not bound to this session at all")
	}
	if r.VerifierInput == ([32]byte{}) {
		return fmt.Errorf("nymauth: verifier_input is zero; the pseudonym would not be scoped to this verifier")
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
