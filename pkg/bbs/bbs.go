// Package bbs is this repo's interface to blind BBS credentials.
//
// A BBS credential is signed once over a list of messages and later
// presented with only the messages the holder chooses to reveal. Two
// things distinguish it from the mdoc/SD-JWT paths already here:
//
//   - The wallet participates at ISSUANCE. It commits to messages the
//     issuer never sees, and to the public key of a device-held key
//     binding key, and the issuer signs that commitment. So unlike
//     Longfellow and Vega — which are post-issuance transforms over a
//     credential someone else already signed — an issuer cannot bolt BBS
//     on afterwards.
//   - Consequently `vc` needs this on BOTH sides: the issuer verifies a
//     commitment and blind-signs it, the verifier checks a presentation.
//
// # Why these are interfaces
//
// The implementation is cgo over zk-cred-bbs's C ABI, behind the
// `bbsnative` build tag. Everything here is defined in terms of the two
// interfaces below so that an out-of-process implementation later is a
// constructor swap rather than a rewrite of every call site — a decision
// taken deliberately before the call sites exist, since retrofitting a
// seam is the part that never happens.
//
// # Availability
//
// Without the `bbsnative` tag, [Native] returns an implementation whose
// every method fails with [ErrUnavailable].
//
// The issuer builds with the tag by default, because blind BBS has no
// pure-Go path and an issuer built without it resolves a `format: jwp`
// credential configuration, passes every check, and then fails at the
// signer — wired but dead. It stays statically linked while doing it:
// `cgo-static` in the Makefile's BUILD_CONFIGS, with `netgo` and
// `osusergo` restoring the pure-Go DNS and user lookups that turning CGO
// on would otherwise hand to glibc's NSS.
//
// Every other service stays CGO_ENABLED=0 and fully static, and must —
// this tag buys a native dependency, and nothing that does not need blind
// BBS should pay for it. See the repository Makefile's `bbs-native-lib`
// target and the equivalent reasoning for `zknative`.
package bbs

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Suite selects the key binding construction, and with it the domain
// separation the whole credential is bound to. Getting this wrong does not
// produce an error — it produces values that verify against nothing.
type Suite uint32

const (
	// SuitePlain is blind BBS with no device binding.
	SuitePlain Suite = 0
	// SuiteSchnorr is blind BBS with a Schnorr-over-BLS12-381-G1 key
	// binding key, the construction described in zk-cred-bbs's PROFILE.md.
	SuiteSchnorr Suite = 1
)

// Wire names for the suites, as they appear in a credential request.
//
// Names rather than the numbers above: the number is an FFI detail, and a
// request member carrying `1` says nothing to anyone reading a log.
const (
	SuiteNamePlain   = "plain"
	SuiteNameSchnorr = "schnorr"
)

// ParseSuite resolves a wire name to a suite.
//
// The suite selects the domain separation everything is computed under -
// the api_id, and therefore generator derivation and every hash-to-scalar.
// Holder and issuer must agree or the commitment verifies against nothing,
// which is why this is carried explicitly rather than defaulted: a wrong
// guess is indistinguishable from a corrupt commitment, a wrong issuer key,
// or a tampered proof.
func ParseSuite(name string) (Suite, error) {
	switch name {
	case SuiteNamePlain:
		return SuitePlain, nil
	case SuiteNameSchnorr:
		return SuiteSchnorr, nil
	default:
		return 0, fmt.Errorf("bbs: unknown suite %q, want %q or %q", name, SuiteNamePlain, SuiteNameSchnorr)
	}
}

// String returns the wire name.
func (s Suite) String() string {
	switch s {
	case SuitePlain:
		return SuiteNamePlain
	case SuiteSchnorr:
		return SuiteNameSchnorr
	default:
		return fmt.Sprintf("Suite(%d)", uint32(s))
	}
}

// Disclosure is what the holder asked to happen to one message.
type Disclosure uint8

const (
	// Disclose reveals the message to the verifier.
	Disclose Disclosure = 0
	// Hide proves knowledge of it without revealing it.
	Hide Disclosure = 1
	// Commit hides it and emits a Pedersen commitment the verifier can
	// carry into a further proof.
	Commit Disclosure = 2
)

var (
	// ErrUnavailable is returned by every operation when the binary was
	// built without the `bbsnative` tag.
	ErrUnavailable = errors.New("bbs: native support not compiled in (build with -tags bbsnative)")

	// ErrVerification is returned when a commitment or proof does not
	// verify.
	//
	// The wrapped message is a coarse discriminator meant for logs — which
	// check failed, and structural facts like a length mismatch. It never
	// contains key material or message contents. **It must not be
	// forwarded to a relying party**: an RP learns "invalid", not where to
	// aim next. Callers surfacing a failure outward should match with
	// errors.Is and emit their own opaque response.
	ErrVerification = errors.New("bbs: verification failed")

	// ErrInternal is returned when the native layer failed for a reason
	// that is not a verdict on the input — today, a panic caught crossing
	// the FFI boundary.
	//
	// Kept distinct from ErrVerification on purpose. "This proof is
	// invalid" and "our prover crashed" call for different responses:
	// the first is a normal outcome to be reported to the caller, the
	// second is an incident. Collapsing them into one error hides
	// breakage inside an expected failure path.
	ErrInternal = errors.New("bbs: native call failed")
)

// BlindSigner is the issuer's half.
type BlindSigner interface {
	// BlindSign verifies the holder's commitment — including each
	// authenticator's proof of possession of its key binding key — and
	// signs it together with the issuer's own messages.
	//
	// A commitment that does not verify is rejected, never signed.
	BlindSign(suite Suite, secretKey, publicKey, commitment, header []byte, messages [][]byte) ([]byte, error)
}

// KeyBinding selects the credential's device-binding layout, and with it
// which message indices are reserved.
type KeyBinding uint32

const (
	// NoKeyBinding issues a credential bound to no device key.
	NoKeyBinding KeyBinding = 0
	// SchnorrKeyBinding is this profile's Schnorr-on-BLS12-381-G1 binding.
	SchnorrKeyBinding KeyBinding = 1
)

// Issuer is the issuer's half at the level of a whole credential, as
// opposed to [BlindSigner]'s raw algebra over an ordered message list.
//
// Prefer this. The mapping from named claims onto that message list lives
// in the native crate, shared with the wallet SDKs and the browser,
// precisely so no two of them can derive it differently — a claim ordered
// differently produces a credential whose every proof fails, with nothing
// in the failure pointing at why.
type Issuer interface {
	// Issue verifies the holder's commitment and returns a finished
	// credential in JWP Compact Serialization.
	Issue(p IssueParams) (string, error)
}

// KeyDeriver derives a public key from a secret one.
//
// Separate from [Issuer] because it is not part of issuing anything: it
// exists so a holder of a key *pair* can establish that the two halves
// belong together, which nothing else here can do. A length check confirms
// the widths and says nothing about the pair, and signing with a mismatched
// one produces credentials that fail at every relying party reporting only
// "does not verify" - a failure with nothing in it pointing at the
// configuration that caused it.
type KeyDeriver interface {
	// SkToPk returns the 96-octet compressed G2 public key for a 32-octet
	// secret scalar (draft-irtf-cfrg-bbs-signatures-08 §3.4.2).
	SkToPk(secretKey []byte) ([]byte, error)
}

// PresentationVerifier is the relying party's half at the level of a whole
// presentation.
type PresentationVerifier interface {
	// VerifyPresentation returns what the presentation disclosed, or an
	// error if it does not verify. A non-nil result means the issuer really
	// signed every claim in it.
	VerifyPresentation(suite Suite, presentedJWP string, publicKey []byte) (*Presentation, error)
}

// DisclosedClaim is one claim a verifier learned from a presentation.
type DisclosedClaim struct {
	// Pointer is the claim's RFC 6901 pointer within the credential.
	Pointer string `json:"pointer"`
	// Value is the claim's JSON value, so a number stays a number and a
	// string stays quoted.
	Value json.RawMessage `json:"value"`
}

// Presentation is what a verified presentation revealed. Withheld claims
// are absent rather than null — the verifier does not learn they were
// withheld beyond their pointer appearing in the credential's map.
type Presentation struct {
	Vct       string           `json:"vct"`
	Disclosed []DisclosedClaim `json:"disclosed"`
}

// ProofVerifier is the relying party's half.
type ProofVerifier interface {
	// VerifyProof returns nil only if the proof is valid for exactly these
	// disclosed messages, this disclosure pattern, these headers and this
	// issuer key.
	//
	// issuerKnownMessages is how many of the credential's messages the
	// issuer supplied itself; the rest were committed by the holder. It is
	// part of what the signature covers, so a wrong value fails to verify
	// rather than being ignored.
	VerifyProof(suite Suite, publicKey, proof, header, presentationHeader []byte,
		issuerKnownMessages int, disclosedMessages [][]byte, disclosures []Disclosure) error
}
