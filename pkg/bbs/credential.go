package bbs

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// MaxMessages bounds how many messages one credential may carry.
//
// Not a protocol limit — a guard. Message count drives generator
// derivation and proof size, so an unbounded document would let a caller
// dictate how much work the issuer does.
//
// The bound on the whole message vector is the native crate's, and has to
// be: the claim-to-message mapping lives there, so this side cannot count
// the issuer's own claims without re-deriving that mapping — the exact
// duplication it was moved into the crate to avoid. What Go checks against
// this constant is [IssueParams.HolderPointers]: the one input that
// arrives already counted and is entirely caller-controlled. That rejects
// the cheap abuse early, with a message naming the field, and the crate
// still refuses whatever gets past it.
const MaxMessages = 512

// ValidateHolderPointers checks a holder pointer list against the rules the
// credential's claim map depends on, so a caller can refuse a request before
// paying for it.
//
// The messages are phrased to read after the caller's own field name -
// `bbs_committed_claims` on the OID4VCI request, `holder_pointers` on the
// gRPC one - because that is the name whoever has to fix it actually sent.
// One implementation, because these are correctness rules and not style:
// each of them describes a credential that cannot be built, and two copies
// is two chances to disagree about which.
func ValidateHolderPointers(pointers []string) error {
	if len(pointers) > MaxMessages {
		return fmt.Errorf("has %d entries, over the %d limit", len(pointers), MaxMessages)
	}
	seen := make(map[string]struct{}, len(pointers))
	for _, pointer := range pointers {
		// A pointer is what places a committed message in the claim map. An
		// empty one names the whole document, and RFC 6901 requires the rest
		// to start with "/", so neither can identify a claim.
		if pointer == "" || !strings.HasPrefix(pointer, "/") {
			return errors.New("must contain RFC 6901 pointers beginning with '/'")
		}
		// Two messages cannot occupy one position in the claim map, so a
		// duplicate means the header would describe fewer claims than the
		// signature covers.
		if _, duplicate := seen[pointer]; duplicate {
			return fmt.Errorf("contains a duplicate pointer: %s", pointer)
		}
		seen[pointer] = struct{}{}
	}
	return nil
}

// IssueParams is everything an issuer needs to produce a BBS credential.
type IssueParams struct {
	// Suite is the key binding construction. Must match what the holder
	// used to build Commitment; a mismatch changes the domain separation
	// and the result verifies against nothing.
	Suite Suite

	// SecretKey and PublicKey are the issuer's BBS key pair. Note this
	// cannot be a pki.Signer or a PKCS#11 key: a BBS secret key is a
	// BLS12-381 scalar consumed inside the signing algebra, not something
	// that signs a digest, and mainstream HSMs do not implement the curve.
	SecretKey []byte
	PublicKey []byte

	// Commitment is the holder's `commitment_with_proof`, carrying the
	// messages the issuer never sees and the key binding public keys,
	// together with proof the holder actually holds those keys.
	Commitment []byte

	// Vct is the SD-JWT VC credential type identifier.
	Vct string

	// DocumentData is the issuer's own claims, as a JSON object.
	DocumentData json.RawMessage

	// HolderPointers names the claims the holder committed to, as RFC 6901
	// pointers. The issuer never sees those values — that is the point —
	// but it must still place them in the message vector, and the count has
	// to match what the holder actually committed. The native side checks
	// that against the commitment and refuses a credential whose header
	// would describe a different message vector than the one being signed.
	HolderPointers []string

	// ExtraHeader, if non-empty, is a JSON object merged into the Issuer
	// Header — `iss`, `iat`, `exp` and the like. It may not restate the
	// parameters the container builds itself.
	ExtraHeader json.RawMessage

	// KeyBinding must agree with whether Commitment carries key binding
	// keys: it selects the message layout a verifier will read under.
	KeyBinding KeyBinding
}

// Issue verifies the holder's commitment and blind-signs it together with
// the issuer's claims, returning a credential in JWP Compact
// Serialization.
//
// The commitment is verified before anything is signed — including each
// authenticator's proof of possession of its key binding key. That check is
// what stops a holder binding a credential to a key it does not control, so
// it is not optional and not deferred to presentation time.
//
// # Where the claim mapping went
//
// An earlier version of this file derived the message list here, in Go:
// each JSON leaf became `["<RFC 6901 pointer>",<value>]`, sorted by
// pointer, under a `LayoutVersion` constant. That is gone, and deliberately
// so.
//
// A BBS signature covers an ordered list of messages, and the issuer, the
// wallet and the verifier must derive byte-identical lists from the same
// claims or nothing verifies — with the failure appearing only as a proof
// that will not check, pointing at nothing. Three implementations of that
// mapping is three chances to disagree. It now lives once, in the native
// crate, which the wallet SDKs and the browser build share; the crate
// follows draft-bormann-jwp-modular-bbs, where the header's `cmap` names
// each claim's index and the header is itself the BBS `header` input, so
// the name-to-position binding is authenticated rather than re-derived.
//
// The `LayoutVersion` constant went with it. Its job — making a layout
// change a detectable migration rather than a silent verification failure —
// is done by the header's own `kb` value and `cmap`, which travel with
// every credential.
func Issue(issuer Issuer, p IssueParams) (string, error) {
	if len(p.Commitment) == 0 {
		return "", fmt.Errorf("bbs: commitment is required")
	}
	if p.Vct == "" {
		return "", fmt.Errorf("bbs: vct is required")
	}
	if err := ValidateHolderPointers(p.HolderPointers); err != nil {
		return "", fmt.Errorf("bbs: holder claim pointer list %w", err)
	}
	return issuer.Issue(p)
}

// DecodeCommitment decodes a base64url-encoded `commitment_with_proof` as
// it arrives on the wire.
func DecodeCommitment(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, fmt.Errorf("bbs: commitment is not valid base64url: %w", err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("bbs: commitment is empty")
	}
	return b, nil
}
