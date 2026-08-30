//go:build bbsnative

package bbs

import (
	"encoding/json"
	"fmt"

	"github.com/SUNET/vc/pkg/bbs/bbsnative"
)

// native adapts the cgo backend to this package's interfaces, keeping the
// C-ABI details (status codes, raw uint32 suites) out of every call site.
type native struct{ backend bbsnative.Backend }

var (
	_ BlindSigner          = native{}
	_ ProofVerifier        = native{}
	_ Issuer               = native{}
	_ PresentationVerifier = native{}
)

// classify maps an ABI status onto this package's sentinels. A panic is
// not a verdict on the input, so it must not arrive as ErrVerification.
func classify(status int32, msg string) error {
	if status == bbsnative.StatusPanic {
		return fmt.Errorf("%w: %s", ErrInternal, bbsnative.Describe(status, msg))
	}
	return fmt.Errorf("%w: %s", ErrVerification, bbsnative.Describe(status, msg))
}

func (n native) BlindSign(suite Suite, secretKey, publicKey, commitment, header []byte, messages [][]byte) ([]byte, error) {
	sig, status, msg := n.backend.BlindSign(uint32(suite), secretKey, publicKey, commitment, header, messages)
	if status != bbsnative.StatusOK {
		return nil, classify(status, msg)
	}
	return sig, nil
}

func (n native) VerifyProof(suite Suite, publicKey, proof, header, presentationHeader []byte,
	issuerKnownMessages int, disclosedMessages [][]byte, disclosures []Disclosure) error {

	codes := make([]byte, len(disclosures))
	for i, d := range disclosures {
		codes[i] = byte(d)
	}
	status, msg := n.backend.VerifyProof(uint32(suite), publicKey, proof, header, presentationHeader,
		issuerKnownMessages, disclosedMessages, codes)
	if status != bbsnative.StatusOK {
		return classify(status, msg)
	}
	return nil
}

func (n native) Issue(p IssueParams) (string, error) {
	claims := p.DocumentData
	if len(claims) == 0 {
		claims = json.RawMessage("{}")
	}
	// Marshaled here rather than taken pre-encoded so the empty case — a
	// credential with no holder-committed claims — does not have to be
	// spelled "[]" by every caller.
	//
	// Which only works if nil actually encodes as `[]`, and it does not:
	// `json.Marshal` writes `null` for a nil slice, and the native side is
	// given a JSON array. A credential committing only key binding keys and
	// no claims at all — the very case the paragraph above promises to
	// handle — is exactly when this field is nil.
	holderPointers := p.HolderPointers
	if holderPointers == nil {
		holderPointers = []string{}
	}
	pointers, err := json.Marshal(holderPointers)
	if err != nil {
		return "", fmt.Errorf("%w: encoding holder pointers: %v", ErrInternal, err)
	}

	jwp, status, msg := n.backend.Issue(uint32(p.Suite), p.SecretKey, p.PublicKey, p.Commitment,
		p.Vct, claims, pointers, p.ExtraHeader, uint32(p.KeyBinding))
	if status != bbsnative.StatusOK {
		return "", classify(status, msg)
	}
	return jwp, nil
}

func (n native) VerifyPresentation(suite Suite, presentedJWP string, publicKey []byte) (*Presentation, error) {
	raw, status, msg := n.backend.VerifyPresentation(uint32(suite), presentedJWP, publicKey)
	if status != bbsnative.StatusOK {
		return nil, classify(status, msg)
	}
	var out Presentation
	if err := json.Unmarshal(raw, &out); err != nil {
		// The native side produced this JSON, so a decode failure here is a
		// bug on our side of the boundary, not a verdict on the caller's
		// presentation.
		return nil, fmt.Errorf("%w: decoding verification result: %v", ErrInternal, err)
	}
	return &out, nil
}

// Native returns the cgo-backed implementation.
func Native() interface {
	BlindSigner
	ProofVerifier
	Issuer
	PresentationVerifier
} {
	return native{}
}

// Available reports whether native BBS support was compiled in.
func Available() bool { return true }
