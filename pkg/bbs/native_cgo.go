//go:build bbsnative

package bbs

import (
	"fmt"

	"github.com/SUNET/vc/pkg/bbs/bbsnative"
)

// native adapts the cgo backend to this package's interfaces, keeping the
// C-ABI details (status codes, raw uint32 suites) out of every call site.
type native struct{ backend bbsnative.Backend }

var (
	_ BlindSigner   = native{}
	_ ProofVerifier = native{}
)

func (n native) BlindSign(suite Suite, secretKey, publicKey, commitment, header []byte, messages [][]byte) ([]byte, error) {
	sig, status, msg := n.backend.BlindSign(uint32(suite), secretKey, publicKey, commitment, header, messages)
	if status != bbsnative.StatusOK {
		return nil, fmt.Errorf("%w: %s", ErrVerification, bbsnative.Describe(status, msg))
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
		return fmt.Errorf("%w: %s", ErrVerification, bbsnative.Describe(status, msg))
	}
	return nil
}

// Native returns the cgo-backed implementation.
func Native() interface {
	BlindSigner
	ProofVerifier
} {
	return native{}
}

// Available reports whether native BBS support was compiled in.
func Available() bool { return true }
