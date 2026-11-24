//go:build !bbsnative

package bbs

type native struct{}

var (
	_ BlindSigner          = native{}
	_ ProofVerifier        = native{}
	_ Issuer               = native{}
	_ KeyDeriver           = native{}
	_ PresentationVerifier = native{}
)

// Native returns a backend whose every operation fails with ErrNotBuilt.
func Native() interface {
	BlindSigner
	ProofVerifier
	Issuer
	KeyDeriver
	PresentationVerifier
} {
	return native{}
}

func (native) BlindSign(Suite, []byte, []byte, []byte, []byte, [][]byte) ([]byte, error) {
	return nil, ErrNotBuilt
}

func (native) VerifyProof(Suite, []byte, []byte, []byte, []byte, int, [][]byte, []Disclosure) error {
	return ErrNotBuilt
}

func (native) Issue(IssueParams) (string, error) { return "", ErrNotBuilt }

func (native) SkToPk([]byte) ([]byte, error) { return nil, ErrNotBuilt }

func (native) VerifyPresentation(Suite, string, []byte) (*Presentation, error) {
	return nil, ErrNotBuilt
}
