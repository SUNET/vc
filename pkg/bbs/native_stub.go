//go:build !bbsnative

package bbs

// unavailable is the default implementation: present so call sites compile
// and can be exercised without cgo, failing loudly rather than silently
// accepting anything.
type unavailable struct{}

var (
	_ BlindSigner          = unavailable{}
	_ ProofVerifier        = unavailable{}
	_ Issuer               = unavailable{}
	_ KeyDeriver           = unavailable{}
	_ PresentationVerifier = unavailable{}
)

func (unavailable) BlindSign(Suite, []byte, []byte, []byte, []byte, [][]byte) ([]byte, error) {
	return nil, ErrUnavailable
}

func (unavailable) VerifyProof(Suite, []byte, []byte, []byte, []byte, int, [][]byte, []Disclosure) error {
	return ErrUnavailable
}

func (unavailable) Issue(IssueParams) (string, error) { return "", ErrUnavailable }

func (unavailable) SkToPk([]byte) ([]byte, error) { return nil, ErrUnavailable }

func (unavailable) VerifyPresentation(Suite, string, []byte) (*Presentation, error) {
	return nil, ErrUnavailable
}

// Native returns the platform implementation. Without the `bbsnative`
// build tag that is a stub whose every method returns [ErrUnavailable].
func Native() interface {
	BlindSigner
	ProofVerifier
	Issuer
	KeyDeriver
	PresentationVerifier
} {
	return unavailable{}
}

// Available reports whether native BBS support was compiled in. Callers
// that can degrade (for example, by not advertising BBS credential
// configurations) should check this rather than discovering it on the
// first request.
func Available() bool { return false }
