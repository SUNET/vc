package oauth2

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// https://www.rfc-editor.org/rfc/inline-errata/rfc7636.html

// Client have to create a new code_verifier for each authorization request
// Client sends code_challenge and code_challenge_method in the authorization request
// Server saves those and sends back authorization code
// Client sends code_verifier in the token request
// Server verifies code_verifier with the saved code_challenge and return the token if it matches

const (
	// CodeChallengeMethodPlain no hash transformation
	CodeChallengeMethodPlain = "plain"

	// CodeChallengeMethodS256 SHA256 hash transformation
	CodeChallengeMethodS256 = "S256"
)

var (
	// ErrInvalidRequest indicates invalid request parameters
	ErrInvalidRequest = errors.New("invalid_request")

	// ErrInvalidGrant indicates invalid grant
	ErrInvalidGrant = errors.New("invalid_grant")
)

// CreateCodeVerifier creates a code verifier. 4.1 Client Creates a Code Verifier
func CreateCodeVerifier() (string, error) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// CreateCodeChallenge creates a code challenge. 4.2 Client Creates a Code Challenge
func CreateCodeChallenge(codeChallengeMethod, codeVerifier string) string {
	if codeChallengeMethod == CodeChallengeMethodS256 {
		hash := sha256.Sum256([]byte(codeVerifier))
		b64 := base64.RawURLEncoding.EncodeToString(hash[:])
		return b64
	}

	return codeVerifier
}

// ValidatePKCE validates the code verifier against the code challenge
func ValidatePKCE(codeVerifier, codeChallenge, codeChallengeMethod string) error {
	if codeChallenge == "" {
		return nil // PKCE not used
	}

	if codeVerifier == "" {
		return ErrInvalidRequest // Code verifier required when challenge is present
	}

	computedChallenge := CreateCodeChallenge(codeChallengeMethod, codeVerifier)
	if computedChallenge != codeChallenge {
		return ErrInvalidGrant
	}

	return nil
}
