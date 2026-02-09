package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenerateSecureToken generates a cryptographically secure random token encoded as a base64 URL-safe string.
// If stringLength > 0, generates a token of exactly that character length (truncated after encoding).
// If stringLength is 0, uses byteSize to determine the number of random bytes to generate before encoding.
// If both are 0, defaults to 32 bytes.
// Maximum byte size is capped at 96, which produces a 128-character encoded token.
// When stringLength exceeds 128, the output is silently capped at 128 characters.
func GenerateSecureToken(byteSize int, stringLength int) (string, error) {
	const maxBytes = 96 // base64.RawURLEncoding.EncodedLen(96) == 128

	var size int

	if stringLength > 0 {
		// Calculate bytes needed for desired string length
		// Base64 RawURL encoding: 4 chars per 3 bytes, so N chars needs (N * 3 + 3) / 4 bytes
		size = min((stringLength*3+3)/4, maxBytes)
	} else {
		size = min(max(byteSize, 1), maxBytes)
		if byteSize == 0 {
			size = 32
		}
	}

	tokenBytes := make([]byte, size)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", fmt.Errorf("could not generate secure token: %w", err)
	}

	encoded := base64.RawURLEncoding.EncodeToString(tokenBytes)

	// If stringLength was specified, truncate to exact length
	if stringLength > 0 && len(encoded) > stringLength {
		encoded = encoded[:stringLength]
	}

	return encoded, nil
}
