package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenerateSecureToken generates a cryptographically secure random token encoded as base64 URL-safe string.
// If stringLength > 0, generates a token of approximately that character length (may be slightly longer due to encoding).
// If stringLength is 0, uses byteSize to determine the number of random bytes to generate before encoding.
// If both are 0, defaults to 32 bytes. Maximum byte size is 94 which results in a 128 character long token.
func GenerateSecureToken(byteSize int, stringLength int) (string, error) {
	var size int

	if stringLength > 0 {
		// Calculate bytes needed for desired string length
		// Base64 RawURL encoding: 4 chars per 3 bytes, so N chars needs (N * 3 + 3) / 4 bytes
		size = (stringLength*3 + 3) / 4
		if size > 94 {
			size = 94
		}
	} else {
		size = byteSize
		if size == 0 {
			size = 32
		}
		if size >= 94 {
			size = 94
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
