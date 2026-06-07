package oauth2

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// ExtractClientIDFromAssertion extracts the "sub" claim from a client_assertion JWT
// without verifying the signature. The sub claim contains the client_id per RFC 7523 §3.
func ExtractClientIDFromAssertion(assertion string) (string, error) {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	if claims.Sub == "" {
		return "", fmt.Errorf("client assertion JWT missing 'sub' claim")
	}

	return claims.Sub, nil
}
