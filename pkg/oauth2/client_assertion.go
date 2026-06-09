package oauth2

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// ExtractClientIDFromAssertion extracts the "sub" claim from a client_assertion JWT
// without verifying the signature. The sub claim contains the client_id per RFC 7523 §3.
//
// NOTE: This does NOT implement full private_key_jwt authentication. The extracted
// client_id is only used for client lookup; actual client authentication relies on
// pre-registered client configurations and DPoP binding. Full JWT assertion
// verification (signature, aud, exp, jti) should be added when proper private_key_jwt
// support is implemented.
//
// SECURITY: Because the JWT is not signature-verified, the caller MUST validate
// the extracted client_id against a trusted client registry before granting access.
// The handler enforces this via Clients.Get() lookup immediately after extraction.
func ExtractClientIDFromAssertion(assertion string) (string, error) {
	assertion = strings.TrimSpace(assertion)
	parts := strings.SplitN(assertion, ".", 4)
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

	// Apply basic sanity constraints matching the client_id field (max=128, printable ASCII).
	if len(claims.Sub) > 128 {
		return "", fmt.Errorf("client assertion 'sub' claim exceeds maximum length (128)")
	}
	for _, r := range claims.Sub {
		if r < 0x20 || r > 0x7E {
			return "", fmt.Errorf("client assertion 'sub' claim contains non-printable character")
		}
	}

	return claims.Sub, nil
}
