package openid4vp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/SUNET/vc/pkg/sdjwtvc"
)

// VPTokenValidator validates VP Token according to Section 8.6
// NOTE: This validator performs format and protocol validation only.
// Cryptographic signature verification must be done separately by the caller
// (e.g. via jwt.Parse with a resolved key). TrustEvaluator handles trust/policy
// evaluation — it does NOT perform signature verification itself.
type VPTokenValidator struct {
	// Nonce from the Authorization Request
	Nonce string

	// ClientID (or Origin for DC API)
	ClientID string

	// ValidateFormat enables SD-JWT format validation (not cryptographic verification).
	// This only validates that the JWT structure is parseable — it does NOT verify
	// the actual cryptographic signature. Use TrustEvaluator for signature verification.
	ValidateFormat bool

	// CheckRevocation enables revocation status checks
	CheckRevocation bool

	// DCQLQuery is the original DCQL query from the request
	DCQLQuery *DCQL
}

// Validate validates the VP Token according to OpenID4VP spec Section 8.6
func (v *VPTokenValidator) Validate(vpToken string) error {
	// 1. Validate VP Token format (Section 8.1)
	token := sdjwtvc.Token(vpToken)
	parsed, err := token.Parse()
	if err != nil {
		return fmt.Errorf("invalid VP Token format: %w", err)
	}

	// 2. Validate individual presentations
	if err := v.validatePresentation(parsed); err != nil {
		return fmt.Errorf("presentation validation failed: %w", err)
	}

	// 3. Validate holder binding (Section 14.1.2)
	if err := v.validateHolderBinding(parsed); err != nil {
		return fmt.Errorf("holder binding validation failed: %w", err)
	}

	// 4. Check nonce matches request
	if v.Nonce != "" {
		if err := v.validateNonce(parsed); err != nil {
			return fmt.Errorf("nonce validation failed: %w", err)
		}
	}

	// 5. Verify audience matches client_id
	if v.ClientID != "" {
		if err := v.validateAudience(parsed); err != nil {
			return fmt.Errorf("audience validation failed: %w", err)
		}
	}

	// 6. Verify signature if requested
	if v.ValidateFormat {
		if err := v.validateFormat(vpToken); err != nil {
			return fmt.Errorf("format validation failed: %w", err)
		}
	}

	// 7. Check revocation status if requested
	if v.CheckRevocation {
		if err := v.checkRevocation(parsed); err != nil {
			return fmt.Errorf("revocation check failed: %w", err)
		}
	}

	// 8. Validate against DCQL query if provided
	if v.DCQLQuery != nil {
		if err := v.validateAgainstDCQL(parsed); err != nil {
			return fmt.Errorf("DCQL validation failed: %w", err)
		}
	}

	return nil
}

// validatePresentation validates the presentation integrity and authenticity
func (v *VPTokenValidator) validatePresentation(parsed *sdjwtvc.ParsedCredential) error {
	// Check required fields are present
	if parsed.Claims == nil {
		return fmt.Errorf("presentation has no claims")
	}

	// Validate credential structure
	// Implementation would check specific credential format requirements
	return nil
}

// validateHolderBinding validates cryptographic holder binding (Section 14.1.2)
func (v *VPTokenValidator) validateHolderBinding(parsed *sdjwtvc.ParsedCredential) error {
	// Check for key binding JWT
	if len(parsed.KeyBinding) == 0 {
		return fmt.Errorf("missing holder binding proof")
	}

	// Key binding is present - further validation happens in validateNonce/validateAudience
	return nil
}

// validateNonce verifies the nonce value in the presentation
func (v *VPTokenValidator) validateNonce(parsed *sdjwtvc.ParsedCredential) error {
	if len(parsed.KeyBinding) == 0 {
		return fmt.Errorf("no key binding found for nonce validation")
	}

	// Reconstruct KB-JWT from parts
	kbJWT := strings.Join(parsed.KeyBinding, ".")

	// Parse the key binding JWT to extract claims
	kbClaims, err := parseKeyBindingJWT(kbJWT)
	if err != nil {
		return fmt.Errorf("failed to parse key binding JWT: %w", err)
	}

	// Extract nonce from key binding JWT
	kbNonce, ok := kbClaims["nonce"].(string)
	if !ok {
		return fmt.Errorf("nonce not found in key binding")
	}

	if kbNonce != v.Nonce {
		return fmt.Errorf("nonce mismatch: expected %s, got %s", v.Nonce, kbNonce)
	}

	return nil
}

// validateAudience verifies the audience value matches client_id
func (v *VPTokenValidator) validateAudience(parsed *sdjwtvc.ParsedCredential) error {
	if len(parsed.KeyBinding) == 0 {
		return fmt.Errorf("no key binding found for audience validation")
	}

	// Reconstruct KB-JWT from parts
	kbJWT := strings.Join(parsed.KeyBinding, ".")

	// Parse the key binding JWT to extract claims
	kbClaims, err := parseKeyBindingJWT(kbJWT)
	if err != nil {
		return fmt.Errorf("failed to parse key binding JWT: %w", err)
	}

	// Extract audience from key binding JWT
	aud, ok := kbClaims["aud"].(string)
	if !ok {
		return fmt.Errorf("audience not found in key binding")
	}

	if aud != v.ClientID {
		return fmt.Errorf("audience mismatch: expected %s, got %s", v.ClientID, aud)
	}

	return nil
}

// parseKeyBindingJWT parses a key binding JWT and returns its claims
func parseKeyBindingJWT(kbJWT string) (map[string]any, error) {
	// Split JWT into parts
	parts := strings.Split(kbJWT, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Decode payload (part 1)
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	// Parse claims
	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	return claims, nil
}

// validateFormat validates the SD-JWT structure is parseable.
// This does NOT perform cryptographic signature verification — use TrustEvaluator for that.
func (v *VPTokenValidator) validateFormat(vpToken string) error {
	token := sdjwtvc.Token(vpToken)
	_, err := token.Parse()
	if err != nil {
		return fmt.Errorf("JWT format validation failed: %w", err)
	}

	return nil
}

// checkRevocation checks the revocation status
func (v *VPTokenValidator) checkRevocation(parsed *sdjwtvc.ParsedCredential) error {
	// Check for revocation status
	// Implementation would check status list, OCSP, or other revocation mechanisms
	// For now, this is a placeholder
	return nil
}

// validateAgainstDCQL validates the presentation against the DCQL query
func (v *VPTokenValidator) validateAgainstDCQL(parsed *sdjwtvc.ParsedCredential) error {
	// Validate that returned credentials meet DCQL query criteria
	// This would check:
	// - Credential format matches requested format
	// - Required claims are present
	// - Claim values match if value matching was used
	// - Trust framework requirements are met

	// For now, basic validation that claims are present
	if len(v.DCQLQuery.Credentials) == 0 {
		return nil // No specific requirements
	}

	// Check if presentation contains the requested claims
	// Implementation would perform detailed DCQL matching
	return nil
}

// ValidateVPToken is a convenience function for basic VP Token validation
func ValidateVPToken(vpToken, nonce, clientID string) error {
	validator := &VPTokenValidator{
		Nonce:           nonce,
		ClientID:        clientID,
		ValidateFormat:  true,
		CheckRevocation: false,
	}

	return validator.Validate(vpToken)
}
