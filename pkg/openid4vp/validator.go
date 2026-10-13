package openid4vp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/SUNET/vc/pkg/sdjwtvc"

	jwt "github.com/golang-jwt/jwt/v5"
)

// VPTokenValidator validates VP Token according to Section 8.6
//
// It verifies the HOLDER's signature - the Key Binding JWT, against the
// key the credential names in cnf - because that is what makes the
// presentation the holder's and nothing else can do it: the key is inside
// the credential being presented.
//
// It does NOT verify the ISSUER's signature or evaluate trust in the
// issuer. Those need a resolved key and a policy, and the caller does them
// (EvaluateIssuerTrust). Both halves are required: this one says the right
// person presented it, the other says the credential is worth anything.
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

	// TransactionData from the Authorization Request (raw base64url strings). When non-empty, the validator checks that the KB-JWT contains matching transaction_data_hashes.
	TransactionData []string
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
	if err := v.validateHolderBinding(vpToken, parsed); err != nil {
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

	// 6. Verify transaction data hashes (Section 8.4)
	if len(v.TransactionData) > 0 {
		if err := v.validateTransactionData(parsed); err != nil {
			return fmt.Errorf("transaction data validation failed: %w", err)
		}
	}

	// 7. Verify signature if requested
	if v.ValidateFormat {
		if err := v.validateFormat(vpToken); err != nil {
			return fmt.Errorf("format validation failed: %w", err)
		}
	}

	// 8. Check revocation status if requested
	if v.CheckRevocation {
		if err := v.checkRevocation(parsed); err != nil {
			return fmt.Errorf("revocation check failed: %w", err)
		}
	}

	// 9. Validate against DCQL query if provided
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

// validateHolderBinding verifies cryptographic holder binding
// (OpenID4VP §14.1.2).
//
// This is what makes a presentation mean "I hold this credential" rather
// than "this credential exists". It checked only that a Key Binding JWT
// was PRESENT, and the nonce and audience were then read out of its
// payload without anyone verifying who signed it - so a copy of a genuine
// credential plus a self-made KB-JWT carrying the expected nonce and
// audience was accepted as its holder's presentation.
//
// Three things have to hold, and all three are the holder's:
//
//   - the credential has to name a holder key, in cnf. One that names
//     none cannot be presented at all, rather than being presentable by
//     anybody;
//   - the KB-JWT has to be signed by that key;
//   - its sd_hash has to cover the SD-JWT actually presented, or the
//     proof belongs to some other presentation of the same credential.
//
// Nonce and audience are still checked separately, by validateNonce and
// validateAudience. They read the same payload, which is now a payload
// somebody proved they could produce.
func (v *VPTokenValidator) validateHolderBinding(vpToken string, parsed *sdjwtvc.ParsedCredential) error {
	if len(parsed.KeyBinding) == 0 {
		return fmt.Errorf("missing holder binding proof")
	}

	cnf, ok := parsed.Claims["cnf"].(map[string]any)
	if !ok {
		return fmt.Errorf("credential carries no cnf claim, so it names no holder")
	}
	jwkMap, ok := cnf["jwk"].(map[string]any)
	if !ok {
		return fmt.Errorf("credential's cnf claim carries no jwk")
	}
	holderKey, err := sdjwtvc.JWKToPublicKey(jwkMap)
	if err != nil {
		return fmt.Errorf("reading the holder key the credential names: %w", err)
	}

	kbJWT := strings.Join(parsed.KeyBinding, ".")

	// Claims validation is off here deliberately: iat on a KB-JWT is the
	// moment of presentation, and a clock skew between wallet and verifier
	// would otherwise reject an honest holder. What this call is for is
	// the signature.
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, err := parser.Parse(kbJWT, func(*jwt.Token) (any, error) { return holderKey, nil })
	if err != nil {
		return fmt.Errorf("key binding JWT is not signed by the key the credential names: %w", err)
	}
	if typ, _ := token.Header["typ"].(string); typ != "kb+jwt" {
		return fmt.Errorf("key binding JWT has typ %q, which must be kb+jwt", typ)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("key binding JWT carries no claims")
	}

	// sd_hash ties the proof to THIS presentation. Without it a KB-JWT
	// made for one presentation of a credential is a KB-JWT for every
	// presentation of it, with whatever disclosures the sender chooses.
	presented := vpToken
	if idx := strings.LastIndex(vpToken, "~"); idx >= 0 {
		presented = vpToken[:idx+1]
	}
	sum := sha256.Sum256([]byte(presented))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if got, _ := claims["sd_hash"].(string); got != want {
		return fmt.Errorf("key binding JWT's sd_hash does not cover the presentation it arrived in")
	}

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

// validateTransactionData verifies that the KB-JWT contains transaction_data_hashes
// that match the TransactionData from the authorization request per OpenID4VP §8.4.
func (v *VPTokenValidator) validateTransactionData(parsed *sdjwtvc.ParsedCredential) error {
	if len(parsed.KeyBinding) == 0 {
		return fmt.Errorf("no key binding found for transaction data validation")
	}

	kbJWT := strings.Join(parsed.KeyBinding, ".")
	kbClaims, err := parseKeyBindingJWT(kbJWT)
	if err != nil {
		return fmt.Errorf("failed to parse key binding JWT: %w", err)
	}

	// Extract transaction_data_hashes_alg
	hashAlg, ok := kbClaims["transaction_data_hashes_alg"].(string)
	if !ok || hashAlg == "" {
		return &ErrorResponse{
			ErrorCode:        ErrorInvalidTransactionData,
			ErrorDescription: "transaction_data_hashes_alg missing from KB-JWT",
		}
	}

	// Extract transaction_data_hashes array
	hashesRaw, ok := kbClaims["transaction_data_hashes"].([]any)
	if !ok || len(hashesRaw) == 0 {
		return &ErrorResponse{
			ErrorCode:        ErrorInvalidTransactionData,
			ErrorDescription: "transaction_data_hashes missing from KB-JWT",
		}
	}

	expectedCount := len(v.TransactionData)

	if len(hashesRaw) != expectedCount {
		return &ErrorResponse{
			ErrorCode:        ErrorInvalidTransactionData,
			ErrorDescription: fmt.Sprintf("transaction_data_hashes count mismatch: expected %d, got %d", expectedCount, len(hashesRaw)),
		}
	}

	// Re-compute expected hashes from the original transaction data
	expectedHashes, err := HashTransactionData(v.TransactionData, hashAlg)
	if err != nil {
		return &ErrorResponse{
			ErrorCode:        ErrorInvalidTransactionData,
			ErrorDescription: fmt.Sprintf("unsupported transaction_data_hashes_alg %q: %v", hashAlg, err),
		}
	}

	for i, raw := range hashesRaw {
		got, ok := raw.(string)
		if !ok {
			return &ErrorResponse{
				ErrorCode:        ErrorInvalidTransactionData,
				ErrorDescription: fmt.Sprintf("transaction_data_hashes[%d] is not a string", i),
			}
		}
		if got != expectedHashes[i] {
			return &ErrorResponse{
				ErrorCode:        ErrorInvalidTransactionData,
				ErrorDescription: fmt.Sprintf("transaction_data_hashes[%d] mismatch", i),
			}
		}
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
