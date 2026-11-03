package openid4vp

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	// keyBindingClockSkew is the tolerance applied to both ends of the
	// KB-JWT iat check. The timestamp is the wallet's, so a holder whose
	// clock is slightly off is not an attacker. Matches
	// pkg/openid4vci's proofIatClockSkew for the same kind of
	// client-supplied iat.
	keyBindingClockSkew = 30 * time.Second

	// defaultMaxKeyBindingAge bounds how long after making a proof a
	// holder may present it. Generous, because the honest gap is network
	// latency and a wallet's clock error, not user think-time: iat is
	// stamped when the KB-JWT is signed, which is the moment of sending.
	// Overridable per validator for deployments that know their clocks
	// are worse.
	defaultMaxKeyBindingAge = 10 * time.Minute
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

	// CredentialQueryID is the DCQL credential query id this presentation
	// answers. When set, only the TransactionData entries whose credential_ids
	// reference it are checked against this presentation's KB-JWT (see
	// TransactionDataForCredential for why). Empty means every entry.
	CredentialQueryID string

	// ResponseModes are the response_mode values the request was issued with.
	// An EC TS12 KB-JWT must echo one of them; empty means the claim cannot
	// be checked, which refuses an SCA presentation.
	ResponseModes []string

	// PresentedJTI is an output: after a successful Validate of an EC TS12
	// SCA presentation it holds the KB-JWT jti. It is empty when no SCA entry
	// applied. The caller must record it in a replay store after issuer
	// authentication and treat a value already recorded as a refusal.
	PresentedJTI string

	// MaxKeyBindingAge bounds how old a Key Binding JWT's iat may be.
	// Zero means defaultMaxKeyBindingAge.
	MaxKeyBindingAge time.Duration
}

// Validate validates the VP Token according to OpenID4VP spec Section 8.6
func (v *VPTokenValidator) Validate(vpToken string) error {
	// The jti output belongs to THIS presentation, so it is cleared
	// before anything can read it.
	//
	// It is written only when an SCA entry applies, and the caller claims
	// a non-empty value in a replay store - a state change that refuses the
	// presentation if the value was already claimed. A validator reused
	// for a second presentation that is not an SCA one would otherwise
	// still carry the first jti, and the caller would claim it a second
	// time and reject an unrelated, valid presentation as a replay.
	v.PresentedJTI = ""

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
	holderKey, err := jose.ParseJWKToPublicKey(jwkMap)
	if err != nil {
		return fmt.Errorf("reading the holder key the credential names: %w", err)
	}
	// Issuance accepts EC, RSA, RSA-PSS and Ed25519 proof keys and copies
	// the proof's JWK into cnf, so all four have to be presentable here.
	// Anything else is refused by type rather than by what the parser
	// happened to return: a symmetric JWK would come back as bytes, and a
	// KB-JWT signed HS256 with those same bytes would then "verify",
	// proving possession of nothing the issuer did not publish inside the
	// credential.
	switch holderKey.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
	default:
		return fmt.Errorf("credential names a %T holder key, which cannot prove possession", holderKey)
	}

	kbJWT := strings.Join(parsed.KeyBinding, ".")

	// The library's own claims validation is off because a KB-JWT has
	// none of the claims it would check - no exp, and an aud this package
	// checks itself against the client_id. iat it would not check at all.
	// The temporal check that does belong here is made below, explicitly.
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

	if err := v.validateKeyBindingAge(claims); err != nil {
		return err
	}

	// sd_hash ties the proof to THIS presentation. Without it a KB-JWT
	// made for one presentation of a credential is a KB-JWT for every
	// presentation of it, with whatever disclosures the sender chooses.
	//
	// Under the issuer's _sd_alg, not sha-256: that claim is what says
	// which hash the holder was told to use, and this repository issues
	// and key-binds sha-384, sha-512 and the SHA-3 variants too.
	// Hard-coding sha-256 would reject every honest holder of one of
	// those.
	sdAlg, err := issuerSDAlg(vpToken)
	if err != nil {
		return err
	}
	hashMethod, err := sdjwtvc.HashFromAlgorithm(sdAlg)
	if err != nil {
		return fmt.Errorf("credential declares _sd_alg %q: %w", sdAlg, err)
	}
	presented := vpToken
	if idx := strings.LastIndex(vpToken, "~"); idx >= 0 {
		presented = vpToken[:idx+1]
	}
	hashMethod.Reset()
	hashMethod.Write([]byte(presented))
	want := base64.RawURLEncoding.EncodeToString(hashMethod.Sum(nil))
	if got, _ := claims["sd_hash"].(string); got != want {
		return fmt.Errorf("key binding JWT's sd_hash does not cover the presentation it arrived in")
	}

	return nil
}

// validateKeyBindingAge checks the KB-JWT's iat, which SD-JWT §4.3 makes
// REQUIRED and which says when the holder made this proof.
//
// Freshness is the nonce's job and the nonce does it well: it is this
// request's, so a proof carrying it cannot predate the request whatever
// its iat says. What iat adds is a bound that does not depend on the
// verifier having issued a nonce at all - this validator runs with Nonce
// empty in some flows - and a refusal for the proof that is simply not
// well formed. Leaving a required claim entirely unread means a KB-JWT
// with no iat, a string where a number belongs, or a timestamp years out
// is accepted as readily as an honest one.
//
// Both bounds carry a skew tolerance, because the timestamp comes from
// the wallet's clock and not ours: an honest holder whose phone is a
// minute fast is still an honest holder. The same reasoning, and the same
// 30 seconds, as the proof JWT check in pkg/openid4vci.
func (v *VPTokenValidator) validateKeyBindingAge(claims jwt.MapClaims) error {
	iat, err := claims.GetIssuedAt()
	if err != nil {
		return fmt.Errorf("key binding JWT's iat is not a timestamp: %w", err)
	}
	if iat == nil {
		return fmt.Errorf("key binding JWT carries no iat, which it is required to carry")
	}

	maxAge := v.MaxKeyBindingAge
	if maxAge <= 0 {
		maxAge = defaultMaxKeyBindingAge
	}

	now := time.Now()
	if iat.After(now.Add(keyBindingClockSkew)) {
		return fmt.Errorf("key binding JWT is dated %s into the future", iat.Sub(now).Round(time.Second))
	}
	if age := now.Sub(iat.Time); age > maxAge+keyBindingClockSkew {
		return fmt.Errorf("key binding JWT was made %s ago, beyond the %s a presentation is accepted within", age.Round(time.Second), maxAge)
	}
	return nil
}

// issuerSDAlg reads the hash algorithm the issuer declared in _sd_alg,
// which is the algorithm sd_hash is taken under (SD-JWT §4.3.1).
//
// It reads the issuer-signed payload again rather than the parsed claims
// because parsing resolves the disclosures and then deletes _sd and
// _sd_alg from the claim tree - by the time the validator sees the
// credential, the algorithm it was built with is gone.
//
// Absent means sha-256, per the spec's default. Present but unreadable is
// an error, not a fallback to the default.
func issuerSDAlg(vpToken string) (string, error) {
	_, body, _, _, _, err := sdjwtvc.Token(vpToken).Split()
	if err != nil {
		return "", fmt.Errorf("reading the issuer-signed payload: %w", err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return "", fmt.Errorf("decoding the issuer-signed payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("parsing the issuer-signed payload: %w", err)
	}
	raw, present := claims["_sd_alg"]
	if !present {
		return "sha-256", nil
	}
	sdAlg, ok := raw.(string)
	if !ok || sdAlg == "" {
		return "", fmt.Errorf("credential declares a non-string _sd_alg (%T), so the hash sd_hash was taken under is unknown", raw)
	}
	return sdAlg, nil
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
// that match the TransactionData from the authorization request per OpenID4VP
// Appendix B.3.3.1 and, when an entry is an EC TS12 SCA type, the TS12 v1.0.1
// section 3.6 claims. Every failure is invalid_transaction_data: a response
// this cannot positively match to what was sent is refused.
func (v *VPTokenValidator) validateTransactionData(parsed *sdjwtvc.ParsedCredential) error {
	if len(parsed.KeyBinding) == 0 {
		return fmt.Errorf("no key binding found for transaction data validation")
	}

	entries, err := decodeTransactionData(v.TransactionData)
	if err != nil {
		return txError("%v", err)
	}
	if v.CredentialQueryID != "" {
		scoped := entries[:0:0]
		for _, e := range entries {
			if slices.Contains(e.CredentialIDs, v.CredentialQueryID) {
				scoped = append(scoped, e)
			}
		}
		entries = scoped
	}
	if len(entries) == 0 {
		// Nothing in the request is bound to this credential.
		return nil
	}

	kbJWT := strings.Join(parsed.KeyBinding, ".")
	kbClaims, err := parseKeyBindingJWT(kbJWT)
	if err != nil {
		return fmt.Errorf("failed to parse key binding JWT: %w", err)
	}

	// transaction_data_hashes_alg: a STRING in the KB-JWT. REQUIRED when the
	// request carried a list; the sha-256 default applies when it did not.
	allowed := allowedHashAlgs(entries)
	hashAlg := TransactionDataHashAlgDefault
	if claim, present := kbClaims["transaction_data_hashes_alg"]; present {
		s, ok := claim.(string)
		if !ok || s == "" {
			return txError("transaction_data_hashes_alg in KB-JWT must be a string")
		}
		hashAlg = s
	} else if slices.ContainsFunc(entries, func(e decodedTransactionData) bool { return e.HasAlgList }) {
		return txError("transaction_data_hashes_alg missing from KB-JWT")
	}
	if !slices.Contains(allowed, hashAlg) {
		return txError("transaction_data_hashes_alg %q is not one the request allowed", hashAlg)
	}

	hashesRaw, ok := kbClaims["transaction_data_hashes"].([]any)
	if !ok || len(hashesRaw) == 0 {
		return txError("transaction_data_hashes missing from KB-JWT")
	}
	if len(hashesRaw) != len(entries) {
		return txError("transaction_data_hashes count mismatch: expected %d, got %d", len(entries), len(hashesRaw))
	}

	raws := make([]string, len(entries))
	for i, e := range entries {
		raws[i] = e.Raw
	}
	// Over the strings as sent, never a re-encoding of a decoded object.
	expectedHashes, err := HashTransactionData(raws, hashAlg)
	if err != nil {
		return txError("unsupported transaction_data_hashes_alg %q: %v", hashAlg, err)
	}
	for i, raw := range hashesRaw {
		got, ok := raw.(string)
		if !ok {
			return txError("transaction_data_hashes[%d] is not a string", i)
		}
		if got != expectedHashes[i] {
			return txError("transaction_data_hashes[%d] mismatch", i)
		}
	}

	if slices.ContainsFunc(entries, func(e decodedTransactionData) bool { return strings.HasPrefix(e.Type, TS12TypePrefix) }) {
		return v.validateTS12Claims(kbClaims)
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
