package trust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// WalletAttestationResult holds the outcome of a wallet attestation trust evaluation.
type WalletAttestationResult struct {
	// Trusted indicates whether the PDP approved the wallet attestation.
	Trusted bool
	// Issuer is the wallet provider identifier.
	// Derived from `iss` claim (IETF draft) or x5c leaf certificate SAN/CN (TS03).
	Issuer string
	// Subject is the wallet instance identifier (sub claim = JWK thumbprint).
	Subject string
	// AttestationSource indicates the attestation tier (e.g., "backend_attested",
	// "ios_app_attest", "android_play_integrity"). Empty if not present in the WIA.
	AttestationSource string
	// Reason is the PDP's trust decision reason.
	Reason string
	// TrustFramework identifies which mechanism validated the attestation.
	TrustFramework string
}

// WalletAttestationEvaluator evaluates wallet attestation JWTs by delegating the
// trust decision to the go-trust AuthZEN PDP. The PDP validates the wallet provider's
// signature against its configured trust lists and federation anchors.
//
// Supports two WIA formats:
//   - IETF draft-ietf-oauth-attestation-based-client-auth: iss claim present
//   - EC TS03 §2.2.1 (EUDI): no iss, identity from x5c certificate chain in header
//
// PKCE (mandatory for public clients) is the sole code-binding mechanism.
type WalletAttestationEvaluator struct {
	TrustEvaluator TrustEvaluator
}

// NewWalletAttestationEvaluator creates a new evaluator.
func NewWalletAttestationEvaluator(evaluator TrustEvaluator) *WalletAttestationEvaluator {
	return &WalletAttestationEvaluator{TrustEvaluator: evaluator}
}

// Evaluate verifies a wallet attestation JWT via the trust PDP.
func (e *WalletAttestationEvaluator) Evaluate(ctx context.Context, attestation string) (*WalletAttestationResult, error) {
	if e.TrustEvaluator == nil {
		return nil, errors.New("no trust evaluator configured (pdp_url required)")
	}

	// Extract routing info (PDP performs actual signature verification)
	identity, err := parseAttestationIdentity(attestation)
	if err != nil {
		return nil, err
	}

	// Build evaluation request based on key type
	evalReq := &EvaluationRequest{}
	evalReq.SubjectID = identity.issuer
	evalReq.Role = RoleWalletProvider

	if identity.hasX5C {
		// x5c-based WIA (TS03): send cert chain for validation
		evalReq.KeyType = KeyTypeX5C
		evalReq.Key = identity.x5cChain
	} else {
		// iss-based WIA (IETF draft): send raw JWT for JWK-based validation
		evalReq.KeyType = KeyTypeJWK
		evalReq.Key = attestation
	}

	decision, err := e.TrustEvaluator.Evaluate(ctx, evalReq)
	if err != nil {
		return nil, fmt.Errorf("wallet attestation trust evaluation failed: %w", err)
	}

	result := &WalletAttestationResult{
		Trusted:           decision.Trusted,
		Issuer:            identity.issuer,
		Subject:           identity.sub,
		AttestationSource: identity.attestationSource,
		Reason:            decision.Reason,
		TrustFramework:    decision.TrustFramework,
	}

	if !decision.Trusted {
		return result, fmt.Errorf("wallet provider %q not trusted: %s", identity.issuer, decision.Reason)
	}
	if identity.sub == "" {
		return nil, errors.New("wallet attestation missing required 'sub' claim")
	}

	return result, nil
}

// EvaluateWithPoP validates a wallet attestation (WIA) and its PoP JWT per
// draft-ietf-oauth-attestation-based-client-auth-04 §3.1 and §5.2.
//
// When popJWT is non-empty, it validates:
//   - typ header = "oauth-client-attestation-pop+jwt"
//   - signature matches the cnf.jwk from the WIA
//   - aud claim contains the expectedAudience (this AS's issuer URL)
//   - exp is not in the past, iat is present
//
// When popJWT is empty (legacy form-body mode), only the WIA is validated.
func (e *WalletAttestationEvaluator) EvaluateWithPoP(ctx context.Context, attestation, popJWT, expectedAudience string) (*WalletAttestationResult, error) {
	// First evaluate the WIA itself via PDP
	result, err := e.Evaluate(ctx, attestation)
	if err != nil {
		return result, err
	}

	// If no PoP provided (legacy mode), accept without PoP validation.
	// This maintains backward compatibility with form-body client_assertion.
	if popJWT == "" {
		return result, nil
	}

	// Validate PoP JWT per §5.2
	if err := validateAttestationPoP(attestation, popJWT, expectedAudience); err != nil {
		return nil, fmt.Errorf("attestation PoP validation failed: %w", err)
	}

	return result, nil
}

// validateAttestationPoP validates an OAuth-Client-Attestation-PoP JWT.
// It extracts the cnf.jwk from the WIA and verifies the PoP signature and claims.
func validateAttestationPoP(attestation, popJWT, expectedAudience string) error {
	// Extract cnf.jwk from the WIA (we trust the WIA since PDP validated it)
	cnfKey, err := extractCNFKeyFromWIA(attestation)
	if err != nil {
		return fmt.Errorf("extract cnf key from WIA: %w", err)
	}

	// Parse and validate the PoP JWT
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(popJWT, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected PoP signing method: %v", t.Header["alg"])
		}
		return cnfKey, nil
	}, jwt.WithValidMethods([]string{"ES256", "ES384", "ES512"}),
		jwt.WithLeeway(30*time.Second),
		jwt.WithExpirationRequired())
	if err != nil {
		return fmt.Errorf("PoP signature verification: %w", err)
	}

	// Validate typ header
	typ, _ := token.Header["typ"].(string)
	if typ != "oauth-client-attestation-pop+jwt" {
		return fmt.Errorf("invalid PoP typ %q, expected oauth-client-attestation-pop+jwt", typ)
	}

	// Validate aud contains our AS issuer URL
	if expectedAudience != "" {
		audValid := false
		for _, aud := range claims.Audience {
			if aud == expectedAudience {
				audValid = true
				break
			}
		}
		if !audValid {
			return fmt.Errorf("PoP aud %v does not contain expected audience %q", claims.Audience, expectedAudience)
		}
	}

	// exp is required (jwt.WithExpirationRequired) and already validated by jwt.Parse (with leeway)
	// iat presence check
	if claims.IssuedAt == nil {
		return errors.New("PoP missing iat claim")
	}

	return nil
}

// extractCNFKeyFromWIA parses the WIA JWT and extracts the EC public key from cnf.jwk.
func extractCNFKeyFromWIA(attestation string) (*ecdsa.PublicKey, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(attestation, jwt.MapClaims{}) //nolint:gosec // PDP already validated
	if err != nil {
		return nil, fmt.Errorf("parse WIA: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("unexpected claims type")
	}

	cnfRaw, ok := claims["cnf"]
	if !ok {
		return nil, errors.New("WIA missing cnf claim")
	}
	cnf, ok := cnfRaw.(map[string]interface{})
	if !ok {
		return nil, errors.New("WIA cnf claim is not an object")
	}

	jwkRaw, ok := cnf["jwk"]
	if !ok {
		return nil, errors.New("WIA cnf missing jwk")
	}
	jwk, ok := jwkRaw.(map[string]interface{})
	if !ok {
		return nil, errors.New("WIA cnf.jwk is not an object")
	}

	return parseECPublicKeyFromCNF(jwk)
}

// parseECPublicKeyFromCNF parses an EC public key from a JWK map (P-256, P-384, P-521).
func parseECPublicKeyFromCNF(jwk map[string]interface{}) (*ecdsa.PublicKey, error) {
	kty, _ := jwk["kty"].(string)
	if kty != "EC" {
		return nil, fmt.Errorf("unsupported cnf key type %q, expected EC", kty)
	}

	crv, _ := jwk["crv"].(string)
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve %q", crv)
	}

	xB64, _ := jwk["x"].(string)
	yB64, _ := jwk["y"].(string)
	if xB64 == "" || yB64 == "" {
		return nil, errors.New("cnf.jwk missing x or y coordinate")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xB64)
	if err != nil {
		return nil, fmt.Errorf("decode x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yB64)
	if err != nil {
		return nil, fmt.Errorf("decode y: %w", err)
	}

	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	if !curve.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("cnf.jwk point is not on curve")
	}

	return pub, nil
}

// attestationIdentity holds parsed identity information from a WIA JWT.
type attestationIdentity struct {
	issuer            string   // wallet provider identifier
	sub               string   // wallet instance identifier (JWK thumbprint)
	attestationSource string   // tier indicator (may be empty)
	hasX5C            bool     // true if x5c header is present
	x5cChain          []string // base64-encoded certificate chain (when hasX5C)
}

// parseAttestationIdentity extracts identity from a WIA JWT.
// Handles two formats:
//   - If `iss` claim present: use as issuer (IETF draft format)
//   - If x5c header present and no iss: derive issuer from leaf cert (TS03 format)
func parseAttestationIdentity(attestation string) (*attestationIdentity, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, parseErr := parser.ParseUnverified(attestation, jwt.MapClaims{}) //nolint:gosec // PDP verifies
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse wallet attestation: %w", parseErr)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("unexpected JWT claims type")
	}

	result := &attestationIdentity{}

	// Extract sub (wallet instance identifier)
	result.sub, _ = claims["sub"].(string)

	// Extract attestation_source (tier indicator) — may be absent
	result.attestationSource, _ = claims["attestation_source"].(string)

	// Extract iss claim (may be absent in TS03 format)
	issClaim, _ := claims["iss"].(string)

	// Check for x5c in JWT header
	if x5cRaw, ok := token.Header["x5c"]; ok {
		if x5cArr, ok := x5cRaw.([]interface{}); ok && len(x5cArr) > 0 {
			result.hasX5C = true
			for _, cert := range x5cArr {
				if s, ok := cert.(string); ok {
					result.x5cChain = append(result.x5cChain, s)
				}
			}

			// Fail closed: x5c header present but no valid cert strings extracted.
			// This prevents falling back to self-asserted iss with a malformed x5c.
			if len(result.x5cChain) == 0 {
				return nil, errors.New("x5c header present but contains no valid certificate strings")
			}

			// When x5c is present, identity MUST come from the certificate.
			// The x5c chain is the cryptographic proof; iss is self-asserted
			// and must not override the cert-derived identity.
			if len(result.x5cChain) > 0 {
				certIdentity, err := issuerFromX5CLeaf(result.x5cChain[0])
				if err != nil {
					return nil, fmt.Errorf("failed to extract issuer from x5c: %w", err)
				}
				// If iss is present, validate consistency (not strict equality —
				// iss is typically a URL like "https://host" while cert SAN is
				// a bare hostname "host")
				if issClaim != "" && !issMatchesCertIdentity(issClaim, certIdentity) {
					return nil, fmt.Errorf("iss claim %q does not match x5c certificate identity %q", issClaim, certIdentity)
				}
				result.issuer = certIdentity
			}
		}
	}

	// No x5c: use iss claim (IETF draft format — PDP validates via JWKS)
	if result.issuer == "" {
		result.issuer = issClaim
	}

	if result.issuer == "" {
		return nil, errors.New("wallet attestation has neither 'iss' claim nor x5c header")
	}

	return result, nil
}

// issuerFromX5CLeaf extracts a wallet provider identifier from the leaf certificate.
// Preference order: DNS SAN > URI SAN > Subject CN.
func issuerFromX5CLeaf(b64Cert string) (string, error) {
	der, err := base64.StdEncoding.DecodeString(b64Cert)
	if err != nil {
		return "", fmt.Errorf("invalid base64 in x5c: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", fmt.Errorf("invalid certificate in x5c: %w", err)
	}

	// Prefer SAN DNS name (matches x509_san_dns pattern)
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0], nil
	}
	// Prefer SAN URI
	if len(cert.URIs) > 0 {
		return cert.URIs[0].String(), nil
	}
	// Fall back to CN
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName, nil
	}
	return "", errors.New("x5c leaf has no SAN or CN to derive issuer identity")
}

// issMatchesCertIdentity checks if an iss claim is consistent with a cert-derived identity.
// Handles the common case where iss is a URL ("https://host") and cert identity is
// a bare hostname ("host") from a DNS SAN, or iss is a full URI matching a URI SAN.
func issMatchesCertIdentity(iss, certIdentity string) bool {
	// Exact match (URI SAN, CN, or iss happens to be bare hostname)
	if iss == certIdentity {
		return true
	}
	// iss is a URL whose host matches the cert's DNS SAN
	if u, err := url.Parse(iss); err == nil && u.Host != "" {
		if u.Host == certIdentity {
			return true
		}
	}
	return false
}
