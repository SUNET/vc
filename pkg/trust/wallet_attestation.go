package trust

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"

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
// Uses the first DNS SAN if available, otherwise falls back to the Subject CN.
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
