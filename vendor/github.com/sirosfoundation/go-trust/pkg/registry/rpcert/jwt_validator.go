// Deprecated WRPRC JWT validator, retained for compatibility.
//
// This type predates the three-step model the package now follows and
// conflates all three steps in one call, which is why nothing in this
// repository uses it. Prefer verifying the signature yourself, then
// ParseWRPRCClaims, then the evaluation primitives - see doc.go.

package rpcert

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// OIDWRPRCPolicy is the WRPRC certificate policy OID per ETSI TS 119 475
// v1.1.1, clause OVR-6.1.3-01.
//
//	wrprc OBJECT IDENTIFIER ::=
//	  { itu-t(0) identified-organization(4) etsi(0) eudiwrpa(19475) policy-identifiers(3) wrprc(1) }
const OIDWRPRCPolicy = "0.4.0.19475.3.1"

// WRPRCTyp is the JWT `typ` header value for a WRPRC per Table 5.
const WRPRCTyp = "rc-wrp+jwt"

// JWTRegistrationCertValidator checks a WRPRC JWT's x5c chain and decodes
// its payload.
//
// Deprecated: this type does not verify the JWT signature, despite its name.
// It checks that the certificate chain in the x5c header leads to a trusted
// root, then decodes the payload - but never checks that the payload was
// signed by the key in that chain. A payload swapped under an authentic
// header therefore passes. go-trust has no JWS implementation and should not
// grow one: signature verification is the caller's step, not a trust
// registry's.
//
// Callers should verify the signature themselves, then call
// ParseWRPRCClaims on the payload, then evaluate the chain with their own
// trust anchors. Because the signature is unverified here, the returned
// entitlements carry StatusUnknown, so IsValid reports false and nothing
// that gates on it can mistake this for a validated document.
type JWTRegistrationCertValidator struct {
	// roots is the certificate pool for WRPRC provider CAs (from Trusted List).
	roots *x509.CertPool
}

// NewJWTRegistrationCertValidator creates a new WRPRC JWT validator.
// roots must contain the trusted WRPRC provider CA certificates from the
// national Trusted List. Passing nil roots causes all validations to fail.
//
// Deprecated: see JWTRegistrationCertValidator.
func NewJWTRegistrationCertValidator(roots *x509.CertPool) *JWTRegistrationCertValidator {
	return &JWTRegistrationCertValidator{roots: roots}
}

// Format returns "jwt".
func (v *JWTRegistrationCertValidator) Format() string {
	return "jwt"
}

// jwtHeader holds the fields we care about from the WRPRC JWT header.
type jwtHeader struct {
	Typ string   `json:"typ"`
	Alg string   `json:"alg"`
	X5C []string `json:"x5c"`
}

// Validate checks the typ header, evaluates the x5c chain against the
// configured roots, and decodes the payload via ParseWRPRCClaims.
//
// Deprecated: the JWT signature is not verified - see
// JWTRegistrationCertValidator. The result is returned with
// RegistrationStatus StatusUnknown for that reason.
func (v *JWTRegistrationCertValidator) Validate(_ context.Context, certData []byte) (*RPEntitlements, error) {
	if v.roots == nil {
		return nil, fmt.Errorf("wrprc: no trust anchors configured for WRPRC JWT validation")
	}

	token := strings.TrimSpace(string(certData))
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("wrprc: invalid compact JWT: expected 3 parts, got %d", len(parts))
	}

	// Decode header (base64url, no padding)
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("wrprc: decoding JWT header: %w", err)
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("wrprc: parsing JWT header: %w", err)
	}

	// Validate typ = "rc-wrp+jwt" (GEN-5.2.2-01), compared exactly.
	//
	// A JWT typ is nominally a media type and so case-insensitive, but
	// Registrars emit the lowercase form and callers compare it exactly, so
	// the latitude buys nothing and costs a second rule.
	if header.Typ != WRPRCTyp {
		return nil, fmt.Errorf("wrprc: unexpected JWT typ %q, want %q", header.Typ, WRPRCTyp)
	}

	// Extract and evaluate the x5c certificate chain (Table 5). This
	// establishes that the chain is trusted - not that it signed anything
	// below.
	if len(header.X5C) == 0 {
		return nil, fmt.Errorf("wrprc: JWT header missing x5c certificate chain")
	}
	leaf, intermediates, err := parseX5CChain(header.X5C)
	if err != nil {
		return nil, fmt.Errorf("wrprc: parsing x5c chain: %w", err)
	}
	opts := x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := leaf.Verify(opts); err != nil {
		return nil, fmt.Errorf("wrprc: x5c certificate chain validation failed: %w", err)
	}

	payloadBytes, err := ParseWRPRCJWTPayload(token)
	if err != nil {
		return nil, err
	}
	ent, err := ParseWRPRCClaims(payloadBytes)
	if err != nil {
		return nil, err
	}
	if err := CheckWRPRCValidityPeriod(ent); err != nil {
		return nil, err
	}
	ent.Raw = token

	// RegistrationStatus stays StatusUnknown as set by the parser: without
	// a verified signature nothing here has been established, and marking
	// it registered would let a gate on IsValid pass on unverified data.
	return ent, nil
}

// parseX5CChain parses a base64-encoded DER certificate chain from a JWT x5c
// header. Returns the leaf certificate and a pool of intermediates.
func parseX5CChain(x5c []string) (*x509.Certificate, *x509.CertPool, error) {
	intermediates := x509.NewCertPool()
	var leaf *x509.Certificate

	for i, certB64 := range x5c {
		der, err := base64.StdEncoding.DecodeString(certB64)
		if err != nil {
			return nil, nil, fmt.Errorf("decoding x5c[%d]: %w", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing x5c[%d]: %w", i, err)
		}
		if i == 0 {
			leaf = cert
		} else {
			intermediates.AddCert(cert)
		}
	}

	if leaf == nil {
		return nil, nil, fmt.Errorf("x5c chain is empty")
	}
	return leaf, intermediates, nil
}
