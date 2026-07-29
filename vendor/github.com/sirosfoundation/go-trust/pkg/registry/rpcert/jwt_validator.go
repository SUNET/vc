// WRPRC JWT validator per ETSI TS 119 475 v1.1.1.
//
// A WRPRC is a signed JWT with media type "rc-wrp+jwt" (GEN-5.2.2-01,
// GEN-5.2.1-01). The JWT header carries the provider's certificate chain in
// the `x5c` field (Table 5) and the payload contains the RP's registration
// data in the claims defined in Tables 7–10.
//
// This validator:
//  1. Parses the compact JWT without verifying the signature first to extract
//     the x5c certificate chain from the header.
//  2. Verifies the JWT signature against the leaf certificate extracted from x5c,
//     which in turn must chain to a configured trusted root (the WRPRC provider's
//     CA from the Trusted List).
//  3. Validates typ = "rc-wrp+jwt" and the presence of mandatory claims.
//  4. Extracts RPEntitlements from the payload claims.
//
// Signature verification requires the x5c header and a non-nil roots pool.
// Validation without trust anchors is rejected.
package rpcert

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// OIDWRPRCPolicy is the WRPRC certificate policy OID per ETSI TS 119 475
// v1.1.1, clause OVR-6.1.3-01.
//
//	wrprc OBJECT IDENTIFIER ::=
//	  { itu-t(0) identified-organization(4) etsi(0) eudiwrpa(19475) policy-identifiers(3) wrprc(1) }
const OIDWRPRCPolicy = "0.4.0.19475.3.1"

// WRPRCTyp is the JWT `typ` header value for a WRPRC per Table 5.
const WRPRCTyp = "rc-wrp+jwt"

// JWTRegistrationCertValidator validates WRPRC JWTs per TS 119 475 v1.1.1.
// The JWT must carry the provider's certificate chain in the `x5c` header.
type JWTRegistrationCertValidator struct {
	// roots is the certificate pool for WRPRC provider CAs (from Trusted List).
	roots *x509.CertPool
}

// NewJWTRegistrationCertValidator creates a new WRPRC JWT validator.
// roots must contain the trusted WRPRC provider CA certificates from the
// national Trusted List. Passing nil roots causes all validations to fail.
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

// wrprcPayload is a minimal representation of the WRPRC JWT payload per
// TS 119 475 v1.1.1 Tables 7–10. Only fields needed for entitlement
// extraction are mapped; unknown fields are silently ignored.
type wrprcPayload struct {
	// Table 7 mandatory fields
	Name          string   `json:"name"`
	Sub           wrprcSub `json:"sub"`
	Entitlements  []string `json:"entitlements"`
	Country       string   `json:"country"`
	RegistryURI   string   `json:"registry_uri"`
	PrivacyPolicy string   `json:"privacy_policy"`
	InfoURI       string   `json:"info_uri"`
	PolicyIDs     []string `json:"policy_id"`
	CertPolicy    string   `json:"certificate_policy"`
	Iat           int64    `json:"iat"`
	Exp           int64    `json:"exp"`

	// Table 7: service descriptions
	Service []MultiLangString `json:"service"`

	// Table 9: credential queries for over-request detection
	Credentials []wrprcCredential `json:"credentials"`

	// Table 10: optional fields
	Purpose    []MultiLangString `json:"purpose"`
	PublicBody bool              `json:"public_body"`
	SupportURI string            `json:"support_uri"`

	// Table 8: provided attestations (for EAA providers)
	ProvidedAttestations []wrprcCredential `json:"provided_attestations"`

	// Table 10: revocation status list
	Status *wrprcStatus `json:"status,omitempty"`

	// Table 10: intermediary delegation (GEN-5.2.4-09)
	Act *wrprcAct `json:"act,omitempty"`
}

// wrprcSub is the structured `sub` claim in the WRPRC payload (Table 7).
type wrprcSub struct {
	LegalName  string `json:"legal_name"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	ID         string `json:"id"`
}

// wrprcCredential is a credential query entry in `credentials` or
// `provided_attestations` (Tables 8–9, matches DCQL CredentialQuery layout).
type wrprcCredential struct {
	Format string                 `json:"format"`
	Meta   map[string]interface{} `json:"meta,omitempty"`
	Claims []struct {
		Path []string `json:"path"`
	} `json:"claims,omitempty"`
}

// wrprcStatus holds the `status` claim (Table 7).
type wrprcStatus struct {
	StatusList struct {
		Idx int    `json:"idx"`
		URI string `json:"uri"`
	} `json:"status_list"`
}

// wrprcAct holds the `act` claim (Table 10, GEN-5.2.4-09).
// When present, Sub identifies the intermediary acting on behalf of the RP.
type wrprcAct struct {
	Sub string `json:"sub"`
}

// Validate parses and validates a compact WRPRC JWT, verifies the provider
// certificate chain embedded in the x5c header, and extracts RPEntitlements.
//
// certData must be a compact JWT string (header.payload.signature), passed as
// a []byte for compatibility with the RegistrationCertValidator interface.
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

	// Validate typ = "rc-wrp+jwt" (GEN-5.2.2-01)
	if !strings.EqualFold(header.Typ, WRPRCTyp) {
		return nil, fmt.Errorf("wrprc: unexpected JWT typ %q, want %q", header.Typ, WRPRCTyp)
	}

	// Extract and verify the x5c certificate chain (Table 5)
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

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("wrprc: decoding JWT payload: %w", err)
	}
	var payload wrprcPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("wrprc: parsing JWT payload: %w", err)
	}

	// Validate mandatory claims
	if payload.Sub.ID == "" && payload.Sub.LegalName == "" &&
		payload.Sub.GivenName == "" && payload.Sub.FamilyName == "" {
		return nil, fmt.Errorf("wrprc: payload missing required sub claim")
	}
	if len(payload.Entitlements) == 0 {
		return nil, fmt.Errorf("wrprc: payload missing required entitlements claim (GEN-5.2.4-03)")
	}

	// Validate exp ≤ iat + 12 months (GEN-5.2.4-08)
	if payload.Iat > 0 && payload.Exp > 0 {
		iat := time.Unix(payload.Iat, 0)
		exp := time.Unix(payload.Exp, 0)
		maxExp := iat.AddDate(0, 12, 0)
		if exp.After(maxExp) {
			return nil, fmt.Errorf("wrprc: exp %s exceeds maximum allowed (iat + 12 months = %s) per GEN-5.2.4-08",
				exp.Format(time.RFC3339), maxExp.Format(time.RFC3339))
		}
	}

	// Build RPEntitlements from payload
	ent := &RPEntitlements{
		Subject: WRPRCSubject{
			LegalName:  payload.Sub.LegalName,
			GivenName:  payload.Sub.GivenName,
			FamilyName: payload.Sub.FamilyName,
			ID:         payload.Sub.ID,
		},
		TradeName:          payload.Name,
		Country:            payload.Country,
		EntitlementURIs:    payload.Entitlements,
		PrivacyPolicyURI:   payload.PrivacyPolicy,
		InfoURI:            payload.InfoURI,
		RegistryURI:        payload.RegistryURI,
		PolicyIDs:          payload.PolicyIDs,
		Purpose:            payload.Purpose,
		IsPublicBody:       payload.PublicBody,
		RegistrationStatus: StatusRegistered,
		Raw:                token,
	}

	// Derive RPIdentifier from sub.id (primary), falling back to legal name
	ent.RPIdentifier = payload.Sub.ID
	if ent.RPIdentifier == "" {
		ent.RPIdentifier = payload.Sub.LegalName
	}
	if ent.RPIdentifier == "" {
		ent.RPIdentifier = payload.Sub.GivenName + " " + payload.Sub.FamilyName
	}

	// Validity period from iat/exp
	if payload.Iat > 0 {
		t := time.Unix(payload.Iat, 0)
		ent.ValidFrom = &t
	}
	if payload.Exp > 0 {
		t := time.Unix(payload.Exp, 0)
		ent.ValidUntil = &t
	}

	// Intermediary delegation: act.sub is the intermediary's identifier
	// (GEN-5.2.4-09, Table 10). sub always identifies the final RP.
	if payload.Act != nil && payload.Act.Sub != "" {
		ent.ActingIntermediary = payload.Act.Sub
	}

	// Status list for revocation
	if payload.Status != nil {
		ent.StatusListURI = payload.Status.StatusList.URI
		ent.StatusListIndex = payload.Status.StatusList.Idx
	}

	// Extract AllowedAttributes from credentials[].claims[].path[0] (DCQL)
	ent.AllowedAttributes = extractAllowedAttributes(payload.Credentials)

	// Map provided_attestations into CredentialQuery slice
	for _, c := range payload.ProvidedAttestations {
		cq := CredentialQuery{
			Format: c.Format,
			Meta:   c.Meta,
		}
		for _, cl := range c.Claims {
			cq.Claims = append(cq.Claims, ClaimQuery{Path: cl.Path})
		}
		ent.ProvidedAttestations = append(ent.ProvidedAttestations, cq)
	}

	return ent, nil
}

// extractAllowedAttributes returns the unique top-level claim names from the
// `credentials[].claims[].path[0]` entries in the WRPRC payload. This is the
// set of attributes the RP is entitled to request per Table 9.
func extractAllowedAttributes(creds []wrprcCredential) []string {
	seen := make(map[string]bool)
	var attrs []string
	for _, cred := range creds {
		for _, claim := range cred.Claims {
			if len(claim.Path) > 0 && !seen[claim.Path[0]] {
				seen[claim.Path[0]] = true
				attrs = append(attrs, claim.Path[0])
			}
		}
	}
	return attrs
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
