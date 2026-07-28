// WRPAC (Wallet-Relying Party Access Certificate) profile per ETSI TS 119 411-8.
//
// This profile describes the X.509 certificate profile for RP access certificates
// in the EUDI Wallet ecosystem. It defines:
//
//   - Four certificate policy OIDs (NCP/QCP × natural/legal person)
//   - Required extensions (keyUsage, subjectAltName, certificatePolicies, AIA)
//   - Identity extraction from Subject DN and SANs
//   - Security constraints (key usage restricted to nonRepudiation)
//
// The profile is based on the APTITUDE wp2-trust-specifications access-certificate
// topic (derived from ETSI TS 119 411-8, ETSI EN 319 412-x, and CIR 2025/848).
//
// References:
//   - ETSI TS 119 411-8 v1.1.1 — Access Certificate Policy for EUDI Wallet RPs
//   - ETSI EN 319 412-2 — Certificate profiles for natural persons
//   - ETSI EN 319 412-3 — Certificate profiles for legal persons
//   - ETSI EN 319 412-5 — QC statements
//   - CIR (EU) 2025/848 — Implementing regulation for EUDI Wallet RPs
package rpcert

import (
	"crypto/x509"
	"fmt"
)

// WRPAC certificate policy OIDs per ETSI TS 119 411-8 clause GEN-6.6.1-03.
const (
	// OIDNCPNaturalPerson is the Normalised Certificate Policy for natural persons.
	OIDNCPNaturalPerson = "0.4.0.194118.1.1" // NCP-n-eudiwrp

	// OIDNCPLegalPerson is the Normalised Certificate Policy for legal persons.
	OIDNCPLegalPerson = "0.4.0.194118.1.2" // NCP-l-eudiwrp

	// OIDQCPNaturalPerson is the Qualified Certificate Policy for natural persons.
	OIDQCPNaturalPerson = "0.4.0.194118.1.3" // QCP-n-eudiwrp

	// OIDQCPLegalPerson is the Qualified Certificate Policy for legal persons.
	OIDQCPLegalPerson = "0.4.0.194118.1.4" // QCP-l-eudiwrp
)

// WRPACPolicyOIDs is the complete set of WRPAC certificate policy OIDs.
var WRPACPolicyOIDs = []string{
	OIDNCPNaturalPerson,
	OIDNCPLegalPerson,
	OIDQCPNaturalPerson,
	OIDQCPLegalPerson,
}

// WRPACProfile implements RPProfile for ETSI TS 119 411-8 WRPAC certificates.
type WRPACProfile struct{}

// NewWRPACProfile creates a new WRPAC profile instance.
func NewWRPACProfile() *WRPACProfile {
	return &WRPACProfile{}
}

func (p *WRPACProfile) Name() string {
	return "wrpac"
}

func (p *WRPACProfile) Description() string {
	return "ETSI TS 119 411-8 Wallet-Relying Party Access Certificate (WRPAC)"
}

func (p *WRPACProfile) Format() string {
	return "x509"
}

func (p *WRPACProfile) MatchesPolicyOID(oid string) bool {
	for _, o := range WRPACPolicyOIDs {
		if oid == o {
			return true
		}
	}
	return false
}

func (p *WRPACProfile) PolicyOIDs() []string {
	return WRPACPolicyOIDs
}

// ExtractIdentity extracts RP identity from a WRPAC X.509 certificate.
// The credential must be an *x509.Certificate.
//
// Builds on ExtractBaseCertIdentity (shared base) and overlays WRPAC-specific
// fields: subject_type, organization_identifier, policy_level, policy_id, and
// structured contact information from subjectAltName.
func (p *WRPACProfile) ExtractIdentity(credential interface{}) (map[string]interface{}, error) {
	cert, ok := credential.(*x509.Certificate)
	if !ok {
		return nil, fmt.Errorf("wrpac: expected *x509.Certificate, got %T", credential)
	}

	// Start with the shared base identity (org, CN, country, SANs, policy_oids, validity, etc.)
	identity := ExtractBaseCertIdentity(cert)

	// WRPAC-specific: rename serial_number to organization_identifier
	if cert.Subject.SerialNumber != "" {
		identity["organization_identifier"] = cert.Subject.SerialNumber
		delete(identity, "serial_number")
	}

	// Determine subject type (natural vs legal person)
	if len(cert.Subject.Organization) > 0 && cert.Subject.SerialNumber != "" {
		identity["subject_type"] = "legal_person"
	} else {
		identity["subject_type"] = "natural_person"
	}

	// Certificate policy classification
	policyOIDStrs := CertPolicyOIDStrings(cert)
	for _, oidStr := range policyOIDStrs {
		switch oidStr {
		case OIDNCPNaturalPerson:
			identity["policy_level"] = "normalised"
			identity["policy_id"] = "NCP-n-eudiwrp"
		case OIDNCPLegalPerson:
			identity["policy_level"] = "normalised"
			identity["policy_id"] = "NCP-l-eudiwrp"
		case OIDQCPNaturalPerson:
			identity["policy_level"] = "qualified"
			identity["policy_id"] = "QCP-n-eudiwrp"
		case OIDQCPLegalPerson:
			identity["policy_level"] = "qualified"
			identity["policy_id"] = "QCP-l-eudiwrp"
		}
	}

	// Structured contact info from subjectAltName (WRPAC groups into a contact object)
	contacts := make(map[string]interface{})
	if uris, ok := identity["uri_sans"]; ok {
		contacts["uris"] = uris
		delete(identity, "uri_sans")
	}
	if emails, ok := identity["email_sans"]; ok {
		contacts["emails"] = emails
		delete(identity, "email_sans")
	}
	if len(contacts) > 0 {
		identity["contact"] = contacts
	}

	return identity, nil
}

// ValidateCredential performs WRPAC-specific validation on an X.509 certificate.
// Checks required by the profile beyond basic chain verification:
//   - keyUsage must include nonRepudiation (Type A, B, or F per ETSI EN 319 412)
//   - subjectAltName must be present with at least one contact method
//   - certificatePolicies must contain at least one WRPAC policy OID
func (p *WRPACProfile) ValidateCredential(credential interface{}) error {
	cert, ok := credential.(*x509.Certificate)
	if !ok {
		return fmt.Errorf("wrpac: expected *x509.Certificate, got %T", credential)
	}

	// Check keyUsage — WRPAC requires nonRepudiation (contentCommitment)
	if cert.KeyUsage&x509.KeyUsageContentCommitment == 0 {
		return fmt.Errorf("wrpac: certificate keyUsage does not include nonRepudiation (contentCommitment)")
	}

	// Check subjectAltName — must contain at least one contact method
	if len(cert.URIs) == 0 && len(cert.EmailAddresses) == 0 {
		return fmt.Errorf("wrpac: subjectAltName missing required contact information (URI or email)")
	}

	// Check certificatePolicies — must contain at least one WRPAC policy OID
	hasWRPACPolicy := false
	for _, oidStr := range CertPolicyOIDStrings(cert) {
		if p.MatchesPolicyOID(oidStr) {
			hasWRPACPolicy = true
			break
		}
	}
	if !hasWRPACPolicy {
		return fmt.Errorf("wrpac: certificate does not contain a WRPAC policy OID (expected one of %v)", WRPACPolicyOIDs)
	}

	return nil
}
