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
// # Service identifier binding
//
// ETSI TS 119 411-8 v1.1.1 does not yet define a Subject attribute OID for a
// service identifier that would bind a WRPAC to a specific service instance of
// an organisation. Without such a binding, organisation-level binding via
// organizationIdentifier ↔ WRPRC sub.id is the only mechanism, which is
// insufficient when an organisation operates multiple services each with their
// own WRPAC/WRPRC pair.
//
// Stefan Santesson (PTS/Sweden) proposed a de-facto OID under the id-etsi-wrpa
// arc as a placeholder until ETSI formally assigns one:
//
//	OIDWRPACServiceIdentifier = "0.4.0.19475.99.1"
//	arc: id-etsi-wrpa (0.4.0.19475) + .99 (stub, not assigned) + .1
//
// When present in the Subject DN, the value is a URI that identifies the
// specific service the WRPAC was issued for. The corresponding WRPRC JWT is
// expected to carry the same URI in the "service_identifier" claim.
//
// This implementation extracts the service identifier from the Subject DN
// (under OIDWRPACServiceIdentifier) when present and surfaces it as
// "service_identifier" in the identity map. The binding check in
// CheckWRPACWRPRCServiceBinding is optional: it only enforces the match when
// both sides carry the claim. Deployments following strict ETSI TS 119 411-8
// (no service_identifier) continue to work unchanged.
//
// TODO(etsi): Replace OIDWRPACServiceIdentifier with the formally assigned OID
// once ETSI publishes the update to TS 119 411-8 or TS 119 475. Track via:
// https://portal.etsi.org/webapp/WorkProgram/Frame_WorkItemList.asp
//
// # telephoneNumber placement
//
// ETSI TS 119 411-8 currently encodes telephoneNumber as a SAN otherName, which
// violates ASN.1/X.520: telephoneNumber (OID 2.5.4.20) is a directory attribute
// type, not a name form, and must not appear inside the SAN otherName structure.
// Stefan Santesson identified this as a standards defect; the correct placement
// is in the Subject DN as a standard attribute.
//
// This implementation extracts telephoneNumber from BOTH locations:
//   - Subject DN attribute (OID 2.5.4.20) — ASN.1-correct, Stefan's approach
//   - SAN otherName — current ETSI spec (defective, preserved for compatibility)
//
// TODO(etsi): Once ETSI corrects the telephoneNumber placement, remove the SAN
// otherName extraction path.
//
// References:
//   - ETSI TS 119 411-8 v1.1.1 — Access Certificate Policy for EUDI Wallet RPs
//   - ETSI EN 319 412-2 — Certificate profiles for natural persons
//   - ETSI EN 319 412-3 — Certificate profiles for legal persons
//   - ETSI EN 319 412-5 — QC statements
//   - CIR (EU) 2025/848 — Implementing regulation for EUDI Wallet RPs
//   - X.520 / ITU-T — Information technology - Open Systems Interconnection -
//     The Directory: Selected attribute types (defines telephoneNumber as 2.5.4.20)

package rpcert

import (
	"crypto/x509"
	"encoding/asn1"
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

// OIDWRPACServiceIdentifier is a placeholder OID for the service identifier
// Subject attribute in a WRPAC. It lives under the id-etsi-wrpa arc from
// ETSI TS 119 475, with ".99.1" used as a stub since ETSI has not yet formally
// assigned an OID for this attribute.
//
// Value semantics: a URI that identifies the specific service the WRPAC was
// issued for. When present in a WRPAC and in the corresponding WRPRC JWT
// ("service_identifier" claim), the values MUST match (see
// CheckWRPACWRPRCServiceBinding).
//
// Proposed by Stefan Santesson (PTS Sweden) as a de-facto interoperability
// convention pending ETSI standardisation.
//
// TODO(etsi): Replace with the formally assigned OID when ETSI TS 119 411-8
// or TS 119 475 is updated.
const OIDWRPACServiceIdentifier = "0.4.0.19475.99.1"

// oidWRPACServiceIdentifierASN1 is the parsed ASN.1 form of OIDWRPACServiceIdentifier,
// used for low-level Subject DN traversal via cert.Subject.Names.
var oidWRPACServiceIdentifierASN1 = asn1.ObjectIdentifier{0, 4, 0, 19475, 99, 1}

// oidTelephoneNumberASN1 is the X.520 attribute type for telephoneNumber (2.5.4.20).
// Per X.520, this MUST appear as a Subject DN attribute, not as a SAN otherName.
// ETSI TS 119 411-8 currently (incorrectly) places it in SAN otherName; both
// locations are extracted for backward compatibility.
var oidTelephoneNumberASN1 = asn1.ObjectIdentifier{2, 5, 4, 20}

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
//
// Additional fields extracted when present:
//
//   - "service_identifier": URI from Subject attribute OIDWRPACServiceIdentifier
//     (0.4.0.19475.99.1, Stefan Santesson's de-facto convention). When present,
//     the corresponding WRPRC JWT must carry the same value in its
//     "service_identifier" claim (enforced by CheckWRPACWRPRCServiceBinding).
//
//   - "telephone_number": extracted from Subject DN attribute (OID 2.5.4.20,
//     ASN.1-correct per X.520). Also extracted from SAN otherName for
//     backward compatibility with the current ETSI TS 119 411-8 spec.
func (p *WRPACProfile) ExtractIdentity(credential interface{}) (map[string]interface{}, error) {
	cert, ok := credential.(*x509.Certificate)
	if !ok {
		return nil, fmt.Errorf("wrpac: expected *x509.Certificate, got %T", credential)
	}

	// Start with the shared base identity (org, CN, country, SANs, policy_oids, validity, etc.)
	identity := ExtractBaseCertIdentity(cert)

	// WRPAC-specific: surface the organisation identifier.
	//
	// EN 319 412-3 clause 4.2.1 puts it in organizationIdentifier
	// (2.5.4.97), which Go does not model on pkix.Name - it only appears in
	// Subject.Names, so it has to be read out by OID. Fall back to
	// serialNumber (2.5.4.5), which earlier certificates and test fixtures
	// used, so both continue to resolve.
	orgID := SubjectOrganizationIdentifier(cert)
	if orgID != "" {
		identity["organization_identifier"] = orgID
		delete(identity, "serial_number")
	}

	// Determine subject type (natural vs legal person). Keyed off the same
	// organisation identifier as above - reading Subject.SerialNumber
	// directly classified a conformant legal-person certificate, which
	// carries the value in 2.5.4.97, as a natural person. Reusing the one
	// value keeps the two decisions from ever disagreeing.
	if len(cert.Subject.Organization) > 0 && orgID != "" {
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

	// Extract service_identifier from Subject DN (OIDWRPACServiceIdentifier).
	// This is Stefan Santesson's de-facto convention; not yet in ETSI TS 119 411-8.
	// When present it enables service-level WRPAC↔WRPRC binding, which is more
	// precise than organisation-level binding for RPs with multiple services.
	if svcID := extractSubjectAttribute(cert, oidWRPACServiceIdentifierASN1); svcID != "" {
		identity["service_identifier"] = svcID
	}

	// Extract telephoneNumber from Subject DN (OID 2.5.4.20, ASN.1-correct per X.520).
	// ETSI TS 119 411-8 currently encodes this in SAN otherName which is incorrect;
	// we extract from both locations so that both Stefan's (correct) and ETSI's
	// (current spec) approaches work.
	if phone := extractSubjectAttribute(cert, oidTelephoneNumberASN1); phone != "" {
		identity["telephone_number"] = phone
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

// extractSubjectAttribute returns the string value of the first Subject DN
// attribute matching the given OID, or "" if not present. Used to extract
// non-standard attributes like OIDWRPACServiceIdentifier and telephoneNumber.
func extractSubjectAttribute(cert *x509.Certificate, oid asn1.ObjectIdentifier) string {
	for _, name := range cert.Subject.Names {
		if name.Type.Equal(oid) {
			if s, ok := name.Value.(string); ok {
				return s
			}
		}
	}
	return ""
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

// oidOrganizationIdentifier is organizationIdentifier per EN 319 412-1
// clause 5.1.4, the attribute EN 319 412-3 clause 4.2.1 requires in the
// subject DN of a legal-person certificate.
var oidOrganizationIdentifier = asn1.ObjectIdentifier{2, 5, 4, 97}

// SubjectOrganizationIdentifier returns the certificate's
// organizationIdentifier (2.5.4.97), falling back to serialNumber (2.5.4.5)
// when the former is absent.
//
// Go's pkix.Name has no field for organizationIdentifier, so a certificate
// that carries it correctly exposes it only through Subject.Names. Reading
// Subject.SerialNumber alone therefore reports nothing for a conformant
// WRPAC while appearing to work against fixtures that put the value in
// serialNumber instead - which is why the fallback stays.
func SubjectOrganizationIdentifier(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	for _, atv := range cert.Subject.Names {
		if !atv.Type.Equal(oidOrganizationIdentifier) {
			continue
		}
		if v, ok := atv.Value.(string); ok && v != "" {
			return v
		}
	}
	return cert.Subject.SerialNumber
}
