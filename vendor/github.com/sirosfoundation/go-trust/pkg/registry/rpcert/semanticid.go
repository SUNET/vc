package rpcert

import (
	"crypto/x509"
	"regexp"
)

// SubjectKind classifies a WRPAC subject as a natural or legal person.
type SubjectKind int

const (
	// SubjectKindUnknown means the certificate carries no (or contradictory)
	// WRPAC policy OIDs, so its kind cannot be told from the policy.
	SubjectKindUnknown SubjectKind = iota
	// SubjectKindContradictory means the certificate carries both natural- and
	// legal-person WRPAC policy OIDs. It is not "unclassified": consumers that
	// accept unclassified certificates must still refuse this one.
	SubjectKindContradictory
	// SubjectKindNaturalPerson is a certificate under NCP-n-eudiwrp or QCP-n-eudiwrp.
	SubjectKindNaturalPerson
	// SubjectKindLegalPerson is a certificate under NCP-l-eudiwrp or QCP-l-eudiwrp.
	SubjectKindLegalPerson
)

// SubjectKindFromPolicies classifies cert by its WRPAC certificate policy OIDs
// (ETSI TS 119 411-8: the -n and -l policies are what distinguish natural from
// legal person certificates). A certificate carrying neither kind is
// SubjectKindUnknown; one carrying both is SubjectKindContradictory.
func SubjectKindFromPolicies(cert *x509.Certificate) SubjectKind {
	if cert == nil {
		return SubjectKindUnknown
	}
	var natural, legal bool
	for _, oid := range CertPolicyOIDStrings(cert) {
		switch oid {
		case OIDNCPNaturalPerson, OIDQCPNaturalPerson:
			natural = true
		case OIDNCPLegalPerson, OIDQCPLegalPerson:
			legal = true
		}
	}
	switch {
	case natural && legal:
		return SubjectKindContradictory
	case natural:
		return SubjectKindNaturalPerson
	case legal:
		return SubjectKindLegalPerson
	}
	return SubjectKindUnknown
}

// semanticIDPattern is the EN 319 412-1 clause 5.1.3 semantics identifier
// syntax: a 3-letter identifier type, a 2-letter country code, a hyphen-minus
// and a non-empty value without leading or trailing whitespace.
var semanticIDPattern = regexp.MustCompile(`^[A-Z]{3}[A-Z]{2}-[\x21-\x7E]([\x20-\x7E]*[\x21-\x7E])?$`)

// naturalPersonSemanticTypes are the identifier types EN 319 412-1 5.1.3 defines
// for natural persons: passport, identity card, personal number, tax and
// taxpayer identification number. Every other type names a legal person.
var naturalPersonSemanticTypes = map[string]bool{
	"PAS": true, "IDC": true, "PNO": true, "TAX": true, "TIN": true,
}

// IsSemanticIdentifier reports whether s matches the semantic identifier
// syntax (3-letter type, 2-letter country, hyphen, value).
func IsSemanticIdentifier(s string) bool {
	return semanticIDPattern.MatchString(s)
}

// organizationIdentifierAttr reports whether the certificate carries an
// organizationIdentifier attribute (2.5.4.97) at all, and its value when it is a
// non-empty string. present is true for an attribute that is empty or not a
// string, with value "": presence is what tells "absent" from "malformed", and
// only the former may fall back to serialNumber.
func organizationIdentifierAttr(cert *x509.Certificate) (value string, present bool) {
	for _, atv := range cert.Subject.Names {
		if atv.Type.Equal(oidOrganizationIdentifier) {
			if v, ok := atv.Value.(string); ok && v != "" {
				return v, true
			}
			present = true
		}
	}
	return "", present
}

// realOrganizationIdentifier returns only the organizationIdentifier attribute
// (2.5.4.97), without the serialNumber fallback of SubjectOrganizationIdentifier.
func realOrganizationIdentifier(cert *x509.Certificate) string {
	v, _ := organizationIdentifierAttr(cert)
	return v
}

// SemanticIdentifier returns the ETSI semantic identifier of the certificate's
// subject, and false when there is none that can be trusted as one.
//
// Where it lives depends on the subject (ETSI TS 119 475 5.1.3 and 5.1.5, which
// refer to EN 319 412-1 5.1.3):
//   - legal person: organizationIdentifier (2.5.4.97), per EN 319 412-3 4.2.1.
//     The serialNumber fallback exists for older certificates and fixtures that
//     put it there.
//   - natural person: Subject serialNumber (2.5.4.5), never
//     organizationIdentifier, which would name an affiliated organization.
//
// The value must match the semantic identifier syntax, and its type must fit
// the subject: a natural-person type (PNO, IDC, PAS, TAX, TIN) is refused for a
// legal-person certificate and any other type for a natural-person one. The
// subject kind comes from the WRPAC policy OIDs alone; a certificate with
// neither kind has no semantic identifier, because an organizationIdentifier
// there could be the affiliation of a natural person rather than the verifier.
// A serialNumber that is merely a certificate
// serial (or anything else non-semantic) is therefore never returned. An
// organizationIdentifier that is present but not valid is not papered over by
// falling back to serialNumber. A certificate carrying both natural- and
// legal-person policy OIDs has no semantic identifier.
func SemanticIdentifier(cert *x509.Certificate) (string, bool) {
	if cert == nil {
		return "", false
	}
	kind := SubjectKindFromPolicies(cert)
	if kind == SubjectKindContradictory {
		// Both a natural- and a legal-person policy: which identifier is the
		// subject's cannot be told, so none is returned (fail closed).
		return "", false
	}

	// Which attribute names the subject depends on whether it is a natural or a
	// legal person, and only the WRPAC policy OIDs say so. Without one the
	// organizationIdentifier cannot be told from an affiliation of a natural
	// person, so no identifier is returned (fail closed).
	var candidate string
	switch kind {
	case SubjectKindNaturalPerson:
		candidate = cert.Subject.SerialNumber
	case SubjectKindLegalPerson:
		var present bool
		candidate, present = organizationIdentifierAttr(cert)
		if !present {
			// Older certificates put it in serialNumber, but only when 2.5.4.97
			// is absent. A malformed one is not papered over.
			candidate = cert.Subject.SerialNumber
		}
	default:
		return "", false
	}

	if !IsSemanticIdentifier(candidate) {
		return "", false
	}
	if naturalPersonSemanticTypes[candidate[:3]] != (kind == SubjectKindNaturalPerson) {
		return "", false
	}
	return candidate, true
}
