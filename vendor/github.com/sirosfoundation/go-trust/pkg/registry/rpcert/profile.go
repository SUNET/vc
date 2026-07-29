// RP certificate/credential profile abstraction.
//
// An RPProfile describes a concrete RP certificate or credential profile —
// the set of rules governing format, policy OIDs, identity extraction, and
// validation of RP-presented credentials. Profiles are technology-agnostic:
// they can model X.509 certificate profiles (e.g., WRPAC per ETSI TS 119 411-8),
// SD-JWT-based RP credentials, OpenID Federation entity statements, or any
// future trust technology.
//
// Profiles are registered in a ProfileRegistry and selected at evaluation time
// by matching certificate policy OIDs, credential format identifiers, or
// explicit profile names.
package rpcert

import (
	"crypto/x509"
	"time"
)

// RPProfile describes an RP certificate or credential profile. Implementations
// provide profile-specific validation rules, identity extraction, and
// entitlement derivation.
type RPProfile interface {
	// Name returns a short identifier for the profile (e.g., "wrpac", "oidf-rp").
	Name() string

	// Description returns a human-readable description.
	Description() string

	// Format returns the credential technology family (e.g., "x509", "sd-jwt",
	// "oidf"). Used for coarse format-based routing.
	Format() string

	// MatchesPolicyOID returns true if the given certificate policy OID
	// identifies a credential issued under this profile. For non-X.509
	// profiles this may always return false.
	MatchesPolicyOID(oid string) bool

	// PolicyOIDs returns all policy OIDs defined by this profile (may be empty
	// for non-X.509 profiles).
	PolicyOIDs() []string

	// ExtractIdentity extracts structured RP identity from the credential
	// material. The input is profile-dependent: *x509.Certificate for X.509
	// profiles, a parsed JWT for SD-JWT profiles, etc.
	ExtractIdentity(credential interface{}) (map[string]interface{}, error)

	// ValidateCredential performs profile-specific validation beyond basic
	// chain/signature verification (e.g., required extensions, key usage
	// constraints, mandatory SAN fields). Returns nil if valid.
	ValidateCredential(credential interface{}) error
}

// ProfileRegistry holds named RPProfiles and provides lookup by OID, format, or name.
type ProfileRegistry struct {
	byName   map[string]RPProfile
	byOID    map[string]RPProfile
	byFormat map[string][]RPProfile
}

// NewProfileRegistry creates an empty ProfileRegistry.
func NewProfileRegistry() *ProfileRegistry {
	return &ProfileRegistry{
		byName:   make(map[string]RPProfile),
		byOID:    make(map[string]RPProfile),
		byFormat: make(map[string][]RPProfile),
	}
}

// Register adds a profile to the registry.
func (r *ProfileRegistry) Register(p RPProfile) {
	r.byName[p.Name()] = p
	for _, oid := range p.PolicyOIDs() {
		r.byOID[oid] = p
	}
	r.byFormat[p.Format()] = append(r.byFormat[p.Format()], p)
}

// ByName returns the profile with the given name, or nil.
func (r *ProfileRegistry) ByName(name string) RPProfile {
	return r.byName[name]
}

// ByPolicyOID returns the profile that claims the given certificate policy OID,
// or nil if no profile matches.
func (r *ProfileRegistry) ByPolicyOID(oid string) RPProfile {
	return r.byOID[oid]
}

// ByFormat returns all profiles for the given format, or nil.
func (r *ProfileRegistry) ByFormat(format string) []RPProfile {
	return r.byFormat[format]
}

// MatchCertificate returns the first profile whose policy OID matches one of
// the certificate's policy OIDs, or nil if none match. Checks both
// cert.Policies (Go 1.22+ x509.OID) and legacy cert.PolicyIdentifiers.
func (r *ProfileRegistry) MatchCertificate(cert *x509.Certificate) RPProfile {
	// Check newer Policies field first
	for _, policyOID := range cert.Policies {
		if p := r.byOID[policyOID.String()]; p != nil {
			return p
		}
	}
	// Fall back to legacy PolicyIdentifiers
	for _, policyOID := range cert.PolicyIdentifiers {
		if p := r.byOID[policyOID.String()]; p != nil {
			return p
		}
	}
	return nil
}

// Names returns all registered profile names.
func (r *ProfileRegistry) Names() []string {
	names := make([]string, 0, len(r.byName))
	for n := range r.byName {
		names = append(names, n)
	}
	return names
}

// DefaultProfileRegistry returns a ProfileRegistry pre-loaded with all
// built-in RP certificate profiles (currently WRPAC). Registries that
// perform x5c enrichment should use this unless they have a custom set.
func DefaultProfileRegistry() *ProfileRegistry {
	r := NewProfileRegistry()
	r.Register(NewWRPACProfile())
	return r
}

// CertPolicyOIDStrings returns all certificate policy OIDs as strings,
// reading from both cert.Policies (Go 1.22+ x509.OID) and the legacy
// cert.PolicyIdentifiers (encoding/asn1.ObjectIdentifier), deduplicated.
func CertPolicyOIDStrings(cert *x509.Certificate) []string {
	seen := make(map[string]bool)
	var oids []string
	for _, p := range cert.Policies {
		s := p.String()
		if !seen[s] {
			seen[s] = true
			oids = append(oids, s)
		}
	}
	for _, p := range cert.PolicyIdentifiers {
		s := p.String()
		if !seen[s] {
			seen[s] = true
			oids = append(oids, s)
		}
	}
	return oids
}

// ExtractBaseCertIdentity extracts generic RP identity information from an
// X.509 certificate. This is the shared base for both the generic enrichment
// pipeline and profile-specific extractors (which can overlay additional fields).
func ExtractBaseCertIdentity(cert *x509.Certificate) map[string]interface{} {
	identity := map[string]interface{}{}

	if len(cert.Subject.Organization) > 0 {
		identity["organization"] = cert.Subject.Organization
	}
	if cert.Subject.CommonName != "" {
		identity["common_name"] = cert.Subject.CommonName
	}
	if len(cert.Subject.Country) > 0 {
		identity["country"] = cert.Subject.Country
	}
	if cert.Subject.SerialNumber != "" {
		identity["serial_number"] = cert.Subject.SerialNumber
	}
	if cert.SerialNumber != nil {
		identity["certificate_serial_number"] = cert.SerialNumber.String()
	}
	if len(cert.DNSNames) > 0 {
		identity["dns_sans"] = cert.DNSNames
	}
	if len(cert.URIs) > 0 {
		uriSANs := make([]string, 0, len(cert.URIs))
		for _, uri := range cert.URIs {
			if uri != nil {
				uriSANs = append(uriSANs, uri.String())
			}
		}
		if len(uriSANs) > 0 {
			identity["uri_sans"] = uriSANs
		}
	}
	if len(cert.EmailAddresses) > 0 {
		identity["email_sans"] = cert.EmailAddresses
	}

	// Include certificate policy OIDs for downstream consumers
	policyOIDs := CertPolicyOIDStrings(cert)
	if len(policyOIDs) > 0 {
		identity["policy_oids"] = policyOIDs
	}

	// Include validity period
	identity["not_before"] = cert.NotBefore.Format(time.RFC3339)
	identity["not_after"] = cert.NotAfter.Format(time.RFC3339)

	return identity
}
