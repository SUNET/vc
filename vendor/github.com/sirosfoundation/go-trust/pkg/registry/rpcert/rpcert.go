// Package rpcert provides an abstraction layer for Relying Party registration
// certificate (WRPRC) validation and entitlement extraction.
//
// The WRPRC is a signed JWT (rc-wrp+jwt) or CWT (rc-wrp+cwt) per ETSI TS 119 475
// v1.1.1. It carries the RP's registered entitlements, intended use, and DCQL
// attribute queries. This package defines format-agnostic interfaces so the
// validation pipeline works regardless of the token format.
//
// References:
//   - ETSI TS 119 475 v1.1.1 — RP attributes supporting Wallet user's authorisation decisions
//   - ETSI TS 119 411-8 v1.1.1 — Access Certificate Policy for EUDI Wallet Relying Parties
//   - ARF RPRC_16 to RPRC_21 — Registration certificate validation requirements
package rpcert

import (
	"context"
	"fmt"
	"time"
)

// WRPRCSubject represents the structured `sub` object in a WRPRC JWT payload
// per TS 119 475 v1.1.1 Table 7. For legal persons, LegalName and ID are set.
// For natural persons, GivenName, FamilyName and ID are set.
type WRPRCSubject struct {
	// LegalName is the trade/legal name of the WRP (legal person).
	// Mapped from `sub.legal_name` (Table 7).
	LegalName string `json:"legal_name,omitempty"`

	// GivenName is the given name (natural person only).
	// Mapped from `sub.given_name` (Table 3).
	GivenName string `json:"given_name,omitempty"`

	// FamilyName is the family name (natural person only).
	// Mapped from `sub.family_name` (Table 3).
	FamilyName string `json:"family_name,omitempty"`

	// ID is the semantic identifier per TS 119 475 clause 5.1.
	// Format: "<scheme>:<country>-<value>", e.g. "LEIXG-529900T8BM49AURSDO55"
	// or "NTRDEX-HRB123456B". Mapped from `sub.id` (Table 7).
	// Must match the organization_identifier in the corresponding WRPAC.
	ID string `json:"id,omitempty"`
}

// MultiLangString is a localised string entry as used in WRPRC `purpose`,
// `service`, etc. fields (TS 119 475 class B.2.6 MultiLangString).
type MultiLangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// RPEntitlements represents the entitlements and registration data extracted
// from a Relying Party Registration Certificate (WRPRC JWT) or National
// Register lookup. The field names follow the WRPRC JWT payload claim names
// defined in TS 119 475 v1.1.1 Tables 7–10.
type RPEntitlements struct {
	// Subject holds the structured `sub` claim from the WRPRC JWT.
	// For backwards compatibility RPIdentifier is derived from Subject.ID.
	Subject WRPRCSubject `json:"sub"`

	// RPIdentifier is the primary RP identifier derived from Subject.ID.
	// Kept for use by the trust registry matching logic.
	RPIdentifier string `json:"rp_identifier"`

	// TradeName is the `name` claim — the WRP's user-facing trade name
	// (Table 7, tradeName field). This is what wallets display to users.
	TradeName string `json:"name,omitempty"`

	// Country is the two-letter ISO 3166-1 country code where the WRP is
	// established (Table 7, `country` field).
	Country string `json:"country,omitempty"`

	// EntitlementURIs lists the role entitlement URIs from the `entitlements`
	// claim (Table 7, GEN-5.2.4-03). At least one is required. Values are
	// from the Annex A set, e.g. EntitlementNonQEAAProvider.
	EntitlementURIs []string `json:"entitlements,omitempty"`

	// AllowedAttributes lists the top-level claim names extracted from the
	// DCQL `credentials[].claims[].path[0]` entries in the WRPRC payload.
	// Used for over-request detection. Distinct from EntitlementURIs.
	AllowedAttributes []string `json:"allowed_attributes,omitempty"`

	// Purpose contains the multi-language purpose descriptions from the
	// `purpose` claim (Table 9). Preserves all language variants.
	Purpose []MultiLangString `json:"purpose,omitempty"`

	// PrivacyPolicyURI is the URL to the WRP's privacy policy (`privacy_policy`).
	PrivacyPolicyURI string `json:"privacy_policy,omitempty"`

	// InfoURI is the general-purpose web address of the WRP (`info_uri`).
	InfoURI string `json:"info_uri,omitempty"`

	// RegistryURI is the URL to the national registry entry for this WRP
	// (`registry_uri`, Table 7). Used to resolve registration data.
	RegistryURI string `json:"registry_uri,omitempty"`

	// PolicyIDs contains the WRPRC certificate policy identifiers from the
	// `policy_id` claim (OVR-6.1.3-01). The standard WRPRC OID is
	// OIDWRPRCPolicy ("0.4.0.19475.3.1").
	PolicyIDs []string `json:"policy_id,omitempty"`

	// ProvidedAttestations is populated for WRPs with EAA entitlements
	// (QEAA_Provider, Non_Q_EAA_Provider, PUB_EAA_Provider). Contains the
	// `provided_attestations` claim (Table 8, GEN-5.2.4-05).
	ProvidedAttestations []CredentialQuery `json:"provided_attestations,omitempty"`

	// IsPublicBody reflects the `public_body` boolean claim (Table 10).
	IsPublicBody bool `json:"public_body,omitempty"`

	// ActingIntermediary is the identifier of the intermediary presenting this
	// WRPRC on behalf of the RP. Populated from the `act.sub` claim when
	// present (Table 10, GEN-5.2.4-09). The `sub` claim always identifies
	// the final RP, never the intermediary.
	ActingIntermediary string `json:"acting_intermediary,omitempty"`

	// StatusListURI is the URI of the status list for WRPRC revocation
	// checking (`status.status_list.uri`, Table 7).
	StatusListURI string `json:"status_list_uri,omitempty"`

	// StatusListIndex is the index within the status list for this WRPRC
	// (`status.status_list.idx`, Table 7).
	StatusListIndex int `json:"status_list_idx,omitempty"`

	// RegistrationStatus indicates the RP's current registration status.
	// Values: "registered", "suspended", "revoked", "not_found".
	RegistrationStatus RegistrationStatus `json:"registration_status"`

	// ValidFrom is when the registration/entitlements become valid (from `iat`).
	ValidFrom *time.Time `json:"valid_from,omitempty"`

	// ValidUntil is when the registration/entitlements expire (from `exp`,
	// GEN-5.2.4-08: must be within 12 months of iat).
	ValidUntil *time.Time `json:"valid_until,omitempty"`

	// Raw contains the raw registration certificate data for downstream consumers.
	// Excluded from JSON serialization to avoid leaking certificate material.
	Raw interface{} `json:"-"`
}

// RegistrationStatus represents the registration state of an RP.
type RegistrationStatus string

const (
	StatusRegistered RegistrationStatus = "registered"
	StatusSuspended  RegistrationStatus = "suspended"
	StatusRevoked    RegistrationStatus = "revoked"
	StatusNotFound   RegistrationStatus = "not_found"
	StatusUnknown    RegistrationStatus = "unknown"
)

// IsValid returns true if the RP's registration status allows presentations.
func (e *RPEntitlements) IsValid() bool {
	if e.RegistrationStatus != StatusRegistered {
		return false
	}
	now := time.Now()
	if e.ValidFrom != nil && now.Before(*e.ValidFrom) {
		return false
	}
	if e.ValidUntil != nil && now.After(*e.ValidUntil) {
		return false
	}
	return true
}

// RegistrationCertValidator validates a Relying Party Registration Certificate
// and extracts entitlements from it. Implementations handle specific WRPRC formats
// (X.509, SD-JWT, CBOR, etc.).
type RegistrationCertValidator interface {
	// Validate parses and validates the registration certificate data,
	// returning the extracted entitlements. The certData format depends
	// on the implementation (PEM-encoded X.509, SD-JWT string, CBOR bytes, etc.).
	Validate(ctx context.Context, certData []byte) (*RPEntitlements, error)

	// Format returns the certificate format this validator handles
	// (e.g., "x509", "sd-jwt", "cbor").
	Format() string
}

// NationalRegisterClient queries the National Register API (TS5/TS6) to look up
// RP registration data when no WRPRC is provided by the RP.
type NationalRegisterClient interface {
	// LookupRP queries the register for an RP's registration status and entitlements.
	LookupRP(ctx context.Context, rpIdentifier string) (*RPEntitlements, error)

	// Healthy returns true if the register API is reachable.
	Healthy() bool
}

// OverRequestResult contains the result of comparing requested attributes
// against RP entitlements.
type OverRequestResult struct {
	// Allowed lists attributes the RP is entitled to request.
	Allowed []string `json:"allowed"`

	// Requested lists all attributes the RP is requesting.
	Requested []string `json:"requested"`

	// OverRequested lists attributes requested but not in the RP's entitlements.
	OverRequested []string `json:"over_requested,omitempty"`

	// IsOverRequest is true if the RP is requesting attributes beyond their entitlements.
	IsOverRequest bool `json:"is_over_request"`
}

// DetectOverRequest compares the requested attributes against the RP's
// entitled attributes (from the WRPRC `credentials[].claims[]` DCQL paths)
// and returns details about any over-request.
// Note: EntitlementURIs (RP role) and AllowedAttributes (DCQL claim paths)
// are distinct — this function operates on AllowedAttributes only.
func DetectOverRequest(entitlements *RPEntitlements, requestedAttributes []string) *OverRequestResult {
	if entitlements == nil || len(entitlements.AllowedAttributes) == 0 {
		// No entitlement data available — cannot determine over-request
		return &OverRequestResult{
			Requested:     requestedAttributes,
			IsOverRequest: false,
		}
	}

	allowed := make(map[string]bool, len(entitlements.AllowedAttributes))
	for _, attr := range entitlements.AllowedAttributes {
		allowed[attr] = true
	}

	var overRequested []string
	for _, attr := range requestedAttributes {
		if !allowed[attr] {
			overRequested = append(overRequested, attr)
		}
	}

	return &OverRequestResult{
		Allowed:       entitlements.AllowedAttributes,
		Requested:     requestedAttributes,
		OverRequested: overRequested,
		IsOverRequest: len(overRequested) > 0,
	}
}

// Config configures the RP certificate validation pipeline.
type Config struct {
	// CertFormat specifies the expected WRPRC format ("x509", "sd-jwt", "cbor").
	// Determines which RegistrationCertValidator implementation is used.
	CertFormat string `json:"cert_format,omitempty" yaml:"cert_format,omitempty"`

	// RegisterURL is the base URL for the National Register API (TS5/TS6).
	// Used as fallback when no WRPRC is provided by the RP.
	RegisterURL string `json:"register_url,omitempty" yaml:"register_url,omitempty"`

	// StrictEntitlementCheck controls whether over-request results in rejection (true)
	// or just a warning in the response (false). Defaults to false (warn-only).
	StrictEntitlementCheck bool `json:"strict_entitlement_check,omitempty" yaml:"strict_entitlement_check,omitempty"`

	// AllowWithoutWRPRC controls whether presentations are allowed when no WRPRC
	// is available and the National Register lookup fails. Defaults to true.
	AllowWithoutWRPRC bool `json:"allow_without_wrprc,omitempty" yaml:"allow_without_wrprc,omitempty"`

	// Timeout for National Register API calls.
	Timeout time.Duration `json:"timeout,omitempty" yaml:"timeout,omitempty"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		CertFormat:             "jwt",
		StrictEntitlementCheck: false,
		AllowWithoutWRPRC:      true,
		Timeout:                10 * time.Second,
	}
}

// ValidatorRegistry maps certificate formats to their validators.
// This allows runtime selection of the appropriate validator based on config.
type ValidatorRegistry struct {
	validators map[string]RegistrationCertValidator
}

// NewValidatorRegistry creates a new ValidatorRegistry.
func NewValidatorRegistry() *ValidatorRegistry {
	return &ValidatorRegistry{
		validators: make(map[string]RegistrationCertValidator),
	}
}

// Register adds a validator for the given format.
func (r *ValidatorRegistry) Register(format string, v RegistrationCertValidator) {
	r.validators[format] = v
}

// Get returns the validator for the given format, or an error if not registered
// or if a nil validator was registered.
func (r *ValidatorRegistry) Get(format string) (RegistrationCertValidator, error) {
	v, ok := r.validators[format]
	if !ok {
		return nil, fmt.Errorf("no registration certificate validator registered for format %q", format)
	}
	if v == nil {
		return nil, fmt.Errorf("registration certificate validator for format %q is nil", format)
	}
	return v, nil
}

// Formats returns the list of registered validator formats.
func (r *ValidatorRegistry) Formats() []string {
	formats := make([]string, 0, len(r.validators))
	for f := range r.validators {
		formats = append(formats, f)
	}
	return formats
}
