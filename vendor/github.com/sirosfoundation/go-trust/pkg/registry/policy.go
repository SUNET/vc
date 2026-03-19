// Package registry provides trust registry management.
// This file defines policy types for action-based routing.
package registry

// Policy defines a trust evaluation policy that can be selected via action.name.
// Policies allow server-side configuration of trust requirements without
// clients needing to know about underlying trust infrastructure.
type Policy struct {
	// Name is the policy identifier, matched against action.name
	Name string `json:"name" yaml:"name"`

	// Description provides human-readable documentation
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// Registries limits evaluation to specific registry names.
	// If empty, all registries are considered.
	Registries []string `json:"registries,omitempty" yaml:"registries,omitempty"`

	// Constraints contains registry-agnostic constraints
	Constraints PolicyConstraints `json:"constraints,omitempty" yaml:"constraints,omitempty"`

	// OIDFed contains OpenID Federation-specific constraints
	OIDFed *OIDFedPolicyConstraints `json:"oidfed,omitempty" yaml:"oidfed,omitempty"`

	// ETSI contains ETSI TSL-specific constraints
	ETSI *ETSIPolicyConstraints `json:"etsi,omitempty" yaml:"etsi,omitempty"`

	// DID contains DID method-specific constraints (did:web, did:webvh)
	DID *DIDPolicyConstraints `json:"did,omitempty" yaml:"did,omitempty"`

	// MDOCIACA contains mDOC IACA-specific constraints
	MDOCIACA *MDOCIACAPolicyConstraints `json:"mdociaca,omitempty" yaml:"mdociaca,omitempty"`
}

// PolicyConstraints contains registry-agnostic trust constraints.
type PolicyConstraints struct {
	// AllowedKeyTypes restricts accepted resource types (e.g., ["jwk", "x5c"]).
	// If non-empty, requests with a resource.type not in this list are rejected.
	AllowedKeyTypes []string `json:"allowed_key_types,omitempty" yaml:"allowed_key_types,omitempty"`
}

// OIDFedPolicyConstraints contains OpenID Federation-specific constraints.
type OIDFedPolicyConstraints struct {
	// RequiredTrustMarks specifies trust mark types that MUST be present
	RequiredTrustMarks []string `json:"required_trust_marks,omitempty" yaml:"required_trust_marks,omitempty"`

	// EntityTypes filters by OpenID Federation entity types
	EntityTypes []string `json:"entity_types,omitempty" yaml:"entity_types,omitempty"`

	// MaxChainDepth limits trust chain resolution depth
	MaxChainDepth int `json:"max_chain_depth,omitempty" yaml:"max_chain_depth,omitempty"`
}

// ETSIPolicyConstraints contains ETSI TSL-specific constraints.
type ETSIPolicyConstraints struct {
	// ServiceTypes filters by ETSI service type URIs
	ServiceTypes []string `json:"service_types,omitempty" yaml:"service_types,omitempty"`

	// ServiceStatuses filters by ETSI service status URIs
	ServiceStatuses []string `json:"service_statuses,omitempty" yaml:"service_statuses,omitempty"`

	// Countries filters by country codes (e.g., ["DE", "FR"])
	Countries []string `json:"countries,omitempty" yaml:"countries,omitempty"`
}

// DIDPolicyConstraints contains DID method-specific constraints.
// These apply to both did:web and did:webvh registries.
type DIDPolicyConstraints struct {
	// AllowedDomains restricts DIDs to specific domains.
	// Supports wildcards: "*.example.com" matches "sub.example.com"
	// If empty, all domains are allowed.
	AllowedDomains []string `json:"allowed_domains,omitempty" yaml:"allowed_domains,omitempty"`

	// RequiredVerificationMethods requires specific verification method types.
	// E.g., ["Ed25519VerificationKey2020", "JsonWebKey2020"]
	RequiredVerificationMethods []string `json:"required_verification_methods,omitempty" yaml:"required_verification_methods,omitempty"`

	// RequiredServices requires specific service types in the DID document.
	// E.g., ["LinkedDomains", "CredentialRegistry"]
	RequiredServices []string `json:"required_services,omitempty" yaml:"required_services,omitempty"`

	// RequireVerifiableHistory (did:webvh only) requires valid verifiable history.
	// When true, DIDs without valid cryptographic history are rejected.
	RequireVerifiableHistory bool `json:"require_verifiable_history,omitempty" yaml:"require_verifiable_history,omitempty"`
}

// MDOCIACAPolicyConstraints contains mDOC IACA-specific constraints.
type MDOCIACAPolicyConstraints struct {
	// IssuerAllowlist restricts to specific credential issuers.
	// If empty, all issuers with valid IACAs are trusted.
	IssuerAllowlist []string `json:"issuer_allowlist,omitempty" yaml:"issuer_allowlist,omitempty"`

	// RequireIACAEndpoint requires the issuer to publish mdoc_iacas_uri.
	// When true, issuers without IACA endpoints are rejected.
	RequireIACAEndpoint bool `json:"require_iaca_endpoint,omitempty" yaml:"require_iaca_endpoint,omitempty"`
}

// PolicyManager manages trust policies and routes requests based on action.name.
type PolicyManager struct {
	policies       map[string]*Policy
	defaultPolicy  *Policy
	registryFilter map[string][]string // policy name -> allowed registry names
}

// NewPolicyManager creates a new PolicyManager.
func NewPolicyManager() *PolicyManager {
	return &PolicyManager{
		policies:       make(map[string]*Policy),
		registryFilter: make(map[string][]string),
	}
}

// RegisterPolicy adds a policy to the manager.
func (pm *PolicyManager) RegisterPolicy(policy *Policy) {
	pm.policies[policy.Name] = policy
	if len(policy.Registries) > 0 {
		pm.registryFilter[policy.Name] = policy.Registries
	}
}

// SetDefaultPolicy sets the policy used when action.name is not specified.
func (pm *PolicyManager) SetDefaultPolicy(policy *Policy) {
	pm.defaultPolicy = policy
	pm.RegisterPolicy(policy)
}

// GetPolicy returns the policy for the given action name.
// Returns the default policy if no specific policy matches.
// Returns nil if no policy matches and no default is set.
func (pm *PolicyManager) GetPolicy(actionName string) *Policy {
	if actionName == "" {
		return pm.defaultPolicy
	}
	if policy, ok := pm.policies[actionName]; ok {
		return policy
	}
	return pm.defaultPolicy
}

// ListPolicies returns all registered policy names.
func (pm *PolicyManager) ListPolicies() []string {
	names := make([]string, 0, len(pm.policies))
	for name := range pm.policies {
		names = append(names, name)
	}
	return names
}

// GetAllowedRegistries returns the registry names allowed for a policy.
// Returns nil if all registries are allowed.
func (pm *PolicyManager) GetAllowedRegistries(actionName string) []string {
	return pm.registryFilter[actionName]
}

// PolicyContext holds resolved policy information for a request.
// This is passed to registries to apply policy constraints.
type PolicyContext struct {
	// Policy is the resolved policy (may be nil if no policy applies)
	Policy *Policy

	// ActionName is the original action.name from the request
	ActionName string
}

// HasOIDFedConstraints returns true if the policy has OIDF-specific constraints.
func (pc *PolicyContext) HasOIDFedConstraints() bool {
	return pc.Policy != nil && pc.Policy.OIDFed != nil
}

// HasETSIConstraints returns true if the policy has ETSI-specific constraints.
func (pc *PolicyContext) HasETSIConstraints() bool {
	return pc.Policy != nil && pc.Policy.ETSI != nil
}

// GetOIDFedTrustMarks returns required trust marks from the policy, or nil.
func (pc *PolicyContext) GetOIDFedTrustMarks() []string {
	if pc.Policy == nil || pc.Policy.OIDFed == nil {
		return nil
	}
	return pc.Policy.OIDFed.RequiredTrustMarks
}

// GetOIDFedEntityTypes returns entity types from the policy, or nil.
func (pc *PolicyContext) GetOIDFedEntityTypes() []string {
	if pc.Policy == nil || pc.Policy.OIDFed == nil {
		return nil
	}
	return pc.Policy.OIDFed.EntityTypes
}

// GetETSIServiceTypes returns service types from the policy, or nil.
func (pc *PolicyContext) GetETSIServiceTypes() []string {
	if pc.Policy == nil || pc.Policy.ETSI == nil {
		return nil
	}
	return pc.Policy.ETSI.ServiceTypes
}

// HasDIDConstraints returns true if the policy has DID-specific constraints.
func (pc *PolicyContext) HasDIDConstraints() bool {
	return pc.Policy != nil && pc.Policy.DID != nil
}

// GetDIDAllowedDomains returns allowed domains from the policy, or nil.
func (pc *PolicyContext) GetDIDAllowedDomains() []string {
	if pc.Policy == nil || pc.Policy.DID == nil {
		return nil
	}
	return pc.Policy.DID.AllowedDomains
}

// GetDIDRequiredServices returns required services from the policy, or nil.
func (pc *PolicyContext) GetDIDRequiredServices() []string {
	if pc.Policy == nil || pc.Policy.DID == nil {
		return nil
	}
	return pc.Policy.DID.RequiredServices
}

// RequiresVerifiableHistory returns true if verifiable history is required.
func (pc *PolicyContext) RequiresVerifiableHistory() bool {
	return pc.Policy != nil && pc.Policy.DID != nil && pc.Policy.DID.RequireVerifiableHistory
}

// HasMDOCIACAConstraints returns true if the policy has mDOC IACA-specific constraints.
func (pc *PolicyContext) HasMDOCIACAConstraints() bool {
	return pc.Policy != nil && pc.Policy.MDOCIACA != nil
}

// GetMDOCIACAIssuerAllowlist returns issuer allowlist from the policy, or nil.
func (pc *PolicyContext) GetMDOCIACAIssuerAllowlist() []string {
	if pc.Policy == nil || pc.Policy.MDOCIACA == nil {
		return nil
	}
	return pc.Policy.MDOCIACA.IssuerAllowlist
}
