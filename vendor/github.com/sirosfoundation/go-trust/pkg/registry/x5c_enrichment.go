package registry

import (
	"crypto/x509"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry/rpcert"
)

// X5CEnrichmentResult holds the results of post-chain-validation enrichment
// (cert policy OID validation, RP identity extraction, and over-request detection).
type X5CEnrichmentResult struct {
	// Decision is false if required policy OIDs were not found or if
	// strict entitlement check fails due to over-requesting.
	Decision bool

	// MatchedPolicyOIDs lists the policy OIDs that matched the requirements.
	MatchedPolicyOIDs []string

	// MatchedProfile is the name of the RP profile matched by the certificate
	// (e.g., "wrpac"). Empty if no profile matched or no ProfileRegistry was used.
	MatchedProfile string

	// RPIdentity is the extracted RP identity map (nil if not requested).
	RPIdentity map[string]interface{}

	// OverRequest contains the over-request detection result (nil if not checked).
	OverRequest *rpcert.OverRequestResult

	// IntermediaryIdentity is the extracted intermediary identity (nil if no intermediary).
	IntermediaryIdentity map[string]interface{}

	// IsIntermediaryRequest indicates whether this is a proxied/brokered request.
	IsIntermediaryRequest bool

	// ProfileValidationError is set when the matched profile's ValidateCredential
	// returns an error. Non-nil does not necessarily mean Decision=false (depends
	// on policy strictness).
	ProfileValidationError string

	// WRPACOrgID is the organization_identifier extracted from the WRPAC leaf
	// certificate. Populated when the matched profile is "wrpac". Used by callers
	// to perform WRPAC–WRPRC organisation-level binding per ARF RPRC_16.
	WRPACOrgID string

	// WRPACServiceID is the service_identifier URI extracted from the WRPAC leaf
	// certificate Subject attribute OIDWRPACServiceIdentifier (0.4.0.19475.99.1).
	// Populated when the matched profile is "wrpac" AND the attribute is present.
	// Empty for certificates that do not carry this attribute (e.g. Anna's certs
	// following strict ETSI TS 119 411-8 v1.1.1 which does not define this OID).
	//
	// When non-empty, callers should additionally invoke
	// rpcert.CheckWRPACWRPRCServiceBinding(WRPACServiceID, wrprc) after the
	// organisation-level binding check.
	WRPACServiceID string

	// FailureReason is set when Decision is false, describing why.
	FailureReason map[string]interface{}
}

// EnrichX5CResponse performs post-chain-validation enrichment on a successful
// x5c evaluation: validates certificate policy OIDs (if required) and extracts
// RP identity (if requested). Both features are controlled via request context
// fields injected by policy configuration.
//
// Call this after successful chain validation. If the result has Decision=false,
// the caller should return a deny response with result.FailureReason merged
// into the reason map.
func EnrichX5CResponse(req *authzen.EvaluationRequest, leaf *x509.Certificate) *X5CEnrichmentResult {
	return EnrichX5CResponseWithProfiles(req, leaf, nil)
}

// EnrichX5CResponseWithProfiles is like EnrichX5CResponse but additionally
// matches the leaf certificate against registered RP profiles. When a profile
// matches, it is used for identity extraction and profile-specific validation.
// Pass nil for profiles to get the same behaviour as EnrichX5CResponse.
func EnrichX5CResponseWithProfiles(req *authzen.EvaluationRequest, leaf *x509.Certificate, profiles *rpcert.ProfileRegistry) *X5CEnrichmentResult {
	result := &X5CEnrichmentResult{Decision: true}

	// Validate certificate policy OIDs if required
	requiredOIDs := ExtractRequiredCertPolicyOIDs(req)
	if len(requiredOIDs) > 0 {
		matched, matchedOIDs := ValidateCertPolicyOIDs(leaf, requiredOIDs)
		if !matched {
			leafOIDs := rpcert.CertPolicyOIDStrings(leaf)
			result.Decision = false
			result.FailureReason = map[string]interface{}{
				"error":                   "certificate does not contain required policy OIDs",
				"required_policy_oids":    requiredOIDs,
				"certificate_policy_oids": leafOIDs,
			}
			return result
		}
		result.MatchedPolicyOIDs = matchedOIDs
	}

	// Profile matching: if a ProfileRegistry is provided, try to match the
	// certificate against a known RP profile for structured validation and
	// identity extraction.
	var matchedProfile rpcert.RPProfile
	if profiles != nil {
		matchedProfile = profiles.MatchCertificate(leaf)
	}
	if matchedProfile != nil {
		result.MatchedProfile = matchedProfile.Name()

		// Run profile-specific validation (key usage, required extensions, etc.)
		if err := matchedProfile.ValidateCredential(leaf); err != nil {
			result.ProfileValidationError = err.Error()
			// Profile validation failures are warnings unless strict mode
			// is enabled (in which case the caller can act on it).
		}
	}

	// Extract RP identity if requested — prefer profile-specific extraction
	if ShouldExtractRPIdentity(req) {
		var identity map[string]interface{}
		if matchedProfile != nil {
			var err error
			identity, err = matchedProfile.ExtractIdentity(leaf)
			if err != nil {
				identity = ExtractRPIdentity(leaf)
			}
		} else {
			identity = ExtractRPIdentity(leaf)
		}
		result.RPIdentity = identity

		// Populate WRPACOrgID and WRPACServiceID for downstream binding checks
		// when the matched profile is "wrpac".
		if id, ok := identity["organization_identifier"].(string); ok && id != "" {
			result.WRPACOrgID = id
		}
		// WRPACServiceID: only present in certs using Stefan Santesson's
		// de-facto convention (OIDWRPACServiceIdentifier 0.4.0.19475.99.1).
		// Empty for strict ETSI TS 119 411-8 certs — that's intentional.
		if svc, ok := identity["service_identifier"].(string); ok && svc != "" {
			result.WRPACServiceID = svc
		}
	} else if matchedProfile != nil && matchedProfile.Name() == "wrpac" {
		// Extract IDs for binding even when full identity extraction is not
		// requested, so binding checks can run without leaking the full map.
		if identity, err := matchedProfile.ExtractIdentity(leaf); err == nil {
			if id, ok := identity["organization_identifier"].(string); ok {
				result.WRPACOrgID = id
			}
			if svc, ok := identity["service_identifier"].(string); ok {
				result.WRPACServiceID = svc
			}
		}
	}

	// Over-request detection: compare requested attributes against entitlements
	requestedAttrs := extractRequestedAttributes(req)
	allowedAttrs := extractAllowedAttributes(req)
	if len(requestedAttrs) > 0 && len(allowedAttrs) > 0 {
		entitlements := &rpcert.RPEntitlements{
			AllowedAttributes: allowedAttrs,
		}
		result.OverRequest = rpcert.DetectOverRequest(entitlements, requestedAttrs)

		if result.OverRequest.IsOverRequest && isStrictEntitlementCheck(req) {
			result.Decision = false
			result.FailureReason = map[string]interface{}{
				"error":          "RP is requesting attributes beyond their entitlements",
				"over_requested": result.OverRequest.OverRequested,
				"allowed":        result.OverRequest.Allowed,
				"requested":      result.OverRequest.Requested,
			}
			return result
		}
	}

	// Intermediary verification: check if this is a proxied/brokered request
	intermediaryX5C := extractIntermediaryX5C(req)
	if len(intermediaryX5C) > 0 {
		result.IsIntermediaryRequest = true
		if !isIntermediariesAllowed(req) {
			result.Decision = false
			result.FailureReason = map[string]interface{}{
				"error": "intermediary/broker presentation requests are not allowed by policy",
			}
			return result
		}
		// Extract intermediary identity from the first cert in the chain.
		// NOTE: The intermediary certificate chain is NOT validated against any
		// trust store. This metadata is informational only. Full intermediary
		// chain validation will be implemented when the intermediary certificate
		// profile is finalized.
		result.IntermediaryIdentity = map[string]interface{}{
			"intermediary_x5c_leaf": intermediaryX5C[0],
			"rp_subject":            leaf.Subject.CommonName,
			"verified":              false,
		}
	}

	return result
}

// ApplyEnrichmentToResponse merges X5CEnrichmentResult into an existing
// successful EvaluationResponse, adding matched_policy_oids to the reason
// and trust metadata (rp_identity, matched_policy_oids) if present.
func ApplyEnrichmentToResponse(resp *authzen.EvaluationResponse, enrichment *X5CEnrichmentResult) {
	if enrichment == nil {
		return
	}
	if resp.Context == nil {
		resp.Context = &authzen.EvaluationResponseContext{}
	}
	if resp.Context.Reason == nil {
		resp.Context.Reason = make(map[string]interface{})
	}

	if len(enrichment.MatchedPolicyOIDs) > 0 {
		resp.Context.Reason["matched_policy_oids"] = enrichment.MatchedPolicyOIDs
	}
	if enrichment.MatchedProfile != "" {
		resp.Context.Reason["matched_profile"] = enrichment.MatchedProfile
	}

	// Build trust metadata if we have identity or matched OIDs
	var trustMetadata map[string]interface{}
	if enrichment.RPIdentity != nil {
		trustMetadata = map[string]interface{}{
			"rp_identity": enrichment.RPIdentity,
		}
	}
	if len(enrichment.MatchedPolicyOIDs) > 0 {
		if trustMetadata == nil {
			trustMetadata = make(map[string]interface{})
		}
		trustMetadata["matched_policy_oids"] = enrichment.MatchedPolicyOIDs
	}
	if enrichment.MatchedProfile != "" {
		if trustMetadata == nil {
			trustMetadata = make(map[string]interface{})
		}
		trustMetadata["rp_profile"] = enrichment.MatchedProfile
	}

	if trustMetadata != nil {
		// Merge into existing TrustMetadata if it's already a map
		if existing, ok := resp.Context.TrustMetadata.(map[string]interface{}); ok {
			for k, v := range trustMetadata {
				existing[k] = v
			}
		} else if resp.Context.TrustMetadata == nil {
			resp.Context.TrustMetadata = trustMetadata
		}
	}

	// Add profile validation warnings if any
	if enrichment.ProfileValidationError != "" {
		resp.Context.Reason["profile_validation_warning"] = enrichment.ProfileValidationError
	}

	// Add over-request warnings to reason (warn-only mode)
	if enrichment.OverRequest != nil && enrichment.OverRequest.IsOverRequest {
		resp.Context.Reason["over_request_warnings"] = map[string]interface{}{
			"over_requested": enrichment.OverRequest.OverRequested,
			"allowed":        enrichment.OverRequest.Allowed,
			"requested":      enrichment.OverRequest.Requested,
		}
	}

	// Add intermediary metadata to trust metadata
	if enrichment.IsIntermediaryRequest && enrichment.IntermediaryIdentity != nil {
		if resp.Context.TrustMetadata == nil {
			resp.Context.TrustMetadata = make(map[string]interface{})
		}
		if existing, ok := resp.Context.TrustMetadata.(map[string]interface{}); ok {
			existing["intermediary"] = enrichment.IntermediaryIdentity
			existing["is_intermediary_request"] = true
		}
	}
}

// ExtractRequiredCertPolicyOIDs extracts required certificate policy OIDs from
// the request context. These can be set via policy config or passed dynamically.
func ExtractRequiredCertPolicyOIDs(req *authzen.EvaluationRequest) []string {
	if req.Context == nil {
		return nil
	}
	v, ok := req.Context["required_cert_policy_oids"]
	if !ok {
		return nil
	}
	switch oids := v.(type) {
	case []string:
		return oids
	case []interface{}:
		result := make([]string, 0, len(oids))
		for _, s := range oids {
			if str, ok := s.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}
	return nil
}

// ValidateCertPolicyOIDs checks whether the certificate contains at least one
// of the required policy OIDs. Returns true and the matched OIDs if found.
// Checks both cert.Policies (Go 1.22+) and legacy cert.PolicyIdentifiers.
func ValidateCertPolicyOIDs(cert *x509.Certificate, requiredOIDs []string) (bool, []string) {
	required := make(map[string]bool, len(requiredOIDs))
	for _, oid := range requiredOIDs {
		required[oid] = true
	}

	seen := make(map[string]bool)
	var matched []string
	// Check newer Policies field
	for _, policyOID := range cert.Policies {
		oidStr := policyOID.String()
		if required[oidStr] && !seen[oidStr] {
			seen[oidStr] = true
			matched = append(matched, oidStr)
		}
	}
	// Also check legacy PolicyIdentifiers
	for _, policyOID := range cert.PolicyIdentifiers {
		oidStr := policyOID.String()
		if required[oidStr] && !seen[oidStr] {
			seen[oidStr] = true
			matched = append(matched, oidStr)
		}
	}
	return len(matched) > 0, matched
}

// ShouldExtractRPIdentity checks whether RP identity extraction is requested
// via the request context field "extract_rp_identity".
func ShouldExtractRPIdentity(req *authzen.EvaluationRequest) bool {
	if req.Context == nil {
		return false
	}
	v, ok := req.Context["extract_rp_identity"]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}

// ExtractRPIdentity extracts RP identity information from a leaf certificate.
// Returns a map with organization, common name, country, serial number, and SANs.
// Delegates to rpcert.ExtractBaseCertIdentity for the shared extraction logic.
func ExtractRPIdentity(cert *x509.Certificate) map[string]interface{} {
	return rpcert.ExtractBaseCertIdentity(cert)
}

// extractRequestedAttributes extracts the list of attributes the RP is requesting.
// It checks (in order of priority):
//  1. request.Context["requested_attributes"] — explicit flat list
//  2. action.Parameters["query"] — DCQL query, from which claim names are extracted
func extractRequestedAttributes(req *authzen.EvaluationRequest) []string {
	// Check for explicit requested_attributes first
	if req.Context != nil {
		if attrs := extractStringSliceFromContext(req.Context, "requested_attributes"); len(attrs) > 0 {
			return attrs
		}
	}

	// Fall back to extracting claim names from DCQL query in action parameters
	if req.Action != nil && req.Action.Parameters != nil {
		if queryRaw, ok := req.Action.Parameters["query"]; ok {
			if dcql := rpcert.ParseDCQLQuery(queryRaw); dcql != nil {
				return dcql.ExtractRequestedClaimNames()
			}
		}
	}

	return nil
}

// extractAllowedAttributes extracts the RP's entitled attributes
// from request.Context["allowed_attributes"].
func extractAllowedAttributes(req *authzen.EvaluationRequest) []string {
	if req.Context == nil {
		return nil
	}
	return extractStringSliceFromContext(req.Context, "allowed_attributes")
}

// isStrictEntitlementCheck checks whether strict entitlement checking is enabled
// via request.Context["strict_entitlement_check"].
func isStrictEntitlementCheck(req *authzen.EvaluationRequest) bool {
	if req.Context == nil {
		return false
	}
	v, ok := req.Context["strict_entitlement_check"]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}

// extractStringSliceFromContext extracts a []string from a context map value,
// handling both []string and []interface{} (from JSON deserialization).
func extractStringSliceFromContext(ctx map[string]interface{}, key string) []string {
	v, ok := ctx[key]
	if !ok {
		return nil
	}
	switch s := v.(type) {
	case []string:
		return s
	case []interface{}:
		result := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}
	return nil
}

// extractIntermediaryX5C extracts the intermediary certificate chain from
// request.Context["intermediary_x5c"]. This is a list of base64-encoded
// certificates representing the intermediary's access certificate chain.
func extractIntermediaryX5C(req *authzen.EvaluationRequest) []string {
	if req.Context == nil {
		return nil
	}
	return extractStringSliceFromContext(req.Context, "intermediary_x5c")
}

// isIntermediariesAllowed checks whether intermediary/broker presentations are
// allowed via request.Context["allow_intermediaries"].
func isIntermediariesAllowed(req *authzen.EvaluationRequest) bool {
	if req.Context == nil {
		return false
	}
	v, ok := req.Context["allow_intermediaries"]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}
