package registry

import (
	"context"
	"crypto/x509"
	"strconv"
	"strings"

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

	// WRPRCEntitlements holds the parsed and validated entitlements of the
	// FRONTED relying party's WRPRC (ETSI TS 119 475), when the request
	// carried one — request.Context["wrprc"], the content of the ETSI TS
	// 119 472-2 §6.3.2.2 `registration_cert` member. Nil when the request
	// carried no WRPRC (the pre-EAAP shape). When non-nil the registrar's
	// chain anchored in the verifier's roots, the JWT signature verified
	// under the anchored chain's leaf key, the validity period held at
	// evaluation time, and the presenting WRPAC bound to the WRPRC per the
	// presentation actually being made (direct RPRC_16, or the Table 10
	// `act` intermediary binding).
	WRPRCEntitlements *rpcert.RPEntitlements

	// VerifierIDs are the verifier identifiers derived from the verified leaf
	// certificate, for the types the policy enabled (return_verifier_ids). It is
	// empty unless Decision is true and ProfileValidationError is empty: nothing
	// is derived from a certificate that failed profile validation.
	VerifierIDs []authzen.VerifierID

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
	return EnrichX5CResponseWithProfiles(req, leaf, nil, nil)
}

// EnrichX5CResponseWithProfiles is like EnrichX5CResponse but additionally
// matches the leaf certificate against registered RP profiles. When a profile
// matches, it is used for identity extraction and profile-specific validation.
// Pass nil for profiles to get the same behaviour as EnrichX5CResponse.
//
// wrprcValidator evaluates the fronted relying party's WRPRC when the
// request carries one (request.Context["wrprc"], the TS 119 472-2
// registration_cert member's content): the registrar chain is anchored in
// the verifier's roots, the JWT signature is verified under the anchored
// chain's leaf key, the claims are parsed, the validity period is checked,
// and the presenting WRPAC is bound to the WRPRC. A presented WRPRC with a
// nil verifier fails closed — a registry that cannot evaluate a
// registration certificate must not wave it through. See WRPRCVerifier and
// NewAnchoredWRPRCVerifier.
func EnrichX5CResponseWithProfiles(req *authzen.EvaluationRequest, leaf *x509.Certificate, profiles *rpcert.ProfileRegistry, wrprcValidator WRPRCVerifier) *X5CEnrichmentResult {
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

	// The EAAP presentation model (ETSI TS 119 475 + 119 411-8): when the
	// request carries the fronted relying party's registration certificate —
	// request.Context["wrprc"], the content of the ETSI TS 119 472-2
	// §6.3.2.2 `registration_cert` member — evaluate it against the
	// registrar's anchors and bind it to the presenting WRPAC. This path is
	// AUTHORITATIVE: the registrar-issued entitlements supersede the
	// policy-configured allowed_attributes, and the verified binding
	// supersedes the unvalidated intermediary_x5c metadata.
	//
	// A PRESENT but malformed member never falls back to the legacy path:
	// wrprc: {} or null or "" is a request that names a registration
	// certificate and fails to carry one — denied, not reinterpreted.
	wrprcToken, wrprcValid, wrprcPresent := extractWRPRC(req)
	if wrprcPresent {
		if !wrprcValid {
			result.Decision = false
			result.FailureReason = map[string]interface{}{
				"error": "the wrprc member is malformed: expected a non-empty registration certificate string",
			}
			return result
		}
		if wrprcValidator == nil {
			result.Decision = false
			result.FailureReason = map[string]interface{}{
				"error": "a WRPRC was presented but this registry has no registrar trust anchors configured",
			}
			return result
		}
		ent, err := wrprcValidator.VerifyWRPRC(context.Background(), []byte(wrprcToken))
		if err != nil {
			result.Decision = false
			result.FailureReason = map[string]interface{}{
				"error": "the presented WRPRC failed validation",
				"wrprc": err.Error(),
			}
			return result
		}
		result.WRPRCEntitlements = ent

		if ent.ActingIntermediary != "" {
			// An intermediated presentation (Table 10 `act`, GEN-5.2.4-09):
			// the presenting WRPAC is the INTERMEDIARY's access certificate,
			// and the policy must admit intermediaries at all.
			result.IsIntermediaryRequest = true
			if !isIntermediariesAllowed(req) {
				result.Decision = false
				result.FailureReason = map[string]interface{}{
					"error": "intermediary presentations are not allowed by policy (the WRPRC names an acting intermediary)",
				}
				return result
			}
		}
		// The binding is the security property of this path, so its
		// identifiers are REQUIRED here — the optional-skip semantics of the
		// underlying helpers (empty means "not present, do not enforce") are
		// for WRPRC-only flows. The binding identifier is the SUBJECT's
		// semantic identifier: for a legal person the
		// organizationIdentifier, for a natural person the personal
		// identifier from serialNumber (ETSI TS 119 475 §5.1.5) — never an
		// affiliated organization's identifier, which would bind a person's
		// certificate to the organization's WRPRC.
		bindingID, hasBindingID := rpcert.SemanticIdentifier(leaf)
		if !hasBindingID || bindingID == "" {
			result.Decision = false
			result.FailureReason = map[string]interface{}{
				"error": "the presenting certificate carries no usable binding identifier; the WRPRC binding cannot be established",
			}
			return result
		}
		if ent.ActingIntermediary == "" && ent.Subject.ID == "" {
			result.Decision = false
			result.FailureReason = map[string]interface{}{
				"error": "the WRPRC names no identifier to bind the presentation to",
			}
			return result
		}
		if err := rpcert.CheckWRPACWRPRCPresentationBinding(bindingID, ent); err != nil {
			result.Decision = false
			result.FailureReason = map[string]interface{}{
				"error": "the presenting WRPAC does not bind to the WRPRC",
				"wrprc": err.Error(),
			}
			return result
		}
		// The service-identifier binding (the Santesson convention,
		// OIDWRPACServiceIdentifier): when both sides carry one they must
		// match, or a certificate for service A reuses a WRPRC issued for
		// service B within the same organization. DIRECT presentations
		// only: the helper distinguishes services of ONE organization, and
		// an intermediated presentation legitimately carries the
		// INTERMEDIARY's service identifier beside the FRONTED RP's.
		if ent.ActingIntermediary == "" {
			if err := rpcert.CheckWRPACWRPRCServiceBinding(result.WRPACServiceID, ent); err != nil {
				result.Decision = false
				result.FailureReason = map[string]interface{}{
					"error": "the presenting WRPAC's service identifier does not bind to the WRPRC",
					"wrprc": err.Error(),
				}
				return result
			}
		}

		// A whole-credential request — a DCQL credential query without
		// `claims` — is checked FIRST and unconditionally: a MIXED query
		// (one claims-less credential beside one with claims) must not slip
		// the unrepresentable scope past the attribute-level comparison
		// below, which would otherwise see only the explicit claims.
		// In strict mode the unrepresentable scope denies; otherwise it is
		// surfaced as a warning and the attribute comparison still runs.
		if requestsWholeCredential(req) {
			result.OverRequest = &rpcert.OverRequestResult{
				OverRequested: []string{"<the entire credential>"},
				IsOverRequest: true,
			}
			if isStrictEntitlementCheck(req) {
				result.Decision = false
				result.FailureReason = map[string]interface{}{
					"error": "the request asks for a whole credential, which the WRPRC's attribute-level grants cannot represent",
				}
				return result
			}
		}

		// Over-request detection against the AUTHORITATIVE entitlements at
		// their native granularity: the registrar's granted claim paths,
		// exact-path and format-scoped — flattening [namespace, element] to
		// namespace would let a grant for one element authorize the whole
		// namespace. The requested set is the union of EVERY representation
		// the request carries — the flat requested_attributes list and the
		// DCQL queries' claim paths — so one representation cannot hide a
		// beyond-grant request inside another. A WRPRC granting NO queries
		// is an authoritative empty grant: every requested claim is an
		// over-request.
		if requested := requestedClaimGrants(req); len(requested) > 0 {
			overReq := rpcert.DetectOverRequestPaths(ent, requested)
			// A clean attribute comparison must not erase the
			// whole-credential warning recorded above.
			if overReq.IsOverRequest || result.OverRequest == nil {
				result.OverRequest = overReq
			}
			if result.OverRequest.IsOverRequest && isStrictEntitlementCheck(req) {
				denyOverRequest(result)
				return result
			}
		}

		// Verified intermediary metadata for the intermediated shape: the
		// registrar chain anchored and the binding was checked, unlike the
		// unverified intermediary_x5c shape below.
		if ent.ActingIntermediary != "" {
			result.IntermediaryIdentity = map[string]interface{}{
				"acting_intermediary":   ent.ActingIntermediary,
				"fronted_rp_id":         ent.Subject.ID,
				"fronted_rp_legal_name": ent.Subject.LegalName,
				"verified":              true,
			}
		}
	} else {
		// The legacy path: the request carried no wrprc member at all (the
		// pre-EAAP shape) — a present-but-malformed one was denied above.
		// Over-request detection: compare requested attributes against entitlements
		requestedAttrs := extractRequestedAttributes(req)
		allowedAttrs := extractAllowedAttributes(req)
		if len(requestedAttrs) > 0 && len(allowedAttrs) > 0 {
			entitlements := &rpcert.RPEntitlements{
				AllowedAttributes: allowedAttrs,
			}
			result.OverRequest = rpcert.DetectOverRequest(entitlements, requestedAttrs)

			if result.OverRequest.IsOverRequest && isStrictEntitlementCheck(req) {
				denyOverRequest(result)
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
			// trust store. This metadata is informational only. Requests carrying
			// a WRPRC take the verified EAAP path above instead.
			result.IntermediaryIdentity = map[string]interface{}{
				"intermediary_x5c_leaf": intermediaryX5C[0],
				"rp_subject":            leaf.Subject.CommonName,
				"verified":              false,
			}
		}
	}

	// Verifier identifiers: only from a certificate that passed every check
	// above, including the matched profile's validation. A profile failure is
	// otherwise only a warning, so it has to be tested for explicitly here.
	// A VERIFIED intermediated WRPRC is exempt: the leaf is the
	// INTERMEDIARY's certificate, and emitting its semantic identifier as
	// the end RP's verifier ID would attribute the fronted RP's
	// presentations to the intermediary.
	intermediatedWRPRC := result.WRPRCEntitlements != nil && result.WRPRCEntitlements.ActingIntermediary != ""
	if result.Decision && result.ProfileValidationError == "" && !intermediatedWRPRC {
		result.VerifierIDs = deriveX5CVerifierIDs(req, leaf, result.IsIntermediaryRequest)
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

	// The fronted relying party's WRPRC evaluation, when the request carried
	// one: the registrar-anchored entitlements the wallet renders and its EDP
	// layer enforces, plus the acting intermediary for intermediated
	// presentations.
	if enrichment.WRPRCEntitlements != nil {
		if trustMetadata == nil {
			trustMetadata = make(map[string]interface{})
		}
		ent := enrichment.WRPRCEntitlements
		trustMetadata["wrprc"] = map[string]interface{}{
			"fronted_rp_id":         ent.Subject.ID,
			"fronted_rp_legal_name": ent.Subject.LegalName,
			"acting_intermediary":   ent.ActingIntermediary,
			"trade_name":            ent.TradeName,
			"country":               ent.Country,
			"entitlements":          ent.EntitlementURIs,
			// The display-oriented flat names AND the exact grants: an
			// mdoc grant for [namespace, age_over_18] flattens to the
			// namespace alone, and a consumer cannot distinguish it from a
			// grant for [namespace, portrait] without the full paths.
			"allowed_attributes":  ent.AllowedAttributes,
			"allowed_claim_paths": claimPathGrantsMetadata(ent.AllowedClaimPaths),
			"privacy_policy_uri":  ent.PrivacyPolicyURI,
		}
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

	// Verifier identifiers, fail closed: never on a deny, never when the profile
	// validation failed, never from a failed enrichment.
	if resp.Decision && enrichment.Decision && enrichment.ProfileValidationError == "" {
		resp.Context.VerifierIDs = append(resp.Context.VerifierIDs, enrichment.VerifierIDs...)
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
//  2. the DCQL query — from action.Parameters OR request.Context (the
//     manager accepts it in both places), from which claim names are extracted
func extractRequestedAttributes(req *authzen.EvaluationRequest) []string {
	// Check for explicit requested_attributes first
	if req.Context != nil {
		if attrs := extractStringSliceFromContext(req.Context, "requested_attributes"); len(attrs) > 0 {
			return attrs
		}
	}

	// The DCQL query: action parameters first, then the request context —
	// the manager's allowlist admits "query" in both.
	if req.Action != nil && req.Action.Parameters != nil {
		if queryRaw, ok := req.Action.Parameters["query"]; ok {
			if dcql := rpcert.ParseDCQLQuery(queryRaw); dcql != nil {
				return dcql.ExtractRequestedClaimNames()
			}
		}
	}
	if req.Context != nil {
		if queryRaw, ok := req.Context["query"]; ok {
			if dcql := rpcert.ParseDCQLQuery(queryRaw); dcql != nil {
				return dcql.ExtractRequestedClaimNames()
			}
		}
	}

	return nil
}

// requestsWholeCredential reports whether the request's DCQL carries a
// credential query WITHOUT claims — a request for the entire credential,
// which no attribute-level grant can represent.
func requestsWholeCredential(req *authzen.EvaluationRequest) bool {
	var queryRaw interface{}
	if req.Action != nil && req.Action.Parameters != nil {
		queryRaw = req.Action.Parameters["query"]
	}
	if queryRaw == nil && req.Context != nil {
		queryRaw = req.Context["query"]
	}
	if queryRaw == nil {
		return false
	}
	dcql := rpcert.ParseDCQLQuery(queryRaw)
	if dcql == nil {
		return false
	}
	return dcql.RequestsWholeCredential()
}

// claimPathGrantsMetadata renders the registrar's exact claim-path grants
// for response consumers: each entry the credential format and the full
// claim path at its native granularity.
func claimPathGrantsMetadata(grants []rpcert.ClaimPathGrant) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(grants))
	for _, grant := range grants {
		out = append(out, map[string]interface{}{
			"format": grant.Format,
			"path":   append([]string(nil), grant.Path...),
		})
	}
	return out
}

// denyOverRequest marks the enrichment result as a strict-mode over-request
// denial — the shared shape of the WRPRC (authoritative) and legacy
// (policy-configured) over-request paths.
func denyOverRequest(result *X5CEnrichmentResult) {
	result.Decision = false
	result.FailureReason = map[string]interface{}{
		"error":          "RP is requesting attributes beyond their entitlements",
		"over_requested": result.OverRequest.OverRequested,
		"allowed":        result.OverRequest.Allowed,
		"requested":      result.OverRequest.Requested,
	}
}

// extractWRPRC extracts the serialized fronted relying party's WRPRC
// (the TS 119 472-2 §6.3.2.2 `registration_cert` member's content) from
// request.Context["wrprc"], distinguishing ABSENT from PRESENT-but-invalid:
// absent is the pre-EAAP request shape (the legacy path); a present member
// that is not a non-empty string is malformed and must not be reinterpreted
// as an absence.
func extractWRPRC(req *authzen.EvaluationRequest) (token string, valid bool, present bool) {
	if req.Context == nil {
		return "", false, false
	}
	v, ok := req.Context["wrprc"]
	if !ok {
		return "", false, false
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", false, true
	}
	return s, true, true
}

// requestedClaimGrants builds the requested claim set from EVERY
// representation the request carries — the flat requested_attributes list
// and the DCQL queries' claim paths (action parameters or request context,
// both allowlisted) — so one representation cannot hide a beyond-grant
// request inside another. The flat entries carry no credential format; the
// DCQL entries carry their query's.
func requestedClaimGrants(req *authzen.EvaluationRequest) []rpcert.ClaimPathGrant {
	var requested []rpcert.ClaimPathGrant
	seen := map[string]bool{}
	add := func(format string, path []string) {
		if len(path) == 0 {
			return
		}
		// Deduplicate through a key that is injective BY CONSTRUCTION —
		// every field length-prefixed — so ["address", "street"] and
		// ["address.street"] never merge, and the cost stays LINEAR in the
		// requested-claim count: a quadratic scan would let a hostile
		// 20,000-claim request force ~200 million comparisons before the
		// request can be denied.
		key := claimPathKey(format, path)
		if seen[key] {
			return
		}
		seen[key] = true
		requested = append(requested, rpcert.ClaimPathGrant{Format: format, Path: path})
	}
	if req.Context != nil {
		for _, name := range extractStringSliceFromContext(req.Context, "requested_attributes") {
			if name != "" {
				add("", []string{name})
			}
		}
	}
	for _, raw := range dcqlQueries(req) {
		if dcql := rpcert.ParseDCQLQuery(raw); dcql != nil {
			for _, cred := range dcql.Credentials {
				for _, claim := range cred.Claims {
					add(cred.Format, claim.Path)
				}
			}
		}
	}
	return requested
}

// claimPathKey builds an injective string key for a (format, path) claim
// grant: every field length-prefixed as <len>:<content>, so no two distinct
// pairs produce the same key — the parse is deterministic at every step —
// and deduplication stays linear in the requested-claim count.
func claimPathKey(format string, path []string) string {
	var b strings.Builder
	writeField := func(field string) {
		b.WriteString(strconv.Itoa(len(field)))
		b.WriteByte(':')
		b.WriteString(field)
	}
	writeField(format)
	for _, segment := range path {
		writeField(segment)
	}
	return b.String()
}

// dcqlQueries yields the raw DCQL query values the request carries, from
// action parameters and from the request context.
func dcqlQueries(req *authzen.EvaluationRequest) []interface{} {
	var out []interface{}
	if req.Action != nil && req.Action.Parameters != nil {
		if q, ok := req.Action.Parameters["query"]; ok {
			out = append(out, q)
		}
	}
	if req.Context != nil {
		if q, ok := req.Context["query"]; ok {
			out = append(out, q)
		}
	}
	return out
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

// deriveX5CVerifierIDs derives the verifier identifiers of the relying party
// from its verified leaf certificate, for the types the policy enabled.
// The chain has already been validated by the caller.
//
//   - semantic: the ETSI semantic identifier from the leaf (basis x5c-chain),
//     validated against the semantic-id syntax; "semantic_id:" + the value.
//   - dns / uri: the client_id of an x509_san_dns / x509_san_uri request, but
//     only after VerifyLeafBinding confirms it is a SAN of this leaf (basis
//     client-id-binding). The client_id is never echoed otherwise.
//
// For an intermediary request the identifier must be the end relying party's.
// The leaf is the end RP's certificate (the intermediary's own chain is
// unvalidated and is never read here), so semantic is established. The
// client_id of a brokered request cannot be shown to name the end RP, so dns
// and uri are omitted.
func deriveX5CVerifierIDs(req *authzen.EvaluationRequest, leaf *x509.Certificate, intermediary bool) []authzen.VerifierID {
	enabled := VerifierIDTypesEnabled(req)
	if len(enabled) == 0 || leaf == nil {
		return nil
	}
	want := make(map[string]bool, len(enabled))
	for _, t := range enabled {
		want[t] = true
	}

	var ids []authzen.VerifierID
	if want[authzen.VerifierIDTypeSemantic] {
		if sem, ok := rpcert.SemanticIdentifier(leaf); ok {
			ids = append(ids, authzen.VerifierID{
				Type:  authzen.VerifierIDTypeSemantic,
				ID:    authzen.VerifierIDSemanticPrefix + sem,
				Basis: authzen.VerifierIDBasisX5CChain,
			})
		}
	}

	// dns / uri: not for an intermediary request (see above).
	if intermediary {
		return ids
	}
	if id, ok := deriveSANVerifierID(req, leaf, want); ok {
		ids = append(ids, id)
	}
	return ids
}

// deriveSANVerifierID derives the dns or uri identifier from the client_id of
// an x509_san_dns / x509_san_uri request, only when the type is wanted and
// VerifyLeafBinding confirms the value is a SAN of leaf.
func deriveSANVerifierID(req *authzen.EvaluationRequest, leaf *x509.Certificate, want map[string]bool) (authzen.VerifierID, bool) {
	scheme, value, ok := ParseClientIDScheme(OriginalSubjectID(req))
	if !ok || value == "" {
		return authzen.VerifierID{}, false
	}
	var idType, id string
	switch scheme {
	case ClientIDSchemeX509SANDNS:
		// Not an identifier of one RP: a wildcard, or anything that has no
		// canonical form (non-ASCII, empty labels, over-long, ...). Checked
		// here explicitly rather than left to the SAN binding.
		canonical, ok := CanonicalDNSName(value)
		if !ok {
			return authzen.VerifierID{}, false
		}
		// Likewise a client_id that binds only through a wildcard SAN names
		// one of many hosts, not the certificate holder.
		if !sanExactlyContains(leaf.DNSNames, value) {
			return authzen.VerifierID{}, false
		}
		idType, id = authzen.VerifierIDTypeDNS, canonical
	case ClientIDSchemeX509SANURI:
		// Byte-for-byte: URISANMatches is an exact comparison, so the bound
		// value already is the SAN. Not re-serialised through net/url.
		idType, id = authzen.VerifierIDTypeURI, value
	default:
		return authzen.VerifierID{}, false
	}
	if !want[idType] || VerifyLeafBinding(scheme, value, leaf) != nil {
		return authzen.VerifierID{}, false
	}
	return authzen.VerifierID{Type: idType, ID: id, Basis: authzen.VerifierIDBasisClientIDBinding}, true
}
