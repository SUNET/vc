package registry

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sirosfoundation/g119612/pkg/logging"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// RegistryManager coordinates multiple TrustRegistry implementations.
// It routes evaluation requests to applicable registries based on their
// SupportedResourceTypes and executes queries according to the configured
// ResolutionStrategy. Optionally, a PolicyManager can be used to apply
// action-based policy constraints.
type RegistryManager struct {
	registries      []TrustRegistry
	strategy        ResolutionStrategy
	timeout         time.Duration
	circuitBreakers map[string]*CircuitBreaker
	policyManager   *PolicyManager
	logger          logging.Logger
	mu              sync.RWMutex
}

// NewRegistryManager creates a new RegistryManager with the specified strategy and timeout.
//
// strategy: How to aggregate results from multiple registries
// timeout: Maximum time to wait for registry responses
func NewRegistryManager(strategy ResolutionStrategy, timeout time.Duration) *RegistryManager {
	return &RegistryManager{
		registries:      make([]TrustRegistry, 0),
		strategy:        strategy,
		timeout:         timeout,
		circuitBreakers: make(map[string]*CircuitBreaker),
		logger:          logging.SilentLogger(),
	}
}

// SetLogger sets the logger for debug trace messages.
// If not called, a silent (no-op) logger is used.
func (m *RegistryManager) SetLogger(logger logging.Logger) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logger = logger
}

// getLogger returns the configured logger, or a SilentLogger if none is set.
// This guards against nil logger when RegistryManager is created without NewRegistryManager.
func (m *RegistryManager) getLogger() logging.Logger {
	if m.logger == nil {
		return logging.SilentLogger()
	}
	return m.logger
}

// SetPolicyManager sets the policy manager for action-based routing.
func (m *RegistryManager) SetPolicyManager(pm *PolicyManager) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policyManager = pm
}

// GetPolicyManager returns the policy manager, or nil if not set.
func (m *RegistryManager) GetPolicyManager() *PolicyManager {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.policyManager
}

// Register adds a TrustRegistry to the manager. Registries are queried in the
// order they are registered when using Sequential strategy.
func (m *RegistryManager) Register(registry TrustRegistry) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.registries = append(m.registries, registry)

	// Create circuit breaker for this registry
	info := registry.Info()
	m.circuitBreakers[info.Name] = NewCircuitBreaker(5, 30*time.Second)
}

// Evaluate implements the TrustRegistry interface by delegating to registered registries
// according to the configured strategy. If a PolicyManager is set, it resolves the policy
// from action.name and applies constraints.
func (m *RegistryManager) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	startTime := time.Now()
	logger := m.getLogger()

	logger.Debug("Evaluate: incoming request",
		logging.F("subject_id", req.Subject.ID),
		logging.F("subject_type", req.Subject.Type),
		logging.F("resource_type", req.Resource.Type),
		logging.F("resource_id", req.Resource.ID),
		logging.F("resolution_only", req.IsResolutionOnlyRequest()),
		logging.F("strategy", string(m.strategy)))

	// Validate request first
	if err := req.Validate(); err != nil {
		logger.Debug("Evaluate: request validation failed",
			logging.F("error", err.Error()))
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error": fmt.Sprintf("invalid request: %v", err),
				},
			},
		}, nil
	}

	// Strip the inbound context down to the keys a client is allowed to set,
	// before anything else reads or writes it. request.Context is how policy
	// constraints reach the registries, so an unsanitized one lets a client
	// write its own policy: the action.parameters allowlist would guard one
	// door and leave the adjacent one open. It is also how internal state such
	// as _original_subject_id travels, which a client must not be able to forge.
	req.Context = sanitizeRequestContext(req.Context, logger)

	// Preserve the pre-normalization Subject.ID before rewriting it below.
	// Registries that need the raw OpenID4VP client_id_scheme claim (e.g. to
	// verify a presented certificate is actually bound to the claimed
	// x509_san_dns/x509_san_uri/x509_hash identity, not just chained to a
	// trusted CA - see registry.VerifyLeafBinding) recover it via
	// registry.OriginalSubjectID, since the rewrite below is otherwise
	// irreversible from their point of view.
	StashOriginalSubjectID(req, req.Subject.ID)

	// Normalize subject ID: strip OpenID4VP client_id_scheme prefixes
	// (e.g. "x509_san_dns:host" -> "https://host") so all registries
	// receive a consistent identifier.
	req.Subject.ID = NormalizeSubjectID(req.Subject.ID)

	// Resolve policy from action.name
	policyCtx := m.resolvePolicyContext(req)

	if pm := m.GetPolicyManager(); pm != nil && pm.IsUnknownAction(policyCtx.ActionName) {
		if pm.FailClosedOnUnknownAction() {
			if pm.firstUnknownWarning(policyCtx.ActionName) {
				logger.Warn("Evaluate: no policy defined for action; denying (fail-closed)",
					logging.F("action", policyCtx.ActionName))
			}
			return &authzen.EvaluationResponse{
				Decision: false,
				Context: &authzen.EvaluationResponseContext{
					Reason: map[string]interface{}{
						"error":  "no policy defined for action",
						"action": policyCtx.ActionName,
					},
				},
			}, nil
		}
		if pm.firstUnknownWarning(policyCtx.ActionName) {
			if policyCtx.Policy != nil {
				logger.Warn("Evaluate: no policy defined for action; using default policy",
					logging.F("action", policyCtx.ActionName),
					logging.F("default_policy", policyCtx.Policy.Name))
			} else {
				logger.Warn("Evaluate: no policy defined for action and no default policy; evaluating all registries WITHOUT policy constraints",
					logging.F("action", policyCtx.ActionName))
			}
		}
	}

	if policyCtx.Policy != nil {
		logger.Debug("Evaluate: policy resolved",
			logging.F("policy", policyCtx.Policy.Name),
			logging.F("action", policyCtx.ActionName),
			logging.F("allowed_key_types", policyCtx.Policy.Constraints.AllowedKeyTypes),
			logging.F("policy_registries", policyCtx.Policy.Registries))
	} else {
		logger.Debug("Evaluate: no policy matched",
			logging.F("action", policyCtx.ActionName))
	}

	// Enforce RequireKeyBinding at the entry layer: a policy that demands key
	// binding must not be satisfiable by a resolution-only request, which
	// returns resolved metadata without any key having been presented.
	if policyCtx.Policy != nil && policyCtx.Policy.Constraints.RequireKeyBinding && req.IsResolutionOnlyRequest() {
		logger.Debug("Evaluate: resolution-only request rejected by policy",
			logging.F("policy", policyCtx.Policy.Name))
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error":  "policy requires key binding; resolution-only requests are not accepted",
					"policy": policyCtx.Policy.Name,
				},
			},
		}, nil
	}

	// Enforce AllowedKeyTypes at the entry layer before routing to registries
	if policyCtx.Policy != nil && len(policyCtx.Policy.Constraints.AllowedKeyTypes) > 0 && !req.IsResolutionOnlyRequest() {
		allowed := false
		for _, kt := range policyCtx.Policy.Constraints.AllowedKeyTypes {
			if kt == req.Resource.Type {
				allowed = true
				break
			}
		}
		if !allowed {
			logger.Debug("Evaluate: resource type rejected by policy",
				logging.F("resource_type", req.Resource.Type),
				logging.F("allowed_key_types", policyCtx.Policy.Constraints.AllowedKeyTypes))
			return &authzen.EvaluationResponse{
				Decision: false,
				Context: &authzen.EvaluationResponseContext{
					Reason: map[string]interface{}{
						"error":             "resource type not allowed by policy",
						"resource_type":     req.Resource.Type,
						"allowed_key_types": policyCtx.Policy.Constraints.AllowedKeyTypes,
						"policy":            policyCtx.Policy.Name,
					},
				},
			}, nil
		}
	}

	// Apply policy constraints to the request context
	m.applyPolicyToRequest(req, policyCtx)

	logger.Debug("Evaluate: dispatching to strategy",
		logging.F("strategy", string(m.strategy)))

	// Route to appropriate strategy
	var resp *authzen.EvaluationResponse
	var err error
	switch m.strategy {
	case FirstMatch:
		resp, err = m.evaluateFirstMatchWithPolicy(ctx, req, policyCtx)
	case AllRegistries:
		resp, err = m.evaluateAllWithPolicy(ctx, req, policyCtx)
	case BestMatch:
		resp, err = m.evaluateBestMatchWithPolicy(ctx, req, policyCtx)
	case Sequential:
		resp, err = m.evaluateSequentialWithPolicy(ctx, req, policyCtx)
	default:
		resp, err = m.evaluateFirstMatchWithPolicy(ctx, req, policyCtx)
	}

	duration := time.Since(startTime)
	if err != nil {
		logger.Debug("Evaluate: completed with error",
			logging.F("error", err.Error()),
			logging.F("duration_ms", duration.Milliseconds()))
	} else {
		// Log decision with reason: deny at Info level, allow at Debug level.
		action := ""
		if req.Action != nil {
			action = req.Action.Name
		}
		reason := extractDecisionReason(resp)
		fields := []logging.Field{
			logging.F("decision", resp.Decision),
			logging.F("subject_id", req.Subject.ID),
			logging.F("resource_type", req.Resource.Type),
			logging.F("action", action),
			logging.F("reason", reason),
			logging.F("duration_ms", duration.Milliseconds()),
		}
		if resp.Decision {
			logger.Debug("trust decision: allow", fields...)
		} else {
			logger.Info("trust decision: deny", fields...)
		}
	}

	return resp, err
}

// resolvePolicyContext resolves the policy for the request based on action.name.
func (m *RegistryManager) resolvePolicyContext(req *authzen.EvaluationRequest) *PolicyContext {
	m.mu.RLock()
	pm := m.policyManager
	m.mu.RUnlock()

	actionName := ""
	if req.Action != nil {
		actionName = req.Action.Name
	}

	policyCtx := &PolicyContext{
		ActionName: actionName,
	}

	if pm != nil {
		policyCtx.Policy = pm.GetPolicy(actionName)
	}

	return policyCtx
}

// applyPolicyToRequest populates request.Context, the server-controlled channel
// registries read policy constraints from.
//
// Order matters: allowlisted action.parameters are merged in first (they are
// client-supplied data), then policy constraints, so policy wins on a collision.
// Callers are responsible for having sanitized the inbound context first;
// RegistryManager.Evaluate does so before it touches the request at all.
func (m *RegistryManager) applyPolicyToRequest(req *authzen.EvaluationRequest, policyCtx *PolicyContext) {
	// Evaluate has already stripped the inbound context to client-suppliable
	// keys; from here on req.Context is server-controlled.
	if req.Context == nil {
		req.Context = make(map[string]interface{})
	}

	// Merge action.parameters into context (client-supplied data), through the
	// same allowlist for the same reason.
	if req.Action != nil && req.Action.Parameters != nil {
		for k, v := range req.Action.Parameters {
			if clientSuppliableContextKey(k) {
				req.Context[k] = v
			}
		}
	}

	if policyCtx.Policy == nil {
		return
	}

	// Apply OIDF constraints
	if policyCtx.Policy.OIDFed != nil {
		oidfed := policyCtx.Policy.OIDFed
		if len(oidfed.RequiredTrustMarks) > 0 {
			req.Context["required_trust_marks"] = oidfed.RequiredTrustMarks
		}
		if len(oidfed.EntityTypes) > 0 {
			req.Context["allowed_entity_types"] = oidfed.EntityTypes
		}
		if oidfed.MaxChainDepth > 0 {
			req.Context["max_chain_depth"] = oidfed.MaxChainDepth
		}
		if len(oidfed.CredentialTypeTrustMarks) > 0 {
			req.Context["credential_type_trust_marks"] = oidfed.CredentialTypeTrustMarks
		}
	}

	// Apply ETSI constraints
	if policyCtx.Policy.ETSI != nil {
		etsi := policyCtx.Policy.ETSI
		if len(etsi.ServiceTypes) > 0 {
			req.Context["service_types"] = etsi.ServiceTypes
		}
		if len(etsi.ServiceStatuses) > 0 {
			req.Context["service_statuses"] = etsi.ServiceStatuses
		}
		if len(etsi.Countries) > 0 {
			req.Context["countries"] = etsi.Countries
		}
		if len(etsi.CredentialTypes) > 0 {
			req.Context["credential_types"] = etsi.CredentialTypes
		}
		if len(etsi.RequiredCertPolicyOIDs) > 0 {
			req.Context["required_cert_policy_oids"] = etsi.RequiredCertPolicyOIDs
		}
		if etsi.ExtractRPIdentity {
			req.Context["extract_rp_identity"] = true
		}
		if len(etsi.AllowedAttributes) > 0 {
			req.Context["allowed_attributes"] = etsi.AllowedAttributes
		}
		if etsi.StrictEntitlementCheck {
			req.Context["strict_entitlement_check"] = true
		}
		if etsi.AllowIntermediaries {
			req.Context["allow_intermediaries"] = true
		}
	}

	// Apply DID constraints
	if policyCtx.Policy.DID != nil {
		didPolicy := policyCtx.Policy.DID
		if len(didPolicy.AllowedDomains) > 0 {
			req.Context["allowed_domains"] = didPolicy.AllowedDomains
		}
		if len(didPolicy.RequiredVerificationMethods) > 0 {
			req.Context["required_verification_methods"] = didPolicy.RequiredVerificationMethods
		}
		if len(didPolicy.RequiredServices) > 0 {
			req.Context["required_services"] = didPolicy.RequiredServices
		}
		if didPolicy.RequireVerifiableHistory {
			req.Context["require_verifiable_history"] = true
		}
	}

	// Apply mDOC IACA constraints
	if policyCtx.Policy.MDOCIACA != nil {
		mdoc := policyCtx.Policy.MDOCIACA
		if len(mdoc.IssuerAllowlist) > 0 {
			req.Context["issuer_allowlist"] = mdoc.IssuerAllowlist
		}
		if mdoc.RequireIACAEndpoint {
			req.Context["require_iaca_endpoint"] = true
		}
	}

	// Apply FIDO MDS3 constraints
	if policyCtx.Policy.FIDOMDS3 != nil {
		fido := policyCtx.Policy.FIDOMDS3
		if len(fido.AllowedAAGUIDs) > 0 {
			req.Context["allowed_aaguids"] = fido.AllowedAAGUIDs
		}
		if len(fido.BlockedAAGUIDs) > 0 {
			req.Context["blocked_aaguids"] = fido.BlockedAAGUIDs
		}
	}

	// Apply eMRTD constraints. Key names are shared with the emrtd registry.
	if policyCtx.Policy.EMRTD != nil {
		e := policyCtx.Policy.EMRTD
		if e.PathLenMode != "" {
			req.Context["emrtd_path_len_mode"] = e.PathLenMode
		}
		if e.PathLenOverride != nil {
			req.Context["emrtd_path_len_override"] = *e.PathLenOverride
		}
	}

	// Store policy name in context for debugging/logging
	req.Context["_policy"] = policyCtx.Policy.Name
}

// clientSuppliableContextKeys lists the request-context keys a client is
// allowed to set, whether it sends them in request.Context or in
// action.parameters. Everything else in the context namespace is a policy
// control and may only be written server-side by applyPolicyToRequest.
//
// The dividing line is data versus control: these keys describe *what the RP
// is asking for*, which only the client knows. Keys such as
// allowed_attributes, strict_entitlement_check, allow_intermediaries,
// required_cert_policy_oids or extract_rp_identity decide *what the server
// permits*, and a client that could set those would be writing its own policy.
var clientSuppliableContextKeys = map[string]bool{
	// Data-carrying parameters (what the RP is requesting)
	"query":                true, // DCQL query for over-request detection
	"requested_attributes": true, // explicit attribute list
	"credential_types":     true, // credential type identifiers
	// Both of these are safe in a client's hands. doc_type only ever narrows:
	// supplying it can deny, omitting it skips the VICAL docType check.
	// intermediary_x5c is read only when the policy has set allow_intermediaries.
	"doc_type":         true, // mdoc doctype, filters VICAL entries
	"intermediary_x5c": true, // the intermediary's own certificate chain

	// OpenID Federation request data, consumed by OIDFedRegistry. All four
	// are data or hints, not policy: none of them decides what the server
	// permits.
	//
	// trust_chain is the verifier-supplied chain from a signed request
	// (OID4VP 5.9.3.6). Accepting it is safe because it is never taken on
	// trust: validatePreSuppliedTrustChain caps its depth, requires the leaf
	// to be the entity under evaluation, requires the anchor to be a
	// CONFIGURED anchor that self-signs, checks linkage and time validity,
	// and verifies the anchor against the configured JWKS rather than the
	// chain's own. Without a configured JWKS it refuses and falls back to
	// resolving from scratch. A forged chain cannot pass; supplying a real
	// one only saves the resolution.
	//
	// cache_control can only ever ask for FRESHER data. GetWithMaxAge
	// applies max-age on top of normal expiry, so a client can force
	// revalidation but never extend a cache entry's life.
	"trust_chain":          true, // pre-supplied federation trust chain
	"include_trust_chain":  true, // response shaping: include the chain
	"include_certificates": true, // response shaping: include X.509 certs
	"cache_control":        true, // freshness hint; only ever tightens

	// Informational / audit
	"purpose": true, // presentation purpose

	// signing_time is the eMRTD document signing time (RFC 3339) at which the
	// DSC/CSCA validity is evaluated (ICAO 9303 Part 12). It is data about
	// the document, which only the PEP knows. The emrtd registry parses it
	// strictly (malformed => deny); omitting it means "now". It is taken on
	// the PEP's word, which is why the PEP must derive it from the verified
	// SOD and not from unauthenticated input.
	"signing_time": true,
}

// clientSuppliableContextKey returns true if the key may flow from a client
// request into the request context.
func clientSuppliableContextKey(key string) bool {
	return clientSuppliableContextKeys[key]
}

// sanitizeRequestContext returns a context containing only the keys a client
// is permitted to set. It always returns a non-nil, freshly allocated map, so
// the policy values written afterwards cannot alias the caller's map.
func sanitizeRequestContext(ctx map[string]interface{}, logger logging.Logger) map[string]interface{} {
	clean := make(map[string]interface{}, len(ctx))
	var dropped []string
	for k, v := range ctx {
		if clientSuppliableContextKey(k) {
			clean[k] = v
			continue
		}
		dropped = append(dropped, k)
	}
	if len(dropped) > 0 && logger != nil {
		// Key names only: the values are attacker-controlled and may be large.
		sort.Strings(dropped)
		logger.Debug("Evaluate: dropped non-client context keys",
			logging.F("keys", dropped))
	}
	return clean
}

// GetRegistry returns the registered registry with the given Info().Name, or
// nil if none matches.
func (m *RegistryManager) GetRegistry(name string) TrustRegistry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, reg := range m.registries {
		if reg.Info().Name == name {
			return reg
		}
	}
	return nil
}

// CountRegistries returns how many registered registries carry the given
// Info().Name. Register permits duplicates, so a name is not necessarily a
// unique handle, and a caller that needs one must check.
func (m *RegistryManager) CountRegistries(name string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for _, reg := range m.registries {
		if reg.Info().Name == name {
			count++
		}
	}
	return count
}

// Unregister removes every registry with the given Info().Name and returns
// how many were removed.
//
// This exists so a CompositeRegistry can take ownership of its children: a
// child left registered alongside its parent would also be consulted on its
// own, and under FirstMatch could return decision=true by itself — exactly
// the agreement an AND composite was configured to require.
//
// It removes all matches rather than the first because Register permits
// duplicate names. Removing only one would leave a same-named registry
// top-level and reintroduce exactly that bypass.
func (m *RegistryManager) Unregister(name string) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	kept := m.registries[:0]
	removed := 0
	for _, reg := range m.registries {
		if reg.Info().Name == name {
			removed++
			continue
		}
		kept = append(kept, reg)
	}
	m.registries = kept
	return removed
}

// SupportedResourceTypes returns the union of all resource types supported by registered registries
func (m *RegistryManager) SupportedResourceTypes() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	typeSet := make(map[string]bool)
	for _, reg := range m.registries {
		for _, rt := range reg.SupportedResourceTypes() {
			typeSet[rt] = true
		}
	}

	types := make([]string, 0, len(typeSet))
	for t := range typeSet {
		types = append(types, t)
	}
	return types
}

// Info returns metadata about the RegistryManager
func (m *RegistryManager) Info() RegistryInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	anchors := make([]string, 0)
	for _, reg := range m.registries {
		info := reg.Info()
		anchors = append(anchors, info.TrustAnchors...)
	}

	return RegistryInfo{
		Name:         "Registry Manager",
		Type:         "manager",
		Description:  fmt.Sprintf("Manages %d trust registries with %s strategy", len(m.registries), m.strategy),
		Version:      "1.0.0",
		TrustAnchors: anchors,
	}
}

// Healthy returns true if at least one registry is healthy
func (m *RegistryManager) Healthy() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, reg := range m.registries {
		if reg.Healthy() {
			return true
		}
	}
	return len(m.registries) == 0 // No registries = healthy (for startup)
}

// Refresh refreshes all registered registries
func (m *RegistryManager) Refresh(ctx context.Context) error {
	m.mu.RLock()
	registries := make([]TrustRegistry, len(m.registries))
	copy(registries, m.registries)
	m.mu.RUnlock()

	var errs []error
	for _, reg := range registries {
		if err := reg.Refresh(ctx); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", reg.Info().Name, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("refresh errors: %v", errs)
	}
	return nil
}

// getApplicableRegistries filters registries that support the requested resource type.
// For resolution-only requests (where Resource.Type is empty), registries that support
// resolution-only operations are also included.
func (m *RegistryManager) getApplicableRegistries(req *authzen.EvaluationRequest) []TrustRegistry {
	return m.getApplicableRegistriesWithPolicy(req, nil)
}

// getApplicableRegistriesWithPolicy filters registries based on resource type and policy.
func (m *RegistryManager) getApplicableRegistriesWithPolicy(req *authzen.EvaluationRequest, policyCtx *PolicyContext) []TrustRegistry {
	applicable := make([]TrustRegistry, 0)
	isResolutionOnly := req.IsResolutionOnlyRequest()

	// Get allowed registries from policy
	var allowedRegistries map[string]bool
	if policyCtx != nil && policyCtx.Policy != nil && len(policyCtx.Policy.Registries) > 0 {
		allowedRegistries = make(map[string]bool)
		for _, name := range policyCtx.Policy.Registries {
			allowedRegistries[name] = true
		}
	}

	for _, reg := range m.registries {
		info := reg.Info()

		// Filter by policy registries if specified
		if allowedRegistries != nil && !allowedRegistries[info.Name] {
			m.getLogger().Debug("Registry filtering: skipped by policy",
				logging.F("registry", info.Name))
			continue
		}

		// For resolution-only requests, include registries that support resolution-only
		if isResolutionOnly && reg.SupportsResolutionOnly() {
			applicable = append(applicable, reg)
			continue
		}

		// Check if the registry supports the requested resource type
		supported := reg.SupportedResourceTypes()
		for _, rt := range supported {
			if rt == req.Resource.Type || rt == "*" {
				applicable = append(applicable, reg)
				break
			}
		}
	}

	names := make([]string, len(applicable))
	for i, reg := range applicable {
		names[i] = reg.Info().Name
	}
	m.getLogger().Debug("Registry filtering: applicable registries",
		logging.F("total_registries", len(m.registries)),
		logging.F("applicable_count", len(applicable)),
		logging.F("applicable_names", names),
		logging.F("resource_type", req.Resource.Type),
		logging.F("resolution_only", isResolutionOnly))

	return applicable
}

// Policy-aware evaluation strategy wrappers
// These call the underlying strategies but filter registries by policy first.

func (m *RegistryManager) evaluateFirstMatchWithPolicy(ctx context.Context, req *authzen.EvaluationRequest, policyCtx *PolicyContext) (*authzen.EvaluationResponse, error) {
	m.mu.RLock()
	registries := m.getApplicableRegistriesWithPolicy(req, policyCtx)
	m.mu.RUnlock()

	if len(registries) == 0 {
		reason := map[string]interface{}{
			"error":         "no applicable registries for resource type",
			"resource_type": req.Resource.Type,
		}
		if policyCtx != nil && policyCtx.Policy != nil {
			reason["policy"] = policyCtx.Policy.Name
			if len(policyCtx.Policy.Registries) > 0 {
				reason["policy_registries"] = policyCtx.Policy.Registries
			}
		}
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: reason,
			},
		}, nil
	}

	// Delegate to base strategy with filtered registries
	return m.evaluateFirstMatchFiltered(ctx, req, registries, policyCtx)
}

func (m *RegistryManager) evaluateAllWithPolicy(ctx context.Context, req *authzen.EvaluationRequest, policyCtx *PolicyContext) (*authzen.EvaluationResponse, error) {
	m.mu.RLock()
	registries := m.getApplicableRegistriesWithPolicy(req, policyCtx)
	m.mu.RUnlock()

	if len(registries) == 0 {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error":         "no applicable registries",
					"resource_type": req.Resource.Type,
				},
			},
		}, nil
	}

	return m.evaluateAllFiltered(ctx, req, registries, policyCtx)
}

func (m *RegistryManager) evaluateBestMatchWithPolicy(ctx context.Context, req *authzen.EvaluationRequest, policyCtx *PolicyContext) (*authzen.EvaluationResponse, error) {
	resp, err := m.evaluateAllWithPolicy(ctx, req, policyCtx)
	if err != nil {
		return resp, err
	}

	if resp.Decision && resp.Context != nil && resp.Context.Reason != nil {
		if matched, ok := resp.Context.Reason["registries_matched"].([]string); ok && len(matched) > 0 {
			resp.Context.Reason["registry"] = matched[0]
			resp.Context.Reason["strategy"] = "best_match"
			promoteSelectedAdmin(resp.Context.Reason, matched[0])
			delete(resp.Context.Reason, "all_results")
		}
	}

	return resp, nil
}

func (m *RegistryManager) evaluateSequentialWithPolicy(ctx context.Context, req *authzen.EvaluationRequest, policyCtx *PolicyContext) (*authzen.EvaluationResponse, error) {
	m.mu.RLock()
	registries := m.getApplicableRegistriesWithPolicy(req, policyCtx)
	m.mu.RUnlock()

	if len(registries) == 0 {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error":         "no applicable registries",
					"resource_type": req.Resource.Type,
				},
			},
		}, nil
	}

	return m.evaluateSequentialFiltered(ctx, req, registries, policyCtx)
}

// ListRegistries returns information about all registered registries.
func (m *RegistryManager) ListRegistries() []RegistryInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	infos := make([]RegistryInfo, len(m.registries))
	for i, reg := range m.registries {
		info := reg.Info()
		info.ResourceTypes = reg.SupportedResourceTypes()
		info.ResolutionOnly = reg.SupportsResolutionOnly()
		info.Healthy = reg.Healthy()
		infos[i] = info
	}
	return infos
}

// NormalizeSubjectID normalizes a subject ID by stripping OpenID4VP
// client_id_scheme prefixes and converting bare hostnames to https:// URLs.
// This ensures all registries receive a consistent identifier format.
//
// Examples:
//
//	"x509_san_dns:example.com" -> "https://example.com"
//	"x509_san_uri:https://example.com" -> "https://example.com"
//	"decentralized_identifier:did:web:example.com" -> "did:web:example.com"
//	"https://example.com" -> "https://example.com" (unchanged)
func NormalizeSubjectID(id string) string {
	for _, prefix := range []string{"x509_san_dns:", "x509_san_uri:", "decentralized_identifier:"} {
		if strings.HasPrefix(id, prefix) {
			bare := strings.TrimPrefix(id, prefix)
			// x509_san_uri values are already URIs and decentralized_identifier
			// values are already DIDs; x509_san_dns values are bare hostnames.
			if prefix == "x509_san_dns:" {
				return "https://" + bare
			}
			return bare
		}
	}
	return id
}

// extractDecisionReason extracts a human-readable reason string from an
// evaluation response. It checks for common reason keys in Context.Reason.
// Priority: "admin" (server-side diagnostics, e.g. from LoTE/whitelist registries),
// then decision-specific keys: "error" for denials, "user" for allows.
func extractDecisionReason(resp *authzen.EvaluationResponse) string {
	if resp.Context == nil || resp.Context.Reason == nil {
		return ""
	}
	// "admin" contains server-side diagnostic detail (e.g. "entity X not found in any LoTE")
	// and is the most informative reason for operator logs.
	if v, ok := resp.Context.Reason["admin"]; ok {
		return fmt.Sprintf("%v", v)
	}
	if resp.Decision {
		// Allow: prefer "user" (e.g. "trusted via whitelist (pid-issuers)")
		if v, ok := resp.Context.Reason["user"]; ok {
			return fmt.Sprintf("%v", v)
		}
		if v, ok := resp.Context.Reason["error"]; ok {
			return fmt.Sprintf("%v", v)
		}
	} else {
		// Deny: prefer "error" (e.g. "subject not in whitelist for action 'issuer'")
		if v, ok := resp.Context.Reason["error"]; ok {
			return fmt.Sprintf("%v", v)
		}
		if v, ok := resp.Context.Reason["user"]; ok {
			return fmt.Sprintf("%v", v)
		}
	}
	return ""
}
