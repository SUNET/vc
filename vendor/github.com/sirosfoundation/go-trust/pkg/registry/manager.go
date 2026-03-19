package registry

import (
	"context"
	"fmt"
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

	// Resolve policy from action.name
	policyCtx := m.resolvePolicyContext(req)

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
		logger.Debug("Evaluate: completed",
			logging.F("decision", resp.Decision),
			logging.F("duration_ms", duration.Milliseconds()),
			logging.F("subject_id", req.Subject.ID))
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

// applyPolicyToRequest applies policy constraints to the request context.
// This allows registries to read policy constraints from the request.
func (m *RegistryManager) applyPolicyToRequest(req *authzen.EvaluationRequest, policyCtx *PolicyContext) {
	if policyCtx.Policy == nil {
		return
	}

	// Initialize context if needed
	if req.Context == nil {
		req.Context = make(map[string]interface{})
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

	// Store policy name in context for debugging/logging
	req.Context["_policy"] = policyCtx.Policy.Name
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
