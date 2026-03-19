package registry

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirosfoundation/g119612/pkg/logging"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// evaluateFirstMatch queries registries in parallel and returns first positive match.
// If no registry approves, the response includes aggregated deny reasons from all registries.
func (m *RegistryManager) evaluateFirstMatch(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	m.mu.RLock()
	registries := m.getApplicableRegistries(req)
	m.mu.RUnlock()

	if len(registries) == 0 {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error":         "no applicable registries for resource type",
					"resource_type": req.Resource.Type,
				},
			},
		}, nil
	}

	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	type result struct {
		registry string
		response *authzen.EvaluationResponse
		err      error
		duration int64
	}

	results := make(chan result, len(registries))

	// Query all registries in parallel
	var wg sync.WaitGroup
	for _, reg := range registries {
		wg.Add(1)
		go func(registry TrustRegistry) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					info := registry.Info()
					m.circuitBreakers[info.Name].RecordFailure()
					results <- result{
						registry: info.Name,
						err:      fmt.Errorf("registry panicked: %v", r),
					}
				}
			}()

			info := registry.Info()

			// Check circuit breaker
			if !m.circuitBreakers[info.Name].CanAttempt() {
				m.getLogger().Debug("Strategy[FirstMatch]: circuit breaker open, skipping",
					logging.F("registry", info.Name))
				results <- result{
					registry: info.Name,
					err:      fmt.Errorf("circuit breaker open"),
				}
				return
			}

			m.getLogger().Debug("Strategy[FirstMatch]: evaluating registry",
				logging.F("registry", info.Name))

			startTime := time.Now()
			resp, err := registry.Evaluate(timeoutCtx, req)
			duration := time.Since(startTime).Milliseconds()

			if err != nil {
				m.circuitBreakers[info.Name].RecordFailure()
				m.getLogger().Debug("Strategy[FirstMatch]: registry returned error",
					logging.F("registry", info.Name),
					logging.F("error", err.Error()),
					logging.F("duration_ms", duration))
			} else {
				m.circuitBreakers[info.Name].RecordSuccess()
				decision := false
				if resp != nil {
					decision = resp.Decision
				}
				m.getLogger().Debug("Strategy[FirstMatch]: registry responded",
					logging.F("registry", info.Name),
					logging.F("decision", decision),
					logging.F("duration_ms", duration))
			}

			results <- result{
				registry: info.Name,
				response: resp,
				err:      err,
				duration: duration,
			}
		}(reg)
	}

	// Close channel when all goroutines finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results, returning immediately on first positive match
	var denyDetails []map[string]interface{}

	for r := range results {
		if r.err != nil {
			denyDetails = append(denyDetails, map[string]interface{}{
				"registry":    r.registry,
				"error":       r.err.Error(),
				"duration_ms": r.duration,
			})
			continue
		}
		if r.response != nil && r.response.Decision {
			cancel() // cancel remaining evaluations
			if r.response.Context == nil {
				r.response.Context = &authzen.EvaluationResponseContext{}
			}
			if r.response.Context.Reason == nil {
				r.response.Context.Reason = make(map[string]interface{})
			}
			r.response.Context.Reason["registry"] = r.registry
			r.response.Context.Reason["resolution_ms"] = r.duration
			return r.response, nil
		}
		// Deny — capture the reason
		detail := map[string]interface{}{
			"registry":    r.registry,
			"decision":    false,
			"duration_ms": r.duration,
		}
		if r.response != nil && r.response.Context != nil && r.response.Context.Reason != nil {
			detail["reason"] = r.response.Context.Reason
		}
		denyDetails = append(denyDetails, detail)
	}

	// No positive results — aggregate deny details
	return &authzen.EvaluationResponse{
		Decision: false,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"error":              "no registry returned positive match",
				"registries_queried": len(registries),
				"registry_results":   denyDetails,
			},
		},
	}, nil
}

// evaluateAll queries all applicable registries and aggregates results.
// This strategy is useful for auditing or when you need to know which
// registries matched.
func (m *RegistryManager) evaluateAll(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	m.mu.RLock()
	registries := m.getApplicableRegistries(req)
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

	timeoutCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	type result struct {
		registry string
		response *authzen.EvaluationResponse
		err      error
		duration int64
	}

	results := make(chan result, len(registries))
	var wg sync.WaitGroup

	for _, reg := range registries {
		wg.Add(1)
		go func(registry TrustRegistry) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					info := registry.Info()
					m.circuitBreakers[info.Name].RecordFailure()
					results <- result{
						registry: info.Name,
						err:      fmt.Errorf("registry panicked: %v", r),
					}
				}
			}()

			info := registry.Info()
			startTime := time.Now()

			if !m.circuitBreakers[info.Name].CanAttempt() {
				m.getLogger().Debug("Strategy[All]: circuit breaker open, skipping",
					logging.F("registry", info.Name))
				return
			}

			m.getLogger().Debug("Strategy[All]: evaluating registry",
				logging.F("registry", info.Name))

			resp, err := registry.Evaluate(timeoutCtx, req)
			duration := time.Since(startTime).Milliseconds()

			if err != nil {
				m.circuitBreakers[info.Name].RecordFailure()
				m.getLogger().Debug("Strategy[All]: registry returned error",
					logging.F("registry", info.Name),
					logging.F("error", err.Error()),
					logging.F("duration_ms", duration))
			} else {
				m.circuitBreakers[info.Name].RecordSuccess()
				decision := false
				if resp != nil {
					decision = resp.Decision
				}
				m.getLogger().Debug("Strategy[All]: registry responded",
					logging.F("registry", info.Name),
					logging.F("decision", decision),
					logging.F("duration_ms", duration))
			}

			results <- result{
				registry: info.Name,
				response: resp,
				err:      err,
				duration: duration,
			}
		}(reg)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect all results
	var allResults []map[string]interface{}
	decision := false
	registriesMatched := []string{}

	for r := range results {
		resultInfo := map[string]interface{}{
			"registry":    r.registry,
			"duration_ms": r.duration,
		}

		if r.err != nil {
			resultInfo["error"] = r.err.Error()
		} else if r.response != nil {
			resultInfo["decision"] = r.response.Decision
			if r.response.Decision {
				decision = true
				registriesMatched = append(registriesMatched, r.registry)
			}
		}

		allResults = append(allResults, resultInfo)
	}

	return &authzen.EvaluationResponse{
		Decision: decision,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"registries_queried": len(registries),
				"registries_matched": registriesMatched,
				"all_results":        allResults,
			},
		},
	}, nil
}

// evaluateBestMatch queries all registries and returns the one with highest confidence.
// Currently uses first match as a fallback; confidence scoring could be enhanced
// by examining response context.
func (m *RegistryManager) evaluateBestMatch(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	// For now, delegate to evaluateAll and pick first positive match
	// In future, could extract confidence scores from response context
	resp, err := m.evaluateAll(ctx, req)
	if err != nil {
		return resp, err
	}

	// Transform aggregated result to single best match
	if resp.Decision && resp.Context != nil && resp.Context.Reason != nil {
		if matched, ok := resp.Context.Reason["registries_matched"].([]string); ok && len(matched) > 0 {
			resp.Context.Reason["registry"] = matched[0]
			resp.Context.Reason["strategy"] = "best_match"
			// Remove aggregation details
			delete(resp.Context.Reason, "all_results")
		}
	}

	return resp, nil
}

// evaluateSequential tries registries in registration order until one returns true.
// This strategy is useful when you have preferred registries or want to minimize
// load on rate-limited APIs.
func (m *RegistryManager) evaluateSequential(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	m.mu.RLock()
	registries := m.getApplicableRegistries(req)
	m.mu.RUnlock()

	return m.evaluateSequentialFiltered(ctx, req, registries, nil)
}

// evaluateSequentialFiltered is the internal implementation that works with pre-filtered registries.
func (m *RegistryManager) evaluateSequentialFiltered(ctx context.Context, req *authzen.EvaluationRequest, registries []TrustRegistry, policyCtx *PolicyContext) (*authzen.EvaluationResponse, error) {
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

	var registryResults []map[string]interface{}

	for _, reg := range registries {
		info := reg.Info()

		if !m.circuitBreakers[info.Name].CanAttempt() {
			m.getLogger().Debug("Strategy[Sequential]: circuit breaker open, skipping",
				logging.F("registry", info.Name))
			registryResults = append(registryResults, map[string]interface{}{
				"registry": info.Name,
				"error":    "circuit breaker open",
			})
			continue
		}

		m.getLogger().Debug("Strategy[Sequential]: evaluating registry",
			logging.F("registry", info.Name))

		startTime := time.Now()
		resp, err := reg.Evaluate(ctx, req)
		duration := time.Since(startTime).Milliseconds()

		if err != nil {
			m.circuitBreakers[info.Name].RecordFailure()
			m.getLogger().Debug("Strategy[Sequential]: registry returned error",
				logging.F("registry", info.Name),
				logging.F("error", err.Error()),
				logging.F("duration_ms", duration))
			registryResults = append(registryResults, map[string]interface{}{
				"registry":    info.Name,
				"error":       err.Error(),
				"duration_ms": duration,
			})
			continue
		}

		m.circuitBreakers[info.Name].RecordSuccess()

		if resp != nil && resp.Decision {
			m.getLogger().Debug("Strategy[Sequential]: positive match found",
				logging.F("registry", info.Name),
				logging.F("duration_ms", duration))
			if resp.Context == nil {
				resp.Context = &authzen.EvaluationResponseContext{}
			}
			if resp.Context.Reason == nil {
				resp.Context.Reason = make(map[string]interface{})
			}
			resp.Context.Reason["registry"] = info.Name
			resp.Context.Reason["resolution_ms"] = duration
			if policyCtx != nil && policyCtx.Policy != nil {
				resp.Context.Reason["policy"] = policyCtx.Policy.Name
			}
			return resp, nil
		}

		// Deny — capture reason
		m.getLogger().Debug("Strategy[Sequential]: registry denied",
			logging.F("registry", info.Name),
			logging.F("duration_ms", duration))
		detail := map[string]interface{}{
			"registry":    info.Name,
			"decision":    false,
			"duration_ms": duration,
		}
		if resp != nil && resp.Context != nil && resp.Context.Reason != nil {
			detail["reason"] = resp.Context.Reason
		}
		registryResults = append(registryResults, detail)
	}

	reason := map[string]interface{}{
		"error":              "no registry returned positive match",
		"registries_queried": len(registries),
		"registry_results":   registryResults,
	}
	if policyCtx != nil && policyCtx.Policy != nil {
		reason["policy"] = policyCtx.Policy.Name
	}

	return &authzen.EvaluationResponse{
		Decision: false,
		Context: &authzen.EvaluationResponseContext{
			Reason: reason,
		},
	}, nil
}

// evaluateFirstMatchFiltered is the internal implementation for FirstMatch with pre-filtered registries.
// If no registry approves, the response includes aggregated deny reasons from all registries.
func (m *RegistryManager) evaluateFirstMatchFiltered(ctx context.Context, req *authzen.EvaluationRequest, registries []TrustRegistry, policyCtx *PolicyContext) (*authzen.EvaluationResponse, error) {
	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	type result struct {
		registry string
		response *authzen.EvaluationResponse
		err      error
		duration int64
	}

	results := make(chan result, len(registries))

	// Query all registries in parallel
	var wg sync.WaitGroup
	for _, reg := range registries {
		wg.Add(1)
		go func(registry TrustRegistry) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					info := registry.Info()
					m.circuitBreakers[info.Name].RecordFailure()
					results <- result{
						registry: info.Name,
						err:      fmt.Errorf("registry panicked: %v", r),
					}
				}
			}()

			info := registry.Info()

			if !m.circuitBreakers[info.Name].CanAttempt() {
				m.getLogger().Debug("Strategy[FirstMatch]: circuit breaker open, skipping",
					logging.F("registry", info.Name))
				results <- result{
					registry: info.Name,
					err:      fmt.Errorf("circuit breaker open"),
				}
				return
			}

			m.getLogger().Debug("Strategy[FirstMatch]: evaluating registry",
				logging.F("registry", info.Name))

			startTime := time.Now()
			resp, err := registry.Evaluate(timeoutCtx, req)
			duration := time.Since(startTime).Milliseconds()

			if err != nil {
				m.circuitBreakers[info.Name].RecordFailure()
				m.getLogger().Debug("Strategy[FirstMatch]: registry returned error",
					logging.F("registry", info.Name),
					logging.F("error", err.Error()),
					logging.F("duration_ms", duration))
			} else {
				m.circuitBreakers[info.Name].RecordSuccess()
				decision := false
				if resp != nil {
					decision = resp.Decision
				}
				m.getLogger().Debug("Strategy[FirstMatch]: registry responded",
					logging.F("registry", info.Name),
					logging.F("decision", decision),
					logging.F("duration_ms", duration))
			}

			results <- result{
				registry: info.Name,
				response: resp,
				err:      err,
				duration: duration,
			}
		}(reg)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results, returning immediately on first positive match
	var denyDetails []map[string]interface{}

	for r := range results {
		if r.err != nil {
			denyDetails = append(denyDetails, map[string]interface{}{
				"registry":    r.registry,
				"error":       r.err.Error(),
				"duration_ms": r.duration,
			})
			continue
		}
		if r.response != nil && r.response.Decision {
			cancel()
			m.getLogger().Debug("Strategy[FirstMatch]: positive match found",
				logging.F("registry", r.registry),
				logging.F("duration_ms", r.duration))
			if r.response.Context == nil {
				r.response.Context = &authzen.EvaluationResponseContext{}
			}
			if r.response.Context.Reason == nil {
				r.response.Context.Reason = make(map[string]interface{})
			}
			r.response.Context.Reason["registry"] = r.registry
			r.response.Context.Reason["resolution_ms"] = r.duration
			if policyCtx != nil && policyCtx.Policy != nil {
				r.response.Context.Reason["policy"] = policyCtx.Policy.Name
			}
			return r.response, nil
		}
		// Deny — capture the reason
		detail := map[string]interface{}{
			"registry":    r.registry,
			"decision":    false,
			"duration_ms": r.duration,
		}
		if r.response != nil && r.response.Context != nil && r.response.Context.Reason != nil {
			detail["reason"] = r.response.Context.Reason
		}
		denyDetails = append(denyDetails, detail)
	}

	// No positive results — aggregate deny details
	m.getLogger().Debug("Strategy[FirstMatch]: no positive match from any registry",
		logging.F("registries_queried", len(registries)),
		logging.F("deny_count", len(denyDetails)))

	reason := map[string]interface{}{
		"error":              "no registry returned positive match",
		"registries_queried": len(registries),
		"registry_results":   denyDetails,
	}
	if policyCtx != nil && policyCtx.Policy != nil {
		reason["policy"] = policyCtx.Policy.Name
	}

	return &authzen.EvaluationResponse{
		Decision: false,
		Context: &authzen.EvaluationResponseContext{
			Reason: reason,
		},
	}, nil
}

// evaluateAllFiltered is the internal implementation for AllRegistries with pre-filtered registries.
func (m *RegistryManager) evaluateAllFiltered(ctx context.Context, req *authzen.EvaluationRequest, registries []TrustRegistry, policyCtx *PolicyContext) (*authzen.EvaluationResponse, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	type result struct {
		registry string
		response *authzen.EvaluationResponse
		err      error
		duration int64
	}

	results := make(chan result, len(registries))
	var wg sync.WaitGroup

	for _, reg := range registries {
		wg.Add(1)
		go func(registry TrustRegistry) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					info := registry.Info()
					m.circuitBreakers[info.Name].RecordFailure()
					results <- result{
						registry: info.Name,
						err:      fmt.Errorf("registry panicked: %v", r),
					}
				}
			}()

			info := registry.Info()
			startTime := time.Now()

			if !m.circuitBreakers[info.Name].CanAttempt() {
				m.getLogger().Debug("Strategy[AllFiltered]: circuit breaker open, skipping",
					logging.F("registry", info.Name))
				return
			}

			m.getLogger().Debug("Strategy[AllFiltered]: evaluating registry",
				logging.F("registry", info.Name))

			resp, err := registry.Evaluate(timeoutCtx, req)
			duration := time.Since(startTime).Milliseconds()

			if err != nil {
				m.circuitBreakers[info.Name].RecordFailure()
				m.getLogger().Debug("Strategy[AllFiltered]: registry returned error",
					logging.F("registry", info.Name),
					logging.F("error", err.Error()),
					logging.F("duration_ms", duration))
			} else {
				m.circuitBreakers[info.Name].RecordSuccess()
				decision := false
				if resp != nil {
					decision = resp.Decision
				}
				m.getLogger().Debug("Strategy[AllFiltered]: registry responded",
					logging.F("registry", info.Name),
					logging.F("decision", decision),
					logging.F("duration_ms", duration))
			}

			results <- result{
				registry: info.Name,
				response: resp,
				err:      err,
				duration: duration,
			}
		}(reg)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect all results
	var allResults []map[string]interface{}
	decision := false
	registriesMatched := []string{}

	for r := range results {
		resultInfo := map[string]interface{}{
			"registry":    r.registry,
			"duration_ms": r.duration,
		}

		if r.err != nil {
			resultInfo["error"] = r.err.Error()
		} else if r.response != nil {
			resultInfo["decision"] = r.response.Decision
			if r.response.Decision {
				decision = true
				registriesMatched = append(registriesMatched, r.registry)
			}
		}

		allResults = append(allResults, resultInfo)
	}

	reason := map[string]interface{}{
		"registries_queried": len(registries),
		"registries_matched": registriesMatched,
		"all_results":        allResults,
	}
	if policyCtx != nil && policyCtx.Policy != nil {
		reason["policy"] = policyCtx.Policy.Name
	}

	return &authzen.EvaluationResponse{
		Decision: decision,
		Context: &authzen.EvaluationResponseContext{
			Reason: reason,
		},
	}, nil
}
