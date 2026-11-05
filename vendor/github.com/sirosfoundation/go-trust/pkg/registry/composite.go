package registry

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// LogicOperator defines how a CompositeRegistry combines results from child registries
type LogicOperator string

const (
	// LogicAND requires all child registries to return decision=true
	LogicAND LogicOperator = "AND"

	// LogicOR requires at least one child registry to return decision=true
	LogicOR LogicOperator = "OR"

	// LogicMAJORITY requires more than 50% of child registries to return decision=true
	LogicMAJORITY LogicOperator = "MAJORITY"

	// LogicQUORUM requires a configurable threshold of child registries to return decision=true
	LogicQUORUM LogicOperator = "QUORUM"
)

// CompositeRegistry implements TrustRegistry by combining multiple child registries
// using boolean logic. This enables complex trust policies like "(A OR B) AND C" by
// nesting CompositeRegistry instances.
type CompositeRegistry struct {
	name        string
	description string
	operator    LogicOperator
	registries  []TrustRegistry
	threshold   int           // Used for QUORUM operator
	timeout     time.Duration // Timeout for evaluating child registries
}

// compositeResult holds the result from evaluating a child registry
type compositeResult struct {
	registry TrustRegistry
	response *authzen.EvaluationResponse
	err      error
	duration time.Duration
}

// CompositeOption is a functional option for configuring CompositeRegistry
type CompositeOption func(*CompositeRegistry)

// WithThreshold sets the quorum threshold for LogicQUORUM operator
func WithThreshold(threshold int) CompositeOption {
	return func(c *CompositeRegistry) {
		c.threshold = threshold
	}
}

// WithTimeout sets the timeout for evaluating child registries
func WithTimeout(timeout time.Duration) CompositeOption {
	return func(c *CompositeRegistry) {
		c.timeout = timeout
	}
}

// WithDescription sets the description for the composite registry
func WithDescription(desc string) CompositeOption {
	return func(c *CompositeRegistry) {
		c.description = desc
	}
}

// NewCompositeRegistry creates a new CompositeRegistry that combines child registries
// using the specified boolean logic operator.
//
// Example:
//
//	// Require BOTH ETSI-TSL AND OpenID Federation
//	composite := NewCompositeRegistry("defense-in-depth", LogicAND, etsiReg, oidfReg)
//
//	// Require at least 2 of 3 validators
//	composite := NewCompositeRegistry("quorum", LogicQUORUM, reg1, reg2, reg3,
//	    WithThreshold(2))
//
//	// Complex nesting: (A OR B) AND C
//	orGroup := NewCompositeRegistry("or-group", LogicOR, regA, regB)
//	composite := NewCompositeRegistry("main", LogicAND, orGroup, regC)
func NewCompositeRegistry(name string, operator LogicOperator, registries ...TrustRegistry) *CompositeRegistry {
	return &CompositeRegistry{
		name:       name,
		operator:   operator,
		registries: registries,
		threshold:  1,
		timeout:    5 * time.Second,
	}
}

// NewCompositeRegistryWithOptions creates a CompositeRegistry with functional options
func NewCompositeRegistryWithOptions(name string, operator LogicOperator, registries []TrustRegistry, opts ...CompositeOption) *CompositeRegistry {
	c := &CompositeRegistry{
		name:       name,
		operator:   operator,
		registries: registries,
		threshold:  1,
		timeout:    5 * time.Second,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Evaluate performs trust evaluation by applying boolean logic to child registry results
func (c *CompositeRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	if len(c.registries) == 0 {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error":    "no child registries configured",
					"registry": c.name,
					"operator": string(c.operator),
				},
			},
		}, nil
	}

	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	// Evaluate all child registries in parallel
	results := make(chan compositeResult, len(c.registries))
	var wg sync.WaitGroup

	for _, reg := range c.registries {
		wg.Add(1)
		go func(registry TrustRegistry) {
			defer wg.Done()

			startTime := time.Now()
			resp, err := registry.Evaluate(timeoutCtx, req)
			duration := time.Since(startTime)

			results <- compositeResult{
				registry: registry,
				response: resp,
				err:      err,
				duration: duration,
			}
		}(reg)
	}

	// Wait for all results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var collectedResults []compositeResult
	for r := range results {
		collectedResults = append(collectedResults, r)
	}

	// Apply boolean logic
	return c.applyLogic(collectedResults), nil
}

// applyLogic applies the boolean operator to collected results
func (c *CompositeRegistry) applyLogic(results []compositeResult) *authzen.EvaluationResponse {
	// Count agreements and build details
	var agreedCount, disagreedCount, errorCount int
	var agreedRegistries, disagreedRegistries []string
	var positive []*authzen.EvaluationResponse
	var details []map[string]interface{}

	for _, r := range results {
		info := r.registry.Info()
		detail := map[string]interface{}{
			"registry":    info.Name,
			"type":        info.Type,
			"duration_ms": r.duration.Milliseconds(),
		}

		if r.err != nil {
			errorCount++
			detail["error"] = r.err.Error()
			detail["decision"] = false
			disagreedRegistries = append(disagreedRegistries, info.Name)
		} else if r.response != nil && r.response.Decision {
			agreedCount++
			positive = append(positive, r.response)
			detail["decision"] = true
			agreedRegistries = append(agreedRegistries, info.Name)
		} else {
			disagreedCount++
			detail["decision"] = false
			disagreedRegistries = append(disagreedRegistries, info.Name)
		}

		details = append(details, detail)
	}

	totalCount := len(results)

	// Apply operator logic
	var decision bool
	reason := map[string]interface{}{
		"registry":             c.name,
		"operator":             string(c.operator),
		"total_registries":     totalCount,
		"agreed_count":         agreedCount,
		"disagreed_count":      disagreedCount,
		"error_count":          errorCount,
		"agreed_registries":    agreedRegistries,
		"disagreed_registries": disagreedRegistries,
		"details":              details,
	}

	switch c.operator {
	case LogicAND:
		decision = agreedCount == totalCount
		reason["requires_all"] = true

	case LogicOR:
		decision = agreedCount > 0
		reason["requires_any"] = true

	case LogicMAJORITY:
		majorityThreshold := totalCount / 2
		decision = agreedCount > majorityThreshold
		reason["majority_threshold"] = majorityThreshold
		reason["has_majority"] = decision

	case LogicQUORUM:
		if c.threshold > totalCount {
			decision = false
			reason["error"] = fmt.Sprintf("quorum threshold (%d) exceeds total registries (%d)", c.threshold, totalCount)
		} else {
			decision = agreedCount >= c.threshold
			reason["quorum_threshold"] = c.threshold
			reason["meets_quorum"] = decision
		}

	default:
		decision = false
		reason["error"] = fmt.Sprintf("unknown operator: %s", c.operator)
	}

	resp := &authzen.EvaluationResponse{
		Decision: decision,
		Context: &authzen.EvaluationResponseContext{
			Reason: reason,
		},
	}
	// Every identifier was verified by a child that returned true; carry them
	// through when the composite as a whole allows (AND: all children, OR,
	// MAJORITY and QUORUM: the agreeing ones).
	mergeVerifierIDs(resp, positive)
	return resp
}

// SupportedResourceTypes returns the union of all child registry resource types
func (c *CompositeRegistry) SupportedResourceTypes() []string {
	typeSet := make(map[string]bool)

	for _, reg := range c.registries {
		for _, t := range reg.SupportedResourceTypes() {
			typeSet[t] = true
		}
	}

	types := make([]string, 0, len(typeSet))
	for t := range typeSet {
		types = append(types, t)
	}

	return types
}

// SupportsResolutionOnly returns true if any child registry supports resolution-only requests.
// For OR logic, resolution-only support means at least one child can resolve.
// For AND logic, all children would need to support resolution-only for a meaningful result.
func (c *CompositeRegistry) SupportsResolutionOnly() bool {
	// For OR logic, any child supporting resolution-only is sufficient
	if c.operator == LogicOR {
		for _, reg := range c.registries {
			if reg.SupportsResolutionOnly() {
				return true
			}
		}
		return false
	}

	// For AND, MAJORITY, QUORUM logic, we require all children to support resolution-only
	for _, reg := range c.registries {
		if !reg.SupportsResolutionOnly() {
			return false
		}
	}
	return len(c.registries) > 0
}

// Info returns metadata about this composite registry
func (c *CompositeRegistry) Info() RegistryInfo {
	desc := c.description
	if desc == "" {
		desc = fmt.Sprintf("Composite registry combining %d registries with %s logic", len(c.registries), c.operator)
	}

	// Collect child registry names for trust anchors field
	var childNames []string
	for _, reg := range c.registries {
		childNames = append(childNames, reg.Info().Name)
	}

	return RegistryInfo{
		Name:         c.name,
		Type:         "composite",
		Description:  desc,
		Version:      "1.0.0",
		TrustAnchors: childNames,
	}
}

// Healthy returns true if all child registries are healthy
func (c *CompositeRegistry) Healthy() bool {
	for _, reg := range c.registries {
		if !reg.Healthy() {
			return false
		}
	}
	return true
}

// Refresh triggers refresh on all child registries
func (c *CompositeRegistry) Refresh(ctx context.Context) error {
	var errors []error

	for _, reg := range c.registries {
		if err := reg.Refresh(ctx); err != nil {
			errors = append(errors, fmt.Errorf("%s: %w", reg.Info().Name, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("refresh failed for %d registries: %v", len(errors), errors)
	}

	return nil
}
