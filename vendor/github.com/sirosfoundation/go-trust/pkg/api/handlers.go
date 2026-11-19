package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirosfoundation/g119612/pkg/logging"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// StatusHandler godoc
// @Summary Get server status (DEPRECATED - use GET /readyz)
// @Description Returns the current server status including TSL count and last processing time
// @Description
// @Description DEPRECATED: This endpoint is deprecated. Use GET /readyz for health checks.
// @Tags Status
// @Deprecated true
// @Produce json
// @Success 200 {object} map[string]interface{} "tsl_count, last_processed"
// @Router /status [get]
func StatusHandler(serverCtx *ServerContext) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Add deprecation headers
		c.Header("Deprecation", "true")
		c.Header("Link", "</readyz>; rel=\"alternate\"")
		c.Header("X-API-Warn", "This endpoint is deprecated. Please use GET /readyz instead.")

		serverCtx.RLock()
		defer serverCtx.RUnlock()
		tslCount := getRegistryCount(serverCtx)

		// Log the status request with structured logging
		serverCtx.Logger.Debug("API status request (deprecated endpoint)",
			logging.F("remote_ip", c.ClientIP()),
			logging.F("registry_count", tslCount),
			logging.F("replacement", "GET /readyz"))

		c.JSON(200, gin.H{
			"registry_count": tslCount,
		})
	}
}

// getRegistryCount returns the number of registered trust registries.
func getRegistryCount(serverCtx *ServerContext) int {
	if serverCtx.RegistryManager == nil {
		return 0
	}
	return len(serverCtx.RegistryManager.ListRegistries())
}

// maxEvaluationBodyBytes bounds an /evaluation request body (certificate
// chains included) so an oversized body cannot exhaust server memory.
const maxEvaluationBodyBytes = 1 << 20

// evaluator is what the evaluation handlers need from the registry manager.
type evaluator interface {
	Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error)
}

// evaluateAndRecord runs one evaluation against the registry manager and
// logs it and records its metrics. It is shared by /evaluation and
// /evaluations so that both behave identically per item. A non-nil error
// means the evaluation could not be carried out.
func evaluateAndRecord(c *gin.Context, serverCtx *ServerContext, registryMgr evaluator, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	actionName := ""
	if req.Action != nil {
		actionName = req.Action.Name
	}
	serverCtx.Logger.Debug("Processing AuthZEN request",
		logging.F("remote_ip", c.ClientIP()),
		logging.F("subject_id", req.Subject.ID),
		logging.F("subject_type", req.Subject.Type),
		logging.F("resource_type", req.Resource.Type),
		logging.F("resource_id", req.Resource.ID),
		logging.F("action", actionName),
		logging.F("has_key", len(req.Resource.Key) > 0),
		logging.F("has_context", req.Context != nil))

	start := time.Now()
	resp, evalErr := registryMgr.Evaluate(c.Request.Context(), req)
	validationDuration := time.Since(start)

	if evalErr != nil {
		serverCtx.Logger.Error("AuthZEN evaluation error",
			logging.F("remote_ip", c.ClientIP()),
			logging.F("subject_id", req.Subject.ID),
			logging.F("error", evalErr.Error()))
		if serverCtx.Metrics != nil {
			serverCtx.Metrics.RecordError("evaluation_error", "authzen_decision")
		}
		return nil, evalErr
	}

	if resp.Decision {
		serverCtx.Logger.Debug("AuthZEN request approved",
			logging.F("remote_ip", c.ClientIP()),
			logging.F("subject_id", req.Subject.ID),
			logging.F("resource_type", req.Resource.Type),
			logging.F("duration_ms", validationDuration.Milliseconds()))
		if serverCtx.Metrics != nil {
			serverCtx.Metrics.RecordCertValidation(validationDuration, true)
		}
	} else {
		serverCtx.Logger.Debug("AuthZEN request denied",
			logging.F("remote_ip", c.ClientIP()),
			logging.F("subject_id", req.Subject.ID),
			logging.F("resource_type", req.Resource.Type),
			logging.F("duration_ms", validationDuration.Milliseconds()))
		if serverCtx.Metrics != nil {
			serverCtx.Metrics.RecordCertValidation(validationDuration, false)
		}
	}

	if resp.Context != nil && resp.Context.Reason != nil {
		if regName, ok := resp.Context.Reason["registry"]; ok {
			serverCtx.Logger.Debug("AuthZEN response details",
				logging.F("decision", resp.Decision),
				logging.F("registry", regName),
				logging.F("duration_ms", validationDuration.Milliseconds()))
		}
	}
	return resp, nil
}

// AuthZENDecisionHandler godoc
// @Summary Evaluate trust decision (AuthZEN Trust Registry Profile)
// @Description Evaluates whether a name-to-key binding is trusted according to loaded trust registries
// @Description
// @Description This endpoint implements the AuthZEN Trust Registry Profile as specified in
// @Description draft-johansson-authzen-trust. It validates that a public key (in resource.key)
// @Description is correctly bound to a name (in subject.id) using configured trust registries
// @Description (ETSI TS 119612 TSLs, OpenID Federation, DID methods, etc.).
// @Description
// @Description ## Full Trust Evaluation
// @Description The request MUST have:
// @Description - subject.type = "key" and subject.id = the name to validate
// @Description - resource.type = "jwk" or "x5c" with resource.key containing the public key/certificates
// @Description - resource.id MUST equal subject.id
// @Description - action (optional) with name = the role being validated
// @Description
// @Description ## Resolution-Only Requests
// @Description When resource.type or resource.key are omitted, the request is treated as resolution-only.
// @Description Registries that support resolution-only mode (did:web, did:key, OpenID Federation) will
// @Description return decision=true with trust_metadata containing the resolved DID document or entity
// @Description configuration. ETSI TSL registries do not support resolution-only mode.
// @Tags AuthZEN
// @Accept json
// @Produce json
// @Param request body authzen.EvaluationRequest true "AuthZEN Trust Registry Evaluation Request"
// @Success 200 {object} authzen.EvaluationResponse "Trust decision (decision=true for trusted, false for untrusted)"
// @Failure 400 {object} map[string]string "Invalid request format or validation error"
// @Router /evaluation [post]
func AuthZENDecisionHandler(serverCtx *ServerContext) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req authzen.EvaluationRequest
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxEvaluationBodyBytes)
		if err := c.ShouldBindJSON(&req); err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				serverCtx.Logger.Error("AuthZEN request body too large",
					logging.F("remote_ip", c.ClientIP()),
					logging.F("limit", maxEvaluationBodyBytes))
				c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body too large"})
				return
			}
			// Log invalid request with structured logging
			serverCtx.Logger.Error("Invalid AuthZEN request",
				logging.F("remote_ip", c.ClientIP()),
				logging.F("error", err.Error()))
			c.JSON(400, gin.H{"error": "invalid request"})
			return
		}

		// Use RegistryManager for trust evaluation
		serverCtx.RLock()
		registryMgr := serverCtx.RegistryManager
		serverCtx.RUnlock()

		if registryMgr == nil {
			c.JSON(500, gin.H{"error": "server not configured: no registry manager"})
			return
		}

		resp, evalErr := evaluateAndRecord(c, serverCtx, registryMgr, &req)
		if evalErr != nil {
			c.JSON(500, buildResponse(false, "internal evaluation error"))
			return
		}

		c.JSON(200, resp)
	}
}

// DefaultMaxBatchEvaluations is the item limit of POST /evaluations when none is configured.
const DefaultMaxBatchEvaluations = 50

// maxBatchBodyBytes bounds a /evaluations request body. Each item may carry a
// certificate chain, so it is a multiple of the single-evaluation bound.
const maxBatchBodyBytes = 8 * maxEvaluationBodyBytes

// AuthZENBatchDecisionHandler godoc
// @Summary Evaluate several trust decisions (AuthZEN access evaluations)
// @Description Evaluates many name-to-key bindings in one request. The top-level subject, resource,
// @Description action and context are defaults; each item of `evaluations` may replace any of them.
// @Description The response has one result per item, in request order, each shaped like a
// @Description POST /evaluation response (including context.id and context.trust_data).
// @Description
// @Description An item that is invalid or cannot be evaluated yields decision=false for that item and
// @Description does not fail the request. A request with more items than the configured limit
// @Description (server.max_batch_evaluations, default 50) is refused with 400.
// @Description
// @Description options.evaluations_semantic may be execute_all (default), deny_on_first_deny or
// @Description permit_on_first_permit; the latter two end the response after the deciding item.
// @Tags AuthZEN
// @Accept json
// @Produce json
// @Param request body authzen.BatchEvaluationRequest true "AuthZEN access evaluations request"
// @Success 200 {object} authzen.BatchEvaluationResponse "One decision per evaluated item"
// @Failure 400 {object} map[string]string "Malformed request, no items, too many items or unknown semantic"
// @Failure 413 {object} map[string]string "Request body too large"
// @Router /evaluations [post]
func AuthZENBatchDecisionHandler(serverCtx *ServerContext) gin.HandlerFunc {
	return func(c *gin.Context) {
		req, semantic, ok := bindBatchRequest(c, serverCtx)
		if !ok {
			return
		}

		serverCtx.RLock()
		registryMgr := serverCtx.RegistryManager
		serverCtx.RUnlock()
		if registryMgr == nil {
			c.JSON(500, gin.H{"error": "server not configured: no registry manager"})
			return
		}

		results := make([]authzen.EvaluationResponse, 0, len(req.Evaluations))
		for i := range req.Evaluations {
			result := evaluateBatchItem(c, serverCtx, registryMgr, req, i)
			results = append(results, result)
			if batchDecided(semantic, result.Decision) {
				break
			}
		}
		c.JSON(200, authzen.BatchEvaluationResponse{Evaluations: results})
	}
}

// bindBatchRequest parses and checks a batch request. On a refusal it has
// already written the response and returns ok=false.
func bindBatchRequest(c *gin.Context, serverCtx *ServerContext) (req *authzen.BatchEvaluationRequest, semantic string, ok bool) {
	req = &authzen.BatchEvaluationRequest{}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBatchBodyBytes)
	if err := c.ShouldBindJSON(req); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body too large"})
			return nil, "", false
		}
		serverCtx.Logger.Error("Invalid AuthZEN batch request",
			logging.F("remote_ip", c.ClientIP()),
			logging.F("error", err.Error()))
		c.JSON(400, gin.H{"error": "invalid request"})
		return nil, "", false
	}
	if len(req.Evaluations) == 0 {
		c.JSON(400, gin.H{"error": "evaluations must contain at least one item"})
		return nil, "", false
	}

	serverCtx.RLock()
	limit := serverCtx.MaxBatchEvaluations
	serverCtx.RUnlock()
	if limit <= 0 {
		limit = DefaultMaxBatchEvaluations
	}
	if len(req.Evaluations) > limit {
		c.JSON(400, gin.H{"error": fmt.Sprintf("too many evaluations: %d, limit is %d", len(req.Evaluations), limit)})
		return nil, "", false
	}
	semantic, err := req.Semantic()
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return nil, "", false
	}
	return req, semantic, true
}

// evaluateBatchItem evaluates item i. A malformed item or a failure to
// evaluate is a denial of that item with an error reason and a decision id; it
// never fails the batch.
func evaluateBatchItem(c *gin.Context, serverCtx *ServerContext, registryMgr evaluator, batch *authzen.BatchEvaluationRequest, i int) authzen.EvaluationResponse {
	item, err := batch.Item(i)
	if err != nil {
		return batchDenial(err.Error())
	}
	resp, err := evaluateAndRecord(c, serverCtx, registryMgr, item)
	if err != nil {
		return batchDenial("internal evaluation error")
	}
	return *resp
}

// batchDenial is the decision=false result of an item that was not evaluated.
func batchDenial(reason string) authzen.EvaluationResponse {
	resp := buildResponse(false, reason)
	resp.Context.ID = uuid.NewString()
	return resp
}

// batchDecided reports whether the semantic ends the batch after a decision.
func batchDecided(semantic string, decision bool) bool {
	switch semantic {
	case authzen.EvaluationsSemanticDenyOnFirstDeny:
		return !decision
	case authzen.EvaluationsSemanticPermitOnFirstPermit:
		return decision
	}
	return false
}

// InfoHandler godoc
// @Summary Get registry information (DEPRECATED - use GET /registries)
// @Description Returns the same registry metadata as GET /registries.
// @Description
// @Description DEPRECATED: This endpoint is deprecated. Use GET /registries instead.
// @Description Response includes deprecation headers.
// @Tags Status
// @Deprecated true
// @Produce json
// @Success 200 {object} map[string]interface{} "registries"
// @Router /info [get]
func InfoHandler(serverCtx *ServerContext) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Add deprecation headers
		c.Header("Deprecation", "true")
		c.Header("Link", "</registries>; rel=\"alternate\"")
		c.Header("X-API-Warn", "This endpoint is deprecated. Please use GET /registries instead.")

		serverCtx.RLock()
		defer serverCtx.RUnlock()

		// Return registry info instead of TSL summaries
		registryInfos := make([]map[string]interface{}, 0)
		registryCount := 0

		if serverCtx.RegistryManager != nil {
			for _, info := range serverCtx.RegistryManager.ListRegistries() {
				registryInfos = append(registryInfos, map[string]interface{}{
					"name":            info.Name,
					"type":            info.Type,
					"description":     info.Description,
					"resource_types":  info.ResourceTypes,
					"resolution_only": info.ResolutionOnly,
					"healthy":         info.Healthy,
				})
			}
			registryCount = len(registryInfos)
		}

		// Log info request with structured logging
		serverCtx.Logger.Debug("API info request (deprecated endpoint)",
			logging.F("remote_ip", c.ClientIP()),
			logging.F("registry_count", registryCount),
			logging.F("replacement", "GET /registries"))

		c.JSON(200, gin.H{
			"registries": registryInfos,
		})
	}
}

// RegistriesHandler godoc
// @Summary List Trust Registries
// @Description Returns comprehensive information about all configured trust registries
// @Description
// @Description This is the primary endpoint for retrieving registry metadata including:
// @Description - Registry names and types
// @Description - Supported resource types
// @Description - Health status
// @Tags Registries
// @Produce json
// @Success 200 {object} map[string]interface{} "count, registries"
// @Router /registries [get]
func RegistriesHandler(serverCtx *ServerContext) gin.HandlerFunc {
	return func(c *gin.Context) {
		serverCtx.RLock()
		defer serverCtx.RUnlock()

		registryInfos := make([]map[string]interface{}, 0)
		registryCount := 0

		if serverCtx.RegistryManager != nil {
			for _, info := range serverCtx.RegistryManager.ListRegistries() {
				registryInfos = append(registryInfos, map[string]interface{}{
					"name":            info.Name,
					"type":            info.Type,
					"description":     info.Description,
					"trust_anchors":   info.TrustAnchors,
					"resource_types":  info.ResourceTypes,
					"resolution_only": info.ResolutionOnly,
					"healthy":         info.Healthy,
				})
			}
			registryCount = len(registryInfos)
		}

		serverCtx.Logger.Debug("API /registries request",
			logging.F("remote_ip", c.ClientIP()),
			logging.F("registry_count", registryCount))

		c.JSON(200, gin.H{
			"count":      registryCount,
			"registries": registryInfos,
		})
	}
}

// DeprecatedTSLsHandler wraps RegistriesHandler with deprecation headers.
// This preserves backward compatibility for clients still using GET /tsls
// while signaling they should migrate to GET /registries.
func DeprecatedTSLsHandler(serverCtx *ServerContext) gin.HandlerFunc {
	handler := RegistriesHandler(serverCtx)
	return func(c *gin.Context) {
		c.Header("Deprecation", "true")
		c.Header("Link", "</registries>; rel=\"alternate\"")
		c.Header("X-API-Warn", "This endpoint is deprecated. Please use GET /registries instead.")
		handler(c)
	}
}

// WellKnownHandler godoc
// @Summary AuthZEN PDP discovery endpoint
// @Description Returns Policy Decision Point metadata according to Section 9 of the AuthZEN specification
// @Description This endpoint provides service discovery information including supported endpoints and capabilities
// @Description per RFC 8615 well-known URI registration
// @Tags AuthZEN
// @Produce json
// @Success 200 {object} authzen.PDPMetadata "PDP metadata"
// @Router /.well-known/authzen-configuration [get]
func WellKnownHandler(baseURL string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Construct metadata according to AuthZEN spec Section 9.1
		metadata := authzen.PDPMetadata{
			PolicyDecisionPoint:       baseURL,
			AccessEvaluationEndpoint:  baseURL + "/evaluation",
			AccessEvaluationsEndpoint: baseURL + "/evaluations",
			// Optional endpoints - not implemented yet
			// SearchSubjectEndpoint: baseURL + "/search/subject",
			// SearchResourceEndpoint: baseURL + "/search/resource",
			// SearchActionEndpoint: baseURL + "/search/action",
			// Capabilities: []string{}, // Could list custom capabilities here
		}

		// Return metadata with proper Content-Type
		c.JSON(200, metadata)
	}
}

// TestShutdownHandler godoc (test mode only)
func TestShutdownHandler(serverCtx *ServerContext) gin.HandlerFunc {
	return func(c *gin.Context) {
		serverCtx.Logger.Info("Shutdown requested via /test/shutdown endpoint",
			logging.F("remote_ip", c.ClientIP()))

		c.JSON(200, gin.H{"message": "shutting down"})

		// Trigger graceful shutdown after response is sent
		go func() {
			time.Sleep(100 * time.Millisecond) // Give time for response to be sent
			os.Exit(0)
		}()
	}
}
