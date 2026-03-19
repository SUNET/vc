package api

import (
	"os"
	"time"

	"github.com/gin-gonic/gin"
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
		if err := c.BindJSON(&req); err != nil {
			// Log invalid request with structured logging
			serverCtx.Logger.Error("Invalid AuthZEN request",
				logging.F("remote_ip", c.ClientIP()),
				logging.F("error", err.Error()))
			c.JSON(400, gin.H{"error": "invalid request"})
			return
		}

		// Log valid request with full trace details
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

		// Use RegistryManager for trust evaluation
		serverCtx.RLock()
		registryMgr := serverCtx.RegistryManager
		serverCtx.RUnlock()

		var resp *authzen.EvaluationResponse
		var evalErr error

		if registryMgr == nil {
			c.JSON(500, gin.H{"error": "server not configured: no registry manager"})
			return
		}

		resp, evalErr = registryMgr.Evaluate(c.Request.Context(), &req)

		validationDuration := time.Since(start)

		if evalErr != nil {
			serverCtx.Logger.Error("AuthZEN evaluation error",
				logging.F("remote_ip", c.ClientIP()),
				logging.F("subject_id", req.Subject.ID),
				logging.F("error", evalErr.Error()))

			// Record error metrics
			if serverCtx.Metrics != nil {
				serverCtx.Metrics.RecordError("evaluation_error", "authzen_decision")
			}

			c.JSON(500, buildResponse(false, "internal evaluation error"))
			return
		}

		if resp.Decision {
			serverCtx.Logger.Debug("AuthZEN request approved",
				logging.F("remote_ip", c.ClientIP()),
				logging.F("subject_id", req.Subject.ID),
				logging.F("resource_type", req.Resource.Type),
				logging.F("duration_ms", validationDuration.Milliseconds()))

			// Record successful validation metrics
			if serverCtx.Metrics != nil {
				serverCtx.Metrics.RecordCertValidation(validationDuration, true)
			}
		} else {
			serverCtx.Logger.Debug("AuthZEN request denied",
				logging.F("remote_ip", c.ClientIP()),
				logging.F("subject_id", req.Subject.ID),
				logging.F("resource_type", req.Resource.Type),
				logging.F("duration_ms", validationDuration.Milliseconds()))

			// Record failed validation metrics
			if serverCtx.Metrics != nil {
				serverCtx.Metrics.RecordCertValidation(validationDuration, false)
			}
		}

		// Debug trace: response details
		if resp.Context != nil && resp.Context.Reason != nil {
			if registry, ok := resp.Context.Reason["registry"]; ok {
				serverCtx.Logger.Debug("AuthZEN response details",
					logging.F("decision", resp.Decision),
					logging.F("registry", registry),
					logging.F("duration_ms", validationDuration.Milliseconds()))
			}
		}

		c.JSON(200, resp)
	}
}

// InfoHandler godoc
// @Summary Get TSL information (DEPRECATED - use GET /tsls)
// @Description Returns detailed summaries of all loaded Trust Status Lists
// @Description
// @Description DEPRECATED: This endpoint is deprecated. Use GET /tsls instead.
// @Description
// @Description This endpoint provides comprehensive information about each TSL including:
// @Description - Territory code
// @Description - Sequence number
// @Description - Issue date
// @Description - Next update date
// @Description - Number of services
// @Tags Status
// @Deprecated true
// @Produce json
// @Success 200 {object} map[string]interface{} "tsl_summaries"
// @Router /info [get]
func InfoHandler(serverCtx *ServerContext) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Add deprecation headers
		c.Header("Deprecation", "true")
		c.Header("Link", "</tsls>; rel=\"alternate\"")
		c.Header("X-API-Warn", "This endpoint is deprecated. Please use GET /tsls instead.")

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
			logging.F("replacement", "GET /tsls"))

		c.JSON(200, gin.H{
			"registries": registryInfos,
		})
	}
}

// TSLsHandler godoc
// @Summary List Trust Registries
// @Description Returns comprehensive information about all configured trust registries
// @Description
// @Description This is the primary endpoint for retrieving registry metadata including:
// @Description - Registry names and types
// @Description - Supported resource types
// @Description - Health status
// @Description - Last processing timestamp
// @Tags Registries
// @Produce json
// @Success 200 {object} map[string]interface{} "count, last_updated, registries"
// @Router /tsls [get]
func TSLsHandler(serverCtx *ServerContext) gin.HandlerFunc {
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

		serverCtx.Logger.Debug("API /tsls request",
			logging.F("remote_ip", c.ClientIP()),
			logging.F("registry_count", registryCount))

		c.JSON(200, gin.H{
			"count":      registryCount,
			"registries": registryInfos,
		})
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
			PolicyDecisionPoint:      baseURL,
			AccessEvaluationEndpoint: baseURL + "/evaluation",
			// Optional endpoints - not implemented yet
			// AccessEvaluationsEndpoint: baseURL + "/evaluations",
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
