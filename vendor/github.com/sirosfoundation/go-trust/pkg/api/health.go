package api

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirosfoundation/g119612/pkg/logging"
)

// HealthResponse represents the response from health check endpoints
type HealthResponse struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

// ReadinessResponse represents the response from the readiness endpoint
type ReadinessResponse struct {
	Status        string                   `json:"status"`
	Timestamp     time.Time                `json:"timestamp"`
	RegistryCount int                      `json:"registry_count"`
	HealthyCount  int                      `json:"healthy_count"`
	Ready         bool                     `json:"ready"`
	Message       string                   `json:"message,omitempty"`
	Registries    []map[string]interface{} `json:"registries,omitempty"` // Only included with ?verbose=true
}

// RegisterHealthEndpoints registers health check endpoints on the given Gin router.
// These endpoints are useful for Kubernetes liveness and readiness probes, load balancers,
// and monitoring systems.
//
// Endpoints:
//
//	GET /healthz      - Liveness probe: returns 200 if the server is running
//	GET /readyz       - Readiness probe: returns 200 if server is ready to accept traffic
//	                    Supports ?verbose=true query parameter for detailed TSL information
//
// The /healthz endpoint always returns 200 OK if the server is running, indicating
// that the process is alive and can handle requests.
//
// The /readyz endpoint checks whether the service has:
//   - At least one registry configured
//   - At least one registry reporting healthy
//
// If these conditions are not met, it returns 503 Service Unavailable.
//
// Use ?verbose=true on /readyz to include detailed registry information in the response.
func RegisterHealthEndpoints(r *gin.Engine, serverCtx *ServerContext) {
	r.GET("/healthz", HealthHandler(serverCtx))
	r.GET("/readyz", ReadinessHandler(serverCtx))

	serverCtx.Logger.Info("Health check endpoints registered",
		logging.F("endpoints", []string{"/healthz", "/readyz"}))
}

// HealthHandler godoc
// @Summary Liveness check
// @Description Returns OK if the server is running and able to handle requests
// @Tags Health
// @Produce json
// @Success 200 {object} HealthResponse
// @Router /healthz [get]
func HealthHandler(serverCtx *ServerContext) gin.HandlerFunc {
	return func(c *gin.Context) {
		serverCtx.Logger.Debug("Health check requested",
			logging.F("remote_ip", c.ClientIP()),
			logging.F("endpoint", c.Request.URL.Path))

		c.JSON(200, HealthResponse{
			Status:    "ok",
			Timestamp: time.Now(),
		})
	}
}

// ReadinessHandler godoc
// @Summary Readiness check
// @Description Returns ready status if at least one healthy registry is configured
// @Description
// @Description Query Parameters:
// @Description - verbose=true: Include detailed registry information in the response
// @Tags Health
// @Produce json
// @Param verbose query bool false "Include detailed registry information"
// @Success 200 {object} ReadinessResponse "Service is ready"
// @Failure 503 {object} ReadinessResponse "Service is not ready"
// @Router /readyz [get]
func ReadinessHandler(serverCtx *ServerContext) gin.HandlerFunc {
	return func(c *gin.Context) {
		serverCtx.RLock()
		registryCount := 0
		healthyCount := 0
		verbose := c.Query("verbose") == "true"

		// Collect registry information
		var registryInfos []map[string]interface{}
		if serverCtx.RegistryManager != nil {
			for _, info := range serverCtx.RegistryManager.ListRegistries() {
				registryCount++
				if info.Healthy {
					healthyCount++
				}
				if verbose {
					entry := map[string]interface{}{
						"name":            info.Name,
						"type":            info.Type,
						"resource_types":  info.ResourceTypes,
						"resolution_only": info.ResolutionOnly,
						"healthy":         info.Healthy,
					}
					if info.LastUpdated != nil {
						entry["last_updated"] = info.LastUpdated
					}
					registryInfos = append(registryInfos, entry)
				}
			}
		}
		serverCtx.RUnlock()

		// Service is ready if at least one registry is configured and healthy
		isReady := healthyCount > 0

		response := ReadinessResponse{
			Timestamp:     time.Now(),
			RegistryCount: registryCount,
			HealthyCount:  healthyCount,
			Ready:         isReady,
			Registries:    registryInfos,
		}

		if isReady {
			response.Status = "ready"
			response.Message = "Service is ready to accept traffic"

			serverCtx.Logger.Debug("Readiness check passed",
				logging.F("remote_ip", c.ClientIP()),
				logging.F("endpoint", c.Request.URL.Path),
				logging.F("verbose", verbose),
				logging.F("registry_count", registryCount),
				logging.F("healthy_count", healthyCount))

			c.JSON(200, response)
		} else {
			response.Status = "not_ready"
			if registryCount == 0 {
				response.Message = "No registries configured"
			} else {
				response.Message = "No healthy registries available"
			}

			serverCtx.Logger.Warn("Readiness check failed",
				logging.F("remote_ip", c.ClientIP()),
				logging.F("endpoint", c.Request.URL.Path),
				logging.F("verbose", verbose),
				logging.F("reason", response.Message),
				logging.F("registry_count", registryCount),
				logging.F("healthy_count", healthyCount))

			c.JSON(503, response)
		}
	}
}
