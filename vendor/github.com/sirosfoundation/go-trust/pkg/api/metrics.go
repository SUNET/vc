package api

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus metrics for the API server
type Metrics struct {
	registry *prometheus.Registry // Private registry for this metrics instance

	// Registry refresh metrics
	RefreshExecutionDuration prometheus.Histogram
	RefreshExecutionTotal    prometheus.Counter
	RefreshExecutionErrors   prometheus.Counter
	TSLCount                 prometheus.Gauge
	TSLProcessingDuration    prometheus.Histogram

	// API request metrics
	APIRequestsTotal    *prometheus.CounterVec
	APIRequestDuration  *prometheus.HistogramVec
	APIRequestsInFlight prometheus.Gauge

	// Error metrics
	ErrorsTotal *prometheus.CounterVec

	// Certificate validation metrics
	CertValidationTotal    *prometheus.CounterVec
	CertValidationDuration prometheus.Histogram
}

// NewMetrics creates and registers all Prometheus metrics
func NewMetrics() *Metrics {
	registry := prometheus.NewRegistry()

	m := &Metrics{
		registry: registry,

		// Registry refresh metrics
		RefreshExecutionDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "go_trust_refresh_execution_duration_seconds",
			Help:    "Duration of registry refresh execution in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		RefreshExecutionTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "go_trust_refresh_execution_total",
			Help: "Total number of registry refresh executions",
		}),
		RefreshExecutionErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "go_trust_refresh_execution_errors_total",
			Help: "Total number of registry refresh execution errors",
		}),
		TSLCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "go_trust_tsl_count",
			Help: "Current number of loaded Trust Status Lists",
		}),
		TSLProcessingDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "go_trust_tsl_processing_duration_seconds",
			Help:    "Duration of TSL processing in seconds",
			Buckets: prometheus.DefBuckets,
		}),

		// API request metrics
		APIRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "go_trust_api_requests_total",
				Help: "Total number of API requests",
			},
			[]string{"method", "endpoint", "status"},
		),
		APIRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "go_trust_api_request_duration_seconds",
				Help:    "Duration of API requests in seconds",
				Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
			},
			[]string{"method", "endpoint"},
		),
		APIRequestsInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "go_trust_api_requests_in_flight",
			Help: "Current number of API requests being processed",
		}),

		// Error metrics
		ErrorsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "go_trust_errors_total",
				Help: "Total number of errors by type",
			},
			[]string{"type", "operation"},
		),

		// Certificate validation metrics
		CertValidationTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "go_trust_cert_validation_total",
				Help: "Total number of certificate validations",
			},
			[]string{"result"},
		),
		CertValidationDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "go_trust_cert_validation_duration_seconds",
			Help:    "Duration of certificate validation in seconds",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5},
		}),
	}

	// Register all metrics with the private registry
	registry.MustRegister(
		m.RefreshExecutionDuration,
		m.RefreshExecutionTotal,
		m.RefreshExecutionErrors,
		m.TSLCount,
		m.TSLProcessingDuration,
		m.APIRequestsTotal,
		m.APIRequestDuration,
		m.APIRequestsInFlight,
		m.ErrorsTotal,
		m.CertValidationTotal,
		m.CertValidationDuration,
	)

	return m
}

// MetricsMiddleware creates a Gin middleware that records API metrics
func (m *Metrics) MetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip metrics endpoint itself
		if c.Request.URL.Path == "/metrics" {
			c.Next()
			return
		}

		start := time.Now()
		m.APIRequestsInFlight.Inc()

		// Process request
		c.Next()

		// Record metrics
		duration := time.Since(start).Seconds()
		status := strconv.Itoa(c.Writer.Status())
		endpoint := c.FullPath()
		if endpoint == "" {
			endpoint = "unknown"
		}

		m.APIRequestsTotal.WithLabelValues(c.Request.Method, endpoint, status).Inc()
		m.APIRequestDuration.WithLabelValues(c.Request.Method, endpoint).Observe(duration)
		m.APIRequestsInFlight.Dec()
	}
}

// RecordRefreshExecution records metrics for a registry refresh execution
func (m *Metrics) RecordRefreshExecution(duration time.Duration, registryCount int, err error) {
	m.RefreshExecutionDuration.Observe(duration.Seconds())
	m.RefreshExecutionTotal.Inc()
	m.TSLCount.Set(float64(registryCount))

	if err != nil {
		m.RefreshExecutionErrors.Inc()
		m.ErrorsTotal.WithLabelValues("refresh_execution", "registry").Inc()
	}
}

// RecordTSLProcessing records metrics for TSL processing
func (m *Metrics) RecordTSLProcessing(duration time.Duration) {
	m.TSLProcessingDuration.Observe(duration.Seconds())
}

// RecordError records an error metric
func (m *Metrics) RecordError(errorType, operation string) {
	m.ErrorsTotal.WithLabelValues(errorType, operation).Inc()
}

// RecordCertValidation records certificate validation metrics
func (m *Metrics) RecordCertValidation(duration time.Duration, success bool) {
	m.CertValidationDuration.Observe(duration.Seconds())
	result := "failure"
	if success {
		result = "success"
	}
	m.CertValidationTotal.WithLabelValues(result).Inc()
}

// RegisterMetricsEndpoint registers the /metrics endpoint with the Gin router
func RegisterMetricsEndpoint(r *gin.Engine, metrics *Metrics) {
	// Add middleware to all routes
	r.Use(metrics.MetricsMiddleware())

	// Register Prometheus metrics endpoint with custom registry
	// @Summary Prometheus metrics
	// @Description Exposes Prometheus metrics for monitoring and alerting
	// @Description
	// @Description Metrics include:
	// @Description - Registry refresh execution duration and counts
	// @Description - TSL processing metrics
	// @Description - API request rates and latency
	// @Description - Certificate validation metrics
	// @Description - Error counts by type
	// @Tags Metrics
	// @Produce plain
	// @Success 200 {string} string "Prometheus metrics in text format"
	// @Router /metrics [get]
	r.GET("/metrics", gin.WrapH(promhttp.HandlerFor(metrics.registry, promhttp.HandlerOpts{})))
}
