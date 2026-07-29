package metric

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	promexporter "go.opentelemetry.io/otel/exporters/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// PrometheusExporter holds the Prometheus reader and an HTTP handler for scraping.
type PrometheusExporter struct {
	Reader  sdkmetric.Reader
	Handler http.Handler
}

// NewPrometheusExporter creates a Prometheus exporter that can be added as a
// reader to the MeterProvider and also serves /metrics for scraping.
func NewPrometheusExporter() (*PrometheusExporter, error) {
	exporter, err := promexporter.New()
	if err != nil {
		return nil, err
	}
	return &PrometheusExporter{
		Reader:  exporter,
		Handler: promhttp.Handler(),
	}, nil
}
