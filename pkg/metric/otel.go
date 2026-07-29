package metric

import (
	"context"
	"net/http"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
)

// Meter wraps an OTel MeterProvider and exposes a Meter for creating instruments.
type Meter struct {
	MP         *sdkmetric.MeterProvider
	Meter      otelmetric.Meter
	Prometheus *PrometheusExporter
	log        *logger.Log
}

// New creates a new MeterProvider configured with an OTLP exporter (same
// collector as tracing) when metrics are enabled, or a no-op provider for
// testing and when disabled.
func New(ctx context.Context, cfg *model.Cfg, serviceName string, log *logger.Log) (*Meter, error) {
	if cfg == nil || cfg.Common == nil || !cfg.Common.Metrics.Enable {
		return newNoOp(serviceName, log), nil
	}

	var readers []sdkmetric.Option

	// OTLP push exporter (reuses the same collector as tracing)
	if cfg.Common.Metrics.Addr != "" {
		exp, err := otlpmetrichttp.New(ctx,
			otlpmetrichttp.WithEndpoint(cfg.Common.Metrics.Addr),
			otlpmetrichttp.WithInsecure(),
		)
		if err != nil {
			return nil, err
		}
		readers = append(readers, sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp)))
	}

	// Prometheus scrape exporter (always enabled when metrics are on)
	promExp, err := NewPrometheusExporter()
	if err != nil {
		return nil, err
	}
	readers = append(readers, sdkmetric.WithReader(promExp.Reader))

	opts := append(readers, sdkmetric.WithResource(resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(serviceName),
	)))

	mp := sdkmetric.NewMeterProvider(opts...)
	otel.SetMeterProvider(mp)

	return &Meter{
		MP:         mp,
		Meter:      mp.Meter(serviceName),
		Prometheus: promExp,
		log:        log.New("metric"),
	}, nil
}

// NewForTesting returns a Meter backed by a no-op provider.
func NewForTesting(serviceName string, log *logger.Log) *Meter {
	return newNoOp(serviceName, log)
}

func newNoOp(serviceName string, log *logger.Log) *Meter {
	return &Meter{
		Meter: noop.Meter{},
		log:   log.New("metric"),
	}
}

// Shutdown flushes and shuts down the meter provider.
func (m *Meter) Shutdown(ctx context.Context) error {
	if m.MP != nil {
		m.log.Info("Shutting down meter provider")
		return m.MP.Shutdown(ctx)
	}
	return nil
}

// HTTPHandler returns the Prometheus scrape HTTP handler, or nil if metrics are disabled.
func (m *Meter) HTTPHandler() http.Handler {
	if m.Prometheus != nil {
		return m.Prometheus.Handler
	}
	return nil
}
