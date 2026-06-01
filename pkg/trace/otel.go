package trace

import (
	"context"
	"time"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	jaegerPropagator "go.opentelemetry.io/contrib/propagators/jaeger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"

	//"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
	//"go.opentelemetry.io/otel/api/trace/tracetest"
	//"go.opentelemetry.io/otel/exporters/stdout"
	//"go.opentelemetry.io/otel/sdk/export/trace/tracetest"
)

// Tracer is a wrapper for opentelemetry tracer
type Tracer struct {
	TP *sdktrace.TracerProvider
	trace.Tracer
	log *logger.Log
}

// New return a new tracer
func New(ctx context.Context, cfg *model.Cfg, serviceName string, log *logger.Log) (*Tracer, error) {
	var exp sdktrace.SpanExporter
	var err error

	// Use no-op exporter if cfg.Common is nil (test environment) or tracing is not enabled
	if cfg == nil || cfg.Common == nil || !cfg.Common.Tracing.Enable {
		exp, err = newNoOpExporter()
	} else {
		exp, err = newExporter(ctx, cfg)
	}

	if err != nil {
		return nil, err
	}

	tracer := &Tracer{
		TP:  newTraceProvider(exp, serviceName),
		log: log.New("trace"),
	}

	otel.SetTracerProvider(tracer.TP)
	otel.SetTextMapPropagator(jaegerPropagator.Jaeger{})

	tracer.Tracer = otel.Tracer("")

	return tracer, nil
}

// NewForTesting return a new tracer for testing purpose without exporting the trace
func NewForTesting(ctx context.Context, projectName string, log *logger.Log) (*Tracer, error) {
	// Use a no-op exporter that discards all spans
	exp, err := newNoOpExporter()
	if err != nil {
		return nil, err
	}

	tracer := &Tracer{
		TP:  newTraceProvider(exp, projectName),
		log: log,
	}

	otel.SetTracerProvider(tracer.TP)
	otel.SetTextMapPropagator(jaegerPropagator.Jaeger{})

	tracer.Tracer = otel.Tracer("")

	return tracer, nil
}

// Shutdown shuts down the tracer
func (t *Tracer) Shutdown(ctx context.Context) error {
	t.log.Info("Shutting down tracer")
	return t.TP.Shutdown(ctx)
}

// noOpExporter is an exporter that discards all spans
type noOpExporter struct{}

func (e *noOpExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	return nil
}

func (e *noOpExporter) Shutdown(ctx context.Context) error {
	return nil
}

func newNoOpExporter() (sdktrace.SpanExporter, error) {
	return &noOpExporter{}, nil
}

func newExporter(ctx context.Context, cfg *model.Cfg) (sdktrace.SpanExporter, error) {
	return otlptracehttp.New(
		ctx,
		otlptracehttp.WithEndpoint(cfg.Common.Tracing.Addr),
		otlptracehttp.WithInsecure(),
		otlptracehttp.WithTimeout(time.Duration(cfg.Common.Tracing.Timeout)*time.Second),
	)
}

func newTraceProvider(exp sdktrace.SpanExporter, serviceName string) *sdktrace.TracerProvider {
	return sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
		)),
	)
}
