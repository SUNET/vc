package metric

import (
	"context"
	"testing"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

func TestNewForTesting(t *testing.T) {
	log, _ := logger.New("test", "", false)
	m := NewForTesting("test-service", log)

	assert.NotNil(t, m)
	assert.NotNil(t, m.Meter)
	assert.Nil(t, m.MP)
	assert.Nil(t, m.Prometheus)
	assert.Nil(t, m.HTTPHandler())
}

func TestNewDisabled(t *testing.T) {
	log, _ := logger.New("test", "", false)
	cfg := &model.Cfg{
		Common: &model.Common{
			Metrics: model.OTEL{Enable: false},
		},
	}

	m, err := New(context.Background(), cfg, "test-service", log)
	require.NoError(t, err)
	assert.NotNil(t, m)
	assert.Nil(t, m.MP)
	assert.Nil(t, m.HTTPHandler())
}

func TestVCIMetrics(t *testing.T) {
	log, _ := logger.New("test", "", false)
	m := NewForTesting("test-service", log)

	vci, err := NewVCI(m.Meter)
	require.NoError(t, err)
	assert.NotNil(t, vci.OffersCreated)
	assert.NotNil(t, vci.TokensIssued)
	assert.NotNil(t, vci.CredentialsIssued)
	assert.NotNil(t, vci.CredentialsFailed)
	assert.NotNil(t, vci.DeferredCredentials)
	assert.NotNil(t, vci.Notifications)
	assert.NotNil(t, vci.TokenLatency)
	assert.NotNil(t, vci.IssuanceLatency)

	// Verify recording doesn't panic with no-op meter
	ctx := context.Background()
	vci.OffersCreated.Add(ctx, 1, metric.WithAttributes(
		attribute.String("grant_type", "pre-authorized_code"),
		attribute.String("credential_config_id", "test_cred"),
		attribute.String("source", "test"),
	))
	vci.TokensIssued.Add(ctx, 1, metric.WithAttributes(
		attribute.String("grant_type", "authorization_code"),
	))
	vci.CredentialsIssued.Add(ctx, 1, metric.WithAttributes(
		attribute.String("format", "vc+sd-jwt"),
		attribute.String("credential_config_id", "test_cred"),
	))
	vci.CredentialsFailed.Add(ctx, 1, metric.WithAttributes(
		attribute.String("format", "mso_mdoc"),
		attribute.String("error_class", "proof_invalid"),
	))
	vci.TokenLatency.Record(ctx, 0.05, metric.WithAttributes(
		attribute.String("grant_type", "pre-authorized_code"),
	))
	vci.IssuanceLatency.Record(ctx, 0.1, metric.WithAttributes(
		attribute.String("format", "vc+sd-jwt"),
	))
}

func TestVPMetrics(t *testing.T) {
	log, _ := logger.New("test", "", false)
	m := NewForTesting("test-service", log)

	vp, err := NewVP(m.Meter)
	require.NoError(t, err)
	assert.NotNil(t, vp.RequestsCreated)
	assert.NotNil(t, vp.PresentationsReceived)
	assert.NotNil(t, vp.VerificationsFailed)
	assert.NotNil(t, vp.VerificationLatency)

	// Verify recording doesn't panic with no-op meter
	ctx := context.Background()
	vp.RequestsCreated.Add(ctx, 1)
	vp.PresentationsReceived.Add(ctx, 1)
	vp.VerificationsFailed.Add(ctx, 1, metric.WithAttributes(
		attribute.String("error_class", "claims_extraction"),
	))
	vp.VerificationLatency.Record(ctx, 0.5)
}

func TestPrometheusExporter(t *testing.T) {
	exp, err := NewPrometheusExporter()
	require.NoError(t, err)
	assert.NotNil(t, exp.Reader)
	assert.NotNil(t, exp.Handler)
}

func TestNewEnabled(t *testing.T) {
	// Uses a non-existent OTLP endpoint; the exporter is created but won't
	// actually push. This tests the wiring, not the network.
	log, _ := logger.New("test", "", false)
	cfg := &model.Cfg{
		Common: &model.Common{
			Metrics: model.OTEL{Enable: true, Addr: "localhost:4318"},
		},
	}

	m, err := New(context.Background(), cfg, "test-service", log)
	require.NoError(t, err)
	assert.NotNil(t, m.MP)
	assert.NotNil(t, m.Prometheus)
	assert.NotNil(t, m.HTTPHandler())

	// Shutdown may return an error if the OTLP endpoint is unreachable (expected in tests)
	_ = m.Shutdown(context.Background())
}
