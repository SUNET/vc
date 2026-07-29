package metric

import (
	"go.opentelemetry.io/otel/metric"
)

// VP holds OpenID4VP (verifiable presentation) metric instruments.
// Labels are restricted to protocol-level metadata to avoid PII exposure.
type VP struct {
	// RequestsCreated counts verification request objects created.
	// Attributes: (none — all requests are equivalent)
	RequestsCreated metric.Int64Counter

	// PresentationsReceived counts VP tokens received via direct_post.
	// Attributes: format
	PresentationsReceived metric.Int64Counter

	// VerificationsFailed counts presentation verification failures.
	// Attributes: error_class
	VerificationsFailed metric.Int64Counter

	// VerificationLatency records direct_post processing duration.
	// Attributes: (none)
	VerificationLatency metric.Float64Histogram
}

// NewVP creates VP metric instruments from the given meter.
func NewVP(m metric.Meter) (*VP, error) {
	vp := &VP{}
	var err error

	vp.RequestsCreated, err = m.Int64Counter("vp.requests.created",
		metric.WithDescription("Number of verification request objects created"),
		metric.WithUnit("{request}"))
	if err != nil {
		return nil, err
	}

	vp.PresentationsReceived, err = m.Int64Counter("vp.presentations.received",
		metric.WithDescription("Number of VP tokens received"),
		metric.WithUnit("{presentation}"))
	if err != nil {
		return nil, err
	}

	vp.VerificationsFailed, err = m.Int64Counter("vp.verifications.failed",
		metric.WithDescription("Number of presentation verification failures"),
		metric.WithUnit("{verification}"))
	if err != nil {
		return nil, err
	}

	vp.VerificationLatency, err = m.Float64Histogram("vp.verification.duration",
		metric.WithDescription("Direct post verification duration"),
		metric.WithUnit("s"))
	if err != nil {
		return nil, err
	}

	return vp, nil
}
