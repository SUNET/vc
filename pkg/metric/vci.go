package metric

import (
	"go.opentelemetry.io/otel/metric"
)

// VCI holds OpenID4VCI (credential issuance) metric instruments.
// Labels are restricted to protocol-level metadata to avoid PII exposure.
type VCI struct {
	// OffersCreated counts credential offers generated.
	// Attributes: grant_type, credential_config_id, source
	OffersCreated metric.Int64Counter

	// TokensIssued counts access tokens issued at the token endpoint.
	// Attributes: grant_type
	TokensIssued metric.Int64Counter

	// CredentialsIssued counts successfully issued credentials.
	// Attributes: format, credential_config_id
	CredentialsIssued metric.Int64Counter

	// CredentialsFailed counts credential issuance failures.
	// Attributes: format, error_class
	CredentialsFailed metric.Int64Counter

	// DeferredCredentials counts deferred credential retrievals.
	// Attributes: status (issued, pending, expired)
	DeferredCredentials metric.Int64Counter

	// Notifications counts wallet notification events.
	// Attributes: event (credential_accepted, credential_failure)
	Notifications metric.Int64Counter

	// TokenLatency records token endpoint request duration.
	// Attributes: grant_type
	TokenLatency metric.Float64Histogram

	// IssuanceLatency records credential endpoint request duration.
	// Attributes: format
	IssuanceLatency metric.Float64Histogram
}

// NewVCI creates VCI metric instruments from the given meter.
func NewVCI(m metric.Meter) (*VCI, error) {
	vci := &VCI{}
	var err error

	vci.OffersCreated, err = m.Int64Counter("vci.offers.created",
		metric.WithDescription("Number of credential offers generated"),
		metric.WithUnit("{offer}"))
	if err != nil {
		return nil, err
	}

	vci.TokensIssued, err = m.Int64Counter("vci.tokens.issued",
		metric.WithDescription("Number of access tokens issued"),
		metric.WithUnit("{token}"))
	if err != nil {
		return nil, err
	}

	vci.CredentialsIssued, err = m.Int64Counter("vci.credentials.issued",
		metric.WithDescription("Number of credentials successfully issued"),
		metric.WithUnit("{credential}"))
	if err != nil {
		return nil, err
	}

	vci.CredentialsFailed, err = m.Int64Counter("vci.credentials.failed",
		metric.WithDescription("Number of credential issuance failures"),
		metric.WithUnit("{credential}"))
	if err != nil {
		return nil, err
	}

	vci.DeferredCredentials, err = m.Int64Counter("vci.deferred.credentials",
		metric.WithDescription("Number of deferred credential retrievals"),
		metric.WithUnit("{credential}"))
	if err != nil {
		return nil, err
	}

	vci.Notifications, err = m.Int64Counter("vci.notifications",
		metric.WithDescription("Number of wallet notification events"),
		metric.WithUnit("{notification}"))
	if err != nil {
		return nil, err
	}

	vci.TokenLatency, err = m.Float64Histogram("vci.token.duration",
		metric.WithDescription("Token endpoint request duration"),
		metric.WithUnit("s"))
	if err != nil {
		return nil, err
	}

	vci.IssuanceLatency, err = m.Float64Histogram("vci.credential.duration",
		metric.WithDescription("Credential endpoint request duration"),
		metric.WithUnit("s"))
	if err != nil {
		return nil, err
	}

	return vci, nil
}
