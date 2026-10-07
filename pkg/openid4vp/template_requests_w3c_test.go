package openid4vp

import "testing"

// stubTemplate is the smallest thing satisfying PresentationRequestTemplate.
type stubTemplate struct {
	id     string
	scopes []string
	dcql   *DCQL
}

func (s stubTemplate) GetID() string           { return s.id }
func (s stubTemplate) GetOIDCScopes() []string { return s.scopes }
func (s stubTemplate) GetDCQLQuery() *DCQL     { return s.dcql }

// The verifier asks "could this session have asked for a W3C credential?"
// exactly when the persisted request cannot be read back, so it has to be
// answered from configuration. Reading common.credential_metadata alone
// missed template-driven requests: a template names its credential queries
// with ids of its own choosing and can request ldp_vc for a scope that
// configures no metadata at all.
func TestTemplateRequestsW3C(t *testing.T) {
	w3c := stubTemplate{
		id:     "degree",
		scopes: []string{"degree"},
		dcql: &DCQL{Credentials: []CredentialQuery{
			// An id unrelated to any configured scope, which is the point.
			{ID: "q1", Format: FormatLdpVCDCQL},
		}},
	}
	sdjwt := stubTemplate{
		id:     "pid",
		scopes: []string{"pid"},
		dcql:   &DCQL{Credentials: []CredentialQuery{{ID: "q1", Format: "dc+sd-jwt"}}},
	}
	builder := NewPresentationBuilder([]PresentationRequestTemplate{w3c, sdjwt})

	t.Run("a template requesting ldp_vc is found", func(t *testing.T) {
		if !builder.TemplateRequestsW3C([]string{"degree"}) {
			t.Fatal("the template these scopes select asks for a W3C credential")
		}
	})

	// The control: an SD-JWT-only template must NOT be reported, or the
	// carve-out this feeds would refuse every flow that needs nothing from
	// the W3C path - which is the outage its comment warns about.
	t.Run("an SD-JWT template is not", func(t *testing.T) {
		if builder.TemplateRequestsW3C([]string{"pid"}) {
			t.Fatal("an SD-JWT-only template asks for no W3C credential")
		}
	})

	t.Run("scopes selecting no template are not", func(t *testing.T) {
		if builder.TemplateRequestsW3C([]string{"unknown"}) {
			t.Fatal("no template, nothing to report")
		}
	})

	t.Run("a nil builder is safe", func(t *testing.T) {
		var nilBuilder *PresentationBuilder
		if nilBuilder.TemplateRequestsW3C([]string{"degree"}) {
			t.Fatal("a verifier with no templates configured asks for nothing")
		}
	})
}
