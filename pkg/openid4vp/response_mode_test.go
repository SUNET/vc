package openid4vp

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWithDCAPIRequestDiffersOnlyInDelivery is the guarantee that matters
// once a session serves two request objects: they are the same request seen
// through two delivery channels, so anything a wallet checks must agree
// (SUNET/vc#652).
//
// Three fields are exempt, all for the same reason stated three ways. Each
// of response_mode, response_uri and expected_origins says how the request
// is delivered and answered: a dc_api answer returns inside the browser
// call rather than to a response_uri, and a signed dc_api request must name
// the origin that invoked it so the wallet can bind it there. They are
// asserted individually below, then normalised before everything else is
// compared.
//
// An earlier version of this comment said only response_mode may differ,
// and the assertion matched it - which made both of the bugs fixed here
// (a copied response_uri, a missing expected_origins) mandatory.
func TestWithDCAPIRequestDiffersOnlyInDelivery(t *testing.T) {
	base := &RequestObject{
		ResponseURI:  "https://verifier.example.com/verification/direct_post",
		AUD:          "https://self-issued.me/v2",
		ISS:          "verifier.example.com",
		ClientID:     "x509_san_dns:verifier.example.com",
		ResponseType: "vp_token",
		ResponseMode: ResponseModeDirectPostJWT,
		State:        "state-1",
		Nonce:        "nonce-1",
		ClientMetadata: &ClientMetadata{
			EncryptedResponseEncValuesSupported: []string{"A256GCM"},
		},
	}

	variant := base.WithDCAPIRequest("https://verifier.example.com")
	require.NotNil(t, variant)

	assert.Equal(t, ResponseModeDCAPIJWT, variant.ResponseMode,
		"the DC API channel is the only one a dc_api mode is defined for")
	assert.Equal(t, ResponseModeDirectPostJWT, base.ResponseMode,
		"the link channel's own object must not be mutated")

	assert.Empty(t, variant.ResponseURI,
		"a dc_api response returns inside the browser call, so the request must not name a response_uri")
	assert.NotEmpty(t, base.ResponseURI,
		"the link channel's own object must keep the one it needs")

	assert.Equal(t, []string{"https://verifier.example.com"}, variant.ExpectedOrigins,
		"a signed dc_api request must name the origin the wallet binds it to (OpenID4VP 1.0 Appendix A.3)")
	assert.Empty(t, base.ExpectedOrigins,
		"the link channel has no invoking origin to name")

	// Compare with all three delivery-dependent fields normalised: every
	// other field, including any added to RequestObject later, has to be
	// identical. The count is load-bearing - this comment is where the
	// exceptions to the cross-channel equality invariant are written down,
	// and an earlier version of it claiming only one is what made the two
	// bugs fixed here mandatory.
	normalised := *variant
	normalised.ResponseMode = base.ResponseMode
	normalised.ResponseURI = base.ResponseURI
	normalised.ExpectedOrigins = base.ExpectedOrigins
	assert.True(t, reflect.DeepEqual(*base, normalised),
		"the two channels must differ only in how the response is delivered")

	// The pointer field is shared, not deep-copied - which is what we want:
	// the wallet must see the same client_metadata either way.
	assert.Same(t, base.ClientMetadata, variant.ClientMetadata)
}

func TestWithDCAPIRequestNilIsNil(t *testing.T) {
	assert.Nil(t, (*RequestObject)(nil).WithDCAPIRequest("https://verifier.example.com"))
}

// TestResponseModeConstantsMatchOneofTag makes the constants' doc comment true.
//
// That comment claimed the constants sit beside the field's oneof validation
// "so the two cannot drift". They could: the oneof list is a struct tag in
// request_object.go, and a Go tag is an uninterpreted string literal - it
// cannot reference a constant, so adding a mode in one place and not the
// other compiles and passes everything. Review caught the claim; this test
// is what makes it hold, by reading the tag back and comparing it to the
// constants as sets.
//
// A mismatch in either direction is a bug with real consequences. A mode in
// the tag but not the constants validates while no code can name it. A mode
// in the constants but not the tag is worse: code sets it and validation
// then rejects the request object it just built.
func TestResponseModeConstantsMatchOneofTag(t *testing.T) {
	field, ok := reflect.TypeFor[RequestObject]().FieldByName("ResponseMode")
	require.True(t, ok, "RequestObject has no ResponseMode field - this test must be updated with it")

	var oneof string
	for rule := range strings.SplitSeq(field.Tag.Get("validate"), ",") {
		if after, found := strings.CutPrefix(rule, "oneof="); found {
			oneof = after
			break
		}
	}
	require.NotEmpty(t, oneof, "ResponseMode's validate tag has no oneof= rule; the accepted set is no longer enforced there")

	assert.ElementsMatch(t,
		[]string{
			ResponseModeFormPost, ResponseModeDirectPost, ResponseModeDirectPostJWT, ResponseModeDCAPIJWT,
			ResponseModeIAPost, ResponseModeIAPostJWT,
		},
		strings.Fields(oneof),
		"the response-mode constants and the oneof validation tag have drifted; update both",
	)
}

// IsInteractiveAuthorization is the one place that decides whether a
// response goes back to the Authorization Challenge Endpoint instead of to
// a response_uri, so it must not drift from the constants either.
func TestIsInteractiveAuthorization(t *testing.T) {
	for _, mode := range []string{ResponseModeIAPost, ResponseModeIAPostJWT} {
		assert.True(t, IsInteractiveAuthorization(mode), mode)
	}
	for _, mode := range []string{
		ResponseModeFormPost, ResponseModeDirectPost, ResponseModeDirectPostJWT,
		ResponseModeDCAPIJWT, "", "ia_post.other",
	} {
		assert.False(t, IsInteractiveAuthorization(mode), mode)
	}
}
