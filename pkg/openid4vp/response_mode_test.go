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

// The Interactive Authorization request must advertise exactly what the
// Authorization Challenge Endpoint will accept.
//
// The Digital Credentials API request this is derived from offers A256GCM
// and A128GCM, and a wallet is entitled to pick either. The challenge
// endpoint accepts only A256GCM, so a wallet that chose the second
// advertised option was refused AFTER its auth_session had been claimed -
// losing the whole exchange for doing exactly what the request permitted,
// with no way to know in advance and nothing to retry.
func TestInteractiveAuthorizationAdvertisesOnlyWhatItAccepts(t *testing.T) {
	base := &RequestObject{
		ClientID:     "x509_san_dns:issuer.example",
		ResponseMode: ResponseModeDirectPostJWT,
		ResponseURI:  "https://issuer.example/verification/direct_post",
		ClientMetadata: &ClientMetadata{
			EncryptedResponseEncValuesSupported: []string{"A256GCM", "A128GCM"},
			AuthorizationEncryptedResponseENC:   "A256GCM",
		},
	}

	variant := base.WithInteractiveAuthorization(ResponseModeIAPostJWT, "https://issuer.example")
	require.NotNil(t, variant)
	require.NotNil(t, variant.ClientMetadata)

	assert.Equal(t, InteractiveAuthorizationEncValues, variant.ClientMetadata.EncryptedResponseEncValuesSupported)
	assert.NotContains(t, variant.ClientMetadata.EncryptedResponseEncValuesSupported, "A128GCM")

	// The base request is untouched: the browser flow still offers both,
	// and the copy is shallow, so narrowing in place would have changed
	// the channel this was derived from.
	assert.Equal(t, []string{"A256GCM", "A128GCM"}, base.ClientMetadata.EncryptedResponseEncValuesSupported)
	assert.NotSame(t, base.ClientMetadata, variant.ClientMetadata)

	// And the returned slice is a copy, so a caller cannot edit the
	// package-level list through it.
	variant.ClientMetadata.EncryptedResponseEncValuesSupported[0] = "A128GCM"
	assert.Equal(t, []string{"A256GCM"}, InteractiveAuthorizationEncValues)
}

// The Authorization Challenge Endpoint verifies holder binding, so its
// request has to say so. The query it is built from is shared with the
// browser channel, which sets require_cryptographic_holder_binding to
// false - so without this the request invites the wallet to select an
// unbound credential and the endpoint then refuses it, after the user has
// consented and answered.
//
// Both halves are asserted: the flag the wallet reads, and the original
// query's preservation. A variant built by mutating the shared query in
// place would satisfy the first assertion alone while changing what the
// browser channel asks for.
func TestWithInteractiveAuthorizationRequiresHolderBinding(t *testing.T) {
	shared := &DCQL{Credentials: []CredentialQuery{
		{ID: "pid", Format: "dc+sd-jwt", RequireCryptographicHolderBinding: new(false)},
		{ID: "eduid", Format: "dc+sd-jwt"}, // omitted: §6.1 default is true
	}}
	base := &RequestObject{
		ResponseURI:  "https://issuer.example.com/verification/direct_post",
		ClientID:     "x509_san_dns:issuer.example.com",
		ResponseType: "vp_token",
		ResponseMode: ResponseModeDirectPostJWT,
		Nonce:        "nonce-1",
		DCQLQuery:    shared,
	}

	variant := base.WithInteractiveAuthorization(ResponseModeIAPostJWT, "https://issuer.example.com")
	require.NotNil(t, variant)
	require.NotNil(t, variant.DCQLQuery)
	require.Len(t, variant.DCQLQuery.Credentials, 2)

	for _, cred := range variant.DCQLQuery.Credentials {
		require.NotNil(t, cred.RequireCryptographicHolderBinding,
			"query %q must state the requirement rather than rely on a default that may move", cred.ID)
		assert.True(t, *cred.RequireCryptographicHolderBinding,
			"query %q: this endpoint rejects an unbound credential, so the request must not permit one", cred.ID)
		assert.True(t, cred.RequiresCryptographicHolderBinding(), "query %q", cred.ID)
	}

	// The browser channel's query is untouched - including the explicit
	// false, which is that channel's own behaviour and not this one's to
	// change.
	require.Len(t, shared.Credentials, 2)
	require.NotNil(t, shared.Credentials[0].RequireCryptographicHolderBinding)
	assert.False(t, *shared.Credentials[0].RequireCryptographicHolderBinding,
		"the browser channel's request must not be mutated by building the IA one")
	assert.Nil(t, shared.Credentials[1].RequireCryptographicHolderBinding,
		"an omitted flag must stay omitted on the original")
	assert.NotSame(t, shared, variant.DCQLQuery, "the IA variant needs its own query")

	// And the DC API variant, which answers at the browser's endpoint, is
	// not narrowed: this is the IA channel's requirement, not a global one.
	dcapi := base.WithDCAPIRequest("https://issuer.example.com")
	require.NotNil(t, dcapi.DCQLQuery)
	assert.Same(t, shared, dcapi.DCQLQuery,
		"the DC API channel must keep sharing the query it was built from")
}

// Everything else about the IA request still matches the DC API one, so a
// field added to either path cannot quietly differ between the channels.
//
// The count of exceptions is load-bearing, which is why they are listed
// here rather than normalised away in a loop: this comment is where the
// differences between the two channels are written down, and the
// equivalent comment on WithDCAPIRequest claiming one exception too few
// is what made two bugs mandatory.
//
// Three, all of them this endpoint narrowing the request to what it will
// actually accept: the response mode, one encryption algorithm instead of
// two, and a query that requires cryptographic holder binding.
func TestWithInteractiveAuthorizationDiffersOnlyInModeAndWhatItNarrows(t *testing.T) {
	base := &RequestObject{
		ResponseURI:  "https://issuer.example.com/verification/direct_post",
		ClientID:     "x509_san_dns:issuer.example.com",
		ResponseType: "vp_token",
		ResponseMode: ResponseModeDirectPostJWT,
		State:        "state-1",
		Nonce:        "nonce-1",
		DCQLQuery:    &DCQL{Credentials: []CredentialQuery{{ID: "pid", Format: "dc+sd-jwt"}}},
		ClientMetadata: &ClientMetadata{
			EncryptedResponseEncValuesSupported: []string{"A256GCM", "A128GCM"},
		},
	}

	origin := "https://issuer.example.com"
	dcapi := base.WithDCAPIRequest(origin)
	ia := base.WithInteractiveAuthorization(ResponseModeIAPostJWT, origin)
	require.NotNil(t, dcapi)
	require.NotNil(t, ia)

	assert.Equal(t, ResponseModeIAPostJWT, ia.ResponseMode)
	assert.Equal(t, ResponseModeDCAPIJWT, dcapi.ResponseMode)

	// Each exception is asserted before being normalised, so a change that
	// stopped making one would fail here rather than pass by being
	// normalised out of the comparison below.
	assert.Equal(t, InteractiveAuthorizationEncValues, ia.ClientMetadata.EncryptedResponseEncValuesSupported)
	assert.Equal(t, []string{"A256GCM", "A128GCM"}, dcapi.ClientMetadata.EncryptedResponseEncValuesSupported)
	require.NotEmpty(t, ia.DCQLQuery.Credentials)
	assert.True(t, ia.DCQLQuery.Credentials[0].RequiresCryptographicHolderBinding())

	normalised := *ia
	normalised.ResponseMode = dcapi.ResponseMode
	normalised.DCQLQuery = dcapi.DCQLQuery
	normalised.ClientMetadata = dcapi.ClientMetadata
	assert.True(t, reflect.DeepEqual(*dcapi, normalised),
		"the IA request must differ from the DC API one only in the response mode and the two narrowings")
}

func TestWithInteractiveAuthorizationNilIsNil(t *testing.T) {
	assert.Nil(t, (*RequestObject)(nil).WithInteractiveAuthorization(ResponseModeIAPostJWT, "https://issuer.example.com"))
}

// A request carrying no query at all must not acquire one.
func TestWithInteractiveAuthorizationWithoutAQuery(t *testing.T) {
	base := &RequestObject{ResponseMode: ResponseModeDirectPostJWT, Nonce: "n"}
	variant := base.WithInteractiveAuthorization(ResponseModeIAPostJWT, "https://issuer.example.com")
	require.NotNil(t, variant)
	assert.Nil(t, variant.DCQLQuery)
}
