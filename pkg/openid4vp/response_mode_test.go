package openid4vp

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWithDCAPIResponseModeDiffersOnlyInResponseMode is the guarantee that matters
// once a session serves two request objects: they are the same request seen
// through two delivery channels, so anything a wallet checks must agree.
// Only response_mode may differ, because only response_mode depends on how
// the request was delivered (SUNET/vc#652).
func TestWithDCAPIResponseModeDiffersOnlyInResponseMode(t *testing.T) {
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

	variant := base.WithDCAPIResponseMode()
	require.NotNil(t, variant)

	assert.Equal(t, ResponseModeDCAPIJWT, variant.ResponseMode,
		"the DC API channel is the only one a dc_api mode is defined for")
	assert.Equal(t, ResponseModeDirectPostJWT, base.ResponseMode,
		"the link channel's own object must not be mutated")

	// Compare with response_mode normalised: every other field, including any
	// added to RequestObject later, has to be identical.
	normalised := *variant
	normalised.ResponseMode = base.ResponseMode
	assert.True(t, reflect.DeepEqual(*base, normalised),
		"the two channels must differ only in response_mode")

	// The pointer field is shared, not deep-copied - which is what we want:
	// the wallet must see the same client_metadata either way.
	assert.Same(t, base.ClientMetadata, variant.ClientMetadata)
}

func TestWithDCAPIResponseModeNilIsNil(t *testing.T) {
	assert.Nil(t, (*RequestObject)(nil).WithDCAPIResponseMode())
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
	field, ok := reflect.TypeOf(RequestObject{}).FieldByName("ResponseMode")
	require.True(t, ok, "RequestObject has no ResponseMode field - this test must be updated with it")

	var oneof string
	for _, rule := range strings.Split(field.Tag.Get("validate"), ",") {
		if after, found := strings.CutPrefix(rule, "oneof="); found {
			oneof = after
			break
		}
	}
	require.NotEmpty(t, oneof, "ResponseMode's validate tag has no oneof= rule; the accepted set is no longer enforced there")

	assert.ElementsMatch(t,
		[]string{ResponseModeFormPost, ResponseModeDirectPost, ResponseModeDirectPostJWT, ResponseModeDCAPIJWT},
		strings.Fields(oneof),
		"the response-mode constants and the oneof validation tag have drifted; update both",
	)
}
