package openid4vp

import (
	"reflect"
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
