package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWRPRCClaims_StatusReference covers the revocation reference surviving
// extraction. go-trust's parser surfaces it, and it was previously dropped
// on the way into WRPRCClaims - so the one field a revocation check needs
// never reached the caller.
func TestWRPRCClaims_StatusReference(t *testing.T) {
	claims := &WRPRCClaims{StatusListURI: "https://registrar.example/status", StatusListIndex: 9940}

	uri, index, ok := claims.StatusReference()
	require.True(t, ok)
	assert.Equal(t, "https://registrar.example/status", uri)
	assert.Equal(t, 9940, index)

	t.Run("index zero is a real index", func(t *testing.T) {
		_, index, ok := (&WRPRCClaims{StatusListURI: "https://r.example/s"}).StatusReference()
		require.True(t, ok, "index 0 is the first slot, not a missing reference")
		assert.Equal(t, 0, index)
	})

	t.Run("absent", func(t *testing.T) {
		_, _, ok := (&WRPRCClaims{}).StatusReference()
		assert.False(t, ok, "no URI means the certificate is not revocable")
	})

	t.Run("nil", func(t *testing.T) {
		var nilClaims *WRPRCClaims
		_, _, ok := nilClaims.StatusReference()
		assert.False(t, ok)
	})
}

// TestGermanSandboxStatusReference proves it end to end against the real
// Registrar-issued fixture, which carries idx 9940.
func TestGermanSandboxStatusReference(t *testing.T) {
	v := &Verifier{RegistrationCertificate: &RegistrationCertificate{
		FilePath: "testdata/german-sandbox-wrprc.jwt",
	}}

	loaded, err := v.LoadRegistrationCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, loaded.Claims)

	uri, index, ok := loaded.Claims.StatusReference()
	require.True(t, ok, "the sandbox certificate carries a live status reference")
	assert.Equal(t, "https://sandbox.eudi-wallet.org/api/status-management/status-list", uri)
	assert.Equal(t, 9940, index)
}
