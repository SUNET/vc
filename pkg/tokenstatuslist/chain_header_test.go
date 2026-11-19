package tokenstatuslist

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The chain fixtures are not parsed by the generators - the JOSE header carries
// the certificates base64-encoded and the COSE header carries them as opaque
// byte strings - so distinguishable stand-ins are enough to prove which bytes
// land where, and in what order.
var (
	testLeafB64   = "TEFGLUNFUlQ="
	testIssuerB64 = "SVNTVUVSLUNFUlQ="
	testLeafDER   = []byte("LEAF-CERT")
	testIssuerDER = []byte("ISSUER-CERT")
)

func statusListForChainTest(subject string) *StatusList {
	return &StatusList{
		statuses: []uint8{0, 1},
		Issuer:   "https://example.com",
		Subject:  subject,
	}
}

// decodeCOSEProtectedHeader returns the protected header map of a COSE_Sign1.
// The header is read back from the signed bytes rather than from the config, so
// a chain that never reached the protected header fails the assertion.
func decodeCOSEProtectedHeader(t *testing.T, cwtBytes []byte) map[any]any {
	t.Helper()

	var coseSign1 cbor.Tag
	require.NoError(t, cbor.Unmarshal(cwtBytes, &coseSign1))

	components, ok := coseSign1.Content.([]any)
	require.True(t, ok)
	require.Len(t, components, 4)

	protectedBytes, ok := components[0].([]byte)
	require.True(t, ok)

	var protected map[any]any
	require.NoError(t, cbor.Unmarshal(protectedBytes, &protected))
	return protected
}

func coseHeaderValue(t *testing.T, protected map[any]any, label int) (any, bool) {
	t.Helper()
	for k, v := range protected {
		if n, ok := k.(uint64); ok && n == uint64(label) {
			return v, true
		}
		if n, ok := k.(int64); ok && n == int64(label) {
			return v, true
		}
	}
	return nil, false
}

func TestJWTCarriesTheConfiguredChain(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tokenString, err := statusListForChainTest("https://example.com/statuslists/1").GenerateJWT(JWTSigningConfig{
		SigningKey:    privateKey,
		SigningMethod: jwt.SigningMethodES256,
		PublicKey:     &privateKey.PublicKey,
		X5C:           []string{testLeafB64, testIssuerB64},
	})
	require.NoError(t, err)

	token, err := jwt.Parse(tokenString, func(*jwt.Token) (any, error) { return &privateKey.PublicKey, nil })
	require.NoError(t, err)

	raw, ok := token.Header["x5c"]
	require.True(t, ok, "x5c header must be present when a chain is configured")

	entries, ok := raw.([]any)
	require.True(t, ok, "x5c must be a JSON array (RFC 7515 4.1.6)")
	require.Equal(t, []any{testLeafB64, testIssuerB64}, entries, "leaf first, in configured order")

	// Both carriers describe the same key, and a token may carry both - that
	// is the shape a verifier with either policy can consume.
	_, ok = token.Header["jwk"]
	assert.True(t, ok, "configuring a chain must not displace the embedded jwk")
}

func TestJWTOmitsX5CWhenNoChainIsConfigured(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tokenString, err := statusListForChainTest("https://example.com/statuslists/2").GenerateJWT(JWTSigningConfig{
		SigningKey:    privateKey,
		SigningMethod: jwt.SigningMethodES256,
		PublicKey:     &privateKey.PublicKey,
	})
	require.NoError(t, err)

	token, err := jwt.Parse(tokenString, func(*jwt.Token) (any, error) { return &privateKey.PublicKey, nil })
	require.NoError(t, err)

	_, ok := token.Header["x5c"]
	assert.False(t, ok, "an empty chain must leave the header member out, not emit an empty array")
}

func TestCWTCarriesTheChainInTheProtectedHeader(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t.Run("several certificates are an array of byte strings", func(t *testing.T) {
		cwtBytes, err := statusListForChainTest("https://example.com/statuslists/3").GenerateCWT(CWTSigningConfig{
			SigningKey: privateKey,
			X5Chain:    [][]byte{testLeafDER, testIssuerDER},
		})
		require.NoError(t, err)

		value, ok := coseHeaderValue(t, decodeCOSEProtectedHeader(t, cwtBytes), coseHeaderX5Chain)
		require.True(t, ok, "x5chain must be in the protected header, where the signature covers it")

		entries, ok := value.([]any)
		require.True(t, ok, "RFC 9360: several certificates are an array")
		require.Equal(t, []any{testLeafDER, testIssuerDER}, entries)
	})

	t.Run("a single certificate is a bare byte string", func(t *testing.T) {
		cwtBytes, err := statusListForChainTest("https://example.com/statuslists/4").GenerateCWT(CWTSigningConfig{
			SigningKey: privateKey,
			X5Chain:    [][]byte{testLeafDER},
		})
		require.NoError(t, err)

		value, ok := coseHeaderValue(t, decodeCOSEProtectedHeader(t, cwtBytes), coseHeaderX5Chain)
		require.True(t, ok)
		assert.Equal(t, testLeafDER, value, "RFC 9360: one certificate is a byte string, not a one-element array")
	})

	t.Run("no chain leaves the header out", func(t *testing.T) {
		cwtBytes, err := statusListForChainTest("https://example.com/statuslists/5").GenerateCWT(CWTSigningConfig{
			SigningKey: privateKey,
		})
		require.NoError(t, err)

		_, ok := coseHeaderValue(t, decodeCOSEProtectedHeader(t, cwtBytes), coseHeaderX5Chain)
		assert.False(t, ok)
	})

	t.Run("the token still verifies and parses", func(t *testing.T) {
		cwtBytes, err := statusListForChainTest("https://example.com/statuslists/6").GenerateCWT(CWTSigningConfig{
			SigningKey: privateKey,
			X5Chain:    [][]byte{testLeafDER, testIssuerDER},
		})
		require.NoError(t, err)

		claims, err := ParseCWT(cwtBytes)
		require.NoError(t, err, "a chain in the protected header must not break decoding")
		assert.Equal(t, "https://example.com/statuslists/6", claims[cwtClaimSub])
	})
}
