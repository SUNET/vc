package tokenstatuslistissuer

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// chainFixture is a two-certificate chain in the shape pki.KeyMaterial holds
// one: base64 (standard alphabet) DER, leaf first. The bytes are not a real
// certificate; resolveKeyCarriers transcodes the chain rather than parsing it.
func chainFixture() (encoded []string, der [][]byte) {
	der = [][]byte{{0x30, 0x82, 0x01, 0x0a}, {0x30, 0x82, 0x02, 0x0b}}
	for _, d := range der {
		encoded = append(encoded, base64.StdEncoding.EncodeToString(d))
	}
	return encoded, der
}

func TestUnsetCarriersMeanEverythingAvailable(t *testing.T) {
	encoded, der := chainFixture()

	withChain, err := resolveKeyCarriers(nil, encoded)
	require.NoError(t, err)
	assert.Equal(t, encoded, withChain.x5cBase64, "an unset list carries the chain when one is loaded")
	assert.Equal(t, der, withChain.x5chainDER, "the COSE chain is the same certificates as raw DER")
	assert.True(t, withChain.embedJWK, "an unset list still embeds the jwk")

	// The pre-existing behaviour of every chainless deployment, which the
	// default must not change: an embedded jwk and no x5c.
	chainless, err := resolveKeyCarriers(nil, nil)
	require.NoError(t, err)
	assert.Empty(t, chainless.x5cBase64, "no chain configured means no x5c to carry")
	assert.Empty(t, chainless.x5chainDER)
	assert.True(t, chainless.embedJWK)
}

func TestCarriersNarrowToWhatWasConfigured(t *testing.T) {
	encoded, _ := chainFixture()

	jwkOnly, err := resolveKeyCarriers([]string{"jwk"}, encoded)
	require.NoError(t, err)
	assert.True(t, jwkOnly.embedJWK)
	assert.Empty(t, jwkOnly.x5cBase64, "a chain is loaded but not asked for, so it must not ride")
	assert.Empty(t, jwkOnly.x5chainDER)

	x5cOnly, err := resolveKeyCarriers([]string{"x5c"}, encoded)
	require.NoError(t, err)
	assert.False(t, x5cOnly.embedJWK, "jwk was not asked for")
	assert.Equal(t, encoded, x5cOnly.x5cBase64)
}

func TestX5COnlyWithoutAChainIsRefused(t *testing.T) {
	_, err := resolveKeyCarriers([]string{"x5c"}, nil)
	require.Error(t, err, "issuing tokens that carry no key at all must not be reachable by configuration")
	assert.Contains(t, err.Error(), "no signing chain is loaded")
}

func TestUnknownCarrierIsRefused(t *testing.T) {
	encoded, _ := chainFixture()
	_, err := resolveKeyCarriers([]string{"jwk", "kid"}, encoded)
	require.Error(t, err, "an unknown carrier is a typo, and silently ignoring it issues the wrong token")
	assert.Contains(t, err.Error(), `unknown token key carrier "kid"`)
}

func TestMalformedChainIsRefused(t *testing.T) {
	_, err := resolveKeyCarriers(nil, []string{"not-base64!!"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not valid base64 DER")
}

func TestResolvedChainDoesNotAliasTheKeyMaterial(t *testing.T) {
	encoded, _ := chainFixture()
	original := encoded[0]

	carriers, err := resolveKeyCarriers(nil, encoded)
	require.NoError(t, err)

	carriers.x5cBase64[0] = "tampered"
	assert.Equal(t, original, encoded[0], "the resolved chain must not write back into the loaded key material")
}
