package tokenstatuslistissuer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signingChain mints a key and a two-certificate chain for it, in the shape
// pki.KeyMaterial holds one: the parsed leaf in Cert, and base64 (standard
// alphabet) DER in Chain, leaf first.
func signingChain(t *testing.T) (key *ecdsa.PrivateKey, leaf *x509.Certificate, encoded []string, der [][]byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafDER := selfSigned(t, key, "status list signer")
	issuerDER := selfSigned(t, key, "status list issuing CA")

	leaf, err = x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	der = [][]byte{leafDER, issuerDER}
	for _, d := range der {
		encoded = append(encoded, base64.StdEncoding.EncodeToString(d))
	}
	return key, leaf, encoded, der
}

func selfSigned(t *testing.T, key *ecdsa.PrivateKey, cn string) []byte {
	t.Helper()

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return der
}

func TestUnsetCarriersMeanEverythingAvailable(t *testing.T) {
	key, leaf, encoded, der := signingChain(t)

	withChain, err := resolveKeyCarriers(nil, encoded, leaf, &key.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, encoded, withChain.x5cBase64, "an unset list carries the chain when one is loaded")
	assert.Equal(t, der, withChain.x5chainDER, "the COSE chain is the same certificates as raw DER")
	assert.True(t, withChain.embedJWK, "an unset list still embeds the jwk")

	// The pre-existing behaviour of every chainless deployment, which the
	// default must not change: an embedded jwk and no x5c.
	chainless, err := resolveKeyCarriers(nil, nil, nil, &key.PublicKey)
	require.NoError(t, err)
	assert.Empty(t, chainless.x5cBase64, "no chain configured means no x5c to carry")
	assert.Empty(t, chainless.x5chainDER)
	assert.True(t, chainless.embedJWK)
}

func TestCarriersNarrowToWhatWasConfigured(t *testing.T) {
	key, leaf, encoded, _ := signingChain(t)

	jwkOnly, err := resolveKeyCarriers([]string{"jwk"}, encoded, leaf, &key.PublicKey)
	require.NoError(t, err)
	assert.True(t, jwkOnly.embedJWK)
	assert.Empty(t, jwkOnly.x5cBase64, "a chain is loaded but not asked for, so it must not ride")
	assert.Empty(t, jwkOnly.x5chainDER)

	x5cOnly, err := resolveKeyCarriers([]string{"x5c"}, encoded, leaf, &key.PublicKey)
	require.NoError(t, err)
	assert.False(t, x5cOnly.embedJWK, "jwk was not asked for")
	assert.Equal(t, encoded, x5cOnly.x5cBase64)
}

func TestX5COnlyWithoutAChainIsRefused(t *testing.T) {
	key, _, _, _ := signingChain(t)

	_, err := resolveKeyCarriers([]string{"x5c"}, nil, nil, &key.PublicKey)
	require.Error(t, err, "issuing tokens that carry no key at all must not be reachable by configuration")
	assert.Contains(t, err.Error(), "no signing chain is loaded")
}

func TestUnknownCarrierIsRefused(t *testing.T) {
	key, leaf, encoded, _ := signingChain(t)

	_, err := resolveKeyCarriers([]string{"jwk", "kid"}, encoded, leaf, &key.PublicKey)
	require.Error(t, err, "an unknown carrier is a typo, and silently ignoring it issues the wrong token")
	assert.Contains(t, err.Error(), `unknown token key carrier "kid"`)
}

func TestMalformedChainIsRefused(t *testing.T) {
	key, leaf, encoded, _ := signingChain(t)

	// A good leaf for this key, then a certificate that is not base64 at all:
	// the leaf check passes and the decode is what has to refuse.
	_, err := resolveKeyCarriers(nil, []string{encoded[0], "not-base64!!"}, leaf, &key.PublicKey)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not valid base64 DER")
}

// A chain and a private key are loaded from separate files and never compared
// (pki.loadKeyMaterialFromFile), so a rotation that replaces one and not the
// other leaves a chain that certifies a key these tokens are NOT signed with.
// Every verifier that resolves the signer from x5c then derives the wrong key
// and rejects every token - the whole point of the carrier, inverted.
func TestChainForADifferentKeyIsRefused(t *testing.T) {
	_, staleLeaf, staleChain, _ := signingChain(t)
	currentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = resolveKeyCarriers(nil, staleChain, staleLeaf, &currentKey.PublicKey)
	require.Error(t, err, "a chain certifying a different key must not reach a token")
	assert.Contains(t, err.Error(), "different key than the configured signing key")

	// Asked for explicitly, it must still refuse rather than fall back to jwk.
	_, err = resolveKeyCarriers([]string{"x5c"}, staleChain, staleLeaf, &currentKey.PublicKey)
	require.Error(t, err)
}

// "Cannot compare" is refusal, not a pass: a chain with no parsed leaf, or a
// signer with no public half, has not been shown to belong to this key.
func TestAnUncheckableChainIsRefused(t *testing.T) {
	key, leaf, encoded, _ := signingChain(t)

	_, err := resolveKeyCarriers(nil, encoded, nil, &key.PublicKey)
	require.Error(t, err, "a chain whose leaf was never parsed cannot be checked, so it must not ride")
	assert.Contains(t, err.Error(), "no parsed leaf certificate")

	_, err = resolveKeyCarriers(nil, encoded, leaf, nil)
	require.Error(t, err, "a signer with no public half cannot be checked against the leaf")
	assert.Contains(t, err.Error(), "no public half")
}

func TestResolvedChainDoesNotAliasTheKeyMaterial(t *testing.T) {
	key, leaf, encoded, _ := signingChain(t)
	original := encoded[0]

	carriers, err := resolveKeyCarriers(nil, encoded, leaf, &key.PublicKey)
	require.NoError(t, err)

	carriers.x5cBase64[0] = "tampered"
	assert.Equal(t, original, encoded[0], "the resolved chain must not write back into the loaded key material")
}
