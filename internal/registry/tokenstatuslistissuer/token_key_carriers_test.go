package tokenstatuslistissuer

import (
	"crypto/ecdsa"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/pki"
)

// carrierTestService builds the part of the issuer the token generators
// actually read - the signer and the resolved carriers - without a database or
// a cache, so the wiring from configuration to issued token can be asserted on
// its own.
func carrierTestService(t *testing.T, configured []string, withChain bool) (*Service, *ecdsa.PrivateKey, []string) {
	t.Helper()

	key, leaf, encoded, _ := signingChain(t)

	var chain []string
	if withChain {
		chain = encoded
	} else {
		leaf = nil
	}

	carriers, err := resolveKeyCarriers(configured, chain, leaf, &key.PublicKey)
	require.NoError(t, err)

	return &Service{
		signer: pki.NewKeyMaterialSigner(&pki.KeyMaterial{
			PrivateKey:    key,
			Cert:          leaf,
			Chain:         chain,
			SigningMethod: jwt.SigningMethodES256,
		}),
		carriers: carriers,
		log:      logger.NewSimple("test"),
	}, key, encoded
}

func carrierTestTokenConfig() TokenConfig {
	cfg := TokenConfig{SigningMethod: jwt.SigningMethodES256,
		Issuer:   "https://registry.example.com",
		Subject:  "https://registry.example.com/statuslists/0",
		Statuses: []uint8{0, 1, 0}}
	return cfg
}

func tokenHeader(t *testing.T, service *Service, key *ecdsa.PrivateKey) map[string]any {
	t.Helper()

	tokenString, err := service.GenerateStatusListTokenJWT(t.Context(), carrierTestTokenConfig())
	require.NoError(t, err)

	token, err := jwt.Parse(tokenString, func(*jwt.Token) (any, error) { return &key.PublicKey, nil })
	require.NoError(t, err)
	return token.Header
}

func TestIssuedTokenCarriesBothByDefault(t *testing.T) {
	service, key, chain := carrierTestService(t, []string{"x5c", "jwk"}, true)

	header := tokenHeader(t, service, key)

	assert.Equal(t, []any{chain[0], chain[1]}, header["x5c"], "the configured chain must ride the token")
	assert.Contains(t, header, "jwk", "and so must the bare key")
}

func TestIssuedTokenHonoursACarrierNarrowedToTheChain(t *testing.T) {
	service, key, _ := carrierTestService(t, []string{"x5c"}, true)

	header := tokenHeader(t, service, key)

	assert.Contains(t, header, "x5c")
	assert.NotContains(t, header, "jwk", "a deployment that asked for certificates only must not get a bare key too")
}

func TestIssuedTokenHonoursACarrierNarrowedToTheKey(t *testing.T) {
	service, key, _ := carrierTestService(t, []string{"jwk"}, true)

	header := tokenHeader(t, service, key)

	assert.Contains(t, header, "jwk")
	assert.NotContains(t, header, "x5c", "a loaded chain must not ride a token that did not ask for it")
}

// The behaviour every existing chainless deployment has today, which the new
// setting must leave exactly as it was.
func TestIssuedTokenIsUnchangedForAChainlessDeployment(t *testing.T) {
	service, key, _ := carrierTestService(t, nil, false)

	header := tokenHeader(t, service, key)

	assert.Contains(t, header, "jwk")
	assert.NotContains(t, header, "x5c")
	assert.Equal(t, "statuslist+jwt", header["typ"])
}

func TestPublishedKeySetIsTheSigningKey(t *testing.T) {
	service, key, _ := carrierTestService(t, nil, false)

	keySet, err := service.SigningKeySet(t.Context())
	require.NoError(t, err)
	require.Len(t, keySet.Keys, 1)

	// Same key, compared through the JWK the embedded "jwk" header carries:
	// a published set that is not the signer's key binds nothing.
	published := keySet.Keys[0]
	embedded, err := jose.ParseJWK(tokenHeader(t, service, key)["jwk"].(map[string]any))
	require.NoError(t, err)

	assert.Equal(t, "EC", published.Kty)
	assert.Equal(t, embedded.Crv, published.Crv)
	assert.Equal(t, embedded.X, published.X)
	assert.Equal(t, embedded.Y, published.Y)
	assert.Equal(t, "sig", published.Use)
}

func TestPublishedKeySetFailsClosedWithoutASigner(t *testing.T) {
	service := &Service{log: logger.NewSimple("test")}

	keySet, err := service.SigningKeySet(t.Context())
	require.Error(t, err, "publishing an empty key set would say this list has no signer")
	assert.Nil(t, keySet)
}
