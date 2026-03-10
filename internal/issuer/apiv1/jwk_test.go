package apiv1

import (
	"testing"
	"vc/pkg/logger"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
)

func TestCreateJWK(t *testing.T) {
	ctx := t.Context()
	client := mockNewClient(ctx, t, "ecdsa", logger.NewSimple("testing_apiv1"))

	err := client.createJWK(ctx)
	assert.NoError(t, err)

	// The JWK kid must match the signer's KeyID (what goes into JWT headers)
	expectedKid := client.signer.KeyID()
	assert.NotEmpty(t, expectedKid)

	want := jwt.MapClaims{
		"jwk": jwt.MapClaims{
			"crv": "P-256",
			"kid": expectedKid,
			"kty": "EC",
			"x":   "kVao_jC0orUqlfq6lIEMgxE7mkTKQvrx28Gs7c50jeo",
			"y":   "47JXwoQzMH8_0rC72HAZPWWqsSHZPHniugPjuE03BEM",
		},
	}
	if diff := cmp.Diff(want, client.jwkClaim); diff != "" {
		t.Errorf("diff: mismatch (-want +got):\n%s", diff)
	}
}

func TestCreateJWK_RSA(t *testing.T) {
	ctx := t.Context()
	client := mockNewClient(ctx, t, "rsa", logger.NewSimple("testing_apiv1"))

	err := client.createJWK(ctx)
	assert.NoError(t, err)

	// Verify JWK structure for RSA
	jwk, ok := client.jwkClaim["jwk"].(jwt.MapClaims)
	assert.True(t, ok, "jwk should be a MapClaims")

	assert.Equal(t, "RSA", jwk["kty"], "key type should be RSA")
	// kid must match the signer's KeyID
	assert.Equal(t, client.signer.KeyID(), jwk["kid"])
	assert.NotEmpty(t, jwk["n"], "RSA modulus (n) should be present")
	assert.NotEmpty(t, jwk["e"], "RSA exponent (e) should be present")

	// Ensure private key components are NOT included
	assert.NotContains(t, jwk, "d", "private key component should not be included")
	assert.NotContains(t, jwk, "p", "private key component should not be included")
	assert.NotContains(t, jwk, "q", "private key component should not be included")
}

func TestCreateJWK_KidMatchesSigner(t *testing.T) {
	ctx := t.Context()
	client := mockNewClient(ctx, t, "ecdsa", logger.NewSimple("testing_apiv1"))

	// Even when config has a different kid, the JWK uses the signer's kid
	// to ensure JWT headers and JWKS endpoint are consistent.
	client.cfg.Issuer.JWTAttribute.Kid = "config-value-ignored"

	err := client.createJWK(ctx)
	assert.NoError(t, err)

	// The JWK kid must match signer.KeyID(), not the config value
	expectedKid := client.signer.KeyID()
	assert.Equal(t, expectedKid, client.kid)

	jwk, ok := client.jwkClaim["jwk"].(jwt.MapClaims)
	assert.True(t, ok)
	assert.Equal(t, expectedKid, jwk["kid"])
}
