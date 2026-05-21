package apiv1

import (
	"testing"
	"github.com/SUNET/vc/pkg/logger"

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

	// Verify proto is populated correctly (public key only)
	assert.Equal(t, expectedKid, client.jwkProto.Kid)
	assert.Equal(t, "EC", client.jwkProto.Kty)
	assert.Equal(t, "P-256", client.jwkProto.Crv)
	assert.NotEmpty(t, client.jwkProto.X)
	assert.NotEmpty(t, client.jwkProto.Y)

	// Private key component must NOT be present (public-key-only JWK)
	assert.Empty(t, client.jwkProto.D, "private key component 'd' must not be present")
}

func TestCreateJWK_RSA(t *testing.T) {
	ctx := t.Context()
	client := mockNewClient(ctx, t, "rsa", logger.NewSimple("testing_apiv1"))

	err := client.createJWK(ctx)
	assert.NoError(t, err)

	// kid must match the signer's KeyID
	assert.Equal(t, client.signer.KeyID(), client.jwkProto.Kid)
	assert.Equal(t, "RSA", client.jwkProto.Kty)

	// RSA public key components must be present
	assert.NotEmpty(t, client.jwkProto.N, "RSA modulus 'n' must be present")
	assert.NotEmpty(t, client.jwkProto.E, "RSA exponent 'e' must be present")

	// Private key component must NOT be present
	assert.Empty(t, client.jwkProto.D, "private key component 'd' must not be present")
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
	assert.Equal(t, expectedKid, client.jwkProto.Kid)
}
