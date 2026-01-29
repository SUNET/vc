package apiv1

import (
	"testing"
	"vc/pkg/logger"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
)

// Sometimes this test does not behave deterministically
func TestCreateJWK(t *testing.T) {
	tts := []struct {
		name    string
		keyType string // "ecdsa" or "rsa"
		want    jwt.MapClaims
	}{
		{
			name:    "ECDSA key",
			keyType: "ecdsa",
			want: jwt.MapClaims{
				"jwk": jwt.MapClaims{
					"crv": "P-256",
					"kid": "default_signing_key_id",
					"kty": "EC",
					// Note: "d" (private key) is intentionally excluded for security
					"x": "kVao_jC0orUqlfq6lIEMgxE7mkTKQvrx28Gs7c50jeo",
					"y": "47JXwoQzMH8_0rC72HAZPWWqsSHZPHniugPjuE03BEM",
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			keyType := tt.keyType
			if keyType == "" {
				keyType = "ecdsa" // default for backward compatibility
			}
			client := mockNewClient(ctx, t, keyType, logger.NewSimple("testing_apiv1"))

			err := client.createJWK(ctx)
			assert.NoError(t, err)

			if diff := cmp.Diff(tt.want, client.jwkClaim); diff != "" {
				t.Errorf("diff: mismatch (-want +got):\n%s", diff)
			}
		})
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
	assert.Equal(t, "default_signing_key_id", jwk["kid"])
	assert.NotEmpty(t, jwk["n"], "RSA modulus (n) should be present")
	assert.NotEmpty(t, jwk["e"], "RSA exponent (e) should be present")

	// Ensure private key components are NOT included
	assert.NotContains(t, jwk, "d", "private key component should not be included")
	assert.NotContains(t, jwk, "p", "private key component should not be included")
	assert.NotContains(t, jwk, "q", "private key component should not be included")
}

func TestCreateJWK_KidFromConfig(t *testing.T) {
	ctx := t.Context()
	client := mockNewClient(ctx, t, "ecdsa", logger.NewSimple("testing_apiv1"))

	// Set custom kid in config
	client.cfg.Issuer.JWTAttribute.Kid = "custom-key-id-123"

	err := client.createJWK(ctx)
	assert.NoError(t, err)

	assert.Equal(t, "custom-key-id-123", client.kid)

	jwk, ok := client.jwkClaim["jwk"].(jwt.MapClaims)
	assert.True(t, ok)
	assert.Equal(t, "custom-key-id-123", jwk["kid"])
}
