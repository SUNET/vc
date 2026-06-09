package apiv1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/SUNET/vc/pkg/configuration"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// generateTestRSAKey creates an RSA key pair for testing
func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

// generateTestECDSAKey creates an ECDSA key pair for testing
func generateTestECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// hashPassword creates a bcrypt hash of a password for testing
func hashPassword(t *testing.T, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err)
	return string(hash)
}

// createSimplePresentationTemplate creates a basic presentation template for testing
func createSimplePresentationTemplate(t *testing.T, scopes []string) *configuration.PresentationRequestTemplate {
	t.Helper()
	return &configuration.PresentationRequestTemplate{
		ID:          "test-template",
		Name:        "Test Template",
		Description: "Test presentation template",
		Version:     "1.0",
		OIDCScopes:  scopes,
		DCQLQuery: &openid4vp.DCQL{
			Credentials: []openid4vp.CredentialQuery{
				{
					ID:     "test-credential",
					Format: "vc+sd-jwt",
					Meta: openid4vp.MetaQuery{
						VCTValues: []string{"https://example.com/test"},
					},
					Claims: []openid4vp.ClaimQuery{
						{Path: openid4vp.StringPath("given_name")},
						{Path: openid4vp.StringPath("family_name")},
					},
				},
			},
		},
		ClaimMappings: map[string]string{
			"given_name":  "given_name",
			"family_name": "family_name",
		},
		Enabled: true,
	}
}
