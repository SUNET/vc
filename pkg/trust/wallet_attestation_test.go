package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateAttestationPoP_Valid(t *testing.T) {
	// Generate instance key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create a mock WIA with cnf.jwk
	wia := createTestWIA(t, key)

	// Create a valid PoP
	pop := createTestPoP(t, key, "test-client", "https://as.example.com")

	// Validate
	err = validateAttestationPoP(wia, pop, "https://as.example.com")
	assert.NoError(t, err)
}

func TestValidateAttestationPoP_WrongKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	wia := createTestWIA(t, key)
	pop := createTestPoP(t, wrongKey, "test-client", "https://as.example.com")

	err := validateAttestationPoP(wia, pop, "https://as.example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification")
}

func TestValidateAttestationPoP_WrongAudience(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	wia := createTestWIA(t, key)
	pop := createTestPoP(t, key, "test-client", "https://other-as.example.com")

	err := validateAttestationPoP(wia, pop, "https://as.example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "aud")
}

func TestValidateAttestationPoP_MissingIat(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	wia := createTestWIA(t, key)

	// Create PoP without iat
	claims := jwt.RegisteredClaims{
		Issuer:    "test-client",
		Audience:  jwt.ClaimStrings{"https://as.example.com"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		ID:        uuid.New().String(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "oauth-client-attestation-pop+jwt"
	pop, _ := tok.SignedString(key)

	err := validateAttestationPoP(wia, pop, "https://as.example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "iat")
}

func TestValidateAttestationPoP_WrongTyp(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	wia := createTestWIA(t, key)

	// Create PoP with wrong typ
	claims := jwt.RegisteredClaims{
		Issuer:    "test-client",
		Audience:  jwt.ClaimStrings{"https://as.example.com"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ID:        uuid.New().String(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "dpop+jwt" // wrong!
	pop, _ := tok.SignedString(key)

	err := validateAttestationPoP(wia, pop, "https://as.example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "typ")
}

func TestExtractCNFKeyFromWIA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wia := createTestWIA(t, key)

	extracted, err := extractCNFKeyFromWIA(wia)
	require.NoError(t, err)

	// Verify it's the same key
	assert.Equal(t, key.PublicKey.X, extracted.X)
	assert.Equal(t, key.PublicKey.Y, extracted.Y)
}

func TestExtractCNFKeyFromWIA_MissingCNF(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// WIA without cnf
	claims := jwt.MapClaims{
		"iss": "https://wallet-provider.example.com",
		"sub": "thumbprint123",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	wia, _ := tok.SignedString(key)

	_, err := extractCNFKeyFromWIA(wia)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cnf")
}

// createTestWIA creates a test WIA JWT with cnf.jwk bound to the given key.
func createTestWIA(t *testing.T, instanceKey *ecdsa.PrivateKey) string {
	t.Helper()

	// Create a "wallet provider" signing key (different from instance key)
	wpKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ecdhKey, _ := instanceKey.PublicKey.ECDH()
	raw := ecdhKey.Bytes()

	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(raw[1:33]),
		"y":   base64.RawURLEncoding.EncodeToString(raw[33:65]),
	}

	// Compute JKT
	canonical := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`,
		jwk["crv"], jwk["kty"], jwk["x"], jwk["y"])
	hash := sha256.Sum256([]byte(canonical))
	jkt := base64.RawURLEncoding.EncodeToString(hash[:])

	claims := jwt.MapClaims{
		"iss": "https://wallet-provider.example.com",
		"sub": jkt,
		"cnf": map[string]interface{}{
			"jwk": jwk,
			"jkt": jkt,
		},
		"iat":                jkt, // intentionally wrong type for brevity — doesn't affect test
		"exp":                time.Now().Add(24 * time.Hour).Unix(),
		"attestation_source": "backend_attested",
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "oauth-client-attestation+jwt"
	wia, err := tok.SignedString(wpKey)
	require.NoError(t, err)
	return wia
}

// createTestPoP creates a test PoP JWT signed by the instance key.
func createTestPoP(t *testing.T, key *ecdsa.PrivateKey, clientID, audience string) string {
	t.Helper()

	claims := jwt.RegisteredClaims{
		Issuer:    clientID,
		Audience:  jwt.ClaimStrings{audience},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ID:        uuid.New().String(),
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "oauth-client-attestation-pop+jwt"
	pop, err := tok.SignedString(key)
	require.NoError(t, err)
	return pop
}
