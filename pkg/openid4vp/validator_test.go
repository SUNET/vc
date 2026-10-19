package openid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create a valid SD-JWT-VC token for testing
// testHolderKey is the key the fixtures' credentials name in cnf, so a
// presentation built here can actually be signed by the holder it claims.
//
// It used to be a cnf of {"x":"test","y":"test"} with a literal
// "fake-kb-signature", which validated because holder binding was not
// verified. A fixture that cannot produce a real proof cannot tell a
// correct presentation from a forged one, which is the distinction these
// tests exist to make.
func testHolderKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// testCredentialNaming builds an issuer JWT naming holder in cnf.
//
// The ISSUER signature is still a placeholder: VPTokenValidator does not
// verify it - that is EvaluateIssuerTrust's job, with a resolved key - so
// a real one here would assert nothing these tests are about.
func testCredentialNaming(t *testing.T, holder *ecdsa.PrivateKey, extraClaims map[string]any) string {
	t.Helper()

	header, err := json.Marshal(map[string]any{"alg": "ES256", "typ": "vc+sd-jwt"})
	require.NoError(t, err)

	payload := map[string]any{
		"iss": "https://issuer.example.com",
		"iat": 1234567890,
		"exp": 9999999999,
		"vct": "https://example.com/TestCredential",
		// publicJWK, not a hand-rolled map: RFC 7518 requires P-256
		// coordinates to be exactly 32 bytes, big.Int.Bytes() drops
		// leading zeroes, and a strict parser rejects the short result -
		// so hand-rolling makes this suite fail for roughly one generated
		// key in 128.
		"cnf": map[string]any{"jwk": publicJWK(t, holder.Public())},
	}
	for k, v := range extraClaims {
		payload[k] = v
	}
	payloadJSON, err := json.Marshal(payload)
	require.NoError(t, err)

	return base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJSON) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("issuer-signature-not-checked-here"))
}

// testPresentation appends a Key Binding JWT signed by holder, with the
// sd_hash that covers what is being presented.
func testPresentation(t *testing.T, credential string, holder *ecdsa.PrivateKey, kbClaims map[string]any) string {
	t.Helper()

	sdJWT := credential + "~"
	sum := sha256.Sum256([]byte(sdJWT))

	claims := jwtv5.MapClaims{"sd_hash": base64.RawURLEncoding.EncodeToString(sum[:])}
	for k, v := range kbClaims {
		claims[k] = v
	}

	kb := jwtv5.NewWithClaims(jwtv5.SigningMethodES256, claims)
	kb.Header["typ"] = "kb+jwt"
	signed, err := kb.SignedString(holder)
	require.NoError(t, err)

	return sdJWT + signed
}

func createTestVPToken(t *testing.T, nonce, aud string, includeBinding bool) string {
	t.Helper()

	holder := testHolderKey(t)
	credential := testCredentialNaming(t, holder, nil)
	if !includeBinding {
		return credential + "~"
	}
	return testPresentation(t, credential, holder, map[string]any{
		"nonce": nonce,
		"aud":   aud,
		// The moment of presentation, which is what iat means on a
		// KB-JWT and what the validator now bounds.
		"iat": time.Now().Unix(),
	})
}

func TestVPTokenValidator_Validate_ValidToken(t *testing.T) {
	nonce := "test-nonce-123"
	clientID := "https://verifier.example.com"

	vpToken := createTestVPToken(t, nonce, clientID, true)

	validator := &VPTokenValidator{
		Nonce:           nonce,
		ClientID:        clientID,
		ValidateFormat:  false, // Skip actual signature verification
		CheckRevocation: false,
	}

	err := validator.Validate(vpToken)
	assert.NoError(t, err)
}

func TestVPTokenValidator_Validate_InvalidFormat(t *testing.T) {
	validator := &VPTokenValidator{
		Nonce:    "test-nonce",
		ClientID: "https://verifier.example.com",
	}

	tests := []struct {
		name    string
		vpToken string
	}{
		{
			name:    "empty token",
			vpToken: "",
		},
		{
			name:    "invalid JWT format",
			vpToken: "invalid.token",
		},
		{
			name:    "malformed base64",
			vpToken: "not-base64!.not-base64!.not-base64!",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.Validate(tt.vpToken)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid VP Token format")
		})
	}
}

func TestVPTokenValidator_Validate_MissingHolderBinding(t *testing.T) {
	nonce := "test-nonce-123"
	clientID := "https://verifier.example.com"

	// Create token without key binding
	vpToken := createTestVPToken(t, nonce, clientID, false)

	validator := &VPTokenValidator{
		Nonce:           nonce,
		ClientID:        clientID,
		ValidateFormat:  false,
		CheckRevocation: false,
	}

	err := validator.Validate(vpToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing holder binding proof")
}

func TestVPTokenValidator_Validate_NonceMismatch(t *testing.T) {
	nonce := "test-nonce-123"
	clientID := "https://verifier.example.com"

	// Create token with different nonce
	vpToken := createTestVPToken(t, "wrong-nonce", clientID, true)

	validator := &VPTokenValidator{
		Nonce:           nonce,
		ClientID:        clientID,
		ValidateFormat:  false,
		CheckRevocation: false,
	}

	err := validator.Validate(vpToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nonce mismatch")
}

func TestVPTokenValidator_Validate_AudienceMismatch(t *testing.T) {
	nonce := "test-nonce-123"
	clientID := "https://verifier.example.com"

	// Create token with different audience
	vpToken := createTestVPToken(t, nonce, "https://wrong-verifier.example.com", true)

	validator := &VPTokenValidator{
		Nonce:           nonce,
		ClientID:        clientID,
		ValidateFormat:  false,
		CheckRevocation: false,
	}

	err := validator.Validate(vpToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "audience mismatch")
}

func TestVPTokenValidator_Validate_WithoutNonceValidation(t *testing.T) {
	clientID := "https://verifier.example.com"

	// Create token with any nonce
	vpToken := createTestVPToken(t, "any-nonce", clientID, true)

	validator := &VPTokenValidator{
		Nonce:           "", // Empty nonce means skip nonce validation
		ClientID:        clientID,
		ValidateFormat:  false,
		CheckRevocation: false,
	}

	err := validator.Validate(vpToken)
	assert.NoError(t, err)
}

func TestVPTokenValidator_Validate_WithoutClientIDValidation(t *testing.T) {
	nonce := "test-nonce-123"

	// Create token with any audience
	vpToken := createTestVPToken(t, nonce, "any-audience", true)

	validator := &VPTokenValidator{
		Nonce:           nonce,
		ClientID:        "", // Empty clientID means skip audience validation
		ValidateFormat:  false,
		CheckRevocation: false,
	}

	err := validator.Validate(vpToken)
	assert.NoError(t, err)
}

func TestVPTokenValidator_Validate_WithSignatureVerification(t *testing.T) {
	nonce := "test-nonce-123"
	clientID := "https://verifier.example.com"

	vpToken := createTestVPToken(t, nonce, clientID, true)

	validator := &VPTokenValidator{
		Nonce:           nonce,
		ClientID:        clientID,
		ValidateFormat:  true, // Enable signature verification
		CheckRevocation: false,
	}

	// Should succeed as we're just validating format
	err := validator.Validate(vpToken)
	assert.NoError(t, err)
}

func TestVPTokenValidator_Validate_WithRevocationCheck(t *testing.T) {
	nonce := "test-nonce-123"
	clientID := "https://verifier.example.com"

	vpToken := createTestVPToken(t, nonce, clientID, true)

	validator := &VPTokenValidator{
		Nonce:           nonce,
		ClientID:        clientID,
		ValidateFormat:  false,
		CheckRevocation: true, // Enable revocation check
	}

	// Should succeed as revocation check is placeholder (returns nil)
	err := validator.Validate(vpToken)
	assert.NoError(t, err)
}

func TestVPTokenValidator_Validate_WithDCQLQuery(t *testing.T) {
	nonce := "test-nonce-123"
	clientID := "https://verifier.example.com"

	vpToken := createTestVPToken(t, nonce, clientID, true)

	dcqlQuery := &DCQL{
		Credentials: []CredentialQuery{
			{
				ID:     "credential-1",
				Format: "vc+sd-jwt",
				Meta: MetaQuery{
					VCTValues: []string{"https://example.com/TestCredential"},
				},
			},
		},
	}

	validator := &VPTokenValidator{
		Nonce:           nonce,
		ClientID:        clientID,
		ValidateFormat:  false,
		CheckRevocation: false,
		DCQLQuery:       dcqlQuery,
	}

	// Should succeed as DCQL validation is basic placeholder
	err := validator.Validate(vpToken)
	assert.NoError(t, err)
}

func TestParseKeyBindingJWT_Valid(t *testing.T) {
	// Create a valid KB-JWT
	header := map[string]any{
		"alg": "ES256",
		"typ": "kb+jwt",
	}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	payload := map[string]any{
		"nonce": "test-nonce",
		"aud":   "https://verifier.example.com",
		"iat":   1234567890,
	}
	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signature := base64.RawURLEncoding.EncodeToString([]byte("signature"))
	kbJWT := headerB64 + "." + payloadB64 + "." + signature

	claims, err := parseKeyBindingJWT(kbJWT)
	require.NoError(t, err)
	assert.Equal(t, "test-nonce", claims["nonce"])
	assert.Equal(t, "https://verifier.example.com", claims["aud"])
	assert.Equal(t, float64(1234567890), claims["iat"])
}

func TestParseKeyBindingJWT_InvalidFormat(t *testing.T) {
	tests := []struct {
		name  string
		kbJWT string
	}{
		{
			name:  "missing parts",
			kbJWT: "header.payload",
		},
		{
			name:  "too many parts",
			kbJWT: "header.payload.signature.extra",
		},
		{
			name:  "invalid base64 payload",
			kbJWT: "header.not-base64!.signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseKeyBindingJWT(tt.kbJWT)
			assert.Error(t, err)
		})
	}
}

func TestParseKeyBindingJWT_InvalidJSON(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte("header"))
	payload := base64.RawURLEncoding.EncodeToString([]byte("{invalid json}"))
	signature := base64.RawURLEncoding.EncodeToString([]byte("signature"))
	kbJWT := header + "." + payload + "." + signature

	_, err := parseKeyBindingJWT(kbJWT)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse claims")
}

func TestValidateVPToken_ConvenienceFunction(t *testing.T) {
	t.Run("valid token", func(t *testing.T) {
		nonce := "test-nonce-123"
		clientID := "https://verifier.example.com"
		vpToken := createTestVPToken(t, nonce, clientID, true)

		err := ValidateVPToken(vpToken, nonce, clientID)
		assert.NoError(t, err)
	})

	t.Run("nonce mismatch", func(t *testing.T) {
		nonce := "test-nonce-123"
		clientID := "https://verifier.example.com"
		vpToken := createTestVPToken(t, "wrong-nonce", clientID, true)

		err := ValidateVPToken(vpToken, nonce, clientID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nonce mismatch")
	})

	t.Run("invalid format", func(t *testing.T) {
		err := ValidateVPToken("invalid-token", "nonce", "client-id")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid VP Token format")
	})
}

func TestVPTokenValidator_ValidatePresentation(t *testing.T) {
	t.Run("valid presentation with claims", func(t *testing.T) {
		// Create a test token and parse it
		vpToken := createTestVPToken(t, "nonce", "aud", true)
		parts := strings.Split(vpToken, "~")
		token := parts[0] // Get the issuer-signed JWT part

		// Parse manually to get the structure
		jwtParts := strings.Split(token, ".")
		require.Len(t, jwtParts, 3)

		payloadBytes, err := base64.RawURLEncoding.DecodeString(jwtParts[1])
		require.NoError(t, err)

		var claims map[string]any
		err = json.Unmarshal(payloadBytes, &claims)
		require.NoError(t, err)

		// Verify claims are present (this validates the test helper)
		assert.NotNil(t, claims)
		assert.Contains(t, claims, "iss")
		assert.Contains(t, claims, "vct")
	})
}

func TestVPTokenValidator_ValidateHolderBinding_MissingProof(t *testing.T) {
	validator := &VPTokenValidator{}

	// Create token without key binding
	vpToken := createTestVPToken(t, "nonce", "aud", false)

	err := validator.Validate(vpToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing holder binding proof")
}

func TestVPTokenValidator_ValidateNonce_MissingKeyBinding(t *testing.T) {
	nonce := "test-nonce"
	vpToken := createTestVPToken(t, nonce, "aud", false)

	validator := &VPTokenValidator{
		Nonce: nonce,
	}

	err := validator.Validate(vpToken)
	assert.Error(t, err)
	// Error comes from holder binding validation first
	assert.Contains(t, err.Error(), "holder binding")
}

func TestVPTokenValidator_ValidateAudience_MissingInKeyBinding(t *testing.T) {
	// Otherwise a perfectly good presentation - real holder key, real
	// signature over the right sd_hash - with no aud claim. It has to be
	// valid in every other respect or it fails at holder binding instead
	// and stops testing the audience check it is named for.
	holder := testHolderKey(t)
	vpToken := testPresentation(t, testCredentialNaming(t, holder, nil), holder, map[string]any{
		"nonce": "test-nonce",
		"iat":   time.Now().Unix(),
	})

	validator := &VPTokenValidator{
		Nonce:    "test-nonce",
		ClientID: "https://verifier.example.com",
	}

	err := validator.Validate(vpToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "audience not found")
}

func TestVPTokenValidator_EmptyDCQLQuery(t *testing.T) {
	nonce := "test-nonce-123"
	clientID := "https://verifier.example.com"
	vpToken := createTestVPToken(t, nonce, clientID, true)

	// Empty DCQL query should not cause errors
	validator := &VPTokenValidator{
		Nonce:     nonce,
		ClientID:  clientID,
		DCQLQuery: &DCQL{Credentials: []CredentialQuery{}},
	}

	err := validator.Validate(vpToken)
	assert.NoError(t, err)
}

// createTestVPTokenWithTxHashes creates a test VP token whose KB-JWT includes
// transaction_data_hashes and transaction_data_hashes_alg claims.
func createTestVPTokenWithTxHashes(t *testing.T, nonce, aud string, hashes []string, hashAlg string) string {
	t.Helper()

	holder := testHolderKey(t)
	credential := testCredentialNaming(t, holder, nil)

	kbClaims := map[string]any{
		"nonce": nonce,
		"aud":   aud,
		"iat":   time.Now().Unix(),
	}
	if hashes != nil {
		kbClaims["transaction_data_hashes"] = hashes
		kbClaims["transaction_data_hashes_alg"] = hashAlg
	}
	return testPresentation(t, credential, holder, kbClaims)
}

// encodeTxData encodes TransactionData structs into raw base64url strings for tests.
func encodeTxData(t *testing.T, txData []TransactionData) []string {
	t.Helper()
	raw := make([]string, 0, len(txData))
	for i := range txData {
		encoded, err := txData[i].Base64Encode()
		require.NoErrorf(t, err, "encoding transaction_data[%d]", i)
		raw = append(raw, encoded)
	}
	return raw
}

func TestVPTokenValidator_TransactionData_Valid(t *testing.T) {
	nonce := "test-nonce-123"
	clientID := "https://verifier.example.com"

	raw := encodeTxData(t, []TransactionData{
		{Type: "payment", CredentialIDS: []string{"eudi_pid"}},
	})
	hashes, err := HashTransactionData(raw, "sha-256")
	require.NoError(t, err)

	vpToken := createTestVPTokenWithTxHashes(t, nonce, clientID, hashes, "sha-256")

	validator := &VPTokenValidator{
		Nonce:           nonce,
		ClientID:        clientID,
		TransactionData: raw,
	}

	err = validator.Validate(vpToken)
	assert.NoError(t, err)
}

func TestVPTokenValidator_TransactionData_Missing(t *testing.T) {
	nonce := "test-nonce-123"
	clientID := "https://verifier.example.com"

	raw := encodeTxData(t, []TransactionData{
		{Type: "payment", CredentialIDS: []string{"eudi_pid"}},
	})

	// KB-JWT has no transaction_data_hashes
	vpToken := createTestVPToken(t, nonce, clientID, true)

	validator := &VPTokenValidator{
		Nonce:           nonce,
		ClientID:        clientID,
		TransactionData: raw,
	}

	err := validator.Validate(vpToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "transaction_data_hashes")
}

func TestVPTokenValidator_TransactionData_Mismatch(t *testing.T) {
	nonce := "test-nonce-123"
	clientID := "https://verifier.example.com"

	raw := encodeTxData(t, []TransactionData{
		{Type: "payment", CredentialIDS: []string{"eudi_pid"}},
	})

	// Create a VP with wrong hashes (hashed from different transaction data)
	wrongRaw := encodeTxData(t, []TransactionData{
		{Type: "document_signing", CredentialIDS: []string{"eudi_pid"}},
	})
	wrongHashes, err := HashTransactionData(wrongRaw, "sha-256")
	require.NoError(t, err)

	vpToken := createTestVPTokenWithTxHashes(t, nonce, clientID, wrongHashes, "sha-256")

	validator := &VPTokenValidator{
		Nonce:           nonce,
		ClientID:        clientID,
		TransactionData: raw,
	}

	err = validator.Validate(vpToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mismatch")
}

func TestVPTokenValidator_TransactionData_CountMismatch(t *testing.T) {
	nonce := "test-nonce-123"
	clientID := "https://verifier.example.com"

	raw := encodeTxData(t, []TransactionData{
		{Type: "payment", CredentialIDS: []string{"eudi_pid"}},
		{Type: "sca", CredentialIDS: []string{"eudi_pid"}},
	})
	// Only hash the first one — count mismatch
	hashes, err := HashTransactionData(raw[:1], "sha-256")
	require.NoError(t, err)

	vpToken := createTestVPTokenWithTxHashes(t, nonce, clientID, hashes, "sha-256")

	validator := &VPTokenValidator{
		Nonce:           nonce,
		ClientID:        clientID,
		TransactionData: raw,
	}

	err = validator.Validate(vpToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "count mismatch")
}

func TestVPTokenValidator_TransactionData_NoTxDataSkipsValidation(t *testing.T) {
	nonce := "test-nonce-123"
	clientID := "https://verifier.example.com"

	// No transaction data in request — validation should pass even without hashes in KB-JWT
	vpToken := createTestVPToken(t, nonce, clientID, true)

	validator := &VPTokenValidator{
		Nonce:    nonce,
		ClientID: clientID,
	}

	err := validator.Validate(vpToken)
	assert.NoError(t, err)
}

func TestVPTokenValidator_TransactionData_MultipleEntries(t *testing.T) {
	nonce := "test-nonce-123"
	clientID := "https://verifier.example.com"

	raw := encodeTxData(t, []TransactionData{
		{Type: "payment", CredentialIDS: []string{"eudi_pid"}},
		{Type: "document_signing", CredentialIDS: []string{"eudi_pid", "diploma"}},
	})
	hashes, err := HashTransactionData(raw, "sha-256")
	require.NoError(t, err)
	require.Len(t, hashes, 2)

	vpToken := createTestVPTokenWithTxHashes(t, nonce, clientID, hashes, "sha-256")

	validator := &VPTokenValidator{
		Nonce:           nonce,
		ClientID:        clientID,
		TransactionData: raw,
	}

	err = validator.Validate(vpToken)
	assert.NoError(t, err)
}
