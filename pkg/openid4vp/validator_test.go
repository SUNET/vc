package openid4vp

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create a valid SD-JWT-VC token for testing
func createTestVPToken(t *testing.T, nonce, aud string, includeBinding bool) string {
	t.Helper()

	// Create a simple JWT header
	header := map[string]any{
		"alg": "ES256",
		"typ": "vc+sd-jwt",
	}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Create JWT payload with claims
	payload := map[string]any{
		"iss": "https://issuer.example.com",
		"iat": 1234567890,
		"exp": 9999999999,
		"vct": "https://example.com/TestCredential",
		"cnf": map[string]any{
			"jwk": map[string]any{
				"kty": "EC",
				"crv": "P-256",
				"x":   "test",
				"y":   "test",
			},
		},
	}
	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create a fake signature
	signature := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))

	// Build SD-JWT (issuer-signed JWT)
	sdJWT := headerB64 + "." + payloadB64 + "." + signature

	// Add key binding JWT if requested
	if includeBinding {
		kbHeader := map[string]any{
			"alg": "ES256",
			"typ": "kb+jwt",
		}
		kbHeaderJSON, _ := json.Marshal(kbHeader)
		kbHeaderB64 := base64.RawURLEncoding.EncodeToString(kbHeaderJSON)

		kbPayload := map[string]any{
			"nonce": nonce,
			"aud":   aud,
			"iat":   1234567890,
		}
		kbPayloadJSON, _ := json.Marshal(kbPayload)
		kbPayloadB64 := base64.RawURLEncoding.EncodeToString(kbPayloadJSON)

		kbSignature := base64.RawURLEncoding.EncodeToString([]byte("fake-kb-signature"))
		kbJWT := kbHeaderB64 + "." + kbPayloadB64 + "." + kbSignature

		// SD-JWT format: <Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~<KB-JWT>
		// For testing without disclosures: <Issuer-signed JWT>~<KB-JWT>
		return sdJWT + "~" + kbJWT
	}

	// Return without key binding (just the issuer JWT with trailing tilde)
	return sdJWT + "~"
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
	// Create a token with key binding but without audience claim
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"vc+sd-jwt"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://issuer.example.com","vct":"test","cnf":{"jwk":{"kty":"EC"}}}`))
	signature := base64.RawURLEncoding.EncodeToString([]byte("sig"))
	issuerJWT := header + "." + payload + "." + signature

	// Create KB-JWT without audience
	kbHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"kb+jwt"}`))
	kbPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"nonce":"test-nonce","iat":123}`))
	kbSig := base64.RawURLEncoding.EncodeToString([]byte("sig"))
	kbJWT := kbHeader + "." + kbPayload + "." + kbSig

	vpToken := issuerJWT + "~" + kbJWT

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

	header := map[string]any{"alg": "ES256", "typ": "vc+sd-jwt"}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	payload := map[string]any{
		"iss": "https://issuer.example.com",
		"iat": 1234567890,
		"exp": 9999999999,
		"vct": "https://example.com/TestCredential",
		"cnf": map[string]any{"jwk": map[string]any{"kty": "EC", "crv": "P-256", "x": "test", "y": "test"}},
	}
	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signature := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))
	sdJWT := headerB64 + "." + payloadB64 + "." + signature

	kbHeader := map[string]any{"alg": "ES256", "typ": "kb+jwt"}
	kbHeaderJSON, _ := json.Marshal(kbHeader)
	kbHeaderB64 := base64.RawURLEncoding.EncodeToString(kbHeaderJSON)

	kbPayload := map[string]any{
		"nonce": nonce,
		"aud":   aud,
		"iat":   1234567890,
	}
	if len(hashes) > 0 {
		kbPayload["transaction_data_hashes"] = hashes
		kbPayload["transaction_data_hashes_alg"] = hashAlg
	}
	kbPayloadJSON, _ := json.Marshal(kbPayload)
	kbPayloadB64 := base64.RawURLEncoding.EncodeToString(kbPayloadJSON)

	kbSignature := base64.RawURLEncoding.EncodeToString([]byte("fake-kb-signature"))
	kbJWT := kbHeaderB64 + "." + kbPayloadB64 + "." + kbSignature

	return sdJWT + "~" + kbJWT
}

// encodeTxData encodes TransactionData structs into raw base64url strings for tests.
func encodeTxData(t *testing.T, txData []TransactionData) []string {
	t.Helper()
	raw := make([]string, 0, len(txData))
	for i := range txData {
		encoded, err := txData[i].Base64Encode()
		require.NoError(t, err, "encoding transaction_data[%d]", i)
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
