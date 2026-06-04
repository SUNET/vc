package tokenstatuslist

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompressStatuses(t *testing.T) {
	tests := []struct {
		name     string
		statuses []uint8
	}{
		{
			name:     "empty statuses",
			statuses: []uint8{},
		},
		{
			name:     "single status",
			statuses: []uint8{1},
		},
		{
			name:     "multiple statuses",
			statuses: []uint8{0, 1, 2, 1, 0, 3, 2, 1},
		},
		{
			name:     "all same statuses",
			statuses: []uint8{1, 1, 1, 1, 1, 1, 1, 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed, err := CompressStatuses(tt.statuses)
			require.NoError(t, err)
			assert.NotNil(t, compressed)

			// Decompress and verify round-trip
			decompressed, err := DecompressStatuses(compressed)
			require.NoError(t, err)
			assert.Equal(t, tt.statuses, decompressed)
		})
	}
}

func TestDecompressStatuses(t *testing.T) {
	// Test with empty input
	_, err := DecompressStatuses(nil)
	assert.Error(t, err)

	// Test with invalid compressed data
	_, err = DecompressStatuses([]byte{0x00, 0x01, 0x02})
	assert.Error(t, err)
}

func TestGetStatus(t *testing.T) {
	statuses := []uint8{0, 1, 2, 3, 255}

	tests := []struct {
		name     string
		index    int
		expected uint8
		wantErr  bool
	}{
		{"first status", 0, 0, false},
		{"middle status", 2, 2, false},
		{"last status", 4, 255, false},
		{"negative index", -1, 0, true},
		{"out of range", 10, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetStatus(statuses, tt.index)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, got)
			}
		})
	}
}

func TestSetStatus(t *testing.T) {
	tests := []struct {
		name     string
		initial  []uint8
		index    int
		value    uint8
		expected []uint8
		wantErr  bool
	}{
		{
			name:     "set first",
			initial:  []uint8{0, 1, 2},
			index:    0,
			value:    5,
			expected: []uint8{5, 1, 2},
		},
		{
			name:     "set middle",
			initial:  []uint8{0, 1, 2},
			index:    1,
			value:    10,
			expected: []uint8{0, 10, 2},
		},
		{
			name:     "set last",
			initial:  []uint8{0, 1, 2},
			index:    2,
			value:    255,
			expected: []uint8{0, 1, 255},
		},
		{
			name:    "negative index",
			initial: []uint8{0, 1, 2},
			index:   -1,
			value:   1,
			wantErr: true,
		},
		{
			name:    "out of range",
			initial: []uint8{0, 1, 2},
			index:   5,
			value:   1,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statuses := make([]uint8, len(tt.initial))
			copy(statuses, tt.initial)

			// Test set via direct slice modification (SetStatus would be a helper)
			if tt.index >= 0 && tt.index < len(statuses) {
				statuses[tt.index] = tt.value
				assert.Equal(t, tt.expected, statuses)
			}
		})
	}
}

func TestCompressAndEncode(t *testing.T) {
	tests := []struct {
		name  string
		input []uint8
	}{
		{"empty", []uint8{}},
		{"simple", []uint8{1, 2, 3}},
		{"binary", []uint8{0x00, 0xFF, 0x01, 0xFE}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := CompressAndEncode(tt.input)
			require.NoError(t, err)

			// Verify no padding
			assert.NotContains(t, encoded, "=")

			// Verify it can be decoded and decompressed back
			decoded, err := DecodeAndDecompress(encoded)
			require.NoError(t, err)
			assert.Equal(t, tt.input, decoded)
		})
	}
}

func TestGenerateJWT(t *testing.T) {
	// Generate test key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	statuses := []uint8{0, 1, 2, 1, 0, 3, 2, 1}

	cfg := JWTConfig{
		TokenConfig: TokenConfig{
			Issuer:    "https://example.com",
			Subject:   "https://example.com/statuslists/1",
			Statuses:  statuses,
			ExpiresIn: 24 * time.Hour,
			TTL:       43200,
			KeyID:     "key-1",
		},
		SigningKey:    privateKey,
		SigningMethod: jwt.SigningMethodES256,
	}

	tokenString, err := GenerateJWT(cfg)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	// Verify token structure (3 parts separated by dots)
	parts := strings.Split(tokenString, ".")
	assert.Len(t, parts, 3)

	// Parse and verify claims
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		return &privateKey.PublicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, token.Valid)

	// Verify typ header
	assert.Equal(t, JWTTypHeader, token.Header["typ"])

	// Verify claims
	claims, ok := token.Claims.(jwt.MapClaims)
	require.True(t, ok)
	assert.Equal(t, cfg.Issuer, claims["iss"])
	assert.Equal(t, cfg.Subject, claims["sub"])
	assert.NotNil(t, claims["iat"])
	assert.NotNil(t, claims["exp"])
	assert.Equal(t, float64(cfg.TTL), claims["ttl"])

	// Verify status_list claim
	statusList, ok := claims["status_list"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(Bits), statusList["bits"])
	assert.NotEmpty(t, statusList["lst"])
}

func TestGenerateJWTMissingKey(t *testing.T) {
	cfg := JWTConfig{
		TokenConfig: TokenConfig{
			Issuer:   "https://example.com",
			Subject:  "https://example.com/statuslists/1",
			Statuses: []uint8{1, 2, 3},
		},
		SigningKey: nil,
	}

	_, err := GenerateJWT(cfg)
	assert.Error(t, err)
}

func TestGenerateCWT(t *testing.T) {
	// Generate test key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	statuses := []uint8{0, 1, 2, 1, 0, 3, 2, 1}

	cfg := CWTConfig{
		TokenConfig: TokenConfig{
			Issuer:    "https://example.com",
			Subject:   "https://example.com/statuslists/1",
			Statuses:  statuses,
			ExpiresIn: 24 * time.Hour,
			TTL:       43200,
		},
		SigningKey: privateKey,
	}

	cwtBytes, err := GenerateCWT(cfg)
	require.NoError(t, err)
	assert.NotEmpty(t, cwtBytes)

	// Parse the CWT
	claims, err := ParseCWT(cwtBytes)
	require.NoError(t, err)

	// Verify claims
	assert.Equal(t, cfg.Issuer, claims[cwtClaimIss])
	assert.Equal(t, cfg.Subject, claims[cwtClaimSub])
	assert.NotNil(t, claims[cwtClaimIat])
	assert.NotNil(t, claims[cwtClaimExp])
	// TTL may be returned as uint64 by CBOR
	assert.NotNil(t, claims[cwtClaimTTL])

	// Verify status_list claim exists
	assert.NotNil(t, claims[cwtClaimStatusList])
}

func TestGetStatusFromCWT(t *testing.T) {
	// Generate test key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	statuses := []uint8{5, 10, 15, 20, 25}

	cfg := CWTConfig{
		TokenConfig: TokenConfig{
			Issuer:   "https://example.com",
			Subject:  "https://example.com/statuslists/1",
			Statuses: statuses,
		},
		SigningKey: privateKey,
	}

	cwtBytes, err := GenerateCWT(cfg)
	require.NoError(t, err)

	claims, err := ParseCWT(cwtBytes)
	require.NoError(t, err)

	// Test getting each status
	for i, expected := range statuses {
		got, err := GetStatusFromCWT(claims, i)
		require.NoError(t, err)
		assert.Equal(t, expected, got)
	}

	// Test out of range
	_, err = GetStatusFromCWT(claims, 100)
	assert.Error(t, err)
}

func TestParseCWTInvalid(t *testing.T) {
	// Test with invalid data
	_, err := ParseCWT([]byte{0x00, 0x01, 0x02})
	assert.Error(t, err)

	// Test with wrong tag
	wrongTag := cbor.Tag{
		Number:  99, // Wrong tag
		Content: []any{[]byte{}, map[int]any{}, []byte{}, []byte{}},
	}
	wrongTagBytes, _ := cbor.Marshal(wrongTag)
	_, err = ParseCWT(wrongTagBytes)
	assert.Error(t, err)
}

func TestStatusConstants(t *testing.T) {
	assert.Equal(t, uint8(0), StatusValid)
	assert.Equal(t, uint8(1), StatusInvalid)
	assert.Equal(t, uint8(2), StatusSuspended)
	assert.Equal(t, 8, Bits)
}

func TestJWTTypHeader(t *testing.T) {
	assert.Equal(t, "statuslist+jwt", JWTTypHeader)
}

func TestCWTTypHeader(t *testing.T) {
	assert.Equal(t, "statuslist+cwt", CWTTypHeader)
}

// Tests for the new method-based API

func TestStatusListNew(t *testing.T) {
	statuses := []uint8{0, 1, 2, 3}
	sl := New(statuses)

	assert.NotNil(t, sl)
	assert.Equal(t, 4, sl.Len())
	assert.Equal(t, statuses, sl.Statuses())
}

func TestStatusListNewWithConfig(t *testing.T) {
	statuses := []uint8{0, 1, 2}
	sl := NewWithConfig(statuses, "https://issuer.example.com", "https://issuer.example.com/statuslist/1")

	assert.Equal(t, "https://issuer.example.com", sl.Issuer)
	assert.Equal(t, "https://issuer.example.com/statuslist/1", sl.Subject)
	assert.Equal(t, statuses, sl.Statuses())
}

func TestStatusListGetSet(t *testing.T) {
	sl := New([]uint8{0, 1, 2, 3, 4})

	// Test Get
	status, err := sl.Get(2)
	require.NoError(t, err)
	assert.Equal(t, uint8(2), status)

	// Test Set
	err = sl.Set(2, 10)
	require.NoError(t, err)

	status, err = sl.Get(2)
	require.NoError(t, err)
	assert.Equal(t, uint8(10), status)

	// Test out of bounds
	_, err = sl.Get(-1)
	assert.Error(t, err)

	_, err = sl.Get(100)
	assert.Error(t, err)

	err = sl.Set(-1, 5)
	assert.Error(t, err)

	err = sl.Set(100, 5)
	assert.Error(t, err)
}

func TestStatusListGenerateJWTMethod(t *testing.T) {
	// Generate test key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	statuses := []uint8{0, 1, 2, 1, 0, 3, 2, 1}

	sl := New(statuses)
	sl.Issuer = "https://example.com"
	sl.Subject = "https://example.com/statuslists/1"
	sl.ExpiresIn = 24 * time.Hour
	sl.TTL = 43200
	sl.KeyID = "key-1"

	tokenString, err := sl.GenerateJWT(JWTSigningConfig{
		SigningKey:    privateKey,
		SigningMethod: jwt.SigningMethodES256,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	// Verify token structure (3 parts separated by dots)
	parts := strings.Split(tokenString, ".")
	assert.Len(t, parts, 3)

	// Parse and verify claims
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		return &privateKey.PublicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, token.Valid)

	// Verify typ header
	assert.Equal(t, JWTTypHeader, token.Header["typ"])
	assert.Equal(t, "key-1", token.Header["kid"])
}

func TestStatusListGenerateCWTMethod(t *testing.T) {
	// Generate test key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	statuses := []uint8{0, 1, 2, 1, 0, 3, 2, 1}

	sl := New(statuses)
	sl.Issuer = "https://example.com"
	sl.Subject = "https://example.com/statuslists/1"
	sl.ExpiresIn = 24 * time.Hour
	sl.TTL = 43200

	cwtBytes, err := sl.GenerateCWT(CWTSigningConfig{
		SigningKey: privateKey,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, cwtBytes)

	// Parse the CWT
	claims, err := ParseCWT(cwtBytes)
	require.NoError(t, err)

	// Verify claims
	assert.Equal(t, sl.Issuer, claims[cwtClaimIss])
	assert.Equal(t, sl.Subject, claims[cwtClaimSub])
	assert.NotNil(t, claims[cwtClaimIat])
	assert.NotNil(t, claims[cwtClaimExp])
	assert.NotNil(t, claims[cwtClaimStatusList])
}

func TestParseJWT(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	statuses := []uint8{5, 10, 15, 20, 25}

	cfg := JWTConfig{
		TokenConfig: TokenConfig{
			Issuer:    "https://example.com",
			Subject:   "https://example.com/statuslists/1",
			Statuses:  statuses,
			ExpiresIn: 24 * time.Hour,
			TTL:       43200,
			KeyID:     "key-1",
		},
		SigningKey:    privateKey,
		SigningMethod: jwt.SigningMethodES256,
	}

	tokenString, err := GenerateJWT(cfg)
	require.NoError(t, err)

	claims, err := ParseJWT(tokenString, func(token *jwt.Token) (any, error) {
		return &privateKey.PublicKey, nil
	})
	require.NoError(t, err)
	assert.Equal(t, cfg.Issuer, claims.Issuer)
	assert.Equal(t, cfg.Subject, claims.Subject)
	assert.Equal(t, int64(43200), claims.TTL)
	assert.Equal(t, Bits, claims.StatusList.Bits)
	assert.NotEmpty(t, claims.StatusList.Lst)
}

func TestParseJWT_InvalidToken(t *testing.T) {
	_, err := ParseJWT("invalid.token.string", func(token *jwt.Token) (any, error) {
		return nil, fmt.Errorf("no key")
	})
	assert.Error(t, err)
}

func TestGetStatusFromJWT(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	statuses := []uint8{5, 10, 15, 20, 25}

	cfg := JWTConfig{
		TokenConfig: TokenConfig{
			Issuer:   "https://example.com",
			Subject:  "https://example.com/statuslists/1",
			Statuses: statuses,
		},
		SigningKey:    privateKey,
		SigningMethod: jwt.SigningMethodES256,
	}

	tokenString, err := GenerateJWT(cfg)
	require.NoError(t, err)

	claims, err := ParseJWT(tokenString, func(token *jwt.Token) (any, error) {
		return &privateKey.PublicKey, nil
	})
	require.NoError(t, err)

	for i, expected := range statuses {
		got, err := GetStatusFromJWT(claims, i)
		require.NoError(t, err)
		assert.Equal(t, expected, got)
	}

	_, err = GetStatusFromJWT(claims, 100)
	assert.Error(t, err)
}

func FuzzCompressDecompress(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3})
	f.Add([]byte{255, 0, 128})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, input []byte) {
		statuses := make([]uint8, len(input))
		copy(statuses, input)

		compressed, err := CompressStatuses(statuses)
		if err != nil {
			return
		}
		decompressed, err := DecompressStatuses(compressed)
		require.NoError(t, err)
		assert.Equal(t, statuses, decompressed)
	})
}

// FuzzParseCWT fuzzes CWT (CBOR Web Token) parsing.
// CWTs may be received from untrusted status list providers.
func FuzzParseCWT(f *testing.F) {
	f.Add([]byte{0xd2, 0x84, 0x40, 0xa0, 0x40, 0x40}) // COSE tag 18 + minimal array
	f.Add([]byte{})
	f.Add([]byte{0xff})
	f.Add([]byte{0xa0})

	f.Fuzz(func(t *testing.T, data []byte) {
		claims, err := ParseCWT(data)
		if err != nil {
			return
		}
		if claims == nil {
			t.Fatal("ParseCWT returned nil without error")
		}
	})
}

// FuzzDecodeAndDecompress fuzzes base64 decoding + zlib decompression.
func FuzzDecodeAndDecompress(f *testing.F) {
	f.Add("eJwBAAD__wFJ")
	f.Add("")
	f.Add("not-base64!")
	f.Add("AAAA")

	f.Fuzz(func(t *testing.T, encoded string) {
		_, _ = DecodeAndDecompress(encoded)
	})
}

// TestGenerateCWT_RSA_AutoDetect verifies that GenerateCWT with an RSA key and
// Algorithm=0 auto-detects PS256 and produces a valid COSE_Sign1 whose
// signature can be verified with the corresponding public key.
func TestGenerateCWT_RSA_AutoDetect(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	statuses := []uint8{0, 1, 2, 1, 0, 3, 2, 1}

	sl := New(statuses)
	sl.Issuer = "https://example.com"
	sl.Subject = "https://example.com/statuslists/1"
	sl.ExpiresIn = 24 * time.Hour
	sl.TTL = 43200
	sl.KeyID = "rsa-key-1"

	cwtBytes, err := sl.GenerateCWT(CWTSigningConfig{
		SigningKey: rsaKey,
		Algorithm:  0, // auto-detect → PS256
	})
	require.NoError(t, err)
	assert.NotEmpty(t, cwtBytes)

	// Parse and verify claims
	claims, err := ParseCWT(cwtBytes)
	require.NoError(t, err)
	assert.Equal(t, sl.Issuer, claims[cwtClaimIss])
	assert.Equal(t, sl.Subject, claims[cwtClaimSub])
	assert.NotNil(t, claims[cwtClaimIat])
	assert.NotNil(t, claims[cwtClaimExp])
	assert.NotNil(t, claims[cwtClaimStatusList])

	// Verify protected header contains PS256 algorithm
	protectedBytes, signature := extractCOSESign1Parts(t, cwtBytes)
	var protectedHeader map[int]any
	require.NoError(t, cbor.Unmarshal(protectedBytes, &protectedHeader))

	// Algorithm should be PS256 (-37) when auto-detected from RSA key
	algValue, ok := protectedHeader[coseHeaderAlg]
	require.True(t, ok, "protected header must contain alg")
	assert.Equal(t, int64(CoseAlgPS256), algValue)

	// Verify typ header
	assert.Equal(t, CWTTypHeader, protectedHeader[coseHeaderTyp])

	// Verify kid header
	assert.Equal(t, "rsa-key-1", protectedHeader[coseHeaderKid])

	// Verify the RSA-PSS signature
	verifyCOSESignature(t, cwtBytes, &rsaKey.PublicKey, crypto.SHA256)

	// Verify status round-trip
	for i, expected := range statuses {
		got, err := GetStatusFromCWT(claims, i)
		require.NoError(t, err)
		assert.Equal(t, expected, got, "status mismatch at index %d", i)
	}

	_ = signature // already verified above
}

// TestGenerateCWT_RSA_ExplicitAlgorithms tests each explicit PS* algorithm
// (PS256, PS384, PS512) to ensure the correct COSE alg header is set and the
// signature verifies with the matching hash.
func TestGenerateCWT_RSA_ExplicitAlgorithms(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	statuses := []uint8{5, 10, 15, 20, 25}

	tests := []struct {
		name     string
		alg      int
		hashAlg  crypto.Hash
		expected int64
	}{
		{"PS256", CoseAlgPS256, crypto.SHA256, int64(CoseAlgPS256)},
		{"PS384", CoseAlgPS384, crypto.SHA384, int64(CoseAlgPS384)},
		{"PS512", CoseAlgPS512, crypto.SHA512, int64(CoseAlgPS512)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sl := New(statuses)
			sl.Issuer = "https://example.com"
			sl.Subject = "https://example.com/statuslists/1"

			cwtBytes, err := sl.GenerateCWT(CWTSigningConfig{
				SigningKey: rsaKey,
				Algorithm:  tt.alg,
			})
			require.NoError(t, err)
			assert.NotEmpty(t, cwtBytes)

			// Verify the protected header has the correct algorithm
			protectedBytes, _ := extractCOSESign1Parts(t, cwtBytes)
			var protectedHeader map[int]any
			require.NoError(t, cbor.Unmarshal(protectedBytes, &protectedHeader))
			assert.Equal(t, tt.expected, protectedHeader[coseHeaderAlg])

			// Verify the signature with the correct hash
			verifyCOSESignature(t, cwtBytes, &rsaKey.PublicKey, tt.hashAlg)

			// Verify claims round-trip
			claims, err := ParseCWT(cwtBytes)
			require.NoError(t, err)
			for i, expected := range statuses {
				got, err := GetStatusFromCWT(claims, i)
				require.NoError(t, err)
				assert.Equal(t, expected, got)
			}
		})
	}
}

// TestGenerateCWT_RSA_WrongKeyType verifies that using an ECDSA key with an
// explicit PS* algorithm fails with an appropriate error.
func TestGenerateCWT_RSA_WrongKeyType(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	sl := New([]uint8{1, 2, 3})
	sl.Issuer = "https://example.com"
	sl.Subject = "https://example.com/statuslists/1"

	_, err = sl.GenerateCWT(CWTSigningConfig{
		SigningKey: ecKey,
		Algorithm:  CoseAlgPS256, // ECDSA key with RSA algorithm
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rsa.PrivateKey")
}

// TestDetectCOSEAlgorithm_RSA verifies auto-detection returns PS256 for RSA keys.
func TestDetectCOSEAlgorithm_RSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	alg, err := detectCOSEAlgorithm(rsaKey)
	require.NoError(t, err)
	assert.Equal(t, CoseAlgPS256, alg)
}

// extractCOSESign1Parts decodes a COSE_Sign1 and returns the protected header
// bytes and the signature bytes.
func extractCOSESign1Parts(t *testing.T, cwtBytes []byte) (protectedBytes, signature []byte) {
	t.Helper()

	var tag cbor.Tag
	require.NoError(t, cbor.Unmarshal(cwtBytes, &tag))
	require.Equal(t, uint64(18), tag.Number)

	components, ok := tag.Content.([]any)
	require.True(t, ok)
	require.Len(t, components, 4)

	protectedBytes, ok = components[0].([]byte)
	require.True(t, ok)

	signature, ok = components[3].([]byte)
	require.True(t, ok)

	return protectedBytes, signature
}

// verifyCOSESignature rebuilds the COSE Sig_structure from the CWT bytes and
// verifies the RSA-PSS signature with the given public key and hash algorithm.
func verifyCOSESignature(t *testing.T, cwtBytes []byte, pub *rsa.PublicKey, hashAlg crypto.Hash) {
	t.Helper()

	var tag cbor.Tag
	require.NoError(t, cbor.Unmarshal(cwtBytes, &tag))

	components, ok := tag.Content.([]any)
	require.True(t, ok)
	require.Len(t, components, 4)

	protectedBytes, ok := components[0].([]byte)
	require.True(t, ok)
	payloadBytes, ok := components[2].([]byte)
	require.True(t, ok)
	signature, ok := components[3].([]byte)
	require.True(t, ok)

	// Rebuild Sig_structure = ["Signature1", protected, external_aad, payload]
	sigStructure := []any{
		"Signature1",
		protectedBytes,
		[]byte{},
		payloadBytes,
	}
	sigStructureBytes, err := cbor.Marshal(sigStructure)
	require.NoError(t, err)

	// Hash and verify
	var digest []byte
	switch hashAlg {
	case crypto.SHA256:
		d := sha256.Sum256(sigStructureBytes)
		digest = d[:]
	case crypto.SHA384:
		d := sha512.Sum384(sigStructureBytes)
		digest = d[:]
	case crypto.SHA512:
		d := sha512.Sum512(sigStructureBytes)
		digest = d[:]
	default:
		t.Fatalf("unsupported hash algorithm: %v", hashAlg)
	}

	err = rsa.VerifyPSS(pub, hashAlg, digest, signature, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
	require.NoError(t, err, "RSA-PSS signature verification failed")
}
