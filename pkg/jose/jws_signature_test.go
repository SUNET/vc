package jose

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnsureJWSSignature(t *testing.T) {
	t.Run("passes through RSA signatures unchanged", func(t *testing.T) {
		sig := []byte("some-rsa-signature-bytes")
		result, err := ensureJWSSignature(sig, "RS256")
		require.NoError(t, err)
		assert.Equal(t, sig, result)
	})

	t.Run("passes through unknown algorithms unchanged", func(t *testing.T) {
		sig := []byte("some-signature")
		result, err := ensureJWSSignature(sig, "EdDSA")
		require.NoError(t, err)
		assert.Equal(t, sig, result)
	})

	t.Run("passes through JWS-formatted ES256 signature", func(t *testing.T) {
		// 64 bytes = correct JWS length for ES256
		sig := make([]byte, 64)
		rand.Read(sig)
		result, err := ensureJWSSignature(sig, "ES256")
		require.NoError(t, err)
		assert.Equal(t, sig, result)
	})

	t.Run("passes through JWS-formatted ES384 signature", func(t *testing.T) {
		sig := make([]byte, 96)
		rand.Read(sig)
		result, err := ensureJWSSignature(sig, "ES384")
		require.NoError(t, err)
		assert.Equal(t, sig, result)
	})

	t.Run("passes through JWS-formatted ES512 signature", func(t *testing.T) {
		sig := make([]byte, 132)
		rand.Read(sig)
		result, err := ensureJWSSignature(sig, "ES512")
		require.NoError(t, err)
		assert.Equal(t, sig, result)
	})

	t.Run("converts DER-encoded ES256 signature to JWS format", func(t *testing.T) {
		r := big.NewInt(0).SetBytes(make([]byte, 32))
		r.SetBit(r, 200, 1) // Set a bit to make it non-trivial
		s := big.NewInt(0).SetBytes(make([]byte, 32))
		s.SetBit(s, 100, 1)

		derSig, err := asn1.Marshal(ecdsaASN1Signature{R: r, S: s})
		require.NoError(t, err)
		assert.NotEqual(t, 64, len(derSig), "DER sig should not be 64 bytes")

		result, err := ensureJWSSignature(derSig, "ES256")
		require.NoError(t, err)
		assert.Len(t, result, 64, "JWS ES256 signature must be 64 bytes")

		// Verify R and S are correctly extracted
		rOut := new(big.Int).SetBytes(result[:32])
		sOut := new(big.Int).SetBytes(result[32:])
		assert.Equal(t, r, rOut)
		assert.Equal(t, s, sOut)
	})

	t.Run("converts DER-encoded ES384 signature to JWS format", func(t *testing.T) {
		r, _ := rand.Int(rand.Reader, elliptic.P384().Params().N)
		s, _ := rand.Int(rand.Reader, elliptic.P384().Params().N)

		derSig, err := asn1.Marshal(ecdsaASN1Signature{R: r, S: s})
		require.NoError(t, err)

		result, err := ensureJWSSignature(derSig, "ES384")
		require.NoError(t, err)
		assert.Len(t, result, 96)
	})

	t.Run("converts DER-encoded ES512 signature to JWS format", func(t *testing.T) {
		r, _ := rand.Int(rand.Reader, elliptic.P521().Params().N)
		s, _ := rand.Int(rand.Reader, elliptic.P521().Params().N)

		derSig, err := asn1.Marshal(ecdsaASN1Signature{R: r, S: s})
		require.NoError(t, err)

		result, err := ensureJWSSignature(derSig, "ES512")
		require.NoError(t, err)
		assert.Len(t, result, 132)
	})

	t.Run("returns error for invalid non-DER non-JWS ECDSA signature", func(t *testing.T) {
		// 50 bytes — wrong length for ES256 (64) and not valid DER
		sig := make([]byte, 50)
		rand.Read(sig)
		sig[0] = 0xFF // Ensure it's not valid ASN.1

		_, err := ensureJWSSignature(sig, "ES256")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected length")
	})

	t.Run("returns error for DER with trailing bytes", func(t *testing.T) {
		r := big.NewInt(42)
		s := big.NewInt(84)
		derSig, err := asn1.Marshal(ecdsaASN1Signature{R: r, S: s})
		require.NoError(t, err)

		// Append trailing garbage
		derSigWithTrailing := append(derSig, 0x00, 0x01)

		_, err = ensureJWSSignature(derSigWithTrailing, "ES256")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "trailing bytes")
	})
}

// derSignerWrapper wraps an ECDSA key and returns ASN.1 DER-encoded signatures,
// simulating a crypto.Signer or HSM backend that doesn't produce JWS format.
type derSignerWrapper struct {
	key *ecdsa.PrivateKey
	alg string
	kid string
}

func (d *derSignerWrapper) Sign(ctx context.Context, data []byte) ([]byte, error) {
	hash := crypto.SHA256
	switch d.alg {
	case "ES384":
		hash = crypto.SHA384
	case "ES512":
		hash = crypto.SHA512
	}

	h := hash.New()
	h.Write(data)
	hashed := h.Sum(nil)

	// Use x509-level signing which returns ASN.1 DER
	return ecdsa.SignASN1(rand.Reader, d.key, hashed)
}

func (d *derSignerWrapper) Algorithm() string { return d.alg }
func (d *derSignerWrapper) KeyID() string     { return d.kid }
func (d *derSignerWrapper) PublicKey() any    { return &d.key.PublicKey }

func TestMakeJWT_WithDERSigner(t *testing.T) {
	t.Run("ES256 DER signer produces verifiable JWT", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		signer := &derSignerWrapper{key: key, alg: "ES256", kid: "der-key-1"}

		header := jwt.MapClaims{"typ": "JWT"}
		body := jwt.MapClaims{"iss": "test", "sub": "user1"}

		token, err := MakeJWT(context.Background(), header, body, signer)
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify with golang-jwt which expects JWS-formatted signatures
		parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
			return &key.PublicKey, nil
		})
		require.NoError(t, err, "JWT signed with DER-producing signer should verify after normalization")
		assert.True(t, parsed.Valid)
	})

	t.Run("ES384 DER signer produces verifiable JWT", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		signer := &derSignerWrapper{key: key, alg: "ES384", kid: "der-key-2"}

		header := jwt.MapClaims{"typ": "JWT"}
		body := jwt.MapClaims{"iss": "test"}

		token, err := MakeJWT(context.Background(), header, body, signer)
		require.NoError(t, err)

		parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
			return &key.PublicKey, nil
		})
		require.NoError(t, err)
		assert.True(t, parsed.Valid)
	})

	t.Run("ES512 DER signer produces verifiable JWT", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		require.NoError(t, err)

		signer := &derSignerWrapper{key: key, alg: "ES512", kid: "der-key-3"}

		header := jwt.MapClaims{"typ": "JWT"}
		body := jwt.MapClaims{"iss": "test"}

		token, err := MakeJWT(context.Background(), header, body, signer)
		require.NoError(t, err)

		parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
			return &key.PublicKey, nil
		})
		require.NoError(t, err)
		assert.True(t, parsed.Valid)
	})
}

func TestEncodeFixedSizeRS(t *testing.T) {
	t.Run("pads small R and S values", func(t *testing.T) {
		r := big.NewInt(1)
		s := big.NewInt(2)

		result, err := encodeFixedSizeRS(r, s, 32)
		require.NoError(t, err)
		assert.Len(t, result, 64)

		// R should be at position 31 (zero-padded)
		assert.Equal(t, byte(0), result[0])
		assert.Equal(t, byte(1), result[31])

		// S should be at position 63 (zero-padded)
		assert.Equal(t, byte(0), result[32])
		assert.Equal(t, byte(2), result[63])
	})

	t.Run("handles full-size R and S", func(t *testing.T) {
		rBytes := make([]byte, 32)
		sBytes := make([]byte, 32)
		rand.Read(rBytes)
		rand.Read(sBytes)

		r := new(big.Int).SetBytes(rBytes)
		s := new(big.Int).SetBytes(sBytes)

		result, err := encodeFixedSizeRS(r, s, 32)
		require.NoError(t, err)
		assert.Len(t, result, 64)
	})

	t.Run("returns error when R exceeds key size", func(t *testing.T) {
		rBytes := make([]byte, 33) // Too large for keySize=32
		rBytes[0] = 0xFF
		r := new(big.Int).SetBytes(rBytes)
		s := big.NewInt(1)

		_, err := encodeFixedSizeRS(r, s, 32)
		assert.Error(t, err)
	})
}

func TestCurveForAlgorithm(t *testing.T) {
	tests := []struct {
		alg      string
		expected elliptic.Curve
	}{
		{"ES256", elliptic.P256()},
		{"ES384", elliptic.P384()},
		{"ES512", elliptic.P521()},
		{"es256", elliptic.P256()}, // case insensitive
		{"RS256", nil},
		{"EdDSA", nil},
		{"", nil},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			result := curveForAlgorithm(tt.alg)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Verify that a real ECDSA DER signature (via x509) is different from JWS format
// and that ensureJWSSignature correctly converts it.
func TestEnsureJWSSignature_RealDERSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	data := []byte("test data to sign")
	h := crypto.SHA256.New()
	h.Write(data)
	hashed := h.Sum(nil)

	// Get a real DER-encoded signature
	derSig, err := x509.MarshalECPrivateKey(key)
	_ = derSig // just to use the import

	// Sign with ASN1 (DER format)
	derSignature, err := ecdsa.SignASN1(rand.Reader, key, hashed)
	require.NoError(t, err)

	// DER signatures are variable length, typically 70-72 bytes for P-256
	assert.NotEqual(t, 64, len(derSignature), "DER signature should not be exactly 64 bytes")

	// Convert to JWS format
	jwsSig, err := ensureJWSSignature(derSignature, "ES256")
	require.NoError(t, err)
	assert.Len(t, jwsSig, 64, "JWS ES256 signature must be exactly 64 bytes")

	// Verify the converted signature is valid
	rComponent := new(big.Int).SetBytes(jwsSig[:32])
	sComponent := new(big.Int).SetBytes(jwsSig[32:])
	valid := ecdsa.Verify(&key.PublicKey, hashed, rComponent, sComponent)
	assert.True(t, valid, "converted JWS signature must be cryptographically valid")
}
