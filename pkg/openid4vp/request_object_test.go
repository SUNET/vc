package openid4vp

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gotest.tools/v3/golden"
)

func TestAuthorizationRequest(t *testing.T) {
	tts := []struct {
		name       string
		goldenPath string
	}{
		{
			name:       "Valid Request",
			goldenPath: "request_object_from_spec.json",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			want := golden.Get(t, tt.goldenPath)

			mura := &RequestObject{}
			err := json.Unmarshal(want, &mura)
			assert.NoError(t, err, "Unmarshal should not return an error")

			got, err := json.Marshal(mura)
			assert.NoError(t, err, "Marshal should not return an error")

			assert.JSONEq(t, string(want), string(got), "JSON output should match golden file")
		})
	}
}

func TestHashTransactionData(t *testing.T) {
	encode := func(t *testing.T, tds ...TransactionData) []string {
		t.Helper()
		raw := make([]string, 0, len(tds))
		for i := range tds {
			s, err := tds[i].Base64Encode()
			require.NoError(t, err)
			raw = append(raw, s)
		}
		return raw
	}

	t.Run("single entry", func(t *testing.T) {
		raw := encode(t, TransactionData{Type: "payment", CredentialIDS: []string{"eudi_pid"}})
		hashes, err := HashTransactionData(raw, "sha-256")
		require.NoError(t, err)
		require.Len(t, hashes, 1)
		assert.NotEmpty(t, hashes[0])
	})

	t.Run("multiple entries produce ordered hashes", func(t *testing.T) {
		raw := encode(t,
			TransactionData{Type: "payment", CredentialIDS: []string{"eudi_pid"}},
			TransactionData{Type: "document_signing", CredentialIDS: []string{"diploma"}},
		)
		hashes, err := HashTransactionData(raw, "sha-256")
		require.NoError(t, err)
		require.Len(t, hashes, 2)
		assert.NotEqual(t, hashes[0], hashes[1])
	})

	t.Run("same input produces same hash", func(t *testing.T) {
		raw := encode(t, TransactionData{Type: "payment", CredentialIDS: []string{"eudi_pid"}})
		hashes1, err := HashTransactionData(raw, "sha-256")
		require.NoError(t, err)
		hashes2, err := HashTransactionData(raw, "sha-256")
		require.NoError(t, err)
		assert.Equal(t, hashes1[0], hashes2[0])
	})

	t.Run("different algorithms produce different hashes", func(t *testing.T) {
		raw := encode(t, TransactionData{Type: "payment", CredentialIDS: []string{"eudi_pid"}})
		hashes256, err := HashTransactionData(raw, "sha-256")
		require.NoError(t, err)
		hashes512, err := HashTransactionData(raw, "sha-512")
		require.NoError(t, err)
		assert.NotEqual(t, hashes256[0], hashes512[0])
	})

	t.Run("unsupported algorithm returns error", func(t *testing.T) {
		raw := encode(t, TransactionData{Type: "payment", CredentialIDS: []string{"eudi_pid"}})
		_, err := HashTransactionData(raw, "md5")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported hash algorithm")
	})

	t.Run("Base64Encode round-trip", func(t *testing.T) {
		td := TransactionData{Type: "sca", CredentialIDS: []string{"eudi_pid"}}
		encoded, err := td.Base64Encode()
		require.NoError(t, err)
		assert.NotEmpty(t, encoded)

		// Hash should be deterministic over the base64-encoded form
		hashes, err := HashTransactionData([]string{encoded}, "sha-256")
		require.NoError(t, err)
		assert.NotEmpty(t, hashes[0])
	})
}

// TestKeys_UnmarshalJSON_RoundTrip verifies that a RequestObject whose
// ClientMetadata.JWKS carries a jwk.Key survives a plain json.Marshal /
// json.Unmarshal round-trip - the shape the HA MongoCache uses when it
// serializes cached RequestObjects. Without a custom UnmarshalJSON on
// Keys, Unmarshal cannot pick a concrete type for the jwk.Key interface
// and the slice comes back nil, so every HA request_uri/reuse/resume lookup
// would see an incomplete request object.
func TestKeys_UnmarshalJSON_RoundTrip(t *testing.T) {
	raw, err := jwk.ParseKey([]byte(`{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","kid":"test-kid"}`))
	require.NoError(t, err)

	original := &RequestObject{
		ISS:          "https://verifier.example.com",
		AUD:          "https://self-issued.me/v2",
		IAT:          1700000000,
		ResponseType: "code",
		ClientID:     "https://verifier.example.com",
		Nonce:        "nonce-xyz",
		ResponseMode: "direct_post.jwt",
		ResponseURI:  "https://verifier.example.com/direct_post",
		ClientMetadata: &ClientMetadata{
			JWKS: &Keys{Keys: []jwk.Key{raw}},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	decoded := &RequestObject{}
	require.NoError(t, json.Unmarshal(data, decoded))

	require.NotNil(t, decoded.ClientMetadata)
	require.NotNil(t, decoded.ClientMetadata.JWKS)
	require.Len(t, decoded.ClientMetadata.JWKS.Keys, 1)
	gotKID, ok := decoded.ClientMetadata.JWKS.Keys[0].KeyID()
	require.True(t, ok)
	assert.Equal(t, "test-kid", gotKID)
}
