package apiv1

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/pkg/logger"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const testIssuerURL = "https://test-issuer.sunet.se"

// validVCIMetadataJSON returns minimal valid VCI Credential Issuer metadata.
func validVCIMetadataJSON(t *testing.T) []byte {
	t.Helper()
	m := map[string]any{
		"credential_issuer":   testIssuerURL,
		"credential_endpoint": testIssuerURL + "/credential",
		"credential_configurations_supported": map[string]any{
			"test_cred": map[string]any{
				"format": "dc+sd-jwt",
			},
		},
	}
	b, err := json.Marshal(m)
	require.NoError(t, err)
	return b
}

// validOAuth2MetadataJSON returns minimal valid OAuth2 Authorization Server metadata.
func validOAuth2MetadataJSON(t *testing.T) []byte {
	t.Helper()
	m := map[string]any{
		"issuer":                   testIssuerURL,
		"authorization_endpoint":   testIssuerURL + "/authorize",
		"token_endpoint":           testIssuerURL + "/token",
		"response_types_supported": []string{"code"},
	}
	b, err := json.Marshal(m)
	require.NoError(t, err)
	return b
}

// newSignMetadataClient creates a Client wired for SignMetadata tests.
func newSignMetadataClient(t *testing.T) *Client {
	t.Helper()
	log := logger.NewSimple("test")
	client := mockNewClient(t.Context(), t, "", log)
	client.cfg.Issuer.IssuerURL = testIssuerURL
	return client
}

// decodeJWTParts splits a compact JWT and returns decoded header and payload maps.
func decodeJWTParts(t *testing.T, token string) (header, payload map[string]any) {
	t.Helper()
	parts := strings.SplitN(token, ".", 3)
	require.Len(t, parts, 3, "JWT must have 3 parts")

	for i, dst := range []*map[string]any{&header, &payload} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, dst))
	}
	return header, payload
}

// metadataJSON is a helper that marshals a map to JSON, failing the test on error.
func metadataJSON(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	require.NoError(t, err)
	return b
}

func TestSignMetadata_Validation(t *testing.T) {
	// Build an oversized payload once for reuse.
	oversized := make([]byte, 64*1024+1)
	for i := range oversized {
		oversized[i] = 'x'
	}

	tts := []struct {
		name         string
		metadataJSON func(t *testing.T) []byte
		req          *apiv1_issuer.SignMetadataRequest
		wantCode     codes.Code
		wantSubstr   string
	}{
		{
			name:         "empty metadata_json",
			metadataJSON: func(t *testing.T) []byte { return nil },
			req: &apiv1_issuer.SignMetadataRequest{
				MetadataType: MetadataTypeVCIIssuer,
				Iss:          testIssuerURL,
			},
			wantCode:   codes.InvalidArgument,
			wantSubstr: "metadata_json is required",
		},
		{
			name:         "oversized metadata_json",
			metadataJSON: func(t *testing.T) []byte { return oversized },
			req: &apiv1_issuer.SignMetadataRequest{
				MetadataType: MetadataTypeVCIIssuer,
				Iss:          testIssuerURL,
			},
			wantCode:   codes.InvalidArgument,
			wantSubstr: "too large",
		},
		{
			name:         "iss mismatch with configured issuer_url",
			metadataJSON: func(t *testing.T) []byte { return []byte(`{}`) },
			req: &apiv1_issuer.SignMetadataRequest{
				MetadataType: MetadataTypeVCIIssuer,
				Iss:          "https://evil.example.com",
			},
			wantCode:   codes.InvalidArgument,
			wantSubstr: "iss must equal configured issuer_url",
		},
		{
			name:         "unsupported metadata type",
			metadataJSON: func(t *testing.T) []byte { return []byte(`{}`) },
			req: &apiv1_issuer.SignMetadataRequest{
				MetadataType: "bogus-type",
				Iss:          testIssuerURL,
			},
			wantCode:   codes.InvalidArgument,
			wantSubstr: "unsupported metadata type",
		},
		{
			name:         "invalid JSON",
			metadataJSON: func(t *testing.T) []byte { return []byte(`{not valid json`) },
			req: &apiv1_issuer.SignMetadataRequest{
				MetadataType: MetadataTypeVCIIssuer,
				Iss:          testIssuerURL,
			},
			wantCode:   codes.InvalidArgument,
			wantSubstr: "failed to parse metadata",
		},
		{
			name: "validation failure - missing required fields",
			metadataJSON: func(t *testing.T) []byte {
				return []byte(`{"credential_issuer":"` + testIssuerURL + `"}`)
			},
			req: &apiv1_issuer.SignMetadataRequest{
				MetadataType: MetadataTypeVCIIssuer,
				Iss:          testIssuerURL,
			},
			wantCode:   codes.InvalidArgument,
			wantSubstr: "metadata validation failed",
		},
		{
			name:         "sub mismatch",
			metadataJSON: validVCIMetadataJSON,
			req: &apiv1_issuer.SignMetadataRequest{
				MetadataType: MetadataTypeVCIIssuer,
				Iss:          testIssuerURL,
				Sub:          "https://different-subject.example.com",
			},
			wantCode:   codes.InvalidArgument,
			wantSubstr: "sub must be empty or equal to iss",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			client := newSignMetadataClient(t)

			tt.req.MetadataJson = tt.metadataJSON(t)

			_, err := client.SignMetadata(t.Context(), tt.req)
			require.Error(t, err)

			st, ok := status.FromError(err)
			require.True(t, ok, "error should be a gRPC status")
			assert.Equal(t, tt.wantCode, st.Code())
			assert.Contains(t, st.Message(), tt.wantSubstr)
		})
	}
}

func TestSignMetadata_MetadataIssuerMismatch(t *testing.T) {
	client := newSignMetadataClient(t)

	// credential_issuer differs from req.Iss (which matches cfg).
	b := metadataJSON(t, map[string]any{
		"credential_issuer":   "https://attacker.example.com",
		"credential_endpoint": "https://attacker.example.com/credential",
		"credential_configurations_supported": map[string]any{
			"test_cred": map[string]any{"format": "dc+sd-jwt"},
		},
	})

	_, err := client.SignMetadata(t.Context(), &apiv1_issuer.SignMetadataRequest{
		MetadataJson: b,
		MetadataType: MetadataTypeVCIIssuer,
		Iss:          testIssuerURL,
	})
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "does not match request iss")
}

func TestSignMetadata_HappyPath(t *testing.T) {
	tts := []struct {
		name         string
		metadataType string
		metadataJSON func(t *testing.T) []byte
		sub          string
		wantTyp      string
		// Key in the JWT payload that holds the metadata-level issuer identifier
		// (credential_issuer for VCI, issuer for OAuth2).
		issuerPayloadKey string
	}{
		{
			name:             "VCI issuer metadata",
			metadataType:     MetadataTypeVCIIssuer,
			metadataJSON:     validVCIMetadataJSON,
			wantTyp:          "openidvci-issuer-metadata+jwt",
			issuerPayloadKey: "credential_issuer",
		},
		{
			name:             "OAuth2 authorization server metadata",
			metadataType:     MetadataTypeOAuth2,
			metadataJSON:     validOAuth2MetadataJSON,
			wantTyp:          "JWT",
			issuerPayloadKey: "issuer",
		},
		{
			name:             "VCI with sub equal to iss",
			metadataType:     MetadataTypeVCIIssuer,
			metadataJSON:     validVCIMetadataJSON,
			sub:              testIssuerURL,
			wantTyp:          "openidvci-issuer-metadata+jwt",
			issuerPayloadKey: "credential_issuer",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			client := newSignMetadataClient(t)

			reply, err := client.SignMetadata(t.Context(), &apiv1_issuer.SignMetadataRequest{
				MetadataJson: tt.metadataJSON(t),
				MetadataType: tt.metadataType,
				Iss:          testIssuerURL,
				Sub:          tt.sub,
			})
			require.NoError(t, err)
			require.NotEmpty(t, reply.GetSignedMetadata())

			header, payload := decodeJWTParts(t, reply.GetSignedMetadata())
			assert.Equal(t, tt.wantTyp, header["typ"])
			assert.Equal(t, testIssuerURL, payload["iss"])
			assert.Equal(t, testIssuerURL, payload["sub"])
			assert.Contains(t, payload, "iat")
			assert.Equal(t, testIssuerURL, payload[tt.issuerPayloadKey])
			assert.NotContains(t, payload, "signed_metadata", "signed_metadata must be stripped")
		})
	}
}

func TestSignMetadata_JWTVerifiesWithIssuerKey(t *testing.T) {
	client := newSignMetadataClient(t)

	reply, err := client.SignMetadata(t.Context(), &apiv1_issuer.SignMetadataRequest{
		MetadataJson: validVCIMetadataJSON(t),
		MetadataType: MetadataTypeVCIIssuer,
		Iss:          testIssuerURL,
	})
	require.NoError(t, err)

	pubKey := client.signer.PublicKey()
	ecPub, ok := pubKey.(*ecdsa.PublicKey)
	require.True(t, ok, "test key should be ECDSA")

	parsed, err := jwt.Parse(reply.GetSignedMetadata(), func(token *jwt.Token) (any, error) {
		return ecPub, nil
	})
	require.NoError(t, err)
	assert.True(t, parsed.Valid)

	claims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)
	assert.Equal(t, testIssuerURL, claims["iss"])
}

func TestSignMetadata_PayloadSanitization(t *testing.T) {
	tts := []struct {
		name         string
		metadataType string
		metadataJSON func(t *testing.T) []byte
		checkPayload func(t *testing.T, payload map[string]any)
	}{
		{
			name:         "unknown fields stripped",
			metadataType: MetadataTypeVCIIssuer,
			metadataJSON: func(t *testing.T) []byte {
				t.Helper()
				return metadataJSON(t, map[string]any{
					"credential_issuer":   testIssuerURL,
					"credential_endpoint": testIssuerURL + "/credential",
					"credential_configurations_supported": map[string]any{
						"test_cred": map[string]any{"format": "dc+sd-jwt"},
					},
					"injected_evil_field": "should_not_appear",
				})
			},
			checkPayload: func(t *testing.T, payload map[string]any) {
				assert.NotContains(t, payload, "injected_evil_field", "unknown fields must be stripped")
			},
		},
		{
			name:         "signed_metadata field removed",
			metadataType: MetadataTypeVCIIssuer,
			metadataJSON: func(t *testing.T) []byte {
				t.Helper()
				return metadataJSON(t, map[string]any{
					"credential_issuer":   testIssuerURL,
					"credential_endpoint": testIssuerURL + "/credential",
					"credential_configurations_supported": map[string]any{
						"test_cred": map[string]any{"format": "dc+sd-jwt"},
					},
					"signed_metadata": "old.jwt.value",
				})
			},
			checkPayload: func(t *testing.T, payload map[string]any) {
				assert.NotContains(t, payload, "signed_metadata",
					"signed_metadata must be removed to prevent self-referencing")
			},
		},
		{
			name:         "iat/iss/sub overridden from caller-supplied values",
			metadataType: MetadataTypeOAuth2,
			metadataJSON: func(t *testing.T) []byte {
				t.Helper()
				return metadataJSON(t, map[string]any{
					"issuer":                   testIssuerURL,
					"authorization_endpoint":   testIssuerURL + "/authorize",
					"token_endpoint":           testIssuerURL + "/token",
					"response_types_supported": []string{"code"},
					"iss":                      "https://injected.example.com",
					"sub":                      "https://injected.example.com",
					"iat":                      0,
				})
			},
			checkPayload: func(t *testing.T, payload map[string]any) {
				assert.Equal(t, testIssuerURL, payload["iss"], "iss must be server-controlled")
				assert.Equal(t, testIssuerURL, payload["sub"], "sub must be server-controlled")
				iat, ok := payload["iat"].(float64)
				require.True(t, ok)
				assert.Greater(t, iat, float64(0), "iat must be set by the server")
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			client := newSignMetadataClient(t)

			reply, err := client.SignMetadata(t.Context(), &apiv1_issuer.SignMetadataRequest{
				MetadataJson: tt.metadataJSON(t),
				MetadataType: tt.metadataType,
				Iss:          testIssuerURL,
			})
			require.NoError(t, err)

			_, payload := decodeJWTParts(t, reply.GetSignedMetadata())
			tt.checkPayload(t, payload)
		})
	}
}

func TestSignMetadata_RateLimitExhausted(t *testing.T) {
	client := newSignMetadataClient(t)

	// Exhaust the rate limiter (burst=5 by default).
	for i := range 5 {
		_, err := client.SignMetadata(t.Context(), &apiv1_issuer.SignMetadataRequest{
			MetadataJson: validVCIMetadataJSON(t),
			MetadataType: MetadataTypeVCIIssuer,
			Iss:          testIssuerURL,
		})
		require.NoError(t, err, "call %d should succeed", i+1)
	}

	// Next call should be rate-limited.
	_, err := client.SignMetadata(t.Context(), &apiv1_issuer.SignMetadataRequest{
		MetadataJson: validVCIMetadataJSON(t),
		MetadataType: MetadataTypeVCIIssuer,
		Iss:          testIssuerURL,
	})
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.ResourceExhausted, st.Code())
	assert.Contains(t, st.Message(), "rate limit exceeded")
}
