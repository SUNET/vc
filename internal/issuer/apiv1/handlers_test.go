package apiv1

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/pkg/logger"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var mockEhic = []byte(`
{
  "family_name": "TestFamily",
  "authentic_source": {
    "id": "CLEISS",
    "name": "SUNET"
  },
  "date_of_expiry": "2026-04-12",
  "date_of_issuance": "2023-11-18",
  "ending_date": "2026-06-24",
  "issuing_authority": {
    "id": "CLEISS",
    "name": "SUNET"
  },
  "issuing_country": "FR",
  "starting_date": "2025-06-24",
  "personal_administrative_number": "123456789A",
  "document_number": "EHIC1234567890"
}
  `)

var mockPidData = []byte(`
{
  "family_name": "Doe",
  "given_name": "John",
  "birth_date": "1990-01-15",
  "authentic_source": "test-source"
}
`)

var mockDiplomaData = []byte(`
{
  "family_name": "Smith",
  "degree": "Master of Science",
  "field_of_study": "Computer Science",
  "graduation_date": "2020-06-15"
}
`)

// loadTestVCTM reads the VCTM from testdata and returns the raw bytes and its
// SRI integrity hash. This avoids spinning up an HTTP server — the VCTM is
// supplied inline via CreateCredentialRequest.VCTM.
func loadTestVCTM(t *testing.T) (vctmRaw []byte, integrity string) {
	t.Helper()
	raw, err := os.ReadFile("testdata/vctm_test.json")
	if err != nil {
		t.Fatalf("read testdata/vctm_test.json: %v", err)
	}
	h := sha256.Sum256(raw)
	integrity = fmt.Sprintf("sha256-%s", base64.StdEncoding.EncodeToString(h[:]))
	return raw, integrity
}

func TestMakeSDJWT(t *testing.T) {
	vctmRaw, integrity := loadTestVCTM(t)

	tests := []struct {
		name    string
		request *CreateCredentialRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "successful EHIC credential creation",
			request: &CreateCredentialRequest{
				Scope:        "ehic",
				DocumentData: mockEhic,
				VCTM:         vctmRaw,
				Integrity:    integrity,
				JWK: &apiv1_issuer.Jwk{
					Kty: "EC",
					Crv: "P-256",
					X:   "f83OJ3D2xF4c3hXhN3k1j5x5mX5Z5x5Z5x5Z5x5Z5x5Z",
					Y:   "x_FEzRu9mX5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5",
				},
			},
			wantErr: false,
		},
		{
			name: "successful PID credential creation",
			request: &CreateCredentialRequest{
				Scope:        "pid",
				DocumentData: mockPidData,
				VCTM:         vctmRaw,
				Integrity:    integrity,
				JWK: &apiv1_issuer.Jwk{
					Kty: "EC",
					Crv: "P-256",
					X:   "f83OJ3D2xF4c3hXhN3k1j5x5mX5Z5x5Z5x5Z5x5Z5x5Z",
					Y:   "x_FEzRu9mX5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5",
				},
			},
			wantErr: false,
		},
		{
			name: "successful diploma credential creation",
			request: &CreateCredentialRequest{
				Scope:        "diploma",
				DocumentData: mockDiplomaData,
				VCTM:         vctmRaw,
				Integrity:    integrity,
				JWK: &apiv1_issuer.Jwk{
					Kty: "EC",
					Crv: "P-256",
					X:   "f83OJ3D2xF4c3hXhN3k1j5x5mX5Z5x5Z5x5Z5x5Z5x5Z",
					Y:   "x_FEzRu9mX5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5",
				},
			},
			wantErr: false,
		},
		{
			name: "missing integrity",
			request: &CreateCredentialRequest{
				Scope:        "ehic",
				DocumentData: mockEhic,
				VCTM:         vctmRaw,
				Integrity:    "",
				JWK: &apiv1_issuer.Jwk{
					Kty: "EC",
					Crv: "P-256",
					X:   "f83OJ3D2xF4c3hXhN3k1j5x5mX5Z5x5Z5x5Z5x5Z5x5Z",
					Y:   "x_FEzRu9mX5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5",
				},
			},
			wantErr: true,
		},
		{
			name: "missing scope",
			request: &CreateCredentialRequest{
				Scope:        "",
				DocumentData: mockEhic,
				VCTM:         vctmRaw,
				Integrity:    integrity,
				JWK: &apiv1_issuer.Jwk{
					Kty: "EC",
					Crv: "P-256",
					X:   "f83OJ3D2xF4c3hXhN3k1j5x5mX5Z5x5Z5x5Z5x5Z5x5Z",
					Y:   "x_FEzRu9mX5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5",
				},
			},
			wantErr: true,
		},
		{
			name: "missing document data",
			request: &CreateCredentialRequest{
				Scope:        "ehic",
				DocumentData: nil,
				VCTM:         vctmRaw,
				Integrity:    integrity,
				JWK: &apiv1_issuer.Jwk{
					Kty: "EC",
					Crv: "P-256",
					X:   "f83OJ3D2xF4c3hXhN3k1j5x5mX5Z5x5Z5x5Z5x5Z5x5Z",
					Y:   "x_FEzRu9mX5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5",
				},
			},
			wantErr: true,
		},
		{
			name: "missing JWK",
			request: &CreateCredentialRequest{
				Scope:        "ehic",
				DocumentData: mockEhic,
				VCTM:         vctmRaw,
				Integrity:    integrity,
				JWK:          nil,
			},
			wantErr: true,
		},
		{
			name: "missing VCTM",
			request: &CreateCredentialRequest{
				Scope:        "ehic",
				DocumentData: mockEhic,
				VCTM:         nil,
				Integrity:    integrity,
				JWK: &apiv1_issuer.Jwk{
					Kty: "EC",
					Crv: "P-256",
					X:   "f83OJ3D2xF4c3hXhN3k1j5x5mX5Z5x5Z5x5Z5x5Z5x5Z",
					Y:   "x_FEzRu9mX5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid JSON in document data",
			request: &CreateCredentialRequest{
				Scope:        "ehic",
				DocumentData: []byte(`{invalid json`),
				VCTM:         vctmRaw,
				Integrity:    integrity,
				JWK: &apiv1_issuer.Jwk{
					Kty: "EC",
					Crv: "P-256",
					X:   "f83OJ3D2xF4c3hXhN3k1j5x5mX5Z5x5Z5x5Z5x5Z5x5Z",
					Y:   "x_FEzRu9mX5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid VCTM bytes",
			request: &CreateCredentialRequest{
				Scope:        "ehic",
				DocumentData: mockEhic,
				VCTM:         []byte(`{not valid json`),
				Integrity:    integrity,
				JWK: &apiv1_issuer.Jwk{
					Kty: "EC",
					Crv: "P-256",
					X:   "f83OJ3D2xF4c3hXhN3k1j5x5mX5Z5x5Z5x5Z5x5Z5x5Z",
					Y:   "x_FEzRu9mX5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			log := logger.NewSimple("test")
			client := mockNewClient(ctx, t, "ecdsa", log)

			got, err := client.MakeSDJWT(ctx, tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, got)
			assert.NotEmpty(t, got.Data)
			assert.NotEmpty(t, got.Data[0].Credential)

			// Verify it's a valid SD-JWT structure
			parts := strings.Split(got.Data[0].Credential, "~")
			assert.GreaterOrEqual(t, len(parts), 1, "SD-JWT should have at least JWT part")

			// Parse JWT header and payload
			jwtParts := strings.Split(parts[0], ".")
			assert.Len(t, jwtParts, 3, "JWT should have 3 parts (header.payload.signature)")

			// Decode and verify header
			headerBytes, err := base64.RawURLEncoding.DecodeString(jwtParts[0])
			require.NoError(t, err, "should decode JWT header")

			var header map[string]any
			err = json.Unmarshal(headerBytes, &header)
			require.NoError(t, err, "should parse JWT header JSON")

			assert.Contains(t, header, "alg", "header should contain alg")
			assert.Contains(t, header, "typ", "header should contain typ")
			assert.Equal(t, "dc+sd-jwt", header["typ"], "typ should be dc+sd-jwt")

			// Decode and verify payload
			payloadBytes, err := base64.RawURLEncoding.DecodeString(jwtParts[1])
			require.NoError(t, err, "should decode JWT payload")

			var payload map[string]any
			err = json.Unmarshal(payloadBytes, &payload)
			require.NoError(t, err, "should parse JWT payload JSON")

			// Verify standard claims
			assert.Contains(t, payload, "iss", "payload should contain iss")
			assert.Contains(t, payload, "nbf", "payload should contain nbf")
			assert.Contains(t, payload, "exp", "payload should contain exp")
			assert.Contains(t, payload, "jti", "payload should contain jti")
			assert.Contains(t, payload, "vct", "payload should contain vct")
			assert.Contains(t, payload, "cnf", "payload should contain cnf (confirmation)")
			assert.Contains(t, payload, "_sd_alg", "payload should contain _sd_alg")

			// Verify issuer
			assert.Equal(t, "https://test-issuer.sunet.se", payload["iss"])

			// Verify hash algorithm
			assert.Equal(t, "sha-256", payload["_sd_alg"])
		})
	}
}

func TestMakeSDJWT_WithRSAKey(t *testing.T) {
	vctmRaw, integrity := loadTestVCTM(t)
	ctx := t.Context()
	log := logger.NewSimple("test")
	client := mockNewClient(ctx, t, "rsa", log)

	request := &CreateCredentialRequest{
		Scope:        "ehic",
		DocumentData: mockEhic,
		VCTM:         vctmRaw,
		Integrity:    integrity,
		JWK: &apiv1_issuer.Jwk{
			Kty: "EC",
			Crv: "P-256",
			X:   "f83OJ3D2xF4c3hXhN3k1j5x5mX5Z5x5Z5x5Z5x5Z5x5Z",
			Y:   "x_FEzRu9mX5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5",
		},
	}

	got, err := client.MakeSDJWT(ctx, request)

	require.NoError(t, err)
	assert.NotNil(t, got)
	assert.NotEmpty(t, got.Data)
	assert.NotEmpty(t, got.Data[0].Credential)

	// Parse and verify RSA algorithm
	parts := strings.Split(got.Data[0].Credential, "~")
	jwtParts := strings.Split(parts[0], ".")

	headerBytes, err := base64.RawURLEncoding.DecodeString(jwtParts[0])
	require.NoError(t, err)

	var header map[string]any
	err = json.Unmarshal(headerBytes, &header)
	require.NoError(t, err)

	// RSA 2048 key should result in RS256
	assert.Equal(t, "RS256", header["alg"], "2048-bit RSA key should use RS256")
}

func TestMakeSDJWT_VerifySelectiveDisclosure(t *testing.T) {
	vctmRaw, integrity := loadTestVCTM(t)
	ctx := t.Context()
	log := logger.NewSimple("test")
	client := mockNewClient(ctx, t, "ecdsa", log)

	request := &CreateCredentialRequest{
		Scope:        "ehic",
		DocumentData: mockEhic,
		VCTM:         vctmRaw,
		Integrity:    integrity,
		JWK: &apiv1_issuer.Jwk{
			Kty: "EC",
			Crv: "P-256",
			X:   "f83OJ3D2xF4c3hXhN3k1j5x5mX5Z5x5Z5x5Z5x5Z5x5Z",
			Y:   "x_FEzRu9mX5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5",
		},
	}

	got, err := client.MakeSDJWT(ctx, request)
	require.NoError(t, err)

	// Parse SD-JWT
	parts := strings.Split(got.Data[0].Credential, "~")
	assert.GreaterOrEqual(t, len(parts), 2, "SD-JWT should have disclosures")

	// Check JWT payload for _sd arrays
	jwtParts := strings.Split(parts[0], ".")
	payloadBytes, err := base64.RawURLEncoding.DecodeString(jwtParts[1])
	require.NoError(t, err)

	var payload map[string]any
	err = json.Unmarshal(payloadBytes, &payload)
	require.NoError(t, err)

	// Verify selective disclosures are present
	// The payload should have _sd array or nested objects with _sd arrays
	hasSD := false
	if _, ok := payload["_sd"]; ok {
		hasSD = true
	}

	// Check nested objects recursively
	var checkForSD func(m map[string]any) bool
	checkForSD = func(m map[string]any) bool {
		for k, v := range m {
			if k == "_sd" {
				return true
			}
			if nested, ok := v.(map[string]any); ok {
				if checkForSD(nested) {
					return true
				}
			}
		}
		return false
	}

	if !hasSD {
		hasSD = checkForSD(payload)
	}

	assert.True(t, hasSD, "SD-JWT should contain _sd arrays for selective disclosure")
}

func TestMakeSDJWT_MultipleCredentialTypes(t *testing.T) {
	vctmRaw, integrity := loadTestVCTM(t)
	ctx := t.Context()
	log := logger.NewSimple("test")
	client := mockNewClient(ctx, t, "ecdsa", log)

	scopes := []string{"ehic", "pid", "diploma"}

	for _, scope := range scopes {
		t.Run(scope, func(t *testing.T) {
			var docData []byte
			switch scope {
			case "ehic":
				docData = mockEhic
			case "pid":
				docData = mockPidData
			case "diploma":
				docData = mockDiplomaData
			}

			request := &CreateCredentialRequest{
				Scope:        scope,
				DocumentData: docData,
				VCTM:         vctmRaw,
				Integrity:    integrity,
				JWK: &apiv1_issuer.Jwk{
					Kty: "EC",
					Crv: "P-256",
					X:   "f83OJ3D2xF4c3hXhN3k1j5x5mX5Z5x5Z5x5Z5x5Z5x5Z",
					Y:   "x_FEzRu9mX5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5",
				},
			}

			got, err := client.MakeSDJWT(ctx, request)
			require.NoError(t, err, "should create %s credential", scope)
			assert.NotNil(t, got)
			assert.NotEmpty(t, got.Data[0].Credential)
		})
	}
}

func TestMakeSDJWT_ValidationErrors(t *testing.T) {
	vctmRaw, integrity := loadTestVCTM(t)

	tests := []struct {
		name         string
		scope        string
		documentData []byte
		wantErr      bool
		errContains  string
	}{
		{
			name:  "missing mandatory claim in PID",
			scope: "pid",
			documentData: []byte(`{
				"given_name": "John",
				"birth_date": "1990-01-15"
			}`),
			wantErr:     true,
			errContains: "document validation failed",
		},
		{
			name:  "missing mandatory claim in EHIC",
			scope: "ehic",
			documentData: []byte(`{
				"issuing_country": "FR",
				"starting_date": "2025-06-24"
			}`),
			wantErr:     true,
			errContains: "document validation failed",
		},
		{
			name:         "valid PID passes validation",
			scope:        "pid",
			documentData: mockPidData,
			wantErr:      false,
		},
		{
			name:         "valid EHIC passes validation",
			scope:        "ehic",
			documentData: mockEhic,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			log := logger.NewSimple("test")
			client := mockNewClient(ctx, t, "ecdsa", log)

			req := &CreateCredentialRequest{
				Scope:        tt.scope,
				DocumentData: tt.documentData,
				VCTM:         vctmRaw,
				Integrity:    integrity,
				JWK: &apiv1_issuer.Jwk{
					Kty: "EC",
					Crv: "P-256",
					X:   "f83OJ3D2xF4c3hXhN3k1j5x5mX5Z5x5Z5x5Z5x5Z5x5Z",
					Y:   "x_FEzRu9mX5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5",
				},
			}

			got, err := client.MakeSDJWT(ctx, req)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				assert.Nil(t, got)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, got)
				assert.NotEmpty(t, got.Data)
			}
		})
	}
}

func TestMakeSDJWT_InlineVCTMValidation(t *testing.T) {
	vctmRaw, integrity := loadTestVCTM(t)

	defaultJWK := &apiv1_issuer.Jwk{
		Kty: "EC",
		Crv: "P-256",
		X:   "f83OJ3D2xF4c3hXhN3k1j5x5mX5Z5x5Z5x5Z5x5Z5x5Z",
		Y:   "x_FEzRu9mX5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5",
	}

	tests := []struct {
		name        string
		vctm        []byte
		integrity   string
		wantErr     bool
		errContains string
	}{
		{
			name:      "valid VCTM and integrity succeeds",
			vctm:      vctmRaw,
			integrity: integrity,
			wantErr:   false,
		},
		{
			name:        "nil VCTM is rejected by validation",
			vctm:        nil,
			integrity:   integrity,
			wantErr:     true,
			errContains: "vctm",
		},
		{
			name:        "invalid JSON VCTM is rejected",
			vctm:        []byte(`{not json`),
			integrity:   integrity,
			wantErr:     true,
			errContains: "failed to parse inline VCTM",
		},
		{
			name:        "VCTM with empty vct field is rejected",
			vctm:        []byte(`{"vct":"","claims":[]}`),
			integrity:   integrity,
			wantErr:     true,
			errContains: "empty vct field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			log := logger.NewSimple("test")
			client := mockNewClient(ctx, t, "ecdsa", log)

			req := &CreateCredentialRequest{
				Scope:        "ehic",
				DocumentData: mockEhic,
				VCTM:         tt.vctm,
				Integrity:    tt.integrity,
				JWK:          defaultJWK,
			}

			got, err := client.MakeSDJWT(ctx, req)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, got)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, got)
				assert.NotEmpty(t, got.Data)
			}
		})
	}
}
