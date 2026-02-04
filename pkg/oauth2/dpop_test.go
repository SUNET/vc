package oauth2

import (
	"testing"
	"vc/internal/gen/issuer/apiv1_issuer"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

var mockJWT_1 = `eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiZXdpYlNCaC1uVDgwdVJuQ0lfX0t6bkVXOXN6b0RhMDI3YU1kdjJOb3RRcyIsInkiOiJIUlpyYml0dmZmNTk3WXBUV0F1d2d5ZHk3cWpsTGRaNjNuMHFwaW5PbGxFIn19.eyJqdGkiOiI4NGJiMzI2NmNjZDZhYmY4IiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vdmMtaW50ZXJvcC0zLnN1bmV0LnNlL3Rva2VuIiwiaWF0IjoxNzQ4MzM1NTU0fQ.HuAKEiFm6CGFLTWJvf0Ll8Cj9vcltsJ1ThgBqhttuV3diE1lkeJO6QzO-h_F0fes1rm6HqRhDLwhW34SxXK4Eg`
var mockJWK_1 = `{
    "kty": "EC",
    "crv": "P-256",
    "x": "ewibSBh-nT80uRnCI__KznEW9szoDa027aMdv2NotQs",
    "y": "HRZrbitvff597YpTWAuwgydy7qjlLdZ63n0qpinOllE",
	"kid": "key-1"
  }`

var mockJWT_2 = `eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiVl9DSjdmckhmNWlITU1rclI0TDlPVzhRbEFYOE5Ibnk2ZFgxSWxqcloyOCIsInkiOiJ0R3ByVWE1SFg4aERzQlZXd1RIcEhjc3hjZDFqaGN0Ql9ULTZtZzRXLU5nIn19.eyJqdGkiOiJiN2JlNmNkYThkNDIwNjk5IiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vdmMtaW50ZXJvcC0zLnN1bmV0LnNlL3Rva2VuIiwiaWF0IjoxNzQ4MzUzNDgyfQ.MTldxLq3g1g8yzLikj74n_HldPSfwbw_A-9Ut1mf_IIjqqj0SAkTAdlyOqXu9AuPlH5Baz4ZAS5mK_RxGdN4Tg`
var mockJWK_2 = `{
    "crv": "P-256",
    "kty": "EC",
    "x": "V_CJ7frHf5iHMMkrR4L9OW8QlAX8NHny6dX1IljrZ28",
    "y": "tGprUa5HX8hDsBVWwTHpHcsxcd1jhctB_T-6mg4W-Ng"
  }`

func TestParseJWK(t *testing.T) {
	tts := []struct {
		name        string
		jwk         string
		fingerprint string
	}{
		{
			name:        "mockJWK_1",
			jwk:         mockJWK_1,
			fingerprint: "ddd7868c9fd1c0a718f13586206dd47e551fdc1b16bd2ad053e5bf09651392fd",
		},
		{
			name:        "mockJWK_2",
			jwk:         mockJWK_2,
			fingerprint: "9b85a44324a33a89d650d9aef4b3c85d7ae24bbd07ec062322d956e1b82593ff",
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			key, fingerprint, err := parseDpopJWK([]byte(tt.jwk))
			assert.Equal(t, tt.fingerprint, fingerprint, "fingerprint should match expected value")
			assert.NoError(t, err, "parseJWK should not return an error")
			assert.NotNil(t, key, "key should not be nil")
		})
	}
}

func TestValidate(t *testing.T) {
	tts := []struct {
		name string
		jwt  string
		jwk  string
		want *DPoP
	}{
		{
			name: "mockJWT_1",
			jwt:  mockJWT_1,
			want: &DPoP{
				JTI:        "84bb3266ccd6abf8",
				HTM:        "POST",
				HTU:        "https://vc-interop-3.sunet.se/token",
				ATH:        "",
				Thumbprint: "ddd7868c9fd1c0a718f13586206dd47e551fdc1b16bd2ad053e5bf09651392fd",
				JWK: &apiv1_issuer.Jwk{
					Kty:    "EC",
					Crv:    "P-256",
					X:      "ewibSBh-nT80uRnCI__KznEW9szoDa027aMdv2NotQs",
					Y:      "HRZrbitvff597YpTWAuwgydy7qjlLdZ63n0qpinOllE",
					KeyOps: []string{"verify"},
					Ext:    true,
				},
			},
		},
		{
			name: "mockJWT_2",
			jwt:  mockJWT_2,
			want: &DPoP{
				JTI:        "b7be6cda8d420699",
				HTM:        "POST",
				HTU:        "https://vc-interop-3.sunet.se/token",
				ATH:        "",
				Thumbprint: "9b85a44324a33a89d650d9aef4b3c85d7ae24bbd07ec062322d956e1b82593ff",
				JWK: &apiv1_issuer.Jwk{
					Kty:    "EC",
					Crv:    "P-256",
					X:      "V_CJ7frHf5iHMMkrR4L9OW8QlAX8NHny6dX1IljrZ28",
					Y:      "tGprUa5HX8hDsBVWwTHpHcsxcd1jhctB_T-6mg4W-Ng",
					KeyOps: []string{"verify"},
					Ext:    true,
				},
			},
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateAndParseDPoPJWT(tt.jwt)
			assert.NoError(t, err, "ValidateAndParseDPoPJWT should not return an error")

			// Compare field by field to avoid protobuf atomicMessageInfo comparison issues
			assert.Equal(t, tt.want.JTI, got.JTI, "JTI should match")
			assert.Equal(t, tt.want.HTM, got.HTM, "HTM should match")
			assert.Equal(t, tt.want.HTU, got.HTU, "HTU should match")
			assert.Equal(t, tt.want.ATH, got.ATH, "ATH should match")
			assert.Equal(t, tt.want.Thumbprint, got.Thumbprint, "Thumbprint should match")

			// Compare JWK fields individually
			assert.NotNil(t, got.JWK, "JWK should not be nil")
			if got.JWK != nil {
				assert.Equal(t, tt.want.JWK.Kty, got.JWK.Kty, "JWK Kty should match")
				assert.Equal(t, tt.want.JWK.Crv, got.JWK.Crv, "JWK Crv should match")
				assert.Equal(t, tt.want.JWK.X, got.JWK.X, "JWK X should match")
				assert.Equal(t, tt.want.JWK.Y, got.JWK.Y, "JWK Y should match")
				assert.Equal(t, tt.want.JWK.KeyOps, got.JWK.KeyOps, "JWK KeyOps should match")
				assert.Equal(t, tt.want.JWK.Ext, got.JWK.Ext, "JWK Ext should match")
			}
		})
	}
}

func TestIsAccessTokenDPoP(t *testing.T) {
	tests := []struct {
		name  string
		dpop  *DPoP
		token string
		want  bool
	}{
		{
			name: "matching token",
			dpop: &DPoP{
				ATH: "test_token_hash",
			},
			token: "test_token_hash",
			want:  true,
		},
		{
			name: "non-matching token",
			dpop: &DPoP{
				ATH: "test_token_hash",
			},
			token: "different_token",
			want:  false,
		},
		{
			name: "empty ATH",
			dpop: &DPoP{
				ATH: "",
			},
			token: "some_token",
			want:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.dpop.IsAccessTokenDPoP(tt.token)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		claims  jwt.MapClaims
		wantErr bool
	}{
		{
			name: "valid claims",
			claims: jwt.MapClaims{
				"jti": "test-jti",
				"htm": "POST",
				"htu": "https://example.com",
			},
			wantErr: false,
		},
		{
			name:    "empty claims",
			claims:  jwt.MapClaims{},
			wantErr: false,
		},
		{
			name: "claims with ath",
			claims: jwt.MapClaims{
				"jti": "test-jti-2",
				"htm": "GET",
				"htu": "https://api.example.com/resource",
				"ath": "test-access-token-hash",
			},
			wantErr: false,
		},
		{
			name: "claims with iat as float64",
			claims: jwt.MapClaims{
				"jti": "test-jti-3",
				"htm": "POST",
				"htu": "https://example.com/token",
				"iat": float64(1234567890),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &DPoP{}
			err := d.Unmarshal(tt.claims)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				// Verify fields are set
				if jti, ok := tt.claims["jti"].(string); ok {
					assert.Equal(t, jti, d.JTI)
				}
				if htm, ok := tt.claims["htm"].(string); ok {
					assert.Equal(t, htm, d.HTM)
				}
				if htu, ok := tt.claims["htu"].(string); ok {
					assert.Equal(t, htu, d.HTU)
				}
				if ath, ok := tt.claims["ath"].(string); ok {
					assert.Equal(t, ath, d.ATH)
				}
			}
		})
	}
}

func TestParseDpopJWK_Errors(t *testing.T) {
	tests := []struct {
		name    string
		jwk     string
		wantErr bool
	}{
		{
			name:    "invalid JSON",
			jwk:     `{invalid json}`,
			wantErr: true,
		},
		{
			name:    "empty JWK",
			jwk:     `{}`,
			wantErr: true,
		},
		{
			name:    "null bytes",
			jwk:     "",
			wantErr: true,
		},
		{
			name:    "malformed JWK",
			jwk:     `{"kty":"EC"}`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := parseDpopJWK([]byte(tt.jwk))
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateAndParseDPoPJWT_Errors(t *testing.T) {
	tests := []struct {
		name    string
		jwt     string
		wantErr bool
	}{
		{
			name:    "empty JWT",
			jwt:     "",
			wantErr: true,
		},
		{
			name:    "invalid JWT format",
			jwt:     "invalid.jwt.token",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateAndParseDPoPJWT(tt.jwt)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
