package oauth2

import (
	"testing"

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

// TestDPoP_UnmarshalMissingRequiredFields tests behavior when required fields are missing
func TestDPoP_UnmarshalMissingRequiredFields(t *testing.T) {
	tests := []struct {
		name   string
		claims jwt.MapClaims
	}{
		{
			name: "missing jti",
			claims: jwt.MapClaims{
				"htm": "POST",
				"htu": "https://example.com",
			},
		},
		{
			name: "missing htm",
			claims: jwt.MapClaims{
				"jti": "test-jti",
				"htu": "https://example.com",
			},
		},
		{
			name: "missing htu",
			claims: jwt.MapClaims{
				"jti": "test-jti",
				"htm": "POST",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &DPoP{}
			err := d.Unmarshal(tt.claims)
			// Unmarshal doesn't validate, it just parses
			assert.NoError(t, err)

			// But fields should be empty/zero
			if _, ok := tt.claims["jti"]; !ok {
				assert.Empty(t, d.JTI)
			}
			if _, ok := tt.claims["htm"]; !ok {
				assert.Empty(t, d.HTM)
			}
			if _, ok := tt.claims["htu"]; !ok {
				assert.Empty(t, d.HTU)
			}
		})
	}
}

// TestValidateAndParseDPoPJWT_AllowedHTTPMethods verifies that all standard HTTP methods
// are accepted in the HTM claim when properly signed
func TestValidateAndParseDPoPJWT_AllowedHTTPMethods(t *testing.T) {
	// All these methods should be allowed per the DPoP struct definition
	validMethods := []string{"POST", "GET", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}

	// We can verify the struct tag defines these
	dpop := &DPoP{
		JTI: "test-jti-12345",
		HTM: "POST",
		HTU: "https://example.com",
	}

	// Verify validation accepts all valid methods
	for _, method := range validMethods {
		dpop.HTM = method
		err := dpop.ValidateHTM()
		assert.NoError(t, err, "Method %s should be valid", method)
	}
}
