package oauth2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// testKeySetup generates an ECDSA key pair and serves the public key as a JWKS endpoint.
func testKeySetup(t *testing.T) (*ecdsa.PrivateKey, *httptest.Server) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pubJWK, err := jwk.Import(privKey.Public())
	if err != nil {
		t.Fatalf("failed to import public key to JWK: %v", err)
	}
	_ = pubJWK.Set(jwk.KeyIDKey, "test-kid")
	_ = pubJWK.Set(jwk.AlgorithmKey, "ES256")

	set := jwk.NewSet()
	_ = set.AddKey(pubJWK)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(srv.Close)
	return privKey, srv
}

// signAssertion creates a signed JWT client assertion.
func signAssertion(t *testing.T, key *ecdsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "test-kid"
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign assertion: %v", err)
	}
	return signed
}

func validClaims(tokenEndpoint string) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss": "client-id",
		"sub": "client-id",
		"aud": tokenEndpoint,
		"jti": "unique-jti-123",
		"iat": float64(now.Unix()),
		"exp": float64(now.Add(2 * time.Minute).Unix()),
	}
}

func TestClientAssertionVerifier_Verify(t *testing.T) {
	privKey, srv := testKeySetup(t)
	tokenEndpoint := "https://verifier.example.com/token"

	client := &Client{
		JWKSURI: srv.URL,
	}

	tests := []struct {
		name        string
		verifier    *ClientAssertionVerifier
		claims      jwt.MapClaims
		client      *Client
		wantErr     string
		jtiCheck    func(string, time.Time) error
		checkResult func(*testing.T, *ClientAssertionClaims)
	}{
		{
			name: "valid_assertion",
			verifier: &ClientAssertionVerifier{
				TokenEndpoint: tokenEndpoint,
			},
			claims: validClaims(tokenEndpoint),
			client: client,
			checkResult: func(t *testing.T, c *ClientAssertionClaims) {
				if c.Issuer != "client-id" {
					t.Errorf("Issuer = %q, want %q", c.Issuer, "client-id")
				}
				if c.Subject != "client-id" {
					t.Errorf("Subject = %q, want %q", c.Subject, "client-id")
				}
				if c.JTI != "unique-jti-123" {
					t.Errorf("JTI = %q, want %q", c.JTI, "unique-jti-123")
				}
			},
		},
		{
			name: "no_jwks_uri",
			verifier: &ClientAssertionVerifier{
				TokenEndpoint: tokenEndpoint,
			},
			claims:  validClaims(tokenEndpoint),
			client:  &Client{},
			wantErr: "client has no jwks_uri configured",
		},
		{
			name: "wrong_audience",
			verifier: &ClientAssertionVerifier{
				TokenEndpoint: tokenEndpoint,
			},
			claims: func() jwt.MapClaims {
				c := validClaims(tokenEndpoint)
				c["aud"] = "https://wrong.example.com/token"
				return c
			}(),
			client:  client,
			wantErr: "verification failed",
		},
		{
			name: "iss_not_equal_sub",
			verifier: &ClientAssertionVerifier{
				TokenEndpoint: tokenEndpoint,
			},
			claims: func() jwt.MapClaims {
				c := validClaims(tokenEndpoint)
				c["iss"] = "client-id"
				c["sub"] = "different-id"
				return c
			}(),
			client:  client,
			wantErr: "must equal 'sub'",
		},
		{
			name: "missing_jti",
			verifier: &ClientAssertionVerifier{
				TokenEndpoint: tokenEndpoint,
			},
			claims: func() jwt.MapClaims {
				c := validClaims(tokenEndpoint)
				delete(c, "jti")
				return c
			}(),
			client:  client,
			wantErr: "must contain 'jti' claim",
		},
		{
			name: "missing_iss_and_sub",
			verifier: &ClientAssertionVerifier{
				TokenEndpoint: tokenEndpoint,
			},
			claims: func() jwt.MapClaims {
				c := validClaims(tokenEndpoint)
				delete(c, "iss")
				delete(c, "sub")
				return c
			}(),
			client:  client,
			wantErr: "must contain 'iss' and 'sub' claims",
		},
		{
			name: "missing_iat",
			verifier: &ClientAssertionVerifier{
				TokenEndpoint: tokenEndpoint,
			},
			claims: func() jwt.MapClaims {
				c := validClaims(tokenEndpoint)
				delete(c, "iat")
				return c
			}(),
			client:  client,
			wantErr: "must contain a numeric 'iat' claim",
		},
		{
			name: "missing_iat_with_far_future_exp_bypass_attempt",
			verifier: &ClientAssertionVerifier{
				TokenEndpoint: tokenEndpoint,
				MaxLifetime:   5 * time.Minute,
			},
			claims: func() jwt.MapClaims {
				return jwt.MapClaims{
					"iss": "client-id",
					"sub": "client-id",
					"aud": tokenEndpoint,
					"jti": "bypass-jti",
					"exp": float64(time.Now().Add(24 * time.Hour).Unix()),
				}
			}(),
			client:  client,
			wantErr: "must contain a numeric 'iat' claim",
		},
		{
			name: "zero_iat_bypass_attempt",
			verifier: &ClientAssertionVerifier{
				TokenEndpoint: tokenEndpoint,
				MaxLifetime:   5 * time.Minute,
			},
			claims: func() jwt.MapClaims {
				return jwt.MapClaims{
					"iss": "client-id",
					"sub": "client-id",
					"aud": tokenEndpoint,
					"jti": "zero-iat-jti",
					"iat": float64(0),
					"exp": float64(time.Now().Add(24 * time.Hour).Unix()),
				}
			}(),
			client:  client,
			wantErr: "must contain a numeric 'iat' claim",
		},
		{
			name: "non_numeric_iat_bypass_attempt",
			verifier: &ClientAssertionVerifier{
				TokenEndpoint: tokenEndpoint,
				MaxLifetime:   5 * time.Minute,
			},
			claims: func() jwt.MapClaims {
				return jwt.MapClaims{
					"iss": "client-id",
					"sub": "client-id",
					"aud": tokenEndpoint,
					"jti": "string-iat-jti",
					"iat": "not-a-number",
					"exp": float64(time.Now().Add(24 * time.Hour).Unix()),
				}
			}(),
			client:  client,
			wantErr: "must contain a numeric 'iat' claim",
		},
		{
			name: "expired_token",
			verifier: &ClientAssertionVerifier{
				TokenEndpoint: tokenEndpoint,
			},
			claims: func() jwt.MapClaims {
				past := time.Now().Add(-10 * time.Minute)
				return jwt.MapClaims{
					"iss": "client-id",
					"sub": "client-id",
					"aud": tokenEndpoint,
					"jti": "expired-jti",
					"iat": float64(past.Unix()),
					"exp": float64(past.Add(2 * time.Minute).Unix()),
				}
			}(),
			client:  client,
			wantErr: "verification failed",
		},
		{
			name: "exceeds_max_lifetime",
			verifier: &ClientAssertionVerifier{
				TokenEndpoint: tokenEndpoint,
				MaxLifetime:   1 * time.Minute,
			},
			claims: func() jwt.MapClaims {
				now := time.Now()
				return jwt.MapClaims{
					"iss": "client-id",
					"sub": "client-id",
					"aud": tokenEndpoint,
					"jti": "long-lived-jti",
					"iat": float64(now.Unix()),
					"exp": float64(now.Add(10 * time.Minute).Unix()),
				}
			}(),
			client:  client,
			wantErr: "lifetime exceeds maximum",
		},
		{
			name: "jti_replay_detected",
			verifier: &ClientAssertionVerifier{
				TokenEndpoint: tokenEndpoint,
			},
			claims:   validClaims(tokenEndpoint),
			client:   client,
			jtiCheck: func(string, time.Time) error { return errors.New("already seen") },
			wantErr:  "jti replay detected",
		},
		{
			name: "disallowed_algorithm",
			verifier: &ClientAssertionVerifier{
				TokenEndpoint:     tokenEndpoint,
				AllowedAlgorithms: []string{"RS256"},
			},
			claims:  validClaims(tokenEndpoint),
			client:  client,
			wantErr: "verification failed",
		},
		{
			name: "unreachable_jwks_uri",
			verifier: &ClientAssertionVerifier{
				TokenEndpoint: tokenEndpoint,
			},
			claims:  validClaims(tokenEndpoint),
			client:  &Client{JWKSURI: "http://127.0.0.1:1/nonexistent"},
			wantErr: "failed to fetch client JWKS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.jtiCheck != nil {
				tt.verifier.JTICheck = tt.jtiCheck
			}

			assertion := signAssertion(t, privKey, tt.claims)
			result, err := tt.verifier.Verify(context.Background(), assertion, tt.client)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if got := err.Error(); !contains(got, tt.wantErr) {
					t.Fatalf("error = %q, want substring %q", got, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.checkResult != nil {
				tt.checkResult(t, result)
			}
		})
	}
}

func TestClientAssertionVerifier_DefaultAlgorithms(t *testing.T) {
	expected := []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"}
	if len(defaultAllowedAlgorithms) != len(expected) {
		t.Fatalf("defaultAllowedAlgorithms length = %d, want %d", len(defaultAllowedAlgorithms), len(expected))
	}
	for i, alg := range expected {
		if defaultAllowedAlgorithms[i] != alg {
			t.Errorf("defaultAllowedAlgorithms[%d] = %q, want %q", i, defaultAllowedAlgorithms[i], alg)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestClientAssertionVerifier_ValidWithCustomAlgorithms(t *testing.T) {
	privKey, srv := testKeySetup(t)
	tokenEndpoint := "https://verifier.example.com/token"

	verifier := &ClientAssertionVerifier{
		TokenEndpoint:     tokenEndpoint,
		AllowedAlgorithms: []string{"ES256"},
	}

	assertion := signAssertion(t, privKey, validClaims(tokenEndpoint))
	result, err := verifier.Verify(context.Background(), assertion, &Client{JWKSURI: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Issuer != "client-id" {
		t.Errorf("Issuer = %q, want %q", result.Issuer, "client-id")
	}
}

func TestClientAssertionVerifier_JTICheckCalled(t *testing.T) {
	privKey, srv := testKeySetup(t)
	tokenEndpoint := "https://verifier.example.com/token"

	var capturedJTI string
	verifier := &ClientAssertionVerifier{
		TokenEndpoint: tokenEndpoint,
		JTICheck: func(jti string, exp time.Time) error {
			capturedJTI = jti
			return nil
		},
	}

	claims := validClaims(tokenEndpoint)
	claims["jti"] = "specific-jti-value"
	assertion := signAssertion(t, privKey, claims)

	_, err := verifier.Verify(context.Background(), assertion, &Client{JWKSURI: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedJTI != "specific-jti-value" {
		t.Errorf("JTICheck received jti = %q, want %q", capturedJTI, "specific-jti-value")
	}
}

func TestClientAssertionVerifier_KeyLookupFallback(t *testing.T) {
	// Test that verification works even without kid in token header
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pubJWK, err := jwk.Import(privKey.Public())
	if err != nil {
		t.Fatalf("failed to import public key: %v", err)
	}
	// Set algorithm but NO kid
	_ = pubJWK.Set(jwk.AlgorithmKey, "ES256")

	set := jwk.NewSet()
	_ = set.AddKey(pubJWK)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(srv.Close)

	tokenEndpoint := "https://verifier.example.com/token"
	verifier := &ClientAssertionVerifier{TokenEndpoint: tokenEndpoint}

	// Sign without kid in header
	token := jwt.NewWithClaims(jwt.SigningMethodES256, validClaims(tokenEndpoint))
	// No kid header set
	assertion, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	result, err := verifier.Verify(context.Background(), assertion, &Client{JWKSURI: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Subject != "client-id" {
		t.Errorf("Subject = %q, want %q", result.Subject, "client-id")
	}
}

func TestClientAssertionVerifier_InvalidJWT(t *testing.T) {
	_, srv := testKeySetup(t)
	tokenEndpoint := "https://verifier.example.com/token"

	tests := []struct {
		name      string
		assertion string
		wantErr   string
	}{
		{name: "garbage_token", assertion: "not.a.jwt", wantErr: "verification failed"},
		{name: "empty_token", assertion: "", wantErr: "verification failed"},
		{name: "partial_token", assertion: "eyJhbGciOiJFUzI1NiJ9.", wantErr: "verification failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := &ClientAssertionVerifier{TokenEndpoint: tokenEndpoint}
			_, err := verifier.Verify(context.Background(), tt.assertion, &Client{JWKSURI: srv.URL})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if got := fmt.Sprint(err); !contains(got, tt.wantErr) {
				t.Errorf("error = %q, want substring %q", got, tt.wantErr)
			}
		})
	}
}
