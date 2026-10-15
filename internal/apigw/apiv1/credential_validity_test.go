package apiv1

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A signature says who issued a credential, not that it is still valid.
//
// JWTTrustVerifier.VerifyJWTSignature parses with
// jwt.WithoutClaimsValidation - it is answering "who signed this" - and
// neither the VP validator nor the credential parser reads exp or nbf. So
// an expired credential presented with a freshly signed key binding proof
// was accepted: the holder really does hold the key, the nonce really is
// this request's, and the credential really did stop being valid. A fresh
// proof does not renew a credential.
func TestValidIssuerCredentialWindow(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	t.Run("a credential inside its window is accepted", func(t *testing.T) {
		claims := jwt.MapClaims{
			"nbf": float64(now.Add(-time.Hour).Unix()),
			"exp": float64(now.Add(time.Hour).Unix()),
		}
		assert.NoError(t, validIssuerCredentialWindow(claims, now))
	})

	t.Run("an expired credential is refused", func(t *testing.T) {
		claims := jwt.MapClaims{"exp": float64(now.Add(-24 * time.Hour).Unix())}
		err := validIssuerCredentialWindow(claims, now)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("a credential that has not started is refused", func(t *testing.T) {
		claims := jwt.MapClaims{"nbf": float64(now.Add(24 * time.Hour).Unix())}
		err := validIssuerCredentialWindow(claims, now)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not valid until")
	})

	// exp is OPTIONAL in SD-JWT VC, so a credential without one is valid
	// by its own terms and must not be refused for omitting it.
	t.Run("a credential with no dates is accepted", func(t *testing.T) {
		assert.NoError(t, validIssuerCredentialWindow(jwt.MapClaims{"iss": "https://issuer.example"}, now))
	})

	// Clocks differ by seconds between an Issuer, a device and this
	// server, and a user cannot act on a credential refused for being one
	// second early.
	t.Run("a little clock skew is tolerated in both directions", func(t *testing.T) {
		assert.NoError(t, validIssuerCredentialWindow(
			jwt.MapClaims{"exp": float64(now.Add(-5 * time.Second).Unix())}, now))
		assert.NoError(t, validIssuerCredentialWindow(
			jwt.MapClaims{"nbf": float64(now.Add(5 * time.Second).Unix())}, now))

		// But not an unbounded amount of it.
		assert.Error(t, validIssuerCredentialWindow(
			jwt.MapClaims{"exp": float64(now.Add(-10 * time.Minute).Unix())}, now))
	})

	// A claim that is present but is not a date is REFUSED, and that is
	// the third case - not the same as absent and not the same as a date.
	//
	// Absent means the issuer placed no restriction. Present-but-
	// malformed means it placed one this server cannot read, and
	// accepting the credential without it decides in the presenter's
	// favour a question we were unable to answer. Nothing upstream
	// catches it either: the issuer signature check runs with claims
	// validation off.
	//
	// Reading it as zero would be the opposite failure - 1970, expiring
	// every credential carrying one - so it cannot simply be parsed
	// loosely instead.
	t.Run("a date that is not a date is refused", func(t *testing.T) {
		for _, malformed := range []any{
			"not-a-date",
			map[string]any{"iso": "2026-01-01"},
			[]any{1, 2},
			true,
			json.Number("not-a-number"),
		} {
			err := validIssuerCredentialWindow(jwt.MapClaims{"exp": malformed}, now)
			require.Error(t, err, "exp = %#v must be refused, not ignored", malformed)
			assert.Contains(t, err.Error(), "exp")
		}

		// And the same for nbf, which has the same problem and the
		// opposite effect if ignored.
		err := validIssuerCredentialWindow(jwt.MapClaims{"nbf": "not-a-date"}, now)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nbf")
	})

	// An explicit null is the absence of a value, not a malformed one.
	t.Run("a null date is absent", func(t *testing.T) {
		assert.NoError(t, validIssuerCredentialWindow(jwt.MapClaims{"exp": nil}, now))
	})

	// The integer forms a decoder may produce are all dates.
	t.Run("integer forms are read", func(t *testing.T) {
		for _, v := range []any{
			float64(now.Add(time.Hour).Unix()),
			int64(now.Add(time.Hour).Unix()),
			int(now.Add(time.Hour).Unix()),
		} {
			assert.NoError(t, validIssuerCredentialWindow(jwt.MapClaims{"exp": v}, now), "%T", v)
		}
	})

	// json.Number is what a decoder configured with UseNumber produces,
	// and it has to be read as a date rather than silently ignored.
	t.Run("json.Number dates are read", func(t *testing.T) {
		claims := jwt.MapClaims{"exp": json.Number("1000000000")}
		err := validIssuerCredentialWindow(claims, now)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})
}
