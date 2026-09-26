// Package walletflow builds the tokens an OpenID4VCI/OpenID4VP client sends,
// for tests that drive a real wallet flow.
//
// These lived in duplicate in internal/verifier/integration and
// internal/wallet/integration, byte-for-byte apart from blank lines. Two
// copies of a signing helper is two places for a signing bug to hide, and the
// EC coordinate padding fix had to be made in both.
package walletflow

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/testsupport/jwktest"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// ComputeS256 returns the PKCE code challenge for a verifier (RFC 7636 4.2).
func ComputeS256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// DPoPProof returns a signed DPoP proof for one request (RFC 9449), carrying
// the public half in the jwk header. accessToken may be empty; when it is not,
// its S256 hash is bound in as ath.
func DPoPProof(t testing.TB, method, uri, accessToken string, key *ecdsa.PrivateKey) string {
	t.Helper()

	claims := jwtv5.MapClaims{
		"jti": uuid.New().String(),
		"htm": method,
		"htu": uri,
		"iat": time.Now().Unix(),
	}
	if accessToken != "" {
		h := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(h[:])
	}

	return signWithJWK(t, key, "dpop+jwt", claims)
}

// ProofJWT returns an OpenID4VCI proof of possession for the credential
// endpoint. cNonce may be empty when the issuer has not issued one.
func ProofJWT(t testing.TB, audience, cNonce, clientID string, key *ecdsa.PrivateKey) string {
	t.Helper()

	claims := jwtv5.MapClaims{
		"aud": audience,
		"iat": time.Now().Unix(),
		"iss": clientID,
	}
	if cNonce != "" {
		claims["nonce"] = cNonce
	}

	return signWithJWK(t, key, "openid4vci-proof+jwt", claims)
}

// SyntheticSDJWT returns an SD-JWT with no disclosures, bound to the key, for
// tests that need a well-formed credential rather than a real one.
func SyntheticSDJWT(t testing.TB, key *ecdsa.PrivateKey) string {
	t.Helper()

	claims := jwtv5.MapClaims{
		"iss":     "https://test-issuer.example.com",
		"sub":     "test-subject",
		"iat":     time.Now().Unix(),
		"exp":     time.Now().Add(1 * time.Hour).Unix(),
		"vct":     "urn:eudi:pid:1",
		"_sd_alg": "sha-256",
		"cnf": map[string]any{
			"jwk": jwktest.PublicKeyJWK(&key.PublicKey),
		},
	}

	signingMethod, _ := jose.GetSigningMethodFromKey(key)
	token := jwtv5.NewWithClaims(signingMethod, claims)
	signed, err := token.SignedString(key)
	require.NoError(t, err, "signing synthetic SD-JWT")

	// The trailing ~ is what makes it an SD-JWT with an empty disclosure list
	// rather than a plain JWT.
	return signed + "~"
}

// signWithJWK signs claims with typ set and the public key in the jwk header,
// which is the shape both the DPoP proof and the VCI proof take.
func signWithJWK(t testing.TB, key *ecdsa.PrivateKey, typ string, claims jwtv5.MapClaims) string {
	t.Helper()

	signingMethod, alg := jose.GetSigningMethodFromKey(key)
	token := jwtv5.NewWithClaims(signingMethod, claims)
	token.Header["typ"] = typ
	// alg from jose, not the library default: GetSigningMethodFromKey decides
	// the curve-appropriate algorithm and the header has to agree with it.
	token.Header["alg"] = alg
	token.Header["jwk"] = jwktest.PublicKeyJWK(&key.PublicKey)

	signed, err := token.SignedString(key)
	require.NoError(t, err, "signing %s", typ)
	return signed
}
