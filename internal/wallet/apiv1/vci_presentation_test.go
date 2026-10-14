package apiv1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signedIARequest wraps a JWT the way an Authorization Challenge Endpoint
// delivers one: the openid4vp_request member carrying a "request" string.
func signedIARequest(t *testing.T, token string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"request": token})
	require.NoError(t, err)
	return raw
}

// iaRequestClaims is a minimal but well-formed Interactive Authorization
// request object: enough that a wallet which accepted it would go on to
// encrypt a presentation to the key it names.
func iaRequestClaims() jwtv5.MapClaims {
	return jwtv5.MapClaims{
		"response_type": "vp_token",
		"response_mode": "ia_post.jwt",
		"client_id":     "x509_san_dns:issuer.example.com",
		"nonce":         "ia-nonce",
		"state":         "ia-state",
	}
}

// jwkHeaderFor is the public half of key, in the shape requestObjectKeyFunc
// reads out of a JWT header.
func jwkHeaderFor(t *testing.T, key *ecdsa.PrivateKey) map[string]any {
	t.Helper()
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(key.PublicKey.X.FillBytes(make([]byte, 32))),
		"y":   base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.FillBytes(make([]byte, 32))),
	}
}

// TestParseInteractiveAuthorizationRequest_VerifiesTheSignature pins that a
// well-formed ES256 request object signed with the key its own header
// advertises is accepted and read.
func TestParseInteractiveAuthorizationRequest_VerifiesTheSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := jwtv5.NewWithClaims(jwtv5.SigningMethodES256, iaRequestClaims())
	token.Header["jwk"] = jwkHeaderFor(t, key)
	signedToken, err := token.SignedString(key)
	require.NoError(t, err)

	c := &Client{}
	ro, err := c.parseInteractiveAuthorizationRequest(signedIARequest(t, signedToken))
	require.NoError(t, err)
	assert.Equal(t, "ia-nonce", ro.Nonce)
	assert.Equal(t, "ia-state", ro.State)
}

// TestParseInteractiveAuthorizationRequest_RefusesAlgNone is the finding
// SonarCloud raised as go:S5659. An unsigned request object names the key
// the wallet then encrypts its presentation to, so accepting one hands
// whoever wrote it the response.
func TestParseInteractiveAuthorizationRequest_RefusesAlgNone(t *testing.T) {
	token := jwtv5.NewWithClaims(jwtv5.SigningMethodNone, iaRequestClaims())
	unsigned, err := token.SignedString(jwtv5.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	c := &Client{}
	ro, err := c.parseInteractiveAuthorizationRequest(signedIARequest(t, unsigned))
	require.Error(t, err, "an alg=none request object must not be acted on")
	assert.Nil(t, ro)
}

// TestParseInteractiveAuthorizationRequest_RefusesHMAC covers the other half
// of the same rule: a symmetric algorithm proves nothing here, because the
// wallet has no shared secret with the Issuer to check it against.
func TestParseInteractiveAuthorizationRequest_RefusesHMAC(t *testing.T) {
	token := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, iaRequestClaims())
	token.Header["jwk"] = map[string]any{"kty": "oct", "k": "c2VjcmV0"}
	signedToken, err := token.SignedString([]byte("secret"))
	require.NoError(t, err)

	c := &Client{}
	_, err = c.parseInteractiveAuthorizationRequest(signedIARequest(t, signedToken))
	require.Error(t, err, "a symmetric algorithm must not be accepted")
}

// TestParseInteractiveAuthorizationRequest_RefusesTamperedPayload proves the
// signature is actually checked rather than merely required to be present.
func TestParseInteractiveAuthorizationRequest_RefusesTamperedPayload(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := jwtv5.NewWithClaims(jwtv5.SigningMethodES256, iaRequestClaims())
	token.Header["jwk"] = jwkHeaderFor(t, key)
	signedToken, err := token.SignedString(key)
	require.NoError(t, err)

	parts := strings.Split(signedToken, ".")
	require.Len(t, parts, 3)
	tampered := iaRequestClaims()
	tampered["nonce"] = "attacker-nonce"
	body, err := json.Marshal(tampered)
	require.NoError(t, err)
	parts[1] = base64.RawURLEncoding.EncodeToString(body)

	c := &Client{}
	_, err = c.parseInteractiveAuthorizationRequest(signedIARequest(t, strings.Join(parts, ".")))
	require.Error(t, err, "a request object whose payload was swapped must not verify")
}

// TestParseInteractiveAuthorizationRequest_AcceptsInlineParameters keeps the
// other delivery shape working: the draft permits the parameters inline,
// and nothing about verifying the signed form changes that.
func TestParseInteractiveAuthorizationRequest_AcceptsInlineParameters(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		"response_type": "vp_token",
		"response_mode": "ia_post.jwt",
		"nonce":         "inline-nonce",
	})
	require.NoError(t, err)

	c := &Client{}
	ro, err := c.parseInteractiveAuthorizationRequest(raw)
	require.NoError(t, err)
	assert.Equal(t, "inline-nonce", ro.Nonce)
}
