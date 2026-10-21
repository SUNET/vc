package apiv1

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/SUNET/vc/internal/wallet/credential"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ecdhKey(t *testing.T, kid string) (private, public jwk.Key) {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	private, err = jwk.Import(priv)
	require.NoError(t, err)
	require.NoError(t, private.Set(jwk.KeyIDKey, kid))
	public, err = private.PublicKey()
	require.NoError(t, err)
	return private, public
}

func rsaPublicKey(t *testing.T, kid string) jwk.Key {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	key, err := jwk.Import(priv.Public())
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, kid))
	return key
}

func requestWithKeys(keys ...jwk.Key) *openid4vp.RequestObject {
	return &openid4vp.RequestObject{
		ClientMetadata: &openid4vp.ClientMetadata{JWKS: &openid4vp.Keys{Keys: keys}},
	}
}

func TestEncryptToRequestKey_SkipsAKeyItCannotUse(t *testing.T) {
	private, public := ecdhKey(t, "enc")

	encrypted, err := encryptToRequestKey(requestWithKeys(rsaPublicKey(t, "rsa"), public), []byte(`{"ok":true}`))
	require.NoError(t, err)

	decrypted, err := jwe.Decrypt([]byte(encrypted), jwe.WithKey(jwa.ECDH_ES(), private))
	require.NoError(t, err, "the response must be encrypted to the usable EC key, not the first one")
	assert.JSONEq(t, `{"ok":true}`, string(decrypted))
}

func TestEncryptToRequestKey_SkipsASigningOnlyKey(t *testing.T) {
	_, signing := ecdhKey(t, "sig")
	require.NoError(t, signing.Set(jwk.KeyUsageKey, jwk.ForSignature))
	private, enc := ecdhKey(t, "enc")
	require.NoError(t, enc.Set(jwk.KeyUsageKey, jwk.ForEncryption))

	encrypted, err := encryptToRequestKey(requestWithKeys(signing, enc), []byte(`{}`))
	require.NoError(t, err)
	_, err = jwe.Decrypt([]byte(encrypted), jwe.WithKey(jwa.ECDH_ES(), private))
	require.NoError(t, err, "a key marked use=sig must not be encrypted to")
}

func TestEncryptToRequestKey_NoUsableKeyIsAnError(t *testing.T) {
	_, signing := ecdhKey(t, "sig")
	require.NoError(t, signing.Set(jwk.KeyUsageKey, jwk.ForSignature))
	_, wrongAlg := ecdhKey(t, "alg")
	require.NoError(t, wrongAlg.Set(jwk.AlgorithmKey, jwa.ES256()))
	_, wrongOps := ecdhKey(t, "ops")
	require.NoError(t, wrongOps.Set(jwk.KeyOpsKey, jwk.KeyOperationList{jwk.KeyOpVerify}))

	_, err := encryptToRequestKey(requestWithKeys(rsaPublicKey(t, "rsa"), signing, wrongAlg, wrongOps), []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "usable for ECDH-ES")
}

// This wallet cannot read W3C types, so a type_values query must match
// nothing rather than every credential of the format.
func TestMatchingCredentials_TypeValuesMatchNothing(t *testing.T) {
	candidates := []*credential.StoredCredential{{Format: "jwt_vc_json", RawCredential: "x"}}

	constrained := openid4vp.CredentialQuery{
		ID:     "w3c",
		Format: "jwt_vc_json",
		Meta:   openid4vp.MetaQuery{TypeValues: [][]string{{"UniversityDegreeCredential"}}},
	}
	assert.Empty(t, matchingCredentials(candidates, constrained))

	unconstrained := openid4vp.CredentialQuery{ID: "w3c", Format: "jwt_vc_json"}
	assert.Len(t, matchingCredentials(candidates, unconstrained), 1)
}
