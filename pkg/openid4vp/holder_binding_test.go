package openid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Holder binding is what makes a presentation mean "I hold this
// credential" rather than "this credential exists". These build the two
// halves by hand so a presentation can be assembled with the KB-JWT
// signed by a key the credential does NOT name.

// issuedCredential is an issuer-signed SD-JWT naming holderKey in cnf.
func issuedCredential(t *testing.T, issuerKey, holderKey *ecdsa.PrivateKey) string {
	t.Helper()

	holderJWK := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(holderKey.PublicKey.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(holderKey.PublicKey.Y.Bytes()),
	}

	token := jwtv5.NewWithClaims(jwtv5.SigningMethodES256, jwtv5.MapClaims{
		"iss":         "https://issuer.example.com",
		"vct":         "https://credentials.example.com/identity_credential",
		"iat":         time.Now().Unix(),
		"given_name":  "Anna",
		"family_name": "Andersson",
		"cnf":         map[string]any{"jwk": holderJWK},
	})
	token.Header["typ"] = "dc+sd-jwt"

	signed, err := token.SignedString(issuerKey)
	require.NoError(t, err)
	return signed
}

// presentationSignedBy assembles the presentation: the issuer's SD-JWT
// plus a Key Binding JWT signed with signingKey, carrying the nonce and
// audience the verifier will be looking for.
func presentationSignedBy(t *testing.T, credential string, signingKey *ecdsa.PrivateKey, nonce, audience string) string {
	t.Helper()

	// sd_hash over the SD-JWT as presented, which is what a conformant
	// wallet computes.
	sdJWT := credential + "~"
	sum := sha256.Sum256([]byte(sdJWT))

	kb := jwtv5.NewWithClaims(jwtv5.SigningMethodES256, jwtv5.MapClaims{
		"nonce":   nonce,
		"aud":     audience,
		"iat":     time.Now().Unix(),
		"sd_hash": base64.RawURLEncoding.EncodeToString(sum[:]),
	})
	kb.Header["typ"] = "kb+jwt"

	signed, err := kb.SignedString(signingKey)
	require.NoError(t, err)
	return sdJWT + signed
}

// A presentation whose Key Binding JWT is signed by a key the credential
// does not name must be refused.
//
// Without this, holder binding is a formality: the validator confirmed a
// KB-JWT was PRESENT and read the nonce and audience out of its payload
// without checking who signed it. Anyone holding a copy of a genuine
// credential could append a KB-JWT of their own making, carrying the
// expected nonce and audience, and be accepted as its holder - which is
// the whole property a presentation is supposed to establish.
func TestHolderBinding_RefusesAKeyBindingJWTSignedByAnotherKey(t *testing.T) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	attackerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	const (
		nonce    = "request-nonce"
		audience = "x509_san_dns:issuer.example.com"
	)

	credential := issuedCredential(t, issuerKey, holderKey)
	validator := &VPTokenValidator{Nonce: nonce, ClientID: audience}

	t.Run("the holder's own key is accepted", func(t *testing.T) {
		presented := presentationSignedBy(t, credential, holderKey, nonce, audience)
		require.NoError(t, validator.Validate(presented),
			"a presentation by the key the credential names must verify")
	})

	t.Run("somebody else's key is refused", func(t *testing.T) {
		// Everything here is correct except who signed it: the credential
		// is genuine and issuer-signed, the nonce is this request's, the
		// audience is this verifier.
		presented := presentationSignedBy(t, credential, attackerKey, nonce, audience)

		err := validator.Validate(presented)
		require.Error(t, err, "a credential copied from its holder must not present as theirs")
		assert.Contains(t, err.Error(), "not signed by the key the credential names")
	})

	t.Run("an unsigned key binding JWT is refused", func(t *testing.T) {
		// The degenerate case: alg=none, no signature at all.
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"kb+jwt"}`))
		payload, err := json.Marshal(map[string]any{
			"nonce": nonce, "aud": audience, "iat": time.Now().Unix(),
		})
		require.NoError(t, err)
		forged := header + "." + base64.RawURLEncoding.EncodeToString(payload) + "."

		err = validator.Validate(credential + "~" + forged)
		require.Error(t, err)
	})
}

// The credential must say who holds it. One that names no key cannot be
// presented, rather than being presentable by anybody.
func TestHolderBinding_RefusesACredentialWithNoHolderKey(t *testing.T) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	someKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := jwtv5.NewWithClaims(jwtv5.SigningMethodES256, jwtv5.MapClaims{
		"iss": "https://issuer.example.com",
		"vct": "https://credentials.example.com/identity_credential",
		"iat": time.Now().Unix(),
		// No cnf.
	})
	token.Header["typ"] = "dc+sd-jwt"
	credential, err := token.SignedString(issuerKey)
	require.NoError(t, err)

	validator := &VPTokenValidator{Nonce: "n", ClientID: "aud"}
	err = validator.Validate(presentationSignedBy(t, credential, someKey, "n", "aud"))
	require.Error(t, err)
	// On the reason, not just on "holder binding": every refusal in this
	// function wraps to that, so a test stopping there cannot tell a
	// missing cnf from a bad signature and would pass with either check
	// removed.
	assert.Contains(t, err.Error(), "names no holder")
}

// A Key Binding JWT proves possession for the presentation it was made
// for, and sd_hash is what says which one that is.
//
// Without that check a proof made for one presentation of a credential is
// a proof for every presentation of it - so a holder who legitimately
// presented a credential once, disclosing a little, has handed anyone who
// saw it a reusable proof for the same credential disclosing everything.
func TestHolderBinding_RefusesAProofMadeForAnotherPresentation(t *testing.T) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	const (
		nonce    = "request-nonce"
		audience = "x509_san_dns:issuer.example.com"
	)

	// Two credentials for the same holder - two presentations the same
	// person could legitimately make.
	first := issuedCredential(t, issuerKey, holderKey)
	second := issuedCredential(t, issuerKey, holderKey)
	require.NotEqual(t, first, second, "the two presentations must differ for this to test anything")

	// The proof from the first, replayed onto the second.
	presented := presentationSignedBy(t, first, holderKey, nonce, audience)
	proof := presented[strings.LastIndex(presented, "~")+1:]
	replayed := second + "~" + proof

	validator := &VPTokenValidator{Nonce: nonce, ClientID: audience}

	require.NoError(t, validator.Validate(presented),
		"the presentation the proof was made for must still verify")

	err = validator.Validate(replayed)
	require.Error(t, err, "a proof made for another presentation must not carry over")
	assert.Contains(t, err.Error(), "sd_hash")
}
