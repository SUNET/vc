package openid4vp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/sdjwtvc"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Holder binding is what makes a presentation mean "I hold this
// credential" rather than "this credential exists". These build the two
// halves by hand so a presentation can be assembled with the KB-JWT
// signed by a key the credential does NOT name.

// publicJWK renders a public key as the JWK an issuer would copy into
// cnf, using the same library the verifier parses it with so the fixture
// cannot quietly encode something no wallet would send.
func publicJWK(t *testing.T, pub any) map[string]any {
	t.Helper()

	key, err := jwk.Import(pub)
	require.NoError(t, err)
	encoded, err := json.Marshal(key)
	require.NoError(t, err)

	var jwkMap map[string]any
	require.NoError(t, json.Unmarshal(encoded, &jwkMap))
	return jwkMap
}

// issuedCredential is an issuer-signed SD-JWT naming holderKey in cnf.
func issuedCredential(t *testing.T, issuerKey, holderKey *ecdsa.PrivateKey) string {
	t.Helper()
	return issuedCredentialFor(t, issuerKey, publicJWK(t, holderKey.Public()), "")
}

// issuedCredentialFor is the same credential for an arbitrary holder JWK
// and an arbitrary declared _sd_alg. An empty sdAlg leaves the claim out,
// which the spec reads as sha-256.
func issuedCredentialFor(t *testing.T, issuerKey *ecdsa.PrivateKey, holderJWK map[string]any, sdAlg string) string {
	t.Helper()

	claims := jwtv5.MapClaims{
		"iss":         "https://issuer.example.com",
		"vct":         "https://credentials.example.com/identity_credential",
		"iat":         time.Now().Unix(),
		"given_name":  "Anna",
		"family_name": "Andersson",
		"cnf":         map[string]any{"jwk": holderJWK},
	}
	if sdAlg != "" {
		claims["_sd_alg"] = sdAlg
	}

	token := jwtv5.NewWithClaims(jwtv5.SigningMethodES256, claims)
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
	return presentationProvedWith(t, credential, jwtv5.SigningMethodES256, signingKey, nonce, audience, "sha-256")
}

// presentationProvedWith is the same, signing the Key Binding JWT with an
// arbitrary algorithm and key and taking sd_hash under an arbitrary hash
// - the two things a holder does not choose freely, since the credential
// dictates both.
func presentationProvedWith(t *testing.T, credential string, method jwtv5.SigningMethod, signingKey any, nonce, audience, sdAlg string) string {
	t.Helper()

	// sd_hash over the SD-JWT as presented, which is what a conformant
	// wallet computes.
	sdJWT := credential + "~"
	hashMethod, err := sdjwtvc.HashFromAlgorithm(sdAlg)
	require.NoError(t, err)
	hashMethod.Write([]byte(sdJWT))

	kb := jwtv5.NewWithClaims(method, jwtv5.MapClaims{
		"nonce":   nonce,
		"aud":     audience,
		"iat":     time.Now().Unix(),
		"sd_hash": base64.RawURLEncoding.EncodeToString(hashMethod.Sum(nil)),
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

// sd_hash is taken under the algorithm the ISSUER named in _sd_alg, and a
// verifier that assumes sha-256 rejects every honest holder of a
// credential issued under anything else.
//
// This repository issues and key-binds sha-384, sha-512 and the SHA-3
// variants (sdjwtvc.CreateKeyBindingJWT takes the algorithm as a
// parameter, "must match _sd_alg from SD-JWT"), so the wrong-by-default
// case is not hypothetical: it is a credential this issuer can mint.
func TestHolderBinding_TakesSDHashUnderTheIssuersSDAlg(t *testing.T) {
	const (
		nonce    = "request-nonce"
		audience = "x509_san_dns:issuer.example.com"
	)

	for _, sdAlg := range []string{"sha-256", "sha-384", "sha-512", "sha3-256", "sha3-512"} {
		t.Run(sdAlg, func(t *testing.T) {
			issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			credential := issuedCredentialFor(t, issuerKey, publicJWK(t, holderKey.Public()), sdAlg)
			validator := &VPTokenValidator{Nonce: nonce, ClientID: audience}

			require.NoError(t, validator.Validate(
				presentationProvedWith(t, credential, jwtv5.SigningMethodES256, holderKey, nonce, audience, sdAlg)),
				"a holder hashing under the algorithm the credential declares must verify")

			// And the check still bites: the same holder, same key, same
			// presentation, sd_hash taken under some other algorithm.
			other := "sha-512"
			if sdAlg == other {
				other = "sha-256"
			}
			err = validator.Validate(
				presentationProvedWith(t, credential, jwtv5.SigningMethodES256, holderKey, nonce, audience, other))
			require.Error(t, err, "sd_hash under the wrong algorithm must not pass")
			assert.Contains(t, err.Error(), "sd_hash")
		})
	}
}

// Issuance accepts EC, RSA, RSA-PSS and Ed25519 proof keys and copies the
// proof's JWK straight into cnf (openid4vci.proof_jwt), so a verifier that
// can only read EC keys makes credentials it legitimately issued
// unpresentable.
func TestHolderBinding_AcceptsEveryHolderKeyTypeIssuanceAccepts(t *testing.T) {
	const (
		nonce    = "request-nonce"
		audience = "x509_san_dns:issuer.example.com"
	)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	for _, tc := range []struct {
		name   string
		method jwtv5.SigningMethod
		key    crypto.Signer
	}{
		{"EC P-256", jwtv5.SigningMethodES256, p256},
		{"EC P-384", jwtv5.SigningMethodES384, p384},
		{"RSA", jwtv5.SigningMethodRS256, rsaKey},
		{"RSA-PSS", jwtv5.SigningMethodPS256, rsaKey},
		{"Ed25519", jwtv5.SigningMethodEdDSA, ed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			credential := issuedCredentialFor(t, issuerKey, publicJWK(t, tc.key.Public()), "")
			validator := &VPTokenValidator{Nonce: nonce, ClientID: audience}

			require.NoError(t, validator.Validate(
				presentationProvedWith(t, credential, tc.method, tc.key, nonce, audience, "sha-256")),
				"a credential issued to this key type must be presentable with it")

			// The signature check is still the thing being exercised: a
			// different key of the same type must not pass.
			impostor, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			err = validator.Validate(
				presentationProvedWith(t, credential, jwtv5.SigningMethodES256, impostor, nonce, audience, "sha-256"))
			require.Error(t, err, "another key must not present this credential")
		})
	}
}

// A symmetric cnf.jwk proves nothing: the "holder key" is a secret the
// issuer put inside the credential, so everyone who has seen the
// credential can sign a Key Binding JWT with it.
//
// Widening the parser from EC-only to every key type a JWK library will
// return is what makes this reachable, so it is refused by key type
// rather than left to whatever the verifier happens to do with bytes.
func TestHolderBinding_RefusesASymmetricHolderKey(t *testing.T) {
	const (
		nonce    = "request-nonce"
		audience = "x509_san_dns:issuer.example.com"
	)

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	secret := make([]byte, 32)
	_, err = rand.Read(secret)
	require.NoError(t, err)

	credential := issuedCredentialFor(t, issuerKey, map[string]any{
		"kty": "oct",
		"k":   base64.RawURLEncoding.EncodeToString(secret),
	}, "")

	// Signed HS256 with exactly the key the credential names - which is
	// what makes this the dangerous case rather than a malformed one.
	presented := presentationProvedWith(t, credential, jwtv5.SigningMethodHS256, secret, nonce, audience, "sha-256")

	validator := &VPTokenValidator{Nonce: nonce, ClientID: audience}
	err = validator.Validate(presented)
	require.Error(t, err, "a shared secret inside the credential cannot be a holder key")
	assert.Contains(t, err.Error(), "cannot prove possession")
}
