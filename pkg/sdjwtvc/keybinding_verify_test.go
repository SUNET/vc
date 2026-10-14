package sdjwtvc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	kbTestNonce    = "nonce-from-the-challenge"
	kbTestAudience = "ia:https://issuer.example.com/authorize-challenge"
)

// issuerClaimsBinding returns issuer claims binding the credential to key.
func issuerClaimsBinding(t *testing.T, key *ecdsa.PrivateKey) map[string]any {
	t.Helper()
	return map[string]any{
		"iss": "https://issuer.example.com",
		"vct": "urn:example:pid:1",
		"cnf": map[string]any{"jwk": map[string]any{
			"kty": "EC",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(key.PublicKey.X.FillBytes(make([]byte, 32))),
			"y":   base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.FillBytes(make([]byte, 32))),
		}},
	}
}

// presentation assembles an SD-JWT VC presentation: an issuer JWT (whose
// own signature these tests do not depend on - the caller has already
// verified it by the time VerifyKeyBinding runs), disclosures, and a
// KB-JWT signed by signWith over whatever sdHashOver says.
func presentation(t *testing.T, disclosures []string, signWith *ecdsa.PrivateKey, mutate func(jwt.MapClaims)) string {
	t.Helper()

	issuerJWT := "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSJ9.c2ln"

	var presented strings.Builder
	presented.WriteString(issuerJWT)
	for _, d := range disclosures {
		presented.WriteByte('~')
		presented.WriteString(d)
	}
	presented.WriteByte('~')

	sum := sha256.Sum256([]byte(presented.String()))
	claims := jwt.MapClaims{
		"nonce":   kbTestNonce,
		"aud":     kbTestAudience,
		"sd_hash": base64.RawURLEncoding.EncodeToString(sum[:]),
	}
	if mutate != nil {
		mutate(claims)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "kb+jwt"
	kbJWT, err := token.SignedString(signWith)
	require.NoError(t, err)

	return presented.String() + kbJWT
}

// The finding this exists for: a credential and its disclosures are a
// bearer token to anyone who obtains them, so the ONLY thing separating
// the Holder from somebody holding a copy is a key binding proof that
// actually verifies against the key the Issuer bound the credential to.
//
// Parsing the proof - reading its nonce and audience without checking the
// signature - establishes nothing: a copier fabricates those claims
// trivially, because the nonce and audience are handed to them by the
// server that is asking.
func TestVerifyKeyBindingRefusesAForgedHolderProof(t *testing.T) {
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	thief, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuerClaims := issuerClaimsBinding(t, holder)
	expected := KeyBindingExpectations{Nonce: kbTestNonce, Audience: kbTestAudience}
	disclosures := []string{"WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkFsaWNlIl0"}

	t.Run("the holder's own proof is accepted", func(t *testing.T) {
		require.NoError(t, VerifyKeyBinding(presentation(t, disclosures, holder, nil), issuerClaims, expected))
	})

	// The attack in the finding, exactly: a copied credential, the real
	// disclosures, this challenge's nonce and audience - and a proof the
	// copier signed with a key of their own.
	t.Run("a proof signed by another key is refused", func(t *testing.T) {
		err := VerifyKeyBinding(presentation(t, disclosures, thief, nil), issuerClaims, expected)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not signed by the key this credential is bound to")
	})

	t.Run("a proof for another request is refused", func(t *testing.T) {
		forged := presentation(t, disclosures, holder, func(c jwt.MapClaims) {
			c["nonce"] = "a-nonce-from-somewhere-else"
		})
		assert.ErrorContains(t, VerifyKeyBinding(forged, issuerClaims, expected), "different request")
	})

	t.Run("a proof addressed elsewhere is refused", func(t *testing.T) {
		forged := presentation(t, disclosures, holder, func(c jwt.MapClaims) {
			c["aud"] = "https://another-verifier.example"
		})
		assert.ErrorContains(t, VerifyKeyBinding(forged, issuerClaims, expected), "addressed elsewhere")
	})

	// sd_hash is what stops a valid proof being re-attached to the same
	// credential with a different set of claims disclosed.
	t.Run("a proof made over a different set of disclosures is refused", func(t *testing.T) {
		valid := presentation(t, disclosures, holder, nil)
		kbJWT := valid[strings.LastIndex(valid, "~")+1:]
		restated := strings.Join([]string{
			strings.SplitN(valid, "~", 2)[0],
			"WyJzYWx0IiwiYmlydGhkYXRlIiwiMTk4MC0wMS0wMSJd",
			kbJWT,
		}, "~")

		assert.ErrorContains(t, VerifyKeyBinding(restated, issuerClaims, expected), "not made over this presentation")
	})

	t.Run("a JWT minted for another purpose is refused", func(t *testing.T) {
		valid := presentation(t, disclosures, holder, nil)
		head, _, _ := strings.Cut(valid, "~")

		sum := sha256.Sum256([]byte(head + "~" + disclosures[0] + "~"))
		other := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
			"nonce":   kbTestNonce,
			"aud":     kbTestAudience,
			"sd_hash": base64.RawURLEncoding.EncodeToString(sum[:]),
		})
		other.Header["typ"] = "JWT"
		signed, err := other.SignedString(holder)
		require.NoError(t, err)

		err = VerifyKeyBinding(head+"~"+disclosures[0]+"~"+signed, issuerClaims, expected)
		assert.ErrorContains(t, err, "kb+jwt")
	})

	t.Run("a presentation with no proof at all is refused", func(t *testing.T) {
		head, _, _ := strings.Cut(presentation(t, disclosures, holder, nil), "~")
		assert.ErrorContains(t, VerifyKeyBinding(head+"~"+disclosures[0]+"~", issuerClaims, expected),
			"no key binding proof")
	})

	// A presenter must not be able to nominate the key their proof is
	// checked against; that is the same hole one level up.
	t.Run("a credential bound to no key cannot be presented", func(t *testing.T) {
		unbound := map[string]any{"iss": "https://issuer.example.com"}
		assert.ErrorContains(t, VerifyKeyBinding(presentation(t, disclosures, thief, nil), unbound, expected),
			"bound to no key")
	})

	// A verifier with nothing to bind to must refuse rather than skip:
	// a presentation with no nonce to replay against is replayable.
	t.Run("no expectations is refused rather than skipped", func(t *testing.T) {
		valid := presentation(t, disclosures, holder, nil)
		assert.Error(t, VerifyKeyBinding(valid, issuerClaims, KeyBindingExpectations{Audience: kbTestAudience}))
		assert.Error(t, VerifyKeyBinding(valid, issuerClaims, KeyBindingExpectations{Nonce: kbTestNonce}))
	})
}

// A sanity check that the fixture is not accidentally proving the tests
// above by being malformed.
func TestVerifyKeyBindingFixtureIsWellFormed(t *testing.T) {
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	vpToken := presentation(t, []string{"WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkFsaWNlIl0"}, holder, nil)
	issuerJWT, disclosures, kbJWT, err := splitPresentation(vpToken)
	require.NoError(t, err)
	assert.Equal(t, 2, strings.Count(issuerJWT, "."))
	assert.Len(t, disclosures, 1)
	assert.Equal(t, 2, strings.Count(kbJWT, "."))

	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(kbJWT, ".")[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	assert.Equal(t, kbTestNonce, claims["nonce"])
}
