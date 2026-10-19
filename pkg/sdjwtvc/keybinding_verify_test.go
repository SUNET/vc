package sdjwtvc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

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
	return presentationSigned(t, disclosures, "sha-256", jwt.SigningMethodES256, signWith, mutate)
}

// presentationSigned is the same fixture with the credential's hash
// algorithm and the holder's key type both chosen by the caller.
func presentationSigned(t *testing.T, disclosures []string, sdAlg string, method jwt.SigningMethod, signWith any, mutate func(jwt.MapClaims)) string {
	t.Helper()

	issuerJWT := "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSJ9.c2ln"

	var presented strings.Builder
	presented.WriteString(issuerJWT)
	for _, d := range disclosures {
		presented.WriteByte('~')
		presented.WriteString(d)
	}
	presented.WriteByte('~')

	hasher, err := getHashFromAlgorithm(sdAlg)
	require.NoError(t, err)
	hasher.Write([]byte(presented.String()))

	claims := jwt.MapClaims{
		"nonce":   kbTestNonce,
		"aud":     kbTestAudience,
		"iat":     time.Now().Unix(),
		"sd_hash": base64.RawURLEncoding.EncodeToString(hasher.Sum(nil)),
	}
	// Before mutate, so a test can replace or remove it. A fixture that
	// omitted iat is what let the missing check go unnoticed: every
	// successful case here was a proof with no issuance time at all.
	if mutate != nil {
		mutate(claims)
	}

	token := jwt.NewWithClaims(method, claims)
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

		hasher, err := getHashFromAlgorithm("sha-256")
		require.NoError(t, err)
		hasher.Write([]byte(head + "~" + disclosures[0] + "~"))
		other := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
			"nonce":   kbTestNonce,
			"aud":     kbTestAudience,
			"iat":     time.Now().Unix(),
			"sd_hash": base64.RawURLEncoding.EncodeToString(hasher.Sum(nil)),
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

// sd_hash is computed under the hash the ISSUER chose, not under SHA-256
// always.
//
// _sd_alg is what the credential's own disclosure digests use, and
// CreateKeyBindingJWT already takes it - so a holder presenting a
// sha-384 or sha-512 credential computes sd_hash with that, and a
// verifier hardcoding SHA-256 refuses a correct proof. It is read from the
// VERIFIED issuer claims, so a presenter cannot nominate a weaker hash for
// its own proof.
func TestVerifyKeyBindingUsesTheCredentialsHashAlgorithm(t *testing.T) {
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	disclosures := []string{"WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkFsaWNlIl0"}
	expected := KeyBindingExpectations{Nonce: kbTestNonce, Audience: kbTestAudience}

	for _, sdAlg := range []string{"sha-256", "sha-384", "sha-512"} {
		t.Run(sdAlg, func(t *testing.T) {
			issuerClaims := issuerClaimsBinding(t, holder)
			issuerClaims["_sd_alg"] = sdAlg

			vpToken := presentationSigned(t, disclosures, sdAlg, jwt.SigningMethodES256, holder, nil)
			require.NoError(t, VerifyKeyBinding(vpToken, issuerClaims, expected))
		})
	}

	// Absent means sha-256 (SD-JWT VC §4.1.1), which is the case a
	// hardcoded SHA-256 got right and the reason this went unnoticed.
	t.Run("absent _sd_alg is sha-256", func(t *testing.T) {
		issuerClaims := issuerClaimsBinding(t, holder)
		vpToken := presentationSigned(t, disclosures, "sha-256", jwt.SigningMethodES256, holder, nil)
		require.NoError(t, VerifyKeyBinding(vpToken, issuerClaims, expected))
	})

	// The hash is the credential's, so a proof computed under a different
	// one does not match - which is also what stops a presenter choosing
	// a weaker hash for its own proof.
	t.Run("a proof under another hash is refused", func(t *testing.T) {
		issuerClaims := issuerClaimsBinding(t, holder)
		issuerClaims["_sd_alg"] = "sha-512"

		vpToken := presentationSigned(t, disclosures, "sha-256", jwt.SigningMethodES256, holder, nil)
		assert.ErrorContains(t, VerifyKeyBinding(vpToken, issuerClaims, expected), "not made over this presentation")
	})

	t.Run("a hash this build cannot compute is refused", func(t *testing.T) {
		issuerClaims := issuerClaimsBinding(t, holder)
		issuerClaims["_sd_alg"] = "md5"

		vpToken := presentationSigned(t, disclosures, "sha-256", jwt.SigningMethodES256, holder, nil)
		assert.ErrorContains(t, VerifyKeyBinding(vpToken, issuerClaims, expected), "_sd_alg")
	})
}

// A credential may be bound to an RSA or Ed25519 key, and this server
// advertises both families in its proof algorithms and request metadata.
//
// The package's own jwkToPublicKey handles EC alone - it returns an error
// for RSA and has no OKP branch - so routing cnf through it made those
// credentials impossible to present, however correct the proof, while the
// server went on asking wallets for them.
func TestVerifyKeyBindingAcceptsEveryAdvertisedKeyFamily(t *testing.T) {
	disclosures := []string{"WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkFsaWNlIl0"}
	expected := KeyBindingExpectations{Nonce: kbTestNonce, Audience: kbTestAudience}

	t.Run("RSA", func(t *testing.T) {
		holder, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		issuerClaims := map[string]any{"cnf": map[string]any{"jwk": map[string]any{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(holder.PublicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(holder.PublicKey.E)).Bytes()),
		}}}

		vpToken := presentationSigned(t, disclosures, "sha-256", jwt.SigningMethodRS256, holder, nil)
		require.NoError(t, VerifyKeyBinding(vpToken, issuerClaims, expected))

		// And a proof from another RSA key is still refused, so the
		// family being accepted has not weakened the check.
		thief, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		forged := presentationSigned(t, disclosures, "sha-256", jwt.SigningMethodRS256, thief, nil)
		assert.ErrorContains(t, VerifyKeyBinding(forged, issuerClaims, expected), "not signed by the key")
	})

	t.Run("Ed25519", func(t *testing.T) {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		issuerClaims := map[string]any{"cnf": map[string]any{"jwk": map[string]any{
			"kty": "OKP",
			"crv": "Ed25519",
			"x":   base64.RawURLEncoding.EncodeToString(public),
		}}}

		vpToken := presentationSigned(t, disclosures, "sha-256", jwt.SigningMethodEdDSA, private, nil)
		require.NoError(t, VerifyKeyBinding(vpToken, issuerClaims, expected))

		_, thief, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		forged := presentationSigned(t, disclosures, "sha-256", jwt.SigningMethodEdDSA, thief, nil)
		assert.ErrorContains(t, VerifyKeyBinding(forged, issuerClaims, expected), "not signed by the key")
	})

	// A cnf that is not an asymmetric public key at all must be refused
	// rather than reaching the parser as "some key".
	t.Run("a symmetric key is not something a credential may be bound to", func(t *testing.T) {
		issuerClaims := map[string]any{"cnf": map[string]any{"jwk": map[string]any{
			"kty": "oct",
			"k":   base64.RawURLEncoding.EncodeToString([]byte("not-a-public-key-at-all-really")),
		}}}

		holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		vpToken := presentationSigned(t, disclosures, "sha-256", jwt.SigningMethodES256, holder, nil)
		assert.Error(t, VerifyKeyBinding(vpToken, issuerClaims, expected))
	})
}

// iat is REQUIRED of a key binding proof, and nothing here was reading it.
//
// The parser does not check iat by default; enabling its check would not
// have been enough either, because that only rejects a FUTURE stamp and
// treats a missing claim as fine. It also cannot see an iat of exactly 0:
// MapClaims.GetIssuedAt reports the Unix epoch and an absent claim
// identically, as "no error and no date", which is why this check reads
// the claim itself.
func TestVerifyKeyBindingRequiresAFreshIssuedAt(t *testing.T) {
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	issuerClaims := issuerClaimsBinding(t, holder)
	disclosures := []string{"WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkFsaWNlIl0"}
	now := time.Now()
	expected := KeyBindingExpectations{Nonce: kbTestNonce, Audience: kbTestAudience, Now: now}

	for _, tc := range []struct {
		name     string
		iat      any
		remove   bool
		contains string // empty means the proof must be accepted
	}{
		{name: "signed just now", iat: now.Unix()},
		{name: "a fractional NumericDate, which RFC 7519 allows", iat: float64(now.Unix()) + 0.5},
		{name: "inside the window", iat: now.Add(-4 * time.Minute).Unix()},
		{name: "a little ahead, within the clock skew", iat: now.Add(30 * time.Second).Unix()},

		{name: "absent", remove: true, contains: "carries no iat"},
		{name: "the Unix epoch, which the parser cannot tell from absent", iat: 0, contains: "was made"},
		{name: "older than the window", iat: now.Add(-10 * time.Minute).Unix(), contains: "was made"},
		{name: "a decade old", iat: now.AddDate(-10, 0, 0).Unix(), contains: "was made"},
		{name: "stamped in the future", iat: now.Add(2 * time.Hour).Unix(), contains: "in the future"},
		{name: "a string spelling of a date", iat: "1700000000", contains: "not a NumericDate"},
		{name: "an object", iat: map[string]any{"seconds": 1}, contains: "not a NumericDate"},
		{name: "a boolean", iat: true, contains: "not a NumericDate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vpToken := presentation(t, disclosures, holder, func(claims jwt.MapClaims) {
				if tc.remove {
					delete(claims, "iat")
					return
				}
				claims["iat"] = tc.iat
			})

			err := VerifyKeyBinding(vpToken, issuerClaims, expected)
			if tc.contains == "" {
				assert.NoError(t, err, "a proof inside the freshness window must be accepted")
				return
			}
			assert.ErrorContains(t, err, tc.contains)
		})
	}
}

// The window is the caller's to set, and zero means the package default
// rather than "no window at all" - a zero-value Expectations must not
// accept a proof from any moment in history.
func TestVerifyKeyBindingFreshnessWindowIsConfigurable(t *testing.T) {
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	issuerClaims := issuerClaimsBinding(t, holder)
	disclosures := []string{"WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkFsaWNlIl0"}
	now := time.Now()

	anHourOld := presentation(t, disclosures, holder, func(claims jwt.MapClaims) {
		claims["iat"] = now.Add(-time.Hour).Unix()
	})

	assert.ErrorContains(t,
		VerifyKeyBinding(anHourOld, issuerClaims, KeyBindingExpectations{
			Nonce: kbTestNonce, Audience: kbTestAudience, Now: now,
		}), "was made", "the default window is %s, not unbounded", DefaultKeyBindingMaxAge)

	assert.NoError(t,
		VerifyKeyBinding(anHourOld, issuerClaims, KeyBindingExpectations{
			Nonce: kbTestNonce, Audience: kbTestAudience, Now: now,
			MaxAge: 2 * time.Hour,
		}), "a caller that widened the window must get the wider window")

	// And a caller that leaves Now zero measures against the real clock,
	// which is what every caller outside a test does.
	fresh := presentation(t, disclosures, holder, nil)
	assert.NoError(t, VerifyKeyBinding(fresh, issuerClaims, KeyBindingExpectations{
		Nonce: kbTestNonce, Audience: kbTestAudience,
	}))
}
