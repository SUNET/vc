package openid4vci

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"maps"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwe/jwebb"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rfc7518AppendixC is the worked ECDH-ES example in RFC 7518 Appendix C:
// Alice encrypting to Bob with ECDH-ES Direct Key Agreement for A128GCM.
//
// It is the one place where someone other than this codebase has written
// down both the inputs and the answer, which is what makes it worth more
// than any round trip this file could do with itself: a round trip passes
// just as happily if the KDF is wrong in both directions.
var rfc7518AppendixC = struct {
	aliceJWK, bobJWK string
	z                []byte
	derived          string
}{
	aliceJWK: `{"kty":"EC","crv":"P-256",
		"x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
		"y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
		"d":"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"}`,
	bobJWK: `{"kty":"EC","crv":"P-256",
		"x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
		"y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
		"d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}`,
	z: []byte{
		158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132,
		38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121,
		140, 254, 144, 196,
	},
	derived: "VqqN6vgjbSBcIijNcacQGg",
}

// TestConcatKDF_RFC7518AppendixC is the known-answer test for the Concat
// KDF, run against the RFC's own arithmetic rather than against jwx.
func TestConcatKDF_RFC7518AppendixC(t *testing.T) {
	// keydatalen 128 bits, AlgorithmID "A128GCM" (the enc value, because
	// the example is Direct Key Agreement), apu "Alice", apv "Bob".
	got := concatKDF(crypto.SHA256, rfc7518AppendixC.z,
		[]byte("A128GCM"), []byte("Alice"), []byte("Bob"), 16)

	assert.Equal(t, rfc7518AppendixC.derived, base64.RawURLEncoding.EncodeToString(got))
}

// TestSoftwareKeyAgreement_RFC7518AppendixC checks the key agreement that
// feeds the KDF: Bob's key and Alice's ephemeral public key must produce
// exactly the Z the RFC prints.
func TestSoftwareKeyAgreement_RFC7518AppendixC(t *testing.T) {
	bob := parseECPrivateJWK(t, rfc7518AppendixC.bobJWK)
	alice := parseECPrivateJWK(t, rfc7518AppendixC.aliceJWK)

	key, err := NewSoftwareKeyAgreementKey(bob)
	require.NoError(t, err)

	peer, err := alice.PublicKey.ECDH()
	require.NoError(t, err)

	z, err := key.ECDH(peer)
	require.NoError(t, err)
	assert.Equal(t, rfc7518AppendixC.z, z)

	// And end to end through the shape vc actually uses, so a mistake in
	// how the two are wired together cannot hide between two passing
	// halves.
	kek := concatKDF(crypto.SHA256, z, []byte("A128GCM"), []byte("Alice"), []byte("Bob"), 16)
	assert.Equal(t, rfc7518AppendixC.derived, base64.RawURLEncoding.EncodeToString(kek))
}

// TestConcatKDF_LongerThanOneDigest pins the round counter: a key longer
// than the hash output is the concatenation of successive hashes, and a
// loop that forgot to increment it would repeat its first block.
//
// The expectation is spelled out from SP 800-56A here rather than taken
// from the RFC, which only works one round. Note that OtherInfo is not the
// RFC's: SuppPubInfo is the key length, so asking for a longer key changes
// the hash input rather than extending the same stream.
func TestConcatKDF_LongerThanOneDigest(t *testing.T) {
	got := concatKDF(crypto.SHA256, rfc7518AppendixC.z,
		[]byte("A128GCM"), []byte("Alice"), []byte("Bob"), 64)
	require.Len(t, got, 64)

	otherInfo := []byte{
		0, 0, 0, 7, 'A', '1', '2', '8', 'G', 'C', 'M',
		0, 0, 0, 5, 'A', 'l', 'i', 'c', 'e',
		0, 0, 0, 3, 'B', 'o', 'b',
		0, 0, 2, 0, // 512 bits
	}
	var want []byte
	for round := 1; round <= 2; round++ {
		h := sha256.New()
		h.Write([]byte{0, 0, 0, byte(round)})
		h.Write(rfc7518AppendixC.z)
		h.Write(otherInfo)
		want = h.Sum(want)
	}

	assert.Equal(t, want, got)
	assert.NotEqual(t, got[:32], got[32:], "round 2 repeated round 1")
}

// TestDecryptRequest_HSMShapedKey runs a real JWE through the decryption
// path a PKCS#11 key takes - a KeyAgreementKey that is not an
// *ecdsa.PrivateKey, so NewCredentialEncryption cannot unwrap it into one -
// without needing a token. The SoftHSM tests in pkg/pki prove the same
// thing with a real module; this one proves it in every CI run.
func TestDecryptRequest_HSMShapedKey(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	enc, err := NewCredentialEncryption([]crypto.PrivateKey{opaqueKeyAgreement{key: private}}, false, false)
	require.NoError(t, err)
	require.True(t, enc.Enabled())

	set, err := jwk.Parse(enc.RequestMetadata().JWKS)
	require.NoError(t, err)
	published, ok := set.Key(0)
	require.True(t, ok)

	payload := []byte(`{"credential_configuration_id":"hsm"}`)
	encrypted, err := jwe.Encrypt(payload,
		jwe.WithKey(jwa.ECDH_ES_A256KW(), published),
		jwe.WithContentEncryption(jwa.A256GCM()))
	require.NoError(t, err)

	got, err := enc.DecryptRequest(encrypted)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

// opaqueKeyAgreement is a KeyAgreementKey that hides its private key the
// way a token does: nothing can recover an *ecdsa.PrivateKey from it.
type opaqueKeyAgreement struct {
	key *ecdsa.PrivateKey
}

func (o opaqueKeyAgreement) PublicKey() *ecdsa.PublicKey { return &o.key.PublicKey }

func (o opaqueKeyAgreement) ECDH(peer *ecdh.PublicKey) ([]byte, error) {
	private, err := o.key.ECDH()
	if err != nil {
		return nil, err
	}
	return private.ECDH(peer)
}

func parseECPrivateJWK(t *testing.T, serialized string) *ecdsa.PrivateKey {
	t.Helper()
	key, err := jwk.ParseKey([]byte(serialized))
	require.NoError(t, err)
	var private ecdsa.PrivateKey
	require.NoError(t, jwk.Export(key, &private))
	return &private
}

// TestDecryptRequest_BadEphemeralKeyIsRefused covers the two ways the epk
// header can be wrong, and in both cases asserts not only that the request
// was refused but that no key agreement was performed.
//
// That second assertion is the point. An attacker who can get an issuer to
// run an agreement against a point of their choosing - one off the curve,
// or on a different curve - recovers the private key a few bits at a time,
// and an HSM will derive from whatever point it is handed. So the check has
// to happen before the key is reached, not after it fails.
//
// Where it happens differs by case, and the layering is deliberate. jwx
// refuses to build an EC JWK whose point is off the curve, so the off-curve
// case never reaches this package - measured, not assumed: breaking
// ephemeralPublicKey's own check leaves that subtest passing. The wrong
// curve does reach it, and ephemeralPublicKey is what refuses it. The
// off-curve subtest is kept anyway: it pins the property at the endpoint,
// which is where it matters, rather than at whichever layer currently
// delivers it.
func TestDecryptRequest_BadEphemeralKeyIsRefused(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spy := &countingKeyAgreement{opaqueKeyAgreement: opaqueKeyAgreement{key: private}}
	enc, err := NewCredentialEncryption([]crypto.PrivateKey{spy}, false, false)
	require.NoError(t, err)

	set, err := jwk.Parse(enc.RequestMetadata().JWKS)
	require.NoError(t, err)
	published, ok := set.Key(0)
	require.True(t, ok)

	encrypted, err := jwe.Encrypt([]byte(`{"x":1}`),
		jwe.WithKey(jwa.ECDH_ES_A256KW(), published),
		jwe.WithContentEncryption(jwa.A256GCM()))
	require.NoError(t, err)

	// Sanity: the unmodified JWE decrypts, and does so through the key, so
	// the agreement count below is a count of something that happens.
	_, err = enc.DecryptRequest(encrypted)
	require.NoError(t, err)
	require.Equal(t, 1, spy.calls)

	for _, tc := range []struct {
		name   string
		tamper func(t *testing.T, epk map[string]any)
	}{
		{
			// One bit of y. x stays a valid field element, so nothing but
			// the curve equation can tell the difference.
			name: "off the curve",
			tamper: func(t *testing.T, epk map[string]any) {
				y, err := base64.RawURLEncoding.DecodeString(epk["y"].(string))
				require.NoError(t, err)
				y[len(y)-1] ^= 0x01
				epk["y"] = base64.RawURLEncoding.EncodeToString(y)
			},
		},
		{
			// A perfectly good public key, on a curve this issuer's key is
			// not on. jwx parses it happily.
			name: "a different curve",
			tamper: func(t *testing.T, epk map[string]any) {
				other, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				key, err := jwk.Import(other.PublicKey)
				require.NoError(t, err)
				serialized, err := json.Marshal(key)
				require.NoError(t, err)
				var replacement map[string]any
				require.NoError(t, json.Unmarshal(serialized, &replacement))
				clear(epk)
				maps.Copy(epk, replacement)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := spy.calls

			segments := bytes.Split(encrypted, []byte("."))
			require.Len(t, segments, 5)
			raw, err := base64.RawURLEncoding.DecodeString(string(segments[0]))
			require.NoError(t, err)

			var header map[string]any
			require.NoError(t, json.Unmarshal(raw, &header))
			epk, ok := header["epk"].(map[string]any)
			require.True(t, ok)
			tc.tamper(t, epk)

			tampered, err := json.Marshal(header)
			require.NoError(t, err)
			segments[0] = []byte(base64.RawURLEncoding.EncodeToString(tampered))

			_, err = enc.DecryptRequest(bytes.Join(segments, []byte(".")))
			require.Error(t, err)
			assert.Equal(t, before, spy.calls, "the bad point reached the private key")
		})
	}
}

// countingKeyAgreement records how many agreements the decrypter asked for.
type countingKeyAgreement struct {
	opaqueKeyAgreement
	calls int
}

func (c *countingKeyAgreement) ECDH(peer *ecdh.PublicKey) ([]byte, error) {
	c.calls++
	return c.opaqueKeyAgreement.ECDH(peer)
}

// TestDecryptRequest_ContentKeyMustMatchTheEnc builds the JWE by hand, which
// jwe.Encrypt will not do: it wraps a content encryption key of the wrong
// length for the enc the header announces.
//
// aes.NewCipher takes 16, 24 or 32 bytes, so without a length check the
// endpoint would decrypt an "A256GCM" request under AES-128. The 32-byte
// case is here too, and it is the one that earns the test: a hand-built JWE
// that decrypts is independent evidence that concatKDF agrees with the KEK
// jwx derives on the other side.
func TestDecryptRequest_ContentKeyMustMatchTheEnc(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	enc, err := NewCredentialEncryption([]crypto.PrivateKey{private}, false, false)
	require.NoError(t, err)

	set, err := jwk.Parse(enc.RequestMetadata().JWKS)
	require.NoError(t, err)
	published, ok := set.Key(0)
	require.True(t, ok)
	kid, ok := published.KeyID()
	require.True(t, ok)

	payload := []byte(`{"credential_configuration_id":"hand-built"}`)

	t.Run("32 bytes decrypts", func(t *testing.T) {
		got, err := enc.DecryptRequest(buildJWE(t, &private.PublicKey, kid, payload, 32))
		require.NoError(t, err)
		assert.Equal(t, payload, got)
	})

	t.Run("16 bytes is refused", func(t *testing.T) {
		_, err := enc.DecryptRequest(buildJWE(t, &private.PublicKey, kid, payload, 16))
		assert.Error(t, err)
	})
}

// buildJWE assembles an ECDH-ES+A256KW / A256GCM compact JWE for the issuer
// key, with a content encryption key of the caller's chosen length.
func buildJWE(t *testing.T, issuer *ecdsa.PublicKey, kid string, payload []byte, cekLen int) []byte {
	t.Helper()

	ephemeral, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ephemeralPrivate, err := ephemeral.ECDH()
	require.NoError(t, err)
	issuerECDH, err := issuer.ECDH()
	require.NoError(t, err)
	z, err := ephemeralPrivate.ECDH(issuerECDH)
	require.NoError(t, err)

	epk, err := jwk.Import(ephemeral.PublicKey)
	require.NoError(t, err)
	epkJSON, err := json.Marshal(epk)
	require.NoError(t, err)
	var epkFields map[string]any
	require.NoError(t, json.Unmarshal(epkJSON, &epkFields))

	header, err := json.Marshal(map[string]any{
		"alg": AlgECDHESA256KW,
		"enc": EncA256GCM,
		"kid": kid,
		"epk": epkFields,
	})
	require.NoError(t, err)
	protected := base64.RawURLEncoding.EncodeToString(header)

	kek := concatKDF(crypto.SHA256, z, []byte(AlgECDHESA256KW), nil, nil, a256kwKeySize)
	kekBlock, err := aes.NewCipher(kek)
	require.NoError(t, err)

	cek := make([]byte, cekLen)
	_, err = rand.Read(cek)
	require.NoError(t, err)
	wrapped, err := jwebb.Wrap(kekBlock, cek)
	require.NoError(t, err)

	block, err := aes.NewCipher(cek)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	iv := make([]byte, aead.NonceSize())
	_, err = rand.Read(iv)
	require.NoError(t, err)
	sealed := aead.Seal(nil, iv, payload, []byte(protected))
	ciphertext, tag := sealed[:len(sealed)-aead.Overhead()], sealed[len(sealed)-aead.Overhead():]

	b64 := base64.RawURLEncoding.EncodeToString
	return []byte(strings.Join([]string{protected, b64(wrapped), b64(iv), b64(ciphertext), b64(tag)}, "."))
}
