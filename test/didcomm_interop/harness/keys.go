//go:build didcomm_interop

// Package harness provides shared test infrastructure for DIDComm interoperability testing.
package harness

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// TestKeys holds all cryptographic key pairs for testing.
// These keys are deterministically generated from seed for reproducibility.
type TestKeys struct {
	// Ed25519 signing keys
	AliceEdSign *KeyPair
	BobEdSign   *KeyPair

	// X25519 key agreement keys
	AliceX25519 *KeyPair
	BobX25519   *KeyPair

	// P-256 keys (signing and key agreement)
	AliceP256 *KeyPair
	BobP256   *KeyPair

	// P-384 keys (signing and key agreement)
	AliceP384 *KeyPair
	BobP384   *KeyPair
}

// KeyPair holds a private/public key pair in JWK format.
type KeyPair struct {
	KID        string
	PrivateJWK jwk.Key
	PublicJWK  jwk.Key
	PrivateRaw any
	PublicRaw  any
}

// TestDIDs are the DIDs used in interop tests.
const (
	AliceDID = "did:example:alice"
	BobDID   = "did:example:bob"
)

// NewTestKeys generates a complete set of test keys for interoperability testing.
func NewTestKeys() (*TestKeys, error) {
	keys := &TestKeys{}
	var err error

	// Generate Ed25519 signing keys
	keys.AliceEdSign, err = generateEd25519KeyPair(AliceDID + "#key-ed25519-1")
	if err != nil {
		return nil, fmt.Errorf("generating Alice Ed25519: %w", err)
	}

	keys.BobEdSign, err = generateEd25519KeyPair(BobDID + "#key-ed25519-1")
	if err != nil {
		return nil, fmt.Errorf("generating Bob Ed25519: %w", err)
	}

	// Generate X25519 key agreement keys
	keys.AliceX25519, err = generateX25519KeyPair(AliceDID + "#key-x25519-1")
	if err != nil {
		return nil, fmt.Errorf("generating Alice X25519: %w", err)
	}

	keys.BobX25519, err = generateX25519KeyPair(BobDID + "#key-x25519-1")
	if err != nil {
		return nil, fmt.Errorf("generating Bob X25519: %w", err)
	}

	// Generate P-256 keys
	keys.AliceP256, err = generateECDSAKeyPair(elliptic.P256(), AliceDID+"#key-p256-1")
	if err != nil {
		return nil, fmt.Errorf("generating Alice P-256: %w", err)
	}

	keys.BobP256, err = generateECDSAKeyPair(elliptic.P256(), BobDID+"#key-p256-1")
	if err != nil {
		return nil, fmt.Errorf("generating Bob P-256: %w", err)
	}

	// Generate P-384 keys
	keys.AliceP384, err = generateECDSAKeyPair(elliptic.P384(), AliceDID+"#key-p384-1")
	if err != nil {
		return nil, fmt.Errorf("generating Alice P-384: %w", err)
	}

	keys.BobP384, err = generateECDSAKeyPair(elliptic.P384(), BobDID+"#key-p384-1")
	if err != nil {
		return nil, fmt.Errorf("generating Bob P-384: %w", err)
	}

	return keys, nil
}

// generateEd25519KeyPair generates an Ed25519 key pair.
func generateEd25519KeyPair(kid string) (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// Create private JWK
	privJWK, err := jwk.Import(priv)
	if err != nil {
		return nil, fmt.Errorf("importing private key: %w", err)
	}
	if err := privJWK.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, err
	}
	if err := privJWK.Set(jwk.AlgorithmKey, jwa.EdDSA()); err != nil {
		return nil, err
	}

	// Create public JWK
	pubJWK, err := privJWK.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("extracting public key: %w", err)
	}

	return &KeyPair{
		KID:        kid,
		PrivateJWK: privJWK,
		PublicJWK:  pubJWK,
		PrivateRaw: priv,
		PublicRaw:  pub,
	}, nil
}

// generateX25519KeyPair generates an X25519 key pair.
func generateX25519KeyPair(kid string) (*KeyPair, error) {
	// Generate X25519 key pair using ecdh package
	curve := ecdh.X25519()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating X25519 key: %w", err)
	}

	publicKey := privateKey.PublicKey()

	// Get raw bytes
	privateBytes := privateKey.Bytes()
	publicBytes := publicKey.Bytes()

	// Create JWK JSON with both d and x
	keyJSON := fmt.Sprintf(`{
		"kty": "OKP",
		"crv": "X25519",
		"kid": %q,
		"x": %q,
		"d": %q
	}`, kid, base64.RawURLEncoding.EncodeToString(publicBytes), base64.RawURLEncoding.EncodeToString(privateBytes))

	privJWK, err := jwk.ParseKey([]byte(keyJSON))
	if err != nil {
		return nil, fmt.Errorf("parsing X25519 key: %w", err)
	}

	// Extract public key
	pubJWK, err := privJWK.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("extracting public key: %w", err)
	}

	return &KeyPair{
		KID:        kid,
		PrivateJWK: privJWK,
		PublicJWK:  pubJWK,
		PrivateRaw: privateBytes,
		PublicRaw:  publicBytes,
	}, nil
}

// generateECDSAKeyPair generates an ECDSA key pair for the given curve.
func generateECDSAKeyPair(curve elliptic.Curve, kid string) (*KeyPair, error) {
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	// Create private JWK
	privJWK, err := jwk.Import(priv)
	if err != nil {
		return nil, fmt.Errorf("importing private key: %w", err)
	}
	if err := privJWK.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, err
	}

	// Set algorithm based on curve
	var alg jwa.SignatureAlgorithm
	switch curve {
	case elliptic.P256():
		alg = jwa.ES256()
	case elliptic.P384():
		alg = jwa.ES384()
	case elliptic.P521():
		alg = jwa.ES512()
	}
	if err := privJWK.Set(jwk.AlgorithmKey, alg); err != nil {
		return nil, err
	}

	// Create public JWK
	pubJWK, err := privJWK.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("extracting public key: %w", err)
	}

	return &KeyPair{
		KID:        kid,
		PrivateJWK: privJWK,
		PublicJWK:  pubJWK,
		PrivateRaw: priv,
		PublicRaw:  &priv.PublicKey,
	}, nil
}

// ToJSON returns the key pair as JSON for debugging.
func (kp *KeyPair) ToJSON() (string, error) {
	data, err := json.MarshalIndent(kp.PrivateJWK, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// WellKnownTestVectorKeys contains the DIDComm spec test vector keys.
// These are from Appendix C of the DIDComm v2.1 specification.
type WellKnownTestVectorKeys struct {
	// Alice's keys from the spec
	AliceKeyAgreementX25519 jwk.Key
	AliceKeyAgreementP256   jwk.Key
	AliceKeyAgreementP384   jwk.Key
	AliceKeyAgreementP521   jwk.Key
	AliceAuthKeyEd25519     jwk.Key

	// Bob's keys from the spec
	BobKeyAgreementX25519 jwk.Key
	BobKeyAgreementP256   jwk.Key
	BobKeyAgreementP384   jwk.Key
	BobKeyAgreementP521   jwk.Key
}

// LoadWellKnownKeys loads the DIDComm spec test vector keys.
// These keys are from the official DIDComm test vectors.
func LoadWellKnownKeys() (*WellKnownTestVectorKeys, error) {
	keys := &WellKnownTestVectorKeys{}
	var err error

	// Alice's X25519 key agreement key (from DIDComm spec)
	keys.AliceKeyAgreementX25519, err = jwk.ParseKey([]byte(aliceX25519KeyJSON))
	if err != nil {
		return nil, fmt.Errorf("parsing Alice X25519 key: %w", err)
	}

	// Alice's P-256 key agreement key
	keys.AliceKeyAgreementP256, err = jwk.ParseKey([]byte(aliceP256KeyJSON))
	if err != nil {
		return nil, fmt.Errorf("parsing Alice P-256 key: %w", err)
	}

	// Bob's X25519 key agreement key
	keys.BobKeyAgreementX25519, err = jwk.ParseKey([]byte(bobX25519KeyJSON))
	if err != nil {
		return nil, fmt.Errorf("parsing Bob X25519 key: %w", err)
	}

	// Bob's P-256 key agreement key
	keys.BobKeyAgreementP256, err = jwk.ParseKey([]byte(bobP256KeyJSON))
	if err != nil {
		return nil, fmt.Errorf("parsing Bob P-256 key: %w", err)
	}

	return keys, nil
}

// DIDComm spec test vector keys in JWK format.
// These are derived from the examples in the DIDComm v2.1 specification.
const (
	// Alice's X25519 key for key agreement
	aliceX25519KeyJSON = `{
		"kty": "OKP",
		"crv": "X25519",
		"kid": "did:example:alice#key-x25519-1",
		"x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs",
		"d": "r-jK2cO3taR8LQnJB1_ikLBTAnOtShJOsHXRUWT-aZA"
	}`

	// Alice's P-256 key for key agreement
	aliceP256KeyJSON = `{
		"kty": "EC",
		"crv": "P-256",
		"kid": "did:example:alice#key-p256-1",
		"x": "WKn-ZIGevcwGFOMJ0GeEei6YWSXz1xIvJx_kXjXnVwA",
		"y": "j0lbVvfLqvxG8XGq53D7RjMXjXJT5F9cZ3b6m3zB-Fw",
		"d": "mIhKNhNdBa8-u7ClY4wjGRLXr-UOXfJkP-JfPU8HLXM"
	}`

	// Bob's X25519 key for key agreement
	bobX25519KeyJSON = `{
		"kty": "OKP",
		"crv": "X25519",
		"kid": "did:example:bob#key-x25519-1",
		"x": "GDTrI66K0pFfO54tlCSvfjjNapIs44dzpneBgyx0S3E",
		"d": "b9NnuOCB0hm7YGNvaE9DMhwH_wjZA1-gWD6dA0JWdL0"
	}`

	// Bob's P-256 key for key agreement
	bobP256KeyJSON = `{
		"kty": "EC",
		"crv": "P-256",
		"kid": "did:example:bob#key-p256-1",
		"x": "FQVaTOksf-XsCUrt4J1L2UGvtWaDwpboVlqbKBY2AIo",
		"y": "6XFB9PYo7dyC5ViJSO9uXNYkxTJWn0d_mqJ__ZYhcNY",
		"d": "n4epkvCNmg-32YQ_LNULnVp9_FXEG-V-f2X2M_WM1m0"
	}`
)
