//go:build pkcs11

package pki_test

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"os/exec"
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/pki"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateDeriveKeyPair generates an EC P-256 key pair that the token will
// let us derive with.
//
// Separate from generateKeyPair because CKA_DERIVE is not the default:
// pkcs11-tool sets the usage flags it is told to, and a key generated for
// signing refuses CKM_ECDH1_DERIVE with CKR_KEY_FUNCTION_NOT_PERMITTED.
// That is also true of a production HSM, and it is the first thing to check
// when this feature does not work against one.
func (s *softhsmInstance) generateDeriveKeyPair(t *testing.T, keyLabel string) {
	t.Helper()

	cmd := exec.Command("pkcs11-tool",
		"--module", s.modulePath, "--login", "--pin", s.userPIN,
		"--keypairgen", "--key-type", "EC:prime256v1",
		"--usage-derive", "--label", keyLabel)
	cmd.Env = append(os.Environ(), "SOFTHSM2_CONF="+s.configPath)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Key generation failed: %s", string(output))
}

func (s *softhsmInstance) ecdhConfig(keyLabel string) *pki.PKCS11Config {
	return &pki.PKCS11Config{
		ModulePath: s.modulePath,
		SlotID:     s.slotID,
		PIN:        s.userPIN,
		KeyLabel:   keyLabel,
	}
}

// useSoftHSMConf points the module at this test's token directory.
func useSoftHSMConf(t *testing.T, hsm *softhsmInstance) {
	t.Helper()
	old, had := os.LookupEnv("SOFTHSM2_CONF")
	require.NoError(t, os.Setenv("SOFTHSM2_CONF", hsm.configPath))
	t.Cleanup(func() {
		if had {
			os.Setenv("SOFTHSM2_CONF", old)
		} else {
			os.Unsetenv("SOFTHSM2_CONF")
		}
	})
}

// TestPKCS11ECDH_PointEncoding measures what SoftHSM2 wants in
// pPublicData, rather than letting the implementation's fallback hide the
// answer.
//
// PKCS#11 v2.40 says the parameter is "the other party's EC public key";
// modules disagree about whether that is the raw uncompressed point or the
// DER OCTET STRING that CKA_EC_POINT comes wrapped in. PKCS11ECDH.ECDH
// tries raw first and DER second, and the comment there claims SoftHSM2
// takes the raw form. This is that claim, measured.
func TestPKCS11ECDH_PointEncoding(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	hsm := setupLocalSoftHSM2(t)
	useSoftHSMConf(t, hsm)
	const keyLabel = "test-ecdh-encoding"
	hsm.generateDeriveKeyPair(t, keyLabel)

	ctx := pkcs11.New(hsm.modulePath)
	require.NotNil(t, ctx)
	require.NoError(t, ctx.Initialize())
	defer ctx.Finalize()

	session, err := ctx.OpenSession(hsm.slotID, pkcs11.CKF_SERIAL_SESSION)
	require.NoError(t, err)
	defer ctx.CloseSession(session)
	require.NoError(t, ctx.Login(session, pkcs11.CKU_USER, hsm.userPIN))
	defer ctx.Logout(session)

	require.NoError(t, ctx.FindObjectsInit(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
	}))
	objs, _, err := ctx.FindObjects(session, 1)
	require.NoError(t, err)
	require.NoError(t, ctx.FindObjectsFinal(session))
	require.Len(t, objs, 1)

	peer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	peerECDH, err := peer.PublicKey.ECDH()
	require.NoError(t, err)
	raw := peerECDH.Bytes()
	require.Len(t, raw, 65)
	wrapped := append([]byte{0x04, byte(len(raw))}, raw...)

	derive := func(publicData []byte) ([]byte, error) {
		handle, err := ctx.DeriveKey(session,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDH1_DERIVE,
				pkcs11.NewECDH1DeriveParams(pkcs11.CKD_NULL, nil, publicData))},
			objs[0],
			[]*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
				pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
				pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
				pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
				pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
				pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
				pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
			})
		if err != nil {
			return nil, err
		}
		defer ctx.DestroyObject(session, handle)
		attrs, err := ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
		})
		if err != nil {
			return nil, err
		}
		return attrs[0].Value, nil
	}

	zRaw, rawErr := derive(raw)
	zWrapped, wrappedErr := derive(wrapped)

	t.Logf("SoftHSM2 CKM_ECDH1_DERIVE with a raw uncompressed point: err=%v", rawErr)
	t.Logf("SoftHSM2 CKM_ECDH1_DERIVE with a DER OCTET STRING point: err=%v", wrappedErr)

	// The claim in pkcs11_ecdh.go: raw works.
	require.NoError(t, rawErr, "SoftHSM2 refused the raw uncompressed point")
	require.Len(t, zRaw, 32)

	// And whichever of the two forms SoftHSM2 also accepts, it must agree
	// with the other - a module that quietly derived from a different point
	// would hand back a plausible 32 bytes and a JWE that never decrypts.
	if wrappedErr == nil {
		assert.Equal(t, zRaw, zWrapped, "the two point encodings derived different secrets")
	}
}

// TestPKCS11ECDH_AgreesWithSoftware is the arithmetic check: the secret the
// token derives must be the one the other side computes, which is what the
// whole JWE unwrap is built on.
func TestPKCS11ECDH_AgreesWithSoftware(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	hsm := setupLocalSoftHSM2(t)
	useSoftHSMConf(t, hsm)
	const keyLabel = "test-ecdh-agree"
	hsm.generateDeriveKeyPair(t, keyLabel)

	key, err := pki.NewPKCS11ECDH(hsm.ecdhConfig(keyLabel))
	require.NoError(t, err)
	defer key.Close()

	issuerPublic := key.PublicKey()
	require.NotNil(t, issuerPublic)
	require.Equal(t, elliptic.P256(), issuerPublic.Curve)

	// The wallet's side, done in software: Z is the same number from either
	// end, and only one of the two ends is the token.
	wallet, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	issuerECDH, err := issuerPublic.ECDH()
	require.NoError(t, err)
	want, err := wallet.ECDH(issuerECDH)
	require.NoError(t, err)

	got, err := key.ECDH(wallet.PublicKey())
	require.NoError(t, err)
	assert.Equal(t, want, got, "the token and the software side disagree about Z")

	// A second agreement with a different ephemeral key, so a derivation
	// that somehow returned a constant would show up.
	other, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	otherZ, err := key.ECDH(other.PublicKey())
	require.NoError(t, err)
	assert.NotEqual(t, got, otherZ)
}

// TestPKCS11ECDH_RefusesANonDeriveKey pins the diagnostic for the most
// likely production failure: a key the token will not derive with.
//
// The key is generated here rather than with pkcs11-tool so that
// CKA_DERIVE is definitely false - pkcs11-tool's defaults are its own
// business and have changed between versions.
func TestPKCS11ECDH_RefusesANonDeriveKey(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	hsm := setupLocalSoftHSM2(t)
	useSoftHSMConf(t, hsm)
	const keyLabel = "test-ecdh-sign-only"

	ctx := pkcs11.New(hsm.modulePath)
	require.NotNil(t, ctx)
	require.NoError(t, ctx.Initialize())
	session, err := ctx.OpenSession(hsm.slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	require.NoError(t, err)
	require.NoError(t, ctx.Login(session, pkcs11.CKU_USER, hsm.userPIN))

	// prime256v1 as a DER-encoded OID, which is what CKA_EC_PARAMS takes.
	prime256v1 := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
	_, _, err = ctx.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, prime256v1),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_DERIVE, false),
		})
	require.NoError(t, err)

	ctx.Logout(session)
	ctx.CloseSession(session)
	ctx.Finalize()

	key, err := pki.NewPKCS11ECDH(hsm.ecdhConfig(keyLabel))
	if err == nil {
		key.Close()
	}
	require.Error(t, err)
	// The refusal has to come from an agreement that was actually
	// attempted, not from reading CKA_DERIVE and believing it. A token can
	// refuse for reasons the attribute does not describe - a policy against
	// extractable derived secrets among them - and those are the ones that
	// would otherwise be discovered by a wallet.
	assert.Contains(t, err.Error(), "the token will not perform ECDH with it")
	assert.Contains(t, err.Error(), "CKA_DERIVE")
}

// TestPKCS11ECDH_ClosedKeyRefusesToDerive pins the other end of the
// session's life: once Close has run, an agreement must fail rather than
// use a handle the module has reclaimed.
func TestPKCS11ECDH_ClosedKeyRefusesToDerive(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	hsm := setupLocalSoftHSM2(t)
	useSoftHSMConf(t, hsm)
	const keyLabel = "test-ecdh-closed"
	hsm.generateDeriveKeyPair(t, keyLabel)

	key, err := pki.NewPKCS11ECDH(hsm.ecdhConfig(keyLabel))
	require.NoError(t, err)

	peer, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	// It works before Close, so what fails after it is the close and not
	// the key or the peer.
	_, err = key.ECDH(peer.PublicKey())
	require.NoError(t, err)

	require.NoError(t, key.Close())
	require.NoError(t, key.Close(), "Close must be idempotent")

	_, err = key.ECDH(peer.PublicKey())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

// TestCredentialEncryption_SoftHSMRoundTrip is the end-to-end claim: a
// wallet encrypting a Credential Request to the key this issuer publishes,
// and the issuer decrypting it with a private key it has never seen,
// through the configuration an operator actually writes.
func TestCredentialEncryption_SoftHSMRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	hsm := setupLocalSoftHSM2(t)
	useSoftHSMConf(t, hsm)
	const keyLabel = "test-credential-encryption"
	hsm.generateDeriveKeyPair(t, keyLabel)

	// The operator's config, loaded the way the apigw loads it.
	cfg := &model.CredentialEncryption{
		Keys: []model.CredentialEncryptionKey{{PKCS11: hsm.ecdhConfig(keyLabel)}},
	}
	enc, err := cfg.Load()
	require.NoError(t, err)
	require.True(t, enc.Enabled())

	// The wallet's side: read the issuer's key out of the published
	// metadata and encrypt to it, with nothing but jwx.
	metadata := enc.RequestMetadata()
	require.NotNil(t, metadata)
	set, err := jwk.Parse(metadata.JWKS)
	require.NoError(t, err)
	require.Equal(t, 1, set.Len())
	issuerKey, ok := set.Key(0)
	require.True(t, ok)

	kid, ok := issuerKey.KeyID()
	require.True(t, ok)
	require.NotEmpty(t, kid)
	alg, ok := issuerKey.Algorithm()
	require.True(t, ok)
	require.Equal(t, openid4vci.AlgECDHESA256KW, alg.String())

	payload, err := json.Marshal(openid4vci.CredentialRequest{
		CredentialConfigurationID: "urn:credential:softhsm",
	})
	require.NoError(t, err)

	encrypted, err := jwe.Encrypt(payload,
		jwe.WithKey(jwa.ECDH_ES_A256KW(), issuerKey),
		jwe.WithContentEncryption(jwa.A256GCM()))
	require.NoError(t, err)

	plaintext, err := enc.DecryptRequest(encrypted)
	require.NoError(t, err)
	assert.JSONEq(t, string(payload), string(plaintext))

	// A JWE built for a different key must not decrypt, so that the round
	// trip above is evidence of an agreement rather than of a decrypter
	// that returns whatever it is given.
	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	strangerKey, err := jwk.Import(stranger.PublicKey)
	require.NoError(t, err)
	require.NoError(t, strangerKey.Set(jwk.KeyIDKey, kid))
	strangerJWE, err := jwe.Encrypt(payload,
		jwe.WithKey(jwa.ECDH_ES_A256KW(), strangerKey),
		jwe.WithContentEncryption(jwa.A256GCM()))
	require.NoError(t, err)

	_, err = enc.DecryptRequest(strangerJWE)
	assert.Error(t, err)
}

// TestPKCS11Module_SharedAcrossUsers is the collision this package used to
// have: C_Initialize and C_Finalize are library-wide, so a second user of
// the same module could not start, and a user that finalized when it was
// done closed the module under everyone else.
//
// Two encryption keys on one token is what rotation looks like, and an
// HSM-backed apigw.key_config alongside an HSM-backed credential encryption
// key is an ordinary deployment. Both are exercised here.
func TestPKCS11Module_SharedAcrossUsers(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	hsm := setupLocalSoftHSM2(t)
	useSoftHSMConf(t, hsm)
	hsm.generateDeriveKeyPair(t, "rotation-current")
	hsm.generateDeriveKeyPair(t, "rotation-next")

	current, err := pki.NewPKCS11ECDH(hsm.ecdhConfig("rotation-current"))
	require.NoError(t, err)
	defer current.Close()

	next, err := pki.NewPKCS11ECDH(hsm.ecdhConfig("rotation-next"))
	require.NoError(t, err, "a second key on the same module must not collide")
	defer next.Close()

	// The signing path through the same module, as an HSM-backed
	// apigw.key_config would open it.
	signer, err := pki.NewPKCS11Signer(&pki.PKCS11Config{
		ModulePath: hsm.modulePath,
		SlotID:     hsm.slotID,
		PIN:        hsm.userPIN,
		KeyLabel:   "rotation-current",
	})
	require.NoError(t, err, "a signer on the same module must not collide")

	// And the loader path, which used to initialize and finalize the module
	// around each call.
	loader := pki.NewKeyLoader()
	_, err = loader.LoadKeyMaterial(&pki.KeyConfig{
		PKCS11: &pki.PKCS11Config{
			ModulePath: hsm.modulePath,
			SlotID:     hsm.slotID,
			PIN:        hsm.userPIN,
			KeyLabel:   "rotation-current",
		},
		EnableHSM: true,
	})
	require.NoError(t, err)

	// Closing one user must not take the module away from the others.
	require.NoError(t, signer.Close())

	for name, key := range map[string]*pki.PKCS11ECDH{"current": current, "next": next} {
		peer, err := ecdh.P256().GenerateKey(rand.Reader)
		require.NoError(t, err)
		z, err := key.ECDH(peer.PublicKey())
		require.NoError(t, err, "%s stopped working after another user closed the module", name)
		require.Len(t, z, 32)
	}

	// The two keys are different keys, so the JWKS a rotation publishes has
	// two distinct entries rather than one key listed twice.
	assert.NotEqual(t, current.PublicKey().X, next.PublicKey().X)
}
