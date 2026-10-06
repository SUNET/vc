package pki

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/miekg/pkcs11"
)

// PKCS11ECDH performs ECDH key agreement with an EC private key that stays
// inside a PKCS#11 token.
//
// SECURITY: the key never leaves the token, but the shared secret does. The
// derivation runs CKM_ECDH1_DERIVE with CKD_NULL, which makes the agreed
// secret Z itself the derived object, and Z is then read out of the token
// with CKA_VALUE so that the Concat KDF of RFC 7518 §4.6.2 can be applied to
// it here. The alternative - asking the token to run the KDF and the AES key
// unwrap too - needs CKM_ECDH1_DERIVE with CKD_SHA256_KDF_CONCATENATE and an
// agreement on how the module encodes the JWE OtherInfo, which PKCS#11 v2.40
// does not standardize and most modules do not implement. So Z crosses the
// boundary: an attacker with code execution on this host can read one
// request's Z out of process memory, and with it that request's content
// encryption key. They cannot obtain the long-term private key, which is the
// property an HSM is bought for, and they cannot decrypt any other request
// without deriving its Z through the token.
//
// The token must allow the derivation at all: the private key needs
// CKA_DERIVE, and the module must let the derived generic secret be created
// with CKA_EXTRACTABLE true and CKA_SENSITIVE false. A module that refuses
// to produce an extractable derived key cannot be used this way - the
// refusal surfaces as an error from ECDH, not as a wrong answer.
//
// Safe for concurrent use: one PKCS#11 session is shared and serialized,
// since a session is not a concurrency primitive.
type PKCS11ECDH struct {
	mu       sync.Mutex
	ctx      *pkcs11.Ctx
	module   *pkcs11Module
	session  pkcs11.SessionHandle
	private  pkcs11.ObjectHandle
	public   *ecdsa.PublicKey
	keyLabel string
	closed   bool
}

// NewPKCS11ECDH opens a session on the configured token, finds the EC
// private key by label, reads its public half, and proves that the token
// will actually perform the agreement.
//
// Done once at startup rather than per request so that a token that is
// missing, locked, holding the wrong kind of key or unwilling to derive is
// a configuration failure instead of a 500 on a wallet's credential
// request.
func NewPKCS11ECDH(config *PKCS11Config) (*PKCS11ECDH, error) {
	if config == nil {
		return nil, fmt.Errorf("no PKCS#11 configuration")
	}

	// Through the registry, not pkcs11.New + Initialize: C_Initialize is
	// library-wide, so two encryption keys on one token - which is what
	// rotation looks like - or an HSM-backed key_config alongside this one
	// would collide. See pkcs11_module.go.
	module, err := acquireModule(config.ModulePath)
	if err != nil {
		return nil, err
	}

	k := &PKCS11ECDH{ctx: module.ctx, module: module, keyLabel: config.KeyLabel}

	session, err := module.ctx.OpenSession(config.SlotID, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		k.Close()
		return nil, fmt.Errorf("failed to open session: %w", err)
	}
	k.session = session

	if err := loginSession(module.ctx, session, config.PIN); err != nil {
		k.Close()
		return nil, fmt.Errorf("failed to login: %w", err)
	}

	if err := k.findKey(); err != nil {
		k.Close()
		return nil, err
	}

	if err := k.selfTest(); err != nil {
		k.Close()
		return nil, err
	}

	return k, nil
}

// selfTest performs one throwaway agreement, against a public key generated
// here and discarded, and refuses the key if the token will not do it.
//
// The attributes this asks for are not universally granted. The derived
// generic secret is created with CKA_EXTRACTABLE true and CKA_SENSITIVE
// false, because CKD_NULL means the agreed secret Z is the derived object
// and the Concat KDF above it runs in this process; a token under a policy
// that forbids extractable keys will refuse. The private key also needs
// CKA_DERIVE, which keys generated for signing do not have.
//
// Neither is visible from the public key or from the metadata, so without
// this the issuer would start, publish a JWK, and fail every encrypted
// request a wallet built from it - a fault that looks like a wallet problem
// and is discovered by a user. Doing the agreement here moves it to the
// line in the config file that caused it.
func (k *PKCS11ECDH) selfTest() error {
	probe, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("key %s: generating a probe key: %w", k.keyLabel, err)
	}

	z, deriveErr := k.ECDH(probe.PublicKey())
	if deriveErr == nil {
		if len(z) != p256FieldSize {
			return fmt.Errorf("key %s: the token derived %d bytes, want %d", k.keyLabel, len(z), p256FieldSize)
		}
		return nil
	}

	// The agreement is the authority on whether this key can be used. The
	// attribute is read only now, to say why, because a token may refuse
	// for reasons CKA_DERIVE does not describe - the extractable derived
	// secret among them.
	if k.deriveAttributeIsFalse() {
		return fmt.Errorf("key %s: the token will not perform ECDH with it, and its CKA_DERIVE is false: %w", k.keyLabel, deriveErr)
	}

	return fmt.Errorf("key %s: the token refused a test ECDH agreement, so this key cannot decrypt credential requests "+
		"(a token that will not create the derived secret with CKA_EXTRACTABLE true and CKA_SENSITIVE false cannot be used this way): %w",
		k.keyLabel, deriveErr)
}

// deriveAttributeIsFalse reports whether the token says CKA_DERIVE is
// false. A module that does not expose the attribute at all answers false
// here: absence is not a refusal.
func (k *PKCS11ECDH) deriveAttributeIsFalse() bool {
	attrs, err := k.ctx.GetAttributeValue(k.session, k.private, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, nil),
	})
	return err == nil && len(attrs) == 1 && len(attrs[0].Value) > 0 && attrs[0].Value[0] == 0
}

// findKey locates the private key and the matching public key.
func (k *PKCS11ECDH) findKey() error {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, k.keyLabel),
	}

	if err := k.ctx.FindObjectsInit(k.session, template); err != nil {
		return fmt.Errorf("failed to init find objects: %w", err)
	}
	objs, _, err := k.ctx.FindObjects(k.session, 1)
	if err != nil {
		k.ctx.FindObjectsFinal(k.session)
		return fmt.Errorf("failed to find objects: %w", err)
	}
	if err := k.ctx.FindObjectsFinal(k.session); err != nil {
		return fmt.Errorf("failed to finalize find objects: %w", err)
	}
	if len(objs) == 0 {
		return fmt.Errorf("private key not found: %s", k.keyLabel)
	}
	k.private = objs[0]

	attrs, err := k.ctx.GetAttributeValue(k.session, k.private, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
	})
	if err != nil {
		return fmt.Errorf("failed to get key type: %w", err)
	}
	if keyType := bytesToUint(attrs[0].Value); keyType != pkcs11.CKK_EC {
		return fmt.Errorf("key %s: ECDH needs an EC key, got PKCS#11 key type %d", k.keyLabel, keyType)
	}

	public, _, err := extractECPublicKeyFromHSM(k.ctx, k.session, k.keyLabel)
	if err != nil {
		return err
	}
	if public.Curve != elliptic.P256() {
		return fmt.Errorf("key %s: want curve P-256, got %s", k.keyLabel, public.Curve.Params().Name)
	}
	k.public = public

	return nil
}

// PublicKey returns the public half of the token-held key.
func (k *PKCS11ECDH) PublicKey() *ecdsa.PublicKey { return k.public }

// Public implements crypto.Signer's half of the usual key interface, so this
// can be passed anywhere a crypto.PrivateKey is expected.
func (k *PKCS11ECDH) Public() any { return k.public }

// ECDH returns the raw shared secret Z for peer, derived inside the token.
//
// See the type comment: Z leaves the token, the private key does not.
func (k *PKCS11ECDH) ECDH(peer *ecdh.PublicKey) ([]byte, error) {
	if peer == nil {
		return nil, fmt.Errorf("no peer public key")
	}
	if peer.Curve() != ecdh.P256() {
		return nil, fmt.Errorf("peer public key is not on P-256")
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	if k.closed {
		return nil, fmt.Errorf("PKCS#11 session is closed")
	}

	// peer.Bytes() is the uncompressed point 0x04||X||Y, and having come
	// from ecdh.PublicKey it is already known to be on the curve.
	point := peer.Bytes()

	z, err := k.derive(point, p256FieldSize)
	if err == nil {
		return z, nil
	}

	// Modules disagree about how pPublicData is encoded. PKCS#11 v2.40
	// says "the other party's EC public key", which SoftHSM2 and most
	// others read as the raw uncompressed point, while some read it as the
	// DER OCTET STRING that CKA_EC_POINT is wrapped in - the same ambiguity
	// extractECPublicKeyFromHSM already unwraps on the way in. Raw first
	// because that is what SoftHSM2 accepts (measured, see
	// TestPKCS11ECDH_PointEncoding), DER second rather than instead, so a
	// module in the other camp works without a configuration flag.
	wrapped, wrapErr := derOctetString(point)
	if wrapErr != nil {
		return nil, err
	}
	z, derErr := k.derive(wrapped, p256FieldSize)
	if derErr != nil {
		return nil, fmt.Errorf("CKM_ECDH1_DERIVE failed with a raw EC point (%w) and with a DER-wrapped one (%w)", err, derErr)
	}

	return z, nil
}

// p256FieldSize is the length of a P-256 shared secret. CKA_VALUE_LEN has
// to be stated when deriving because a generic secret has no implied
// length, and a module that silently produced a shorter one would produce a
// wrong KEK rather than an error.
const p256FieldSize = 32

// derive runs one CKM_ECDH1_DERIVE and reads the result out of the token.
func (k *PKCS11ECDH) derive(publicData []byte, valueLen int) ([]byte, error) {
	mechanism := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_ECDH1_DERIVE,
			pkcs11.NewECDH1DeriveParams(pkcs11.CKD_NULL, nil, publicData)),
	}

	// CKA_TOKEN false: the derived secret is session-scoped, so a crash
	// cannot leave Z behind in the token's object store.
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, valueLen),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
	}

	handle, err := k.ctx.DeriveKey(k.session, mechanism, k.private, template)
	if err != nil {
		return nil, fmt.Errorf("CKM_ECDH1_DERIVE: %w", err)
	}
	// Destroyed whatever happens next: the object is the shared secret.
	defer k.ctx.DestroyObject(k.session, handle)

	attrs, err := k.ctx.GetAttributeValue(k.session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("reading the derived secret: %w "+
			"(the token may refuse to make a derived key extractable, in which case it cannot be used for ECDH-ES this way)", err)
	}
	if len(attrs) != 1 {
		return nil, fmt.Errorf("the token returned %d attributes for CKA_VALUE, want 1", len(attrs))
	}
	if len(attrs[0].Value) != valueLen {
		return nil, fmt.Errorf("the derived secret is %d bytes, want %d", len(attrs[0].Value), valueLen)
	}

	return attrs[0].Value, nil
}

// derOctetString wraps b in a DER OCTET STRING, for the modules that want
// pPublicData in that form.
func derOctetString(b []byte) ([]byte, error) {
	// An uncompressed P-256 point is 65 bytes, so the short-form length is
	// always enough; anything longer is not a point this code produced.
	if len(b) > 127 {
		return nil, fmt.Errorf("cannot DER-wrap %d bytes in short form", len(b))
	}
	out := make([]byte, 0, len(b)+2)
	out = append(out, 0x04, byte(len(b)))
	return append(out, b...), nil
}

// Close logs out and releases the session and the module.
func (k *PKCS11ECDH) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.closed {
		return nil
	}
	k.closed = true

	if k.session != 0 {
		// No Logout: it is token-wide. See loginSession.
		k.ctx.CloseSession(k.session)
	}
	// releaseModule rather than Finalize: C_Finalize is library-wide, and
	// this process may have other sessions open on the same module.
	releaseModule(k.module)

	return nil
}
