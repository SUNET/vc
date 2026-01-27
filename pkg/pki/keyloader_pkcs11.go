//go:build pkcs11

package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/miekg/pkcs11"
)

// loadKeyMaterialFromHSMWithConfig loads key material from a PKCS#11 HSM with explicit config.
func (kl *KeyLoader) loadKeyMaterialFromHSMWithConfig(keyLabel string, hsmConfig *PKCS11Config) (*KeyMaterial, error) {
	ctx := pkcs11.New(hsmConfig.ModulePath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 module: %s", hsmConfig.ModulePath)
	}

	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize PKCS#11: %w", err)
	}
	defer ctx.Finalize()

	session, err := ctx.OpenSession(hsmConfig.SlotID, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, fmt.Errorf("failed to open session: %w", err)
	}
	defer ctx.CloseSession(session)

	if err := ctx.Login(session, pkcs11.CKU_USER, hsmConfig.PIN); err != nil {
		return nil, fmt.Errorf("failed to login: %w", err)
	}
	defer ctx.Logout(session)

	// Find private key
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
	}

	if err := ctx.FindObjectsInit(session, template); err != nil {
		return nil, fmt.Errorf("failed to init find objects: %w", err)
	}

	objs, _, err := ctx.FindObjects(session, 1)
	if err != nil {
		ctx.FindObjectsFinal(session)
		return nil, fmt.Errorf("failed to find objects: %w", err)
	}

	if err := ctx.FindObjectsFinal(session); err != nil {
		return nil, fmt.Errorf("failed to finalize find objects: %w", err)
	}

	if len(objs) == 0 {
		return nil, fmt.Errorf("private key not found: %s", keyLabel)
	}

	privateKeyHandle := objs[0]

	// Get key type
	attrs, err := ctx.GetAttributeValue(session, privateKeyHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get key type: %w", err)
	}

	keyType := bytesToUint(attrs[0].Value)

	// Extract public key
	var publicKey crypto.PublicKey

	switch keyType {
	case pkcs11.CKK_RSA:
		publicKey, _, err = extractRSAPublicKeyFromHSM(ctx, session, keyLabel)
		if err != nil {
			return nil, err
		}
	case pkcs11.CKK_EC:
		publicKey, _, err = extractECPublicKeyFromHSM(ctx, session, keyLabel)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported key type: %d", keyType)
	}

	// Create PKCS11PrivateKey wrapper that includes the handle
	// This allows the key to be used with standard crypto interfaces
	hsmKey := &PKCS11PrivateKey{
		Config:    hsmConfig,
		KeyLabel:  keyLabel,
		PublicKey: publicKey,
		KeyType:   keyType,
	}

	// Determine signing method
	method, err := getSigningMethod(publicKey)
	if err != nil {
		return nil, err
	}

	km := &KeyMaterial{
		PrivateKey:    hsmKey,
		SigningMethod: method,
	}

	return km, nil
}

// extractRSAPublicKeyFromHSM extracts RSA public key from HSM
func extractRSAPublicKeyFromHSM(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, keyLabel string) (*rsa.PublicKey, any, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
	}

	if err := ctx.FindObjectsInit(session, template); err != nil {
		return nil, nil, fmt.Errorf("failed to init find public key: %w", err)
	}

	objs, _, err := ctx.FindObjects(session, 1)
	if err != nil {
		ctx.FindObjectsFinal(session)
		return nil, nil, fmt.Errorf("failed to find public key: %w", err)
	}

	if err := ctx.FindObjectsFinal(session); err != nil {
		return nil, nil, fmt.Errorf("failed to finalize find public key: %w", err)
	}

	if len(objs) == 0 {
		return nil, nil, fmt.Errorf("public key not found: %s", keyLabel)
	}

	pubKeyHandle := objs[0]

	attrs, err := ctx.GetAttributeValue(session, pubKeyHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get RSA public key attributes: %w", err)
	}

	n := new(big.Int).SetBytes(attrs[0].Value)
	e := int(new(big.Int).SetBytes(attrs[1].Value).Int64())

	publicKey := &rsa.PublicKey{N: n, E: e}

	// Determine algorithm based on key size
	signingMethod := getRSASigningMethod(n.BitLen())

	return publicKey, signingMethod, nil
}

// extractECPublicKeyFromHSM extracts ECDSA public key from HSM
func extractECPublicKeyFromHSM(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, keyLabel string) (*ecdsa.PublicKey, any, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
	}

	if err := ctx.FindObjectsInit(session, template); err != nil {
		return nil, nil, fmt.Errorf("failed to init find public key: %w", err)
	}

	objs, _, err := ctx.FindObjects(session, 1)
	if err != nil {
		ctx.FindObjectsFinal(session)
		return nil, nil, fmt.Errorf("failed to find public key: %w", err)
	}

	if err := ctx.FindObjectsFinal(session); err != nil {
		return nil, nil, fmt.Errorf("failed to finalize find public key: %w", err)
	}

	if len(objs) == 0 {
		return nil, nil, fmt.Errorf("public key not found: %s", keyLabel)
	}

	pubKeyHandle := objs[0]

	attrs, err := ctx.GetAttributeValue(session, pubKeyHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get EC public key attributes: %w", err)
	}

	// Parse curve OID
	curve, err := parseCurveOID(attrs[0].Value)
	if err != nil {
		return nil, nil, err
	}

	// Parse EC point (uncompressed format: 04 || X || Y)
	point := attrs[1].Value
	if len(point) < 3 || point[0] != 0x04 {
		// Try to unwrap DER encoding
		if len(point) > 2 && point[0] == 0x04 && point[1] == byte(len(point)-2) {
			point = point[2:]
		}
	}

	if point[0] != 0x04 {
		return nil, nil, fmt.Errorf("invalid EC point format")
	}

	keyLen := (curve.Params().BitSize + 7) / 8
	if len(point) != 1+2*keyLen {
		return nil, nil, fmt.Errorf("invalid EC point length")
	}

	x := new(big.Int).SetBytes(point[1 : 1+keyLen])
	y := new(big.Int).SetBytes(point[1+keyLen:])

	publicKey := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}

	// Determine signing method
	bits := getCurveBits(curve)
	var signingMethod interface{}
	if method, ok := ecdsaSigningMethods[bits]; ok {
		signingMethod = method
	}

	return publicKey, signingMethod, nil
}

// PKCS11PrivateKey wraps HSM key information for use with standard crypto interfaces
type PKCS11PrivateKey struct {
	Config    *PKCS11Config
	KeyLabel  string
	PublicKey crypto.PublicKey
	KeyType   uint
}

// Public returns the public key associated with this private key
func (k *PKCS11PrivateKey) Public() crypto.PublicKey {
	return k.PublicKey
}

// Sign implements crypto.Signer interface for PKCS11 keys
// Note: This requires opening a new HSM session each time
func (k *PKCS11PrivateKey) Sign(rand any, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	ctx := pkcs11.New(k.Config.ModulePath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 module")
	}

	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize PKCS#11: %w", err)
	}
	defer ctx.Finalize()

	session, err := ctx.OpenSession(k.Config.SlotID, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, fmt.Errorf("failed to open session: %w", err)
	}
	defer ctx.CloseSession(session)

	if err := ctx.Login(session, pkcs11.CKU_USER, k.Config.PIN); err != nil {
		return nil, fmt.Errorf("failed to login: %w", err)
	}
	defer ctx.Logout(session)

	// Find the private key again
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, k.KeyLabel),
	}

	if err := ctx.FindObjectsInit(session, template); err != nil {
		return nil, fmt.Errorf("failed to init find objects: %w", err)
	}

	objs, _, err := ctx.FindObjects(session, 1)
	if err != nil {
		ctx.FindObjectsFinal(session)
		return nil, fmt.Errorf("failed to find objects: %w", err)
	}

	if err := ctx.FindObjectsFinal(session); err != nil {
		return nil, fmt.Errorf("failed to finalize find objects: %w", err)
	}

	if len(objs) == 0 {
		return nil, fmt.Errorf("private key not found: %s", k.KeyLabel)
	}

	privateKeyHandle := objs[0]

	// Sign with the appropriate mechanism
	var mechanism *pkcs11.Mechanism
	switch k.KeyType {
	case pkcs11.CKK_RSA:
		mechanism = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)
	case pkcs11.CKK_EC:
		mechanism = pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)
	default:
		return nil, fmt.Errorf("unsupported key type: %d", k.KeyType)
	}

	if err := ctx.SignInit(session, []*pkcs11.Mechanism{mechanism}, privateKeyHandle); err != nil {
		return nil, fmt.Errorf("failed to init sign: %w", err)
	}

	signature, err := ctx.Sign(session, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return signature, nil
}
