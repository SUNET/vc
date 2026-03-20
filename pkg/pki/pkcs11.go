//go:build pkcs11

package pki

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/miekg/pkcs11"
)

// PKCS11Config holds configuration for PKCS#11 HSM connection.
type PKCS11Config struct {
	// ModulePath is the path to the PKCS#11 library
	ModulePath string `yaml:"module_path" doc_example:"\"/usr/lib/softhsm/libsofthsm2.so\""`
	// SlotID is the HSM slot ID
	SlotID uint `yaml:"slot_id" doc_example:"0"`
	// PIN is the user PIN for the slot
	PIN string `yaml:"pin" doc_example:"\"1234\""`
	// KeyLabel is the label of the key to use
	KeyLabel string `yaml:"key_label" doc_example:"\"my-signing-key\""`
	// KeyID is the identifier for the JWT kid header
	KeyID string `yaml:"key_id" doc_example:"\"key-1\""`
}

// PKCS11Signer implements Signer using a PKCS#11 HSM.
type PKCS11Signer struct {
	ctx        *pkcs11.Ctx
	session    pkcs11.SessionHandle
	privateKey pkcs11.ObjectHandle
	publicKey  any
	algorithm  string
	keyID      string
	keyType    uint
}

// NewPKCS11Signer creates a new PKCS11Signer from HSM configuration.
func NewPKCS11Signer(config *PKCS11Config) (*PKCS11Signer, error) {
	ctx := pkcs11.New(config.ModulePath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 module: %s", config.ModulePath)
	}

	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize PKCS#11: %w", err)
	}

	session, err := ctx.OpenSession(config.SlotID, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		ctx.Finalize()
		return nil, fmt.Errorf("failed to open session: %w", err)
	}

	if err := ctx.Login(session, pkcs11.CKU_USER, config.PIN); err != nil {
		ctx.CloseSession(session)
		ctx.Finalize()
		return nil, fmt.Errorf("failed to login: %w", err)
	}

	s := &PKCS11Signer{
		ctx:     ctx,
		session: session,
		keyID:   config.KeyID,
	}

	if err := s.findKey(config.KeyLabel); err != nil {
		s.Close()
		return nil, err
	}

	return s, nil
}

// findKey locates the private key by label and extracts the public key.
func (s *PKCS11Signer) findKey(label string) error {
	// Find private key
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	if err := s.ctx.FindObjectsInit(s.session, template); err != nil {
		return fmt.Errorf("failed to init find objects: %w", err)
	}

	objs, _, err := s.ctx.FindObjects(s.session, 1)
	if err != nil {
		s.ctx.FindObjectsFinal(s.session)
		return fmt.Errorf("failed to find objects: %w", err)
	}

	if err := s.ctx.FindObjectsFinal(s.session); err != nil {
		return fmt.Errorf("failed to finalize find objects: %w", err)
	}

	if len(objs) == 0 {
		return fmt.Errorf("private key not found: %s", label)
	}

	s.privateKey = objs[0]

	// Get key type
	attrs, err := s.ctx.GetAttributeValue(s.session, s.privateKey, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
	})
	if err != nil {
		return fmt.Errorf("failed to get key type: %w", err)
	}

	s.keyType = bytesToUint(attrs[0].Value)

	// Find and extract public key
	if err := s.extractPublicKey(label); err != nil {
		return err
	}

	return nil
}

// extractPublicKey finds the public key and extracts it for verification.
func (s *PKCS11Signer) extractPublicKey(label string) error {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	if err := s.ctx.FindObjectsInit(s.session, template); err != nil {
		return fmt.Errorf("failed to init find public key: %w", err)
	}

	objs, _, err := s.ctx.FindObjects(s.session, 1)
	if err != nil {
		s.ctx.FindObjectsFinal(s.session)
		return fmt.Errorf("failed to find public key: %w", err)
	}

	if err := s.ctx.FindObjectsFinal(s.session); err != nil {
		return fmt.Errorf("failed to finalize find public key: %w", err)
	}

	if len(objs) == 0 {
		return fmt.Errorf("public key not found: %s", label)
	}

	pubKeyHandle := objs[0]

	switch s.keyType {
	case pkcs11.CKK_RSA:
		return s.extractRSAPublicKey(pubKeyHandle)
	case pkcs11.CKK_EC:
		return s.extractECPublicKey(pubKeyHandle)
	default:
		return fmt.Errorf("unsupported key type: %d", s.keyType)
	}
}

// extractRSAPublicKey extracts RSA public key from HSM.
func (s *PKCS11Signer) extractRSAPublicKey(handle pkcs11.ObjectHandle) error {
	attrs, err := s.ctx.GetAttributeValue(s.session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	})
	if err != nil {
		return fmt.Errorf("failed to get RSA public key attributes: %w", err)
	}

	n := new(big.Int).SetBytes(attrs[0].Value)
	e := int(new(big.Int).SetBytes(attrs[1].Value).Int64())

	s.publicKey = &rsa.PublicKey{N: n, E: e}

	// Determine algorithm based on key size
	keySize := n.BitLen()
	switch {
	case keySize >= 4096:
		s.algorithm = "RS512"
	case keySize >= 3072:
		s.algorithm = "RS384"
	default:
		s.algorithm = "RS256"
	}

	return nil
}

// extractECPublicKey extracts ECDSA public key from HSM.
func (s *PKCS11Signer) extractECPublicKey(handle pkcs11.ObjectHandle) error {
	attrs, err := s.ctx.GetAttributeValue(s.session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return fmt.Errorf("failed to get EC public key attributes: %w", err)
	}

	// Parse curve OID
	curve, err := parseCurveOID(attrs[0].Value)
	if err != nil {
		return err
	}

	// Parse EC point (uncompressed format: 04 || X || Y)
	// SoftHSM2 may wrap the point in a DER OCTET STRING (tag 0x04 || LEN || DATA).
	// Since the uncompressed point marker is also 0x04, we use the length byte to
	// distinguish: if point[1] == len(point)-2, it's a DER wrapper.
	point := attrs[1].Value
	if len(point) > 2 && point[0] == 0x04 {
		length := int(point[1])
		if len(point) >= 2+length && length == len(point)-2 {
			// DER OCTET STRING wrapper detected — unwrap
			point = point[2 : 2+length]
		}
	}

	if len(point) < 3 || point[0] != 0x04 {
		return fmt.Errorf("invalid EC point format: expected uncompressed (0x04), got 0x%02x", point[0])
	}

	keyLen := (curve.Params().BitSize + 7) / 8
	if len(point) != 1+2*keyLen {
		return fmt.Errorf("invalid EC point length: got %d bytes, expected %d bytes for %s curve",
			len(point), 1+2*keyLen, curve.Params().Name)
	}

	x := new(big.Int).SetBytes(point[1 : 1+keyLen])
	y := new(big.Int).SetBytes(point[1+keyLen:])

	s.publicKey = &ecdsa.PublicKey{Curve: curve, X: x, Y: y}

	// Determine algorithm based on curve
	switch curve.Params().BitSize {
	case 384:
		s.algorithm = "ES384"
	case 521:
		s.algorithm = "ES512"
	default:
		s.algorithm = "ES256"
	}

	return nil
}

// Sign signs data using the HSM.
func (s *PKCS11Signer) Sign(ctx context.Context, data []byte) ([]byte, error) {
	var mechanism *pkcs11.Mechanism
	var hash crypto.Hash

	switch s.keyType {
	case pkcs11.CKK_RSA:
		mechanism, hash = s.rsaMechanism()
	case pkcs11.CKK_EC:
		mechanism, hash = s.ecdsaMechanism()
	default:
		return nil, fmt.Errorf("unsupported key type: %d", s.keyType)
	}

	// Hash the data
	h := hash.New()
	h.Write(data)
	hashed := h.Sum(nil)

	// Sign with HSM
	if err := s.ctx.SignInit(s.session, []*pkcs11.Mechanism{mechanism}, s.privateKey); err != nil {
		return nil, fmt.Errorf("failed to init sign: %w", err)
	}

	sig, err := s.ctx.Sign(s.session, hashed)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return sig, nil
}

// Algorithm returns the JWT algorithm name.
func (s *PKCS11Signer) Algorithm() string {
	return s.algorithm
}

// KeyID returns the key identifier.
func (s *PKCS11Signer) KeyID() string {
	return s.keyID
}

// PublicKey returns the public key.
func (s *PKCS11Signer) PublicKey() any {
	return s.publicKey
}

// Close releases HSM resources.
func (s *PKCS11Signer) Close() error {
	if s.ctx != nil {
		s.ctx.Logout(s.session)
		s.ctx.CloseSession(s.session)
		s.ctx.Finalize()
	}
	return nil
}

// rsaMechanism returns the PKCS#11 mechanism for RSA signing.
func (s *PKCS11Signer) rsaMechanism() (*pkcs11.Mechanism, crypto.Hash) {
	switch s.algorithm {
	case "RS384":
		return pkcs11.NewMechanism(pkcs11.CKM_SHA384_RSA_PKCS, nil), crypto.SHA384
	case "RS512":
		return pkcs11.NewMechanism(pkcs11.CKM_SHA512_RSA_PKCS, nil), crypto.SHA512
	default:
		return pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil), crypto.SHA256
	}
}

// ecdsaMechanism returns the PKCS#11 mechanism for ECDSA signing.
func (s *PKCS11Signer) ecdsaMechanism() (*pkcs11.Mechanism, crypto.Hash) {
	switch s.algorithm {
	case "ES384":
		return pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil), crypto.SHA384
	case "ES512":
		return pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil), crypto.SHA512
	default:
		return pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil), crypto.SHA256
	}
}
