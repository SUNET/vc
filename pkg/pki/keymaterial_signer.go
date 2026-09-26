package pki

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// KeyMaterialSigner implements the Signer interface using KeyMaterial.
// It provides a concrete implementation for services that need signing capabilities.
type KeyMaterialSigner struct {
	km    *KeyMaterial
	keyID string
}

// NewKeyMaterialSigner creates a new Signer from KeyMaterial.
// The keyID is automatically determined from the certificate if available,
// or generated from the public key hash.
func NewKeyMaterialSigner(km *KeyMaterial) *KeyMaterialSigner {
	keyID := determineKeyID(km)
	return &KeyMaterialSigner{
		km:    km,
		keyID: keyID,
	}
}

// Sign signs the provided data using the private key.
func (s *KeyMaterialSigner) Sign(ctx context.Context, data []byte) ([]byte, error) {
	// Use the correct hash algorithm based on the signing method
	hash := getHashForAlgorithm(s.km.SigningMethod.Alg())
	h := hash.New()
	h.Write(data)
	hashed := h.Sum(nil)

	switch key := s.km.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		// Sign using ECDSA
		r, sigS, err := ecdsa.Sign(rand.Reader, key, hashed)
		if err != nil {
			return nil, err
		}
		// Convert to IEEE P1363 format (fixed-size R||S concatenation) as required by JWT RFC 7518
		return EncodeECDSASignature(r, sigS, key.Curve)
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, key, hash, hashed)
	case crypto.Signer:
		// An HSM/PKCS#11 key: the device signs, we never see the private
		// half. For ECDSA this returns ASN.1 DER rather than P1363, which
		// the Signer interface documents as expected from crypto.Signer
		// backends and which jose.MakeJWT converts.
		//
		// After the concrete cases, which satisfy crypto.Signer too.
		if err := requireHSMSignable(key); err != nil {
			return nil, err
		}
		sig, err := key.Sign(rand.Reader, hashed, hash)
		if err != nil {
			return nil, err
		}
		return normalizeHSMECDSASignature(key, sig)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", s.km.PrivateKey)
	}
}

// SignDigest signs a pre-computed digest without additional hashing.
// This is useful for protocols like W3C Data Integrity that control the hashing process.
func (s *KeyMaterialSigner) SignDigest(ctx context.Context, digest []byte) ([]byte, error) {
	switch key := s.km.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		// Sign the digest directly using ECDSA
		r, sigS, err := ecdsa.Sign(rand.Reader, key, digest)
		if err != nil {
			return nil, err
		}
		// Convert to IEEE P1363 format (fixed-size R||S concatenation)
		return EncodeECDSASignature(r, sigS, key.Curve)
	case *rsa.PrivateKey:
		// Use crypto.Signer interface for RSA signing. This is PKCS#1 v1.5 signature
		// (not encryption), a standard scheme for JWT RS256/RS384/RS512.
		hash := getHashForAlgorithm(s.km.SigningMethod.Alg())
		return key.Sign(rand.Reader, digest, hash)
	case crypto.Signer:
		// An HSM/PKCS#11 key signing a pre-computed digest, which is what
		// the device does natively. As in Sign, an ECDSA result is ASN.1 DER.
		if err := requireHSMSignable(key); err != nil {
			return nil, err
		}
		hash := getHashForAlgorithm(s.km.SigningMethod.Alg())
		sig, err := key.Sign(rand.Reader, digest, hash)
		if err != nil {
			return nil, err
		}
		return normalizeHSMECDSASignature(key, sig)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", s.km.PrivateKey)
	}
}

// Algorithm returns the JWT algorithm name based on the key type.
func (s *KeyMaterialSigner) Algorithm() string {
	return s.km.SigningMethod.Alg()
}

// KeyID returns the key identifier for JWT headers.
func (s *KeyMaterialSigner) KeyID() string {
	return s.keyID
}

// PublicKey returns the public key for verification.
func (s *KeyMaterialSigner) PublicKey() any {
	switch key := s.km.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		return key.Public()
	case *rsa.PrivateKey:
		return key.Public()
	case crypto.Signer:
		// An HSM/PKCS#11 key. Its private half is unreadable by design, but
		// the public half is exactly what crypto.Signer exists to expose -
		// and returning nil here made every caller that asks for the public
		// key (this one, and determineKeyID's kid derivation) behave as
		// though an HSM key had no public key at all.
		//
		// Listed after the concrete cases on purpose: those types satisfy
		// crypto.Signer too, and a type switch takes the first match.
		return key.Public()
	default:
		return nil
	}
}

// PrivateKey returns the underlying private key.
// This is useful when integrating with libraries that need the raw crypto.PrivateKey.
func (s *KeyMaterialSigner) PrivateKey() crypto.PrivateKey {
	return s.km.PrivateKey
}

// determineKeyID extracts or generates a key identifier.
func determineKeyID(km *KeyMaterial) string {
	// Use certificate CN if available
	if km.Cert != nil {
		return km.Cert.Subject.CommonName
	}

	// Generate key ID from public key hash
	var pubKey crypto.PublicKey
	switch key := km.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		pubKey = key.Public()
	case *rsa.PrivateKey:
		pubKey = key.Public()
	default:
		return "default-key"
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "default-key"
	}

	hash := sha256.Sum256(pubBytes)
	return hex.EncodeToString(hash[:8])
}

// SigningMethod returns the JWT signing method for this key material.
func (s *KeyMaterialSigner) SigningMethod() jwt.SigningMethod {
	return s.km.SigningMethod
}

// GetCertificate returns the certificate if available.
func (s *KeyMaterialSigner) GetCertificate() *x509.Certificate {
	return s.km.Cert
}

// GetCertificateChain returns the certificate chain if available.
func (s *KeyMaterialSigner) GetCertificateChain() []string {
	return s.km.Chain
}

// requireHSMSignable refuses an opaque signer this package cannot drive
// correctly.
//
// ECDSA is fine: the device signs the digest and returns ASN.1 DER, which is
// what crypto.Signer backends do and what jose.MakeJWT converts for JWS.
//
// RSA is not, yet. PKCS11PrivateKey.Sign selects CKM_RSA_PKCS and hands it
// the bare digest, but that mechanism only applies PKCS#1 v1.5 PADDING - it
// does not prepend the DigestInfo structure RFC 8017 requires inside the
// padding, which is why crypto/rsa does that itself and why the hash-
// specific CKM_SHA256_RSA_PKCS mechanisms exist. Signing through it as-is
// produces something that pads correctly and verifies nowhere.
//
// Refused rather than quietly wrong: an RS256 assertion that no verifier
// accepts is worse than a startup error naming the reason. Making it work
// means either wrapping the digest in DigestInfo here or selecting the
// hash-specific mechanism in PKCS11PrivateKey.Sign - a change to HSM code
// that cannot be honestly verified without a device.
func requireHSMSignable(signer crypto.Signer) error {
	switch pub := signer.Public().(type) {
	case *ecdsa.PublicKey:
		return nil
	case *rsa.PublicKey:
		return fmt.Errorf("RSA keys held in an HSM cannot be signed with through this path: "+
			"PKCS#11 CKM_RSA_PKCS is given a bare digest and adds no DigestInfo, so the signature "+
			"would not verify as %s; use an EC (P-256) key, or add DigestInfo encoding to the PKCS#11 signer",
			"RS256")
	default:
		return fmt.Errorf("unsupported HSM public key type: %T", pub)
	}
}

// normalizeHSMECDSASignature converts an opaque signer's ECDSA output to
// IEEE P1363.
//
// Both of this type's signing methods promise that form - Sign because JWS
// requires it, SignDigest because pki.RawSigner's contract says so outright
// and its callers (the VC 2.0 Data Integrity suites) have no converter
// downstream the way jose.MakeJWT does for JWS. An HSM returning ASN.1 DER
// would otherwise produce a Data Integrity proof of the wrong shape, which
// fails as a malformed proof rather than as a wrong key.
func normalizeHSMECDSASignature(signer crypto.Signer, sig []byte) ([]byte, error) {
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		// requireHSMSignable has already refused anything else.
		return sig, nil
	}
	return ECDSASignatureToP1363(sig, pub.Curve)
}
