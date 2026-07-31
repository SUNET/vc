package mdoc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"hash"
	"math"
	"math/big"

	"github.com/fxamacker/cbor/v2"
	"github.com/sirosfoundation/go-cryptoutil"
)

// COSE Algorithm identifiers per RFC 8152 and ISO 18013-5
const (
	// Signing algorithms
	AlgorithmES256 int64 = -7  // ECDSA w/ SHA-256, P-256
	AlgorithmES384 int64 = -35 // ECDSA w/ SHA-384, P-384
	AlgorithmES512 int64 = -36 // ECDSA w/ SHA-512, P-521
	AlgorithmEdDSA int64 = -8  // EdDSA

	// MAC algorithms
	AlgorithmHMAC256 int64 = 5 // HMAC w/ SHA-256
	AlgorithmHMAC384 int64 = 6 // HMAC w/ SHA-384
	AlgorithmHMAC512 int64 = 7 // HMAC w/ SHA-512

	// Key types
	KeyTypeEC2 int64 = 2 // Elliptic Curve with x, y
	KeyTypeOKP int64 = 1 // Octet Key Pair (Ed25519, Ed448)

	// EC curves
	CurveP256 int64 = 1 // NIST P-256
	CurveP384 int64 = 2 // NIST P-384
	CurveP521 int64 = 3 // NIST P-521

	// OKP curves
	CurveEd25519 int64 = 6 // Ed25519
	CurveEd448   int64 = 7 // Ed448
)

// COSE header labels
const (
	HeaderAlgorithm   int64 = 1
	HeaderCritical    int64 = 2
	HeaderContentType int64 = 3
	HeaderKeyID       int64 = 4
	HeaderX5Chain     int64 = 33 // x5chain - certificate chain
	HeaderX5ChainAlt  int64 = 34 // Alternative x5chain label
)

// COSE_Key labels
const (
	KeyLabelKty int64 = 1  // Key type
	KeyLabelAlg int64 = 3  // Algorithm
	KeyLabelCrv int64 = -1 // Curve
	KeyLabelX   int64 = -2 // X coordinate
	KeyLabelY   int64 = -3 // Y coordinate
)

// COSEKey represents a COSE_Key structure per RFC 8152.
// This struct only holds public key material for security reasons.
// Private keys should never be serialized in COSE_Key format.
type COSEKey struct {
	Kty int64  `cbor:"1,keyasint"`            // Key type
	Alg int64  `cbor:"3,keyasint,omitempty"`  // Algorithm
	Crv int64  `cbor:"-1,keyasint"`           // Curve
	X   []byte `cbor:"-2,keyasint"`           // X coordinate
	Y   []byte `cbor:"-3,keyasint,omitempty"` // Y coordinate (for EC2 keys)
}

// NewCOSEKeyFromECDSA creates a COSE_Key from an ECDSA public key.
func NewCOSEKeyFromECDSA(pub *ecdsa.PublicKey) (*COSEKey, error) {
	var crv int64
	switch pub.Curve {
	case elliptic.P256():
		crv = CurveP256
	case elliptic.P384():
		crv = CurveP384
	case elliptic.P521():
		crv = CurveP521
	default:
		return nil, fmt.Errorf("unsupported curve")
	}

	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	x := pub.X.Bytes()
	y := pub.Y.Bytes()

	// Pad to correct length
	if len(x) < byteLen {
		x = append(make([]byte, byteLen-len(x)), x...)
	}
	if len(y) < byteLen {
		y = append(make([]byte, byteLen-len(y)), y...)
	}

	key := &COSEKey{
		Kty: KeyTypeEC2,
		Crv: crv,
		X:   x,
		Y:   y,
	}
	return key, nil
}

// NewCOSEKeyFromCoordinates creates a COSE_Key from raw X/Y coordinates.
// kty is the key type ("EC" for ECDSA, "OKP" for EdDSA).
// crv is the curve name ("P-256", "P-384", "P-521", "Ed25519").
// x and y are the raw coordinate bytes (y should be nil for EdDSA).
func NewCOSEKeyFromCoordinates(kty, crv string, x, y []byte) (*COSEKey, error) {
	key := &COSEKey{}

	// Map kty string to COSE key type
	switch kty {
	case "EC":
		key.Kty = KeyTypeEC2
	case "OKP":
		key.Kty = KeyTypeOKP
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kty)
	}

	// Map curve name to COSE curve value
	switch crv {
	case "P-256":
		key.Crv = CurveP256
	case "P-384":
		key.Crv = CurveP384
	case "P-521":
		key.Crv = CurveP521
	case "Ed25519":
		key.Crv = CurveEd25519
	default:
		return nil, fmt.Errorf("unsupported curve: %s", crv)
	}

	key.X = x
	key.Y = y

	return key, nil
}

// NewCOSEKeyFromEd25519 creates a COSE_Key from an Ed25519 public key.
func NewCOSEKeyFromEd25519(pub ed25519.PublicKey) *COSEKey {
	key := &COSEKey{
		Kty: KeyTypeOKP,
		Crv: CurveEd25519,
		X:   []byte(pub),
	}
	return key
}

// ToPublicKey converts a COSE_Key to a Go crypto public key.
func (k *COSEKey) ToPublicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case KeyTypeEC2:
		return k.toECDSAPublicKey()
	case KeyTypeOKP:
		return k.toEd25519PublicKey()
	default:
		return nil, fmt.Errorf("unsupported key type: %d", k.Kty)
	}
}

func (k *COSEKey) toECDSAPublicKey() (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch k.Crv {
	case CurveP256:
		curve = elliptic.P256()
	case CurveP384:
		curve = elliptic.P384()
	case CurveP521:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %d", k.Crv)
	}

	x := new(big.Int).SetBytes(k.X)
	y := new(big.Int).SetBytes(k.Y)

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

func (k *COSEKey) toEd25519PublicKey() (ed25519.PublicKey, error) {
	if k.Crv != CurveEd25519 {
		return nil, fmt.Errorf("unsupported curve for OKP: %d", k.Crv)
	}
	if len(k.X) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size")
	}
	return ed25519.PublicKey(k.X), nil
}

// Bytes encodes the COSE_Key to CBOR bytes.
func (k *COSEKey) Bytes() ([]byte, error) {
	return cbor.Marshal(k)
}

// COSESign1 represents a COSE_Sign1 structure per RFC 8152.
type COSESign1 struct {
	Protected   []byte      // Protected headers (CBOR encoded)
	Unprotected map[any]any // Unprotected headers
	Payload     []byte      // Payload (may be nil if detached)
	Signature   []byte      // Signature
}

// MarshalCBOR implements cbor.Marshaler for COSESign1.
func (s *COSESign1) MarshalCBOR() ([]byte, error) {
	// COSE_Sign1 = [protected, unprotected, payload, signature]
	arr := []any{
		s.Protected,
		s.Unprotected,
		s.Payload,
		s.Signature,
	}
	return cbor.Marshal(cbor.Tag{Number: 18, Content: arr})
}

// UnmarshalCBOR implements cbor.Unmarshaler for COSESign1.
func (s *COSESign1) UnmarshalCBOR(data []byte) error {
	var tag cbor.Tag
	if err := cbor.Unmarshal(data, &tag); err != nil {
		return err
	}
	if tag.Number != 18 {
		return fmt.Errorf("expected COSE_Sign1 tag 18, got %d", tag.Number)
	}

	arr, ok := tag.Content.([]any)
	if !ok || len(arr) != 4 {
		return fmt.Errorf("invalid COSE_Sign1 structure")
	}

	s.Protected, _ = arr[0].([]byte)
	s.Unprotected, _ = arr[1].(map[any]any)
	s.Payload, _ = arr[2].([]byte)
	s.Signature, _ = arr[3].([]byte)

	return nil
}

// COSESign1Message is a helper for creating and verifying COSE_Sign1 messages.
type COSESign1Message struct {
	Headers   *COSEHeaders
	Payload   []byte
	Signature []byte
}

// COSEHeaders contains protected and unprotected headers.
type COSEHeaders struct {
	Protected   map[int64]any
	Unprotected map[int64]any
}

// NewCOSEHeaders creates new empty headers.
func NewCOSEHeaders() *COSEHeaders {
	headers := &COSEHeaders{
		Protected:   make(map[int64]any),
		Unprotected: make(map[int64]any),
	}
	return headers
}

// Sign creates a COSE_Sign1 signature.
//
// x5chain (when present) goes in the UNPROTECTED header, not protected - per
// RFC 9360 and the ISO 18013-5 mdoc convention followed by real-world
// verifiers (e.g. Google's isomdoc), the protected header for an mdoc
// issuerAuth/deviceAuth COSE_Sign1 contains only the algorithm (label 1);
// the certificate chain isn't itself integrity-critical (trust comes from
// the signature verifying against the chain's leaf key, not from the
// chain's placement) and strict verifiers reject a protected header with
// any additional element. Putting it in protected was a real, confirmed bug
// (caught by Google's public https://digital-credentials.dev/ demo, which
// rejected our issued mdocs with "issuerAuth COSE_Sign1 protected contains
// too many elements").
func Sign1(
	payload []byte,
	signer crypto.Signer,
	algorithm int64,
	x5chain [][]byte,
	externalAAD []byte,
) (*COSESign1, error) {
	// A nil Go []byte and an empty (len-0, non-nil) one both mean "no AAD",
	// but cbor.Marshal encodes them differently - nil as CBOR null (0xf6),
	// empty as an empty byte string (0x40, i.e. h''). Sig_structure's
	// external_aad element MUST be h'' per RFC 8152/9052 - a verifier
	// reconstructing it as an empty byte string (as every real one does,
	// including Google's isomdoc, which is what caught this) computes
	// different bytes-to-be-signed than what a nil-produced signature was
	// actually computed over, so the signature fails to verify even though
	// nothing else about it is wrong. Normalizing here means no caller has
	// to remember this footgun.
	if externalAAD == nil {
		externalAAD = []byte{}
	}

	headers := NewCOSEHeaders()
	headers.Protected[HeaderAlgorithm] = algorithm

	protectedBytes, err := cbor.Marshal(headers.Protected)
	if err != nil {
		return nil, fmt.Errorf("failed to encode protected headers: %w", err)
	}

	// Create Sig_structure
	sigStructure := []any{
		"Signature1", // context
		protectedBytes,
		externalAAD,
		payload,
	}

	toBeSigned, err := cbor.Marshal(sigStructure)
	if err != nil {
		return nil, fmt.Errorf("failed to encode Sig_structure: %w", err)
	}

	// Sign
	signature, err := signPayload(toBeSigned, signer, algorithm)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	unprotected := make(map[any]any)
	if len(x5chain) > 0 {
		unprotected[HeaderX5Chain] = x5chain
	}

	sign1 := &COSESign1{
		Protected:   protectedBytes,
		Unprotected: unprotected,
		Payload:     payload,
		Signature:   signature,
	}
	return sign1, nil
}

// Sign1Detached creates a COSE_Sign1 with detached payload.
func Sign1Detached(
	payload []byte,
	signer crypto.Signer,
	algorithm int64,
	x5chain [][]byte,
	externalAAD []byte,
) (*COSESign1, error) {
	result, err := Sign1(payload, signer, algorithm, x5chain, externalAAD)
	if err != nil {
		return nil, err
	}
	result.Payload = nil // Detach payload
	return result, nil
}

func signPayload(data []byte, signer crypto.Signer, algorithm int64) ([]byte, error) {
	var h hash.Hash
	switch algorithm {
	case AlgorithmES256:
		h = sha256.New()
	case AlgorithmES384:
		h = sha512.New384()
	case AlgorithmES512:
		h = sha512.New()
	case AlgorithmEdDSA:
		// EdDSA doesn't prehash
		return signer.Sign(rand.Reader, data, crypto.Hash(0))
	default:
		return nil, fmt.Errorf("unsupported algorithm: %d", algorithm)
	}

	h.Write(data)
	digest := h.Sum(nil)

	sigBytes, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	// For ECDSA, convert from ASN.1 to raw format
	if algorithm == AlgorithmES256 || algorithm == AlgorithmES384 || algorithm == AlgorithmES512 {
		return convertECDSASignatureToRaw(sigBytes, algorithm)
	}

	return sigBytes, nil
}

func convertECDSASignatureToRaw(asn1Sig []byte, algorithm int64) ([]byte, error) {
	r, s, err := parseASN1Signature(asn1Sig)
	if err != nil {
		return nil, err
	}

	var byteLen int
	switch algorithm {
	case AlgorithmES256:
		byteLen = 32
	case AlgorithmES384:
		byteLen = 48
	case AlgorithmES512:
		byteLen = 66
	}

	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Pad to correct length
	rawSig := make([]byte, byteLen*2)
	copy(rawSig[byteLen-len(rBytes):byteLen], rBytes)
	copy(rawSig[byteLen*2-len(sBytes):], sBytes)

	return rawSig, nil
}

func parseASN1Signature(data []byte) (*big.Int, *big.Int, error) {
	// Parse DER-encoded ECDSA signature (SEQUENCE { INTEGER r, INTEGER s })
	// using encoding/asn1 for correct handling of all DER length encodings.
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(data, &sig); err != nil {
		return nil, nil, fmt.Errorf("invalid ASN.1 ECDSA signature: %w", err)
	}
	return sig.R, sig.S, nil
}

// Verify1 verifies a COSE_Sign1 signature.
func Verify1(sign1 *COSESign1, payload []byte, pubKey crypto.PublicKey, externalAAD []byte) error {
	// Must match Sign1's own nil-vs-empty normalization - see its doc comment.
	if externalAAD == nil {
		externalAAD = []byte{}
	}

	var headers map[int64]any
	if err := cbor.Unmarshal(sign1.Protected, &headers); err != nil {
		return fmt.Errorf("failed to decode protected headers: %w", err)
	}

	algRaw, ok := headers[HeaderAlgorithm]
	if !ok {
		return fmt.Errorf("missing algorithm in protected headers")
	}
	algorithm, ok := algRaw.(int64)
	if !ok {
		// Try other integer types
		switch v := algRaw.(type) {
		case int:
			algorithm = int64(v)
		case uint64:
			if v > math.MaxInt64 {
				return fmt.Errorf("algorithm value overflow")
			}
			algorithm = int64(v)
		default:
			return fmt.Errorf("invalid algorithm type")
		}
	}

	// Use attached payload if detached not provided
	if payload == nil {
		payload = sign1.Payload
	}

	// Create Sig_structure for verification
	sigStructure := []any{
		"Signature1",
		sign1.Protected,
		externalAAD,
		payload,
	}

	toBeSigned, err := cbor.Marshal(sigStructure)
	if err != nil {
		return fmt.Errorf("failed to encode Sig_structure: %w", err)
	}

	return verifySignature(toBeSigned, sign1.Signature, pubKey, algorithm)
}

func verifySignature(data, signature []byte, pubKey crypto.PublicKey, algorithm int64) error {
	switch algorithm {
	case AlgorithmES256, AlgorithmES384, AlgorithmES512:
		return verifyECDSA(data, signature, pubKey.(*ecdsa.PublicKey), algorithm)
	case AlgorithmEdDSA:
		return verifyEdDSA(data, signature, pubKey.(ed25519.PublicKey))
	default:
		return fmt.Errorf("unsupported algorithm: %d", algorithm)
	}
}

func verifyECDSA(data, signature []byte, pubKey *ecdsa.PublicKey, algorithm int64) error {
	var h hash.Hash
	var byteLen int
	switch algorithm {
	case AlgorithmES256:
		h = sha256.New()
		byteLen = 32
	case AlgorithmES384:
		h = sha512.New384()
		byteLen = 48
	case AlgorithmES512:
		h = sha512.New()
		byteLen = 66
	}

	h.Write(data)
	digest := h.Sum(nil)

	if len(signature) != byteLen*2 {
		return fmt.Errorf("invalid signature length")
	}

	r := new(big.Int).SetBytes(signature[:byteLen])
	s := new(big.Int).SetBytes(signature[byteLen:])

	if !ecdsa.Verify(pubKey, digest, r, s) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

func verifyEdDSA(data, signature []byte, pubKey ed25519.PublicKey) error {
	if !ed25519.Verify(pubKey, data, signature) {
		return fmt.Errorf("EdDSA signature verification failed")
	}
	return nil
}

// COSEMac0 represents a COSE_Mac0 structure per RFC 8152.
type COSEMac0 struct {
	Protected   []byte      // Protected headers (CBOR encoded)
	Unprotected map[any]any // Unprotected headers
	Payload     []byte      // Payload
	Tag         []byte      // MAC tag
}

// MarshalCBOR implements cbor.Marshaler for COSEMac0.
func (m *COSEMac0) MarshalCBOR() ([]byte, error) {
	arr := []any{
		m.Protected,
		m.Unprotected,
		m.Payload,
		m.Tag,
	}
	return cbor.Marshal(cbor.Tag{Number: 17, Content: arr})
}

// UnmarshalCBOR implements cbor.Unmarshaler for COSEMac0.
func (m *COSEMac0) UnmarshalCBOR(data []byte) error {
	var tag cbor.Tag
	if err := cbor.Unmarshal(data, &tag); err != nil {
		return err
	}
	if tag.Number != 17 {
		return fmt.Errorf("expected COSE_Mac0 tag 17, got %d", tag.Number)
	}

	arr, ok := tag.Content.([]any)
	if !ok || len(arr) != 4 {
		return fmt.Errorf("invalid COSE_Mac0 structure")
	}

	m.Protected, _ = arr[0].([]byte)
	m.Unprotected, _ = arr[1].(map[any]any)
	m.Payload, _ = arr[2].([]byte)
	m.Tag, _ = arr[3].([]byte)

	return nil
}

// Mac0 creates a COSE_Mac0 message.
func Mac0(
	payload []byte,
	key []byte,
	algorithm int64,
	externalAAD []byte,
) (*COSEMac0, error) {
	headers := map[int64]any{
		HeaderAlgorithm: algorithm,
	}

	protectedBytes, err := cbor.Marshal(headers)
	if err != nil {
		return nil, fmt.Errorf("failed to encode protected headers: %w", err)
	}

	// Create MAC_structure
	macStructure := []any{
		"MAC0",
		protectedBytes,
		externalAAD,
		payload,
	}

	toMAC, err := cbor.Marshal(macStructure)
	if err != nil {
		return nil, fmt.Errorf("failed to encode MAC_structure: %w", err)
	}

	tag, err := computeMAC(toMAC, key, algorithm)
	if err != nil {
		return nil, fmt.Errorf("MAC computation failed: %w", err)
	}

	mac0 := &COSEMac0{
		Protected:   protectedBytes,
		Unprotected: make(map[any]any),
		Payload:     payload,
		Tag:         tag,
	}
	return mac0, nil
}

func computeMAC(data, key []byte, algorithm int64) ([]byte, error) {
	var h func() hash.Hash
	var truncate int

	switch algorithm {
	case AlgorithmHMAC256:
		h = sha256.New
		truncate = 32
	case AlgorithmHMAC384:
		h = sha512.New384
		truncate = 48
	case AlgorithmHMAC512:
		h = sha512.New
		truncate = 64
	default:
		return nil, fmt.Errorf("unsupported MAC algorithm: %d", algorithm)
	}

	mac := hmac.New(h, key)
	mac.Write(data)
	result := mac.Sum(nil)

	if len(result) > truncate {
		result = result[:truncate]
	}

	return result, nil
}

// VerifyCOSEMac0 verifies a COSE_Mac0 message.
func VerifyCOSEMac0(mac0 *COSEMac0, key []byte, externalAAD []byte) error {
	var headers map[int64]any
	if err := cbor.Unmarshal(mac0.Protected, &headers); err != nil {
		return fmt.Errorf("failed to decode protected headers: %w", err)
	}

	algRaw, ok := headers[HeaderAlgorithm]
	if !ok {
		return fmt.Errorf("missing algorithm in protected headers")
	}

	var algorithm int64
	switch v := algRaw.(type) {
	case int64:
		algorithm = v
	case int:
		algorithm = int64(v)
	case uint64:
		if v > math.MaxInt64 {
			return fmt.Errorf("algorithm value overflow: %T", algRaw)
		}
		algorithm = int64(v)
	default:
		return fmt.Errorf("invalid algorithm type: %T", algRaw)
	}

	macStructure := []any{
		"MAC0",
		mac0.Protected,
		externalAAD,
		mac0.Payload,
	}

	toMAC, err := cbor.Marshal(macStructure)
	if err != nil {
		return fmt.Errorf("failed to encode MAC_structure: %w", err)
	}

	expectedTag, err := computeMAC(toMAC, key, algorithm)
	if err != nil {
		return err
	}

	if !hmac.Equal(mac0.Tag, expectedTag) {
		return fmt.Errorf("MAC verification failed")
	}

	return nil
}

// lookupUnprotectedHeader looks up a COSE header label in an already-decoded
// unprotected-header map. cbor.Unmarshal into an `any`-typed map decodes a
// CBOR positive integer key as uint64 (not int64), so a plain `m[label]`
// lookup with an int64 label constant would silently never match - this
// checks both representations (plus plain int, for maps built directly in
// Go code rather than decoded from CBOR).
func lookupUnprotectedHeader(m map[any]any, label int64) (any, bool) {
	if v, ok := m[label]; ok {
		return v, true
	}
	if v, ok := m[uint64(label)]; ok {
		return v, true
	}
	if v, ok := m[int(label)]; ok {
		return v, true
	}
	return nil, false
}

// GetCertificateChainFromSign1 extracts the x5chain from a COSE_Sign1.
// If ext is provided, certificates are parsed using extension-aware parsing
// (e.g. to support brainpool curves).
//
// Checks the unprotected header first (the correct location per RFC 9360 -
// see Sign1's doc comment) and falls back to protected for compatibility
// with mdocs issued before that fix.
func GetCertificateChainFromSign1(sign1 *COSESign1, ext ...*cryptoutil.Extensions) ([]*x509.Certificate, error) {
	x5chainRaw, ok := lookupUnprotectedHeader(sign1.Unprotected, HeaderX5Chain)
	if !ok {
		x5chainRaw, ok = lookupUnprotectedHeader(sign1.Unprotected, HeaderX5ChainAlt)
	}

	if !ok {
		var headers map[int64]any
		if err := cbor.Unmarshal(sign1.Protected, &headers); err != nil {
			return nil, fmt.Errorf("failed to decode protected headers: %w", err)
		}
		x5chainRaw, ok = headers[HeaderX5Chain]
		if !ok {
			x5chainRaw, ok = headers[HeaderX5ChainAlt]
			if !ok {
				return nil, fmt.Errorf("no x5chain in headers")
			}
		}
	}

	var certBytes [][]byte
	switch v := x5chainRaw.(type) {
	case []byte:
		// Single certificate
		certBytes = [][]byte{v}
	case [][]byte:
		// Array of certificates, built directly in Go (not yet round-tripped
		// through CBOR encode/decode - see Sign1).
		certBytes = v
	case []any:
		// Array of certificates, as decoded generically from CBOR.
		for _, c := range v {
			b, ok := c.([]byte)
			if !ok {
				return nil, fmt.Errorf("invalid certificate in x5chain")
			}
			certBytes = append(certBytes, b)
		}
	default:
		return nil, fmt.Errorf("invalid x5chain type")
	}

	var certs []*x509.Certificate
	for _, b := range certBytes {
		var cert *x509.Certificate
		var err error
		if len(ext) > 0 && ext[0] != nil {
			cert, err = ext[0].ParseCertificate(b)
		} else {
			cert, err = x509.ParseCertificate(b)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

// AlgorithmForKey returns the appropriate COSE algorithm for a key.
// It accepts both public keys and signers (private keys).
func AlgorithmForKey(key any) (int64, error) {
	// If it's a signer, extract the public key
	if signer, ok := key.(crypto.Signer); ok {
		key = signer.Public()
	}

	switch k := key.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return AlgorithmES256, nil
		case elliptic.P384():
			return AlgorithmES384, nil
		case elliptic.P521():
			return AlgorithmES512, nil
		default:
			return 0, fmt.Errorf("unsupported ECDSA curve")
		}
	case ed25519.PublicKey:
		return AlgorithmEdDSA, nil
	default:
		return 0, fmt.Errorf("unsupported key type: %T", key)
	}
}
