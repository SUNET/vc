package tokenstatuslist

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// CWT constants per RFC 8392 and draft-ietf-oauth-status-list Section 6
const (
	// CWTTypHeader is the typ header value for Status List Token CWTs (Section 6.1)
	CWTTypHeader = "statuslist+cwt"

	// COSE header parameters (RFC 8152)
	coseHeaderAlg = 1  // Algorithm
	coseHeaderKid = 4  // Key ID
	coseHeaderTyp = 16 // Content Type (used for typ in CWT)

	// CWT claims (RFC 8392 Section 4)
	cwtClaimIss        = 1     // Issuer
	cwtClaimSub        = 2     // Subject
	cwtClaimExp        = 4     // Expiration Time
	cwtClaimIat        = 6     // Issued At
	cwtClaimStatusList = 65534 // status_list claim (draft-ietf-oauth-status-list Section 6.1)
	cwtClaimTTL        = 65535 // ttl claim (custom, for caching)

	// Status list CBOR map keys (Section 6.1)
	statusListKeyBits           = 1 // bits
	statusListKeyLst            = 2 // lst (raw bytes for CWT, not base64)
	statusListKeyAggregationURI = 3 // aggregation_uri
)

// COSE algorithm identifiers (RFC 8152 Section 8.1)
// Use these constants with CWTSigningConfig.Algorithm
const (
	CoseAlgES256 = -7  // ECDSA w/ SHA-256 (P-256 curve)
	CoseAlgES384 = -35 // ECDSA w/ SHA-384 (P-384 curve)
	CoseAlgES512 = -36 // ECDSA w/ SHA-512 (P-521 curve)
	CoseAlgPS256 = -37 // RSASSA-PSS w/ SHA-256
	CoseAlgPS384 = -38 // RSASSA-PSS w/ SHA-384
	CoseAlgPS512 = -39 // RSASSA-PSS w/ SHA-512
)

// CWTStatusList represents the status_list claim in CWT format (Section 6.1).
// Unlike JWT, CWT uses raw bytes for lst instead of base64url encoding.
type CWTStatusList struct {
	Bits           int    `cbor:"1,keyasint"`
	Lst            []byte `cbor:"2,keyasint"`
	AggregationURI string `cbor:"3,keyasint,omitempty"`
}

// CWTSigningConfig holds CWT-specific signing configuration.
type CWTSigningConfig struct {
	// SigningKey is the private key for signing (REQUIRED).
	// Supported types: *ecdsa.PrivateKey (ES256/ES384/ES512),
	// *rsa.PrivateKey (PS256/PS384/PS512).
	SigningKey crypto.PrivateKey

	// Algorithm specifies the COSE algorithm.
	// Use 0 to auto-detect from the key type and curve (ES256 for P-256,
	// ES384 for P-384, ES512 for P-521, PS256 for RSA keys).
	Algorithm int
}

// CWTConfig holds CWT-specific configuration for generating a Status List Token.
// Deprecated: Use StatusList.GenerateCWT with CWTSigningConfig instead.
type CWTConfig struct {
	TokenConfig

	// SigningKey is the private key for signing (REQUIRED).
	SigningKey crypto.PrivateKey

	// Algorithm specifies the COSE algorithm (default: ES256)
	Algorithm int
}

// GenerateCWT creates a signed Status List Token CWT per Section 6.1.
// The token is a COSE_Sign1 structure containing:
// - Protected header: alg, typ=statuslist+cwt, kid
// - Payload: CWT claims (iss, sub, iat, exp, ttl, status_list)
func (sl *StatusList) GenerateCWT(cfg CWTSigningConfig) ([]byte, error) {
	// Compress the status list (raw bytes for CWT, no base64 encoding)
	compressedStatuses, err := sl.Compress()
	if err != nil {
		return nil, fmt.Errorf("failed to compress status list: %w", err)
	}

	now := time.Now()

	// Build the CWT claims as a CBOR map with integer keys
	claims := map[int]any{
		cwtClaimIss: sl.Issuer,
		cwtClaimSub: sl.Subject,
		cwtClaimIat: now.Unix(),
		cwtClaimStatusList: CWTStatusList{
			Bits:           Bits,
			Lst:            compressedStatuses,
			AggregationURI: sl.AggregationURI,
		},
	}

	// Add optional expiration
	if sl.ExpiresIn > 0 {
		claims[cwtClaimExp] = now.Add(sl.ExpiresIn).Unix()
	}

	// Add optional TTL
	if sl.TTL > 0 {
		claims[cwtClaimTTL] = sl.TTL
	}

	// Determine algorithm: use explicit value, or auto-detect from key type.
	alg := cfg.Algorithm
	if alg == 0 {
		var err error
		alg, err = detectCOSEAlgorithm(cfg.SigningKey)
		if err != nil {
			return nil, err
		}
	}

	// Build protected header
	protectedHeader := map[int]any{
		coseHeaderAlg: alg,
		coseHeaderTyp: CWTTypHeader,
	}
	if sl.KeyID != "" {
		protectedHeader[coseHeaderKid] = sl.KeyID
	}

	// Encode protected header to CBOR
	protectedBytes, err := cbor.Marshal(protectedHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to encode protected header: %w", err)
	}

	// Encode payload (CWT claims) to CBOR
	payloadBytes, err := cbor.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to encode CWT claims: %w", err)
	}

	// Sign the COSE_Sign1 structure
	signature, err := signCOSE(protectedBytes, payloadBytes, cfg.SigningKey, alg)
	if err != nil {
		return nil, fmt.Errorf("failed to sign CWT: %w", err)
	}

	// Build COSE_Sign1 structure: [protected, unprotected, payload, signature]
	// Tag 18 indicates COSE_Sign1
	coseSign1 := cbor.Tag{
		Number:  18, // COSE_Sign1 tag
		Content: []any{protectedBytes, map[int]any{}, payloadBytes, signature},
	}

	// Encode the complete COSE_Sign1 structure
	cwtBytes, err := cbor.Marshal(coseSign1)
	if err != nil {
		return nil, fmt.Errorf("failed to encode COSE_Sign1: %w", err)
	}

	return cwtBytes, nil
}

// GenerateCWT creates a signed Status List Token CWT per Section 6.1.
// Deprecated: Use StatusList.GenerateCWT instead.
func GenerateCWT(cfg CWTConfig) ([]byte, error) {
	sl := &StatusList{
		statuses:       cfg.Statuses,
		Issuer:         cfg.Issuer,
		Subject:        cfg.Subject,
		TTL:            cfg.TTL,
		ExpiresIn:      cfg.ExpiresIn,
		KeyID:          cfg.KeyID,
		AggregationURI: cfg.AggregationURI,
	}
	return sl.GenerateCWT(CWTSigningConfig{
		SigningKey: cfg.SigningKey,
		Algorithm:  cfg.Algorithm,
	})
}

// signCOSE creates a COSE signature over the Sig_structure.
// Sig_structure = ["Signature1", protected, external_aad, payload]
func signCOSE(protectedBytes, payloadBytes []byte, key crypto.PrivateKey, alg int) ([]byte, error) {
	// Build Sig_structure per RFC 8152 Section 4.4
	sigStructure := []any{
		"Signature1",   // context
		protectedBytes, // body_protected
		[]byte{},       // external_aad (empty)
		payloadBytes,   // payload
	}

	sigStructureBytes, err := cbor.Marshal(sigStructure)
	if err != nil {
		return nil, fmt.Errorf("failed to encode Sig_structure: %w", err)
	}

	// Sign based on algorithm
	switch alg {
	case CoseAlgES256:
		return signECDSA(sigStructureBytes, key, sha256.New())
	case CoseAlgES384:
		return signECDSA(sigStructureBytes, key, sha512.New384())
	case CoseAlgES512:
		return signECDSA(sigStructureBytes, key, sha512.New())
	case CoseAlgPS256:
		return signRSAPSS(sigStructureBytes, key, crypto.SHA256)
	case CoseAlgPS384:
		return signRSAPSS(sigStructureBytes, key, crypto.SHA384)
	case CoseAlgPS512:
		return signRSAPSS(sigStructureBytes, key, crypto.SHA512)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %d", alg)
	}
}

// signECDSA signs data using ECDSA with the provided hash function.
// This allows callers to specify the hash algorithm (SHA-256, SHA-384, SHA-512).
func signECDSA(data []byte, key crypto.PrivateKey, hasher hash.Hash) ([]byte, error) {
	defer hasher.Reset()

	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key must be *ecdsa.PrivateKey")
	}

	// Hash the data
	hasher.Write(data)
	digest := hasher.Sum(nil)

	// Sign - ECDSA produces two integer components (sigR, sigS)
	sigR, sigS, err := ecdsa.Sign(rand.Reader, ecdsaKey, digest)
	if err != nil {
		return nil, fmt.Errorf("ECDSA signing failed: %w", err)
	}

	// COSE uses fixed-length concatenation of sigR and sigS
	curveBits := ecdsaKey.Curve.Params().BitSize
	keyBytes := (curveBits + 7) / 8

	signature := make([]byte, 2*keyBytes)
	sigRBytes := sigR.Bytes()
	sigSBytes := sigS.Bytes()

	// Pad sigR and sigS to fixed length
	copy(signature[keyBytes-len(sigRBytes):keyBytes], sigRBytes)
	copy(signature[2*keyBytes-len(sigSBytes):], sigSBytes)

	return signature, nil
}

// signRSAPSS signs data using RSASSA-PSS with the provided hash algorithm.
func signRSAPSS(data []byte, key crypto.PrivateKey, hashAlg crypto.Hash) ([]byte, error) {
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key must be *rsa.PrivateKey for PS* algorithms")
	}

	h := hashAlg.New()
	h.Write(data)
	digest := h.Sum(nil)

	return rsa.SignPSS(rand.Reader, rsaKey, hashAlg, digest, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
}

// detectCOSEAlgorithm picks a default COSE algorithm based on the key type and curve.
func detectCOSEAlgorithm(key crypto.PrivateKey) (int, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		switch k.Curve.Params().BitSize {
		case 256:
			return CoseAlgES256, nil
		case 384:
			return CoseAlgES384, nil
		case 521:
			return CoseAlgES512, nil
		default:
			return 0, fmt.Errorf("unsupported ECDSA curve bit size: %d", k.Curve.Params().BitSize)
		}
	case *rsa.PrivateKey:
		return CoseAlgPS256, nil
	default:
		return 0, fmt.Errorf("unsupported key type for CWT signing: %T", key)
	}
}

// ParseCWT parses a Status List Token CWT and returns the claims.
// Note: This function does NOT verify the signature. Use VerifyCWT for full validation.
func ParseCWT(cwtBytes []byte) (map[int]any, error) {
	// Decode COSE_Sign1 structure
	var coseSign1 cbor.Tag
	if err := cbor.Unmarshal(cwtBytes, &coseSign1); err != nil {
		return nil, fmt.Errorf("failed to decode COSE_Sign1: %w", err)
	}

	if coseSign1.Number != 18 {
		return nil, fmt.Errorf("invalid COSE tag: expected 18 (COSE_Sign1), got %d", coseSign1.Number)
	}

	// Extract components: [protected, unprotected, payload, signature]
	components, ok := coseSign1.Content.([]any)
	if !ok || len(components) != 4 {
		return nil, fmt.Errorf("invalid COSE_Sign1 structure")
	}

	payloadBytes, ok := components[2].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid payload in COSE_Sign1")
	}

	// Decode CWT claims
	var claims map[int]any
	if err := cbor.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to decode CWT claims: %w", err)
	}

	return claims, nil
}

// GetStatusFromCWT retrieves a status value from parsed CWT claims.
// The index corresponds to the "idx" value in the Referenced Token's status claim.
func GetStatusFromCWT(claims map[int]any, index int) (uint8, error) {
	// Get the status_list claim
	statusListRaw, ok := claims[cwtClaimStatusList]
	if !ok {
		return 0, fmt.Errorf("status_list claim not found")
	}

	// The status_list can come back in different map formats depending on CBOR decoding
	var lstBytes []byte

	switch sl := statusListRaw.(type) {
	case map[any]any:
		// Try both int and int64 keys
		for k, v := range sl {
			switch key := k.(type) {
			case int:
				if key == statusListKeyLst {
					if b, ok := v.([]byte); ok {
						lstBytes = b
					}
				}
			case int64:
				if key == int64(statusListKeyLst) {
					if b, ok := v.([]byte); ok {
						lstBytes = b
					}
				}
			case uint64:
				if key == uint64(statusListKeyLst) {
					if b, ok := v.([]byte); ok {
						lstBytes = b
					}
				}
			}
		}
	case map[int]any:
		if b, ok := sl[statusListKeyLst].([]byte); ok {
			lstBytes = b
		}
	case CWTStatusList:
		lstBytes = sl.Lst
	default:
		return 0, fmt.Errorf("invalid status_list claim format: %T", statusListRaw)
	}

	if lstBytes == nil {
		return 0, fmt.Errorf("lst not found in status_list")
	}

	// Decompress
	statuses, err := DecompressStatuses(lstBytes)
	if err != nil {
		return 0, fmt.Errorf("failed to decompress status list: %w", err)
	}

	return GetStatus(statuses, index)
}
