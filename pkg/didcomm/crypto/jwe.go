//go:build didcomm && vc20

package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// JWEHeader represents the protected header of a JWE.
type JWEHeader struct {
	// Algorithm is the key agreement algorithm (e.g., ECDH-ES, ECDH-1PU)
	Algorithm string `json:"alg"`

	// Encryption is the content encryption algorithm (e.g., A256GCM, A256CBC-HS512)
	Encryption string `json:"enc"`

	// Type is the media type of the JWE (should be "didcomm-encrypted+json")
	Type string `json:"typ,omitempty"`

	// SenderKeyID is the sender's key ID (for ECDH-1PU authcrypt)
	SenderKeyID string `json:"skid,omitempty"`

	// AgreementPartyUInfo is the APU for ECDH (base64url-encoded sender DID)
	AgreementPartyUInfo string `json:"apu,omitempty"`

	// AgreementPartyVInfo is the APV for ECDH (base64url-encoded recipient DIDs hash)
	AgreementPartyVInfo string `json:"apv,omitempty"`

	// EphemeralPublicKey is the ephemeral public key used for ECDH key agreement
	EphemeralPublicKey json.RawMessage `json:"epk,omitempty"`
}

// EncryptionOptions configures encryption behavior.
type EncryptionOptions struct {
	// Algorithm is the key agreement algorithm. Default: ECDH-ES (anoncrypt)
	Algorithm string

	// Encryption is the content encryption algorithm. Default: A256GCM
	Encryption string

	// SenderKey is the sender's private key (required for ECDH-1PU authcrypt)
	SenderKey jwk.Key

	// SenderDID is the sender's DID (for APU)
	SenderDID string
}

// DefaultEncryptionOptions returns options for anonymous encryption (anoncrypt).
func DefaultEncryptionOptions() EncryptionOptions {
	return EncryptionOptions{
		Algorithm:  "ECDH-ES+A256KW",
		Encryption: "A256GCM",
	}
}

// AuthcryptOptions returns options for authenticated encryption (authcrypt).
func AuthcryptOptions(senderKey jwk.Key, senderDID string) EncryptionOptions {
	return EncryptionOptions{
		Algorithm:  "ECDH-1PU+A256KW",
		Encryption: "A256CBC-HS512",
		SenderKey:  senderKey,
		SenderDID:  senderDID,
	}
}

// Encrypt encrypts a plaintext message for the given recipients.
// Returns a JWE compact serialization or JSON serialization depending on recipient count.
//
// For algorithms not natively supported by jwx (XC20P, ECDH-1PU), this function
// delegates to custom implementations.
func Encrypt(ctx context.Context, plaintext []byte, recipientKeys []jwk.Key, opts EncryptionOptions) ([]byte, error) {
	if len(recipientKeys) == 0 {
		return nil, ErrNoRecipients
	}

	// Check if we need custom implementation for ECDH-1PU
	if opts.Algorithm == AlgECDH1PUA256KW || opts.Algorithm == "ECDH-1PU+A256KW" {
		return encryptECDH1PU(ctx, plaintext, recipientKeys, opts)
	}

	// Check if we need custom implementation for XC20P
	if opts.Encryption == EncXC20P || opts.Encryption == "XC20P" {
		return encryptXC20P(ctx, plaintext, recipientKeys, opts)
	}

	// Use jwx for standard algorithms
	return encryptWithJWX(ctx, plaintext, recipientKeys, opts)
}

// encryptWithJWX uses the jwx library for standard JOSE algorithms.
func encryptWithJWX(ctx context.Context, plaintext []byte, recipientKeys []jwk.Key, opts EncryptionOptions) ([]byte, error) {
	// Determine algorithms
	keyAlg := jwa.ECDH_ES_A256KW()
	if opts.Algorithm != "" {
		var err error
		keyAlg, err = parseKeyAlgorithm(opts.Algorithm)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnsupportedAlgorithm, err)
		}
	}

	contentAlg := jwa.A256GCM()
	if opts.Encryption != "" {
		var err error
		contentAlg, err = parseContentAlgorithm(opts.Encryption)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnsupportedAlgorithm, err)
		}
	}

	// Build encryption options
	encOpts := []jwe.EncryptOption{
		jwe.WithContentEncryption(contentAlg),
	}

	// For multi-recipient, we need to use JSON serialization
	if len(recipientKeys) > 1 {
		// Multi-recipient encryption requires JSON serialization
		encOpts = append(encOpts, jwe.WithJSON())
		for _, recipientKey := range recipientKeys {
			encOpts = append(encOpts, jwe.WithKey(keyAlg, recipientKey))
		}
	} else {
		encOpts = append(encOpts, jwe.WithKey(keyAlg, recipientKeys[0]))
	}

	// Encrypt
	encrypted, err := jwe.Encrypt(plaintext, encOpts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	return encrypted, nil
}

// encryptXC20P encrypts using XChaCha20-Poly1305 content encryption with ECDH-ES key agreement.
func encryptXC20P(ctx context.Context, plaintext []byte, recipientKeys []jwk.Key, opts EncryptionOptions) ([]byte, error) {
	// Generate a random content encryption key
	cek, err := GenerateContentEncryptionKey(EncXC20P)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CEK: %w", err)
	}

	// Create XC20P encryptor
	encryptor, err := NewXC20P(cek)
	if err != nil {
		return nil, fmt.Errorf("failed to create XC20P encryptor: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, XC20PNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// For DIDComm v2, we generate a single ephemeral key and put it in the protected header.
	// All recipients must use the same curve for this to work.
	// Get curve from first recipient
	crv, err := getCurveFromKey(recipientKeys[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get curve from recipient key: %w", err)
	}

	// Generate ephemeral key
	ephemeralKey, err := generateECDHKey(crv)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	ephemeralPubKey, err := ephemeralKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get ephemeral public key: %w", err)
	}

	// Serialize ephemeral public key for protected header
	epkJSON, err := json.Marshal(ephemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ephemeral key: %w", err)
	}

	// Compute APV (Agreement PartyV Info) from recipients
	// APV is SHA-256 hash of sorted recipient KIDs
	kids := make([]string, 0, len(recipientKeys))
	for _, k := range recipientKeys {
		var kid string
		_ = k.Get("kid", &kid)
		kids = append(kids, kid)
	}
	sort.Strings(kids)
	apvInput := strings.Join(kids, ".")
	apvHash := sha256.Sum256([]byte(apvInput))
	// APV is stored as base64url-encoded in header, but passed as raw bytes to KDF
	apvBytes := apvHash[:]
	apvB64 := base64.RawURLEncoding.EncodeToString(apvBytes)

	// APU (Agreement PartyU Info) - typically sender DID for anoncrypt is empty
	var apuBytes []byte
	var apuB64 string
	if opts.SenderDID != "" {
		apuBytes = []byte(opts.SenderDID)
		apuB64 = base64.RawURLEncoding.EncodeToString(apuBytes)
	}

	// Build protected header with EPK and APV
	protectedHeader := JWEHeader{
		Algorithm:           opts.Algorithm,
		Encryption:          EncXC20P,
		Type:                "application/didcomm-encrypted+json",
		EphemeralPublicKey:  epkJSON,
		AgreementPartyVInfo: apvB64,
	}
	if apuB64 != "" {
		protectedHeader.AgreementPartyUInfo = apuB64
	}

	protectedHeaderJSON, err := json.Marshal(protectedHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize protected header: %w", err)
	}
	protectedB64 := base64.RawURLEncoding.EncodeToString(protectedHeaderJSON)

	// Use protected header as AAD (ASCII bytes of base64url-encoded protected header)
	aad := []byte(protectedB64)

	// Encrypt the content with AAD
	ciphertext, tag, err := encryptor.EncryptSeparate(nonce, plaintext, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt content: %w", err)
	}

	// Build recipients using ECDH-ES to wrap the CEK
	recipients := make([]Recipient, len(recipientKeys))

	for i, recipientKey := range recipientKeys {
		// Wrap the CEK using ECDH-ES+A256KW with the shared ephemeral key
		// Pass APU and APV to the KDF
		wrappedKey, _, err := wrapKeyECDHES(cek, ephemeralKey, recipientKey, opts.Algorithm, apuBytes, apvBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to wrap key for recipient %d: %w", i, err)
		}

		// Get recipient key ID
		var kid string
		_ = recipientKey.Get("kid", &kid)

		recipients[i] = Recipient{
			Header: RecipientHeader{
				KeyID: kid,
			},
			EncryptedKey: base64.RawURLEncoding.EncodeToString(wrappedKey),
		}
	}

	// Build the complete JWE
	encryptedMsg := EncryptedMessage{
		Protected:  protectedB64,
		Recipients: recipients,
		IV:         base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
		Tag:        base64.RawURLEncoding.EncodeToString(tag),
	}

	return json.Marshal(encryptedMsg)
}

// encryptECDH1PU encrypts using ECDH-1PU key agreement (authenticated encryption).
// This implements the DIDComm authcrypt mode per DIDComm v2.1 specification.
//
// ECDH-1PU uses key commitment: the content authentication tag (cc_tag) is included
// in the KDF, binding the key derivation to the specific ciphertext.
func encryptECDH1PU(ctx context.Context, plaintext []byte, recipientKeys []jwk.Key, opts EncryptionOptions) ([]byte, error) {
	if opts.SenderKey == nil {
		return nil, fmt.Errorf("%w: sender key required for ECDH-1PU", ErrInvalidKey)
	}

	// Determine content encryption algorithm
	contentEnc := opts.Encryption
	if contentEnc == "" {
		contentEnc = EncA256CBCHS512 // Default for authcrypt
	}

	// Generate CEK based on content encryption algorithm
	cek, err := GenerateContentEncryptionKey(contentEnc)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CEK: %w", err)
	}

	// Generate a single ephemeral key pair shared across all recipients
	crv, err := getCurveFromKey(recipientKeys[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get curve from recipient key: %w", err)
	}
	ephemeralPrivKey, err := generateECDHKey(crv)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	ephemeralPubKey, err := ephemeralPrivKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get ephemeral public key: %w", err)
	}

	// Serialize ephemeral public key for protected header
	epkJSON, err := json.Marshal(ephemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ephemeral key: %w", err)
	}

	// Get sender key ID for skid header
	var skid string
	_ = opts.SenderKey.Get("kid", &skid)

	// Compute APV: SHA-256 hash of sorted recipient key IDs
	apv := computeAPV(recipientKeys)

	// Build protected header first (needed for AAD before content encryption)
	protectedHeader := JWEHeader{
		Algorithm:           opts.Algorithm,
		Encryption:          contentEnc,
		Type:                "application/didcomm-encrypted+json",
		SenderKeyID:         skid,
		EphemeralPublicKey:  epkJSON,
		AgreementPartyVInfo: base64.RawURLEncoding.EncodeToString(apv),
	}
	if opts.SenderDID != "" {
		protectedHeader.AgreementPartyUInfo = base64.RawURLEncoding.EncodeToString([]byte(opts.SenderDID))
	}

	protectedHeaderJSON, err := json.Marshal(protectedHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize protected header: %w", err)
	}
	protectedB64 := base64.RawURLEncoding.EncodeToString(protectedHeaderJSON)

	// Encrypt content based on algorithm
	var ciphertext, tag, nonce []byte
	aad := []byte(protectedB64) // AAD is the ASCII bytes of the base64url-encoded protected header

	switch contentEnc {
	case EncXC20P:
		encryptor, err := NewXC20P(cek)
		if err != nil {
			return nil, fmt.Errorf("failed to create XC20P encryptor: %w", err)
		}
		nonce = make([]byte, XC20PNonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("failed to generate nonce: %w", err)
		}
		// XC20P uses combined ciphertext+tag, but we need to separate them for JWE format
		ciphertext, tag, err = encryptor.EncryptSeparate(nonce, plaintext, aad)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt content: %w", err)
		}

	case EncA256CBCHS512:
		// A256CBC-HS512 encryption per RFC 7518
		ciphertext, tag, nonce, err = encryptA256CBCHS512(plaintext, cek, aad)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt content: %w", err)
		}

	case EncA256GCM:
		// A256GCM encryption
		ciphertext, tag, nonce, err = encryptA256GCM(plaintext, cek, aad)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt content: %w", err)
		}

	default:
		return nil, fmt.Errorf("ECDH-1PU with %s content encryption not supported", contentEnc)
	}

	// Build recipients using ECDH-1PU with key commitment (cc_tag)
	// The tag is included in the KDF per draft-madden-jose-ecdh-1pu
	recipients := make([]Recipient, len(recipientKeys))

	for i, recipientKey := range recipientKeys {
		// Create ECDH-1PU key agreement with cc_tag for key commitment
		agreement, err := NewECDH1PU(opts.SenderKey, recipientKey, opts.Algorithm, contentEnc)
		if err != nil {
			return nil, fmt.Errorf("failed to create ECDH-1PU for recipient %d: %w", i, err)
		}

		// Set ephemeral key (shared across all recipients)
		agreement.EphemeralPrivateKey = ephemeralPrivKey

		// Set APU/APV
		if opts.SenderDID != "" {
			agreement.APU = []byte(opts.SenderDID)
		}
		agreement.APV = apv

		// Set cc_tag for key commitment (binds key derivation to this ciphertext)
		agreement.CCTag = tag

		// Derive key wrapping key using ECDH-1PU with cc_tag
		wrappingKey, _, err := agreement.DeriveKeyWithTag(tag)
		if err != nil {
			return nil, fmt.Errorf("failed to derive key for recipient %d: %w", i, err)
		}

		// Wrap the CEK
		wrappedKey, err := wrapKeyAES(cek, wrappingKey)
		if err != nil {
			return nil, fmt.Errorf("failed to wrap key for recipient %d: %w", i, err)
		}

		// Get recipient key ID
		var kid string
		_ = recipientKey.Get("kid", &kid)

		recipients[i] = Recipient{
			Header: RecipientHeader{
				KeyID: kid,
			},
			EncryptedKey: base64.RawURLEncoding.EncodeToString(wrappedKey),
		}
	}

	// Build the complete JWE
	encryptedMsg := EncryptedMessage{
		Protected:  protectedB64,
		Recipients: recipients,
		IV:         base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
		Tag:        base64.RawURLEncoding.EncodeToString(tag),
	}

	return json.Marshal(encryptedMsg)
}

// computeAPV computes the APV (Agreement PartyV Info) as SHA-256 hash of sorted recipient key IDs.
func computeAPV(recipientKeys []jwk.Key) []byte {
	kids := make([]string, len(recipientKeys))
	for i, key := range recipientKeys {
		var kid string
		_ = key.Get("kid", &kid)
		kids[i] = kid
	}
	sort.Strings(kids)

	h := sha256.New()
	for i, kid := range kids {
		if i > 0 {
			h.Write([]byte("."))
		}
		h.Write([]byte(kid))
	}
	return h.Sum(nil)
}

// encryptA256CBCHS512 encrypts plaintext using AES-256-CBC with HMAC-SHA-512.
// Returns ciphertext, authentication tag, IV, and any error.
func encryptA256CBCHS512(plaintext, cek, aad []byte) (ciphertext, tag, iv []byte, err error) {
	// A256CBC-HS512 uses a 64-byte key: first 32 bytes for HMAC, last 32 bytes for AES
	if len(cek) != 64 {
		return nil, nil, nil, fmt.Errorf("A256CBC-HS512 CEK must be 64 bytes, got %d", len(cek))
	}

	macKey := cek[:32]
	encKey := cek[32:]

	// Generate random IV
	iv = make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// PKCS7 padding
	padded := pkcs7Pad(plaintext, aes.BlockSize)

	// Encrypt using AES-256-CBC (per RFC 7518 A256CBC-HS512)
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	ciphertext = make([]byte, len(padded))
	//nolint:gosec // RFC 7518 A256CBC-HS512 requires CBC mode - this is authenticated encryption with HMAC-SHA-512
	mode := cipher.NewCBCEncrypter(block, iv) //NOSONAR
	mode.CryptBlocks(ciphertext, padded)

	// Compute HMAC-SHA-512 tag
	// Per RFC 7518: MAC_INPUT = AAD || IV || E || AL
	// where AL is the 64-bit big-endian representation of AAD length in bits
	al := make([]byte, 8)
	binary.BigEndian.PutUint64(al, uint64(len(aad)*8))

	macInput := make([]byte, 0, len(aad)+len(iv)+len(ciphertext)+8)
	macInput = append(macInput, aad...)
	macInput = append(macInput, iv...)
	macInput = append(macInput, ciphertext...)
	macInput = append(macInput, al...)

	mac := hmac.New(sha512.New, macKey)
	mac.Write(macInput)
	tag = mac.Sum(nil)[:32] // Use first 32 bytes (256 bits) for A256CBC-HS512

	return ciphertext, tag, iv, nil
}

// encryptA256GCM encrypts plaintext using AES-256-GCM.
// Returns ciphertext, authentication tag, nonce, and any error.
func encryptA256GCM(plaintext, cek, aad []byte) (ciphertext, tag, nonce []byte, err error) {
	if len(cek) != 32 {
		return nil, nil, nil, fmt.Errorf("A256GCM CEK must be 32 bytes, got %d", len(cek))
	}

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// GCM Seal returns ciphertext+tag appended
	sealed := gcm.Seal(nil, nonce, plaintext, aad)

	// Split ciphertext and tag (tag is last 16 bytes)
	tagSize := gcm.Overhead()
	ciphertext = sealed[:len(sealed)-tagSize]
	tag = sealed[len(sealed)-tagSize:]

	return ciphertext, tag, nonce, nil
}

// pkcs7Pad adds PKCS7 padding to a byte slice.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	padding := make([]byte, padLen)
	for i := range padding {
		padding[i] = byte(padLen)
	}
	return append(data, padding...)
}

// wrapKeyECDHES wraps a key using ECDH-ES+A256KW.
func wrapKeyECDHES(cek []byte, ephemeralPriv, recipientPub jwk.Key, algorithm string, apu, apv []byte) ([]byte, jwk.Key, error) {
	// Extract keys for ECDH
	ephPriv, err := extractECDHPrivateKey(ephemeralPriv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract ephemeral private key: %w", err)
	}

	recipPub, err := extractECDHPublicKey(recipientPub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract recipient public key: %w", err)
	}

	// Compute ECDH shared secret
	z, err := ephPriv.ECDH(recipPub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute ECDH: %w", err)
	}

	// Derive key wrapping key using Concat KDF
	// Use the full algorithm name (e.g., "ECDH-ES+A256KW") per RFC 7518 Section 4.6.2
	keySize := 32 // 256 bits for A256KW
	wrappingKey, err := concatKDF(z, algorithm, apu, apv, keySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive wrapping key: %w", err)
	}

	// Wrap the CEK using AES-KW
	wrappedKey, err := wrapKeyAES(cek, wrappingKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to wrap key: %w", err)
	}

	// Get ephemeral public key for header
	ephPubKey, err := ephemeralPriv.PublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get ephemeral public key: %w", err)
	}

	return wrappedKey, ephPubKey, nil
}

// wrapKeyAES wraps a key using AES Key Wrap (RFC 3394).
func wrapKeyAES(cek, wrappingKey []byte) ([]byte, error) {
	if len(wrappingKey) != 16 && len(wrappingKey) != 24 && len(wrappingKey) != 32 {
		return nil, fmt.Errorf("wrapping key must be 16, 24, or 32 bytes")
	}

	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// RFC 3394 AES Key Wrap
	n := len(cek) / 8
	if len(cek)%8 != 0 {
		return nil, fmt.Errorf("CEK length must be multiple of 8 bytes")
	}

	// Initialize A with default IV
	a := []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

	// Initialize R[1]..R[n]
	r := make([][]byte, n+1)
	for i := 1; i <= n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], cek[(i-1)*8:i*8])
	}

	// Wrap per RFC 3394 AES Key Wrap
	for j := 0; j <= 5; j++ {
		for i := 1; i <= n; i++ {
			// B = AES(K, A | R[i])
			b := make([]byte, 16)
			copy(b[:8], a)
			copy(b[8:], r[i])
			//nolint:gosec // RFC 3394 AES Key Wrap - this is a key-wrapping primitive with integrity check
			block.Encrypt(b, b) //NOSONAR

			// A = MSB(64, B) ^ t where t = (n*j)+i
			t := uint64(n*j + i)
			copy(a, b[:8])
			a[7] ^= byte(t)
			a[6] ^= byte(t >> 8)
			a[5] ^= byte(t >> 16)
			a[4] ^= byte(t >> 24)
			a[3] ^= byte(t >> 32)
			a[2] ^= byte(t >> 40)
			a[1] ^= byte(t >> 48)
			a[0] ^= byte(t >> 56)

			// R[i] = LSB(64, B)
			copy(r[i], b[8:])
		}
	}

	// Output: A | R[1] | ... | R[n]
	wrapped := make([]byte, 8+n*8)
	copy(wrapped[:8], a)
	for i := 1; i <= n; i++ {
		copy(wrapped[i*8:(i+1)*8], r[i])
	}

	return wrapped, nil
}

// Decrypt decrypts a JWE using the provided private key.
// Supports both standard JOSE algorithms via jwx and custom algorithms (XC20P, ECDH-1PU).
func Decrypt(ctx context.Context, encrypted []byte, privateKey jwk.Key) ([]byte, error) {
	// First, try to parse as JSON to check the algorithm
	var msg EncryptedMessage
	if err := json.Unmarshal(encrypted, &msg); err == nil && msg.Protected != "" {
		// Parse protected header to determine algorithm
		protectedJSON, err := base64.RawURLEncoding.DecodeString(msg.Protected)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to decode protected header", ErrInvalidJWE)
		}

		var header JWEHeader
		if err := json.Unmarshal(protectedJSON, &header); err != nil {
			return nil, fmt.Errorf("%w: failed to parse protected header", ErrInvalidJWE)
		}

		// Check for custom algorithms
		if header.Encryption == EncXC20P || header.Encryption == "XC20P" {
			return decryptXC20P(ctx, &msg, &header, privateKey, nil)
		}
		if header.Algorithm == AlgECDH1PUA256KW || header.Algorithm == "ECDH-1PU+A256KW" {
			// For ECDH-1PU, we need the sender's public key
			// This should be provided via a different method or looked up
			return nil, fmt.Errorf("ECDH-1PU decryption requires sender public key - use DecryptECDH1PU")
		}
	}

	// Use jwx for standard algorithms
	plaintext, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.ECDH_ES_A256KW(), privateKey))
	if err != nil {
		// Try other algorithms
		plaintext, err = jwe.Decrypt(encrypted, jwe.WithKey(jwa.ECDH_ES_A128KW(), privateKey))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
		}
	}

	return plaintext, nil
}

// DecryptECDH1PU decrypts a JWE that uses ECDH-1PU (authcrypt).
// Requires the recipient's private key and the sender's public key.
func DecryptECDH1PU(ctx context.Context, encrypted []byte, recipientPrivateKey, senderPublicKey jwk.Key) ([]byte, error) {
	var msg EncryptedMessage
	if err := json.Unmarshal(encrypted, &msg); err != nil {
		return nil, fmt.Errorf("%w: failed to parse JWE: %v", ErrInvalidJWE, err)
	}

	// Parse protected header
	protectedJSON, err := base64.RawURLEncoding.DecodeString(msg.Protected)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode protected header", ErrInvalidJWE)
	}

	var header JWEHeader
	if err := json.Unmarshal(protectedJSON, &header); err != nil {
		return nil, fmt.Errorf("%w: failed to parse protected header", ErrInvalidJWE)
	}

	if header.Encryption == EncXC20P || header.Encryption == "XC20P" {
		return decryptXC20P(ctx, &msg, &header, recipientPrivateKey, senderPublicKey)
	}

	if header.Encryption == EncA256CBCHS512 || header.Encryption == "A256CBC-HS512" {
		return decryptA256CBCHS512(ctx, &msg, &header, recipientPrivateKey, senderPublicKey)
	}

	return nil, fmt.Errorf("ECDH-1PU with %s content encryption not yet implemented", header.Encryption)
}

// decryptXC20P decrypts a JWE using XChaCha20-Poly1305.
func decryptXC20P(ctx context.Context, msg *EncryptedMessage, header *JWEHeader, recipientKey jwk.Key, senderPubKey jwk.Key) ([]byte, error) {
	// Get recipient key ID
	var recipientKID string
	_ = recipientKey.Get("kid", &recipientKID)

	// Find matching recipient
	var matchedRecipient *Recipient
	for i := range msg.Recipients {
		if msg.Recipients[i].Header.KeyID == recipientKID {
			matchedRecipient = &msg.Recipients[i]
			break
		}
	}
	if matchedRecipient == nil && len(msg.Recipients) > 0 {
		// Try first recipient if no KID match
		matchedRecipient = &msg.Recipients[0]
	}
	if matchedRecipient == nil {
		return nil, fmt.Errorf("%w: no matching recipient found", ErrRecipientNotFound)
	}

	// Parse ephemeral public key from protected header (standard location) or recipient header
	var ephemeralPubKey jwk.Key
	var err error

	// First, try the protected header (standard DIDComm v2 location)
	if len(header.EphemeralPublicKey) > 0 {
		ephemeralPubKey, err = jwk.ParseKey(header.EphemeralPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ephemeral public key from protected header: %w", err)
		}
	} else if len(matchedRecipient.Header.EphemeralPublicKey) > 0 {
		// Fall back to recipient header (per-recipient EPK)
		ephemeralPubKey, err = jwk.ParseKey(matchedRecipient.Header.EphemeralPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ephemeral public key from recipient header: %w", err)
		}
	}

	if ephemeralPubKey == nil {
		return nil, fmt.Errorf("%w: no ephemeral public key found", ErrInvalidJWE)
	}

	// Decode the authentication tag first - we need it for ECDH-1PU key derivation
	tag, err := base64.RawURLEncoding.DecodeString(msg.Tag)
	if err != nil {
		return nil, fmt.Errorf("failed to decode tag: %w", err)
	}

	// Unwrap the CEK
	var cek []byte

	if header.Algorithm == AlgECDH1PUA256KW || header.Algorithm == "ECDH-1PU+A256KW" {
		// ECDH-1PU key agreement (with tag for key commitment)
		if senderPubKey == nil {
			return nil, fmt.Errorf("%w: sender public key required for ECDH-1PU", ErrInvalidKey)
		}
		cek, err = unwrapKeyECDH1PU(matchedRecipient.EncryptedKey, recipientKey, senderPubKey, ephemeralPubKey, header, tag)
	} else {
		// ECDH-ES key agreement
		cek, err = unwrapKeyECDHES(matchedRecipient.EncryptedKey, recipientKey, ephemeralPubKey, header)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap CEK: %w", err)
	}

	// Create XC20P decryptor
	decryptor, err := NewXC20P(cek)
	if err != nil {
		return nil, fmt.Errorf("failed to create XC20P decryptor: %w", err)
	}

	// Decode IV and ciphertext
	nonce, err := base64.RawURLEncoding.DecodeString(msg.IV)
	if err != nil {
		return nil, fmt.Errorf("failed to decode IV: %w", err)
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(msg.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	// Use protected header as AAD (ASCII bytes of base64url-encoded protected header)
	// This is required per JOSE/JWE spec
	aad := []byte(msg.Protected)

	// Decrypt using separate ciphertext and tag
	plaintext, err := decryptor.DecryptSeparate(nonce, ciphertext, tag, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return plaintext, nil
}

// decryptA256CBCHS512 decrypts a JWE using AES-256-CBC with HMAC-SHA-512.
// This is the standard content encryption for ECDH-1PU authcrypt.
func decryptA256CBCHS512(ctx context.Context, msg *EncryptedMessage, header *JWEHeader, recipientKey jwk.Key, senderPubKey jwk.Key) ([]byte, error) {
	// Get recipient key ID
	var recipientKID string
	_ = recipientKey.Get("kid", &recipientKID)

	// Find matching recipient
	var matchedRecipient *Recipient
	for i := range msg.Recipients {
		if msg.Recipients[i].Header.KeyID == recipientKID {
			matchedRecipient = &msg.Recipients[i]
			break
		}
	}
	if matchedRecipient == nil && len(msg.Recipients) > 0 {
		// Try first recipient if no KID match
		matchedRecipient = &msg.Recipients[0]
	}
	if matchedRecipient == nil {
		return nil, fmt.Errorf("%w: no matching recipient found", ErrRecipientNotFound)
	}

	// Parse ephemeral public key from protected header
	var ephemeralPubKey jwk.Key
	var err error

	if len(header.EphemeralPublicKey) > 0 {
		ephemeralPubKey, err = jwk.ParseKey(header.EphemeralPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ephemeral public key: %w", err)
		}
	} else if len(matchedRecipient.Header.EphemeralPublicKey) > 0 {
		ephemeralPubKey, err = jwk.ParseKey(matchedRecipient.Header.EphemeralPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ephemeral public key from recipient header: %w", err)
		}
	}

	if ephemeralPubKey == nil {
		return nil, fmt.Errorf("%w: no ephemeral public key found", ErrInvalidJWE)
	}

	// Decode the authentication tag first - we need it for ECDH-1PU key derivation
	tag, err := base64.RawURLEncoding.DecodeString(msg.Tag)
	if err != nil {
		return nil, fmt.Errorf("failed to decode tag: %w", err)
	}

	// Unwrap the CEK using ECDH-1PU (with tag for key commitment)
	if senderPubKey == nil {
		return nil, fmt.Errorf("%w: sender public key required for ECDH-1PU", ErrInvalidKey)
	}
	cek, err := unwrapKeyECDH1PU(matchedRecipient.EncryptedKey, recipientKey, senderPubKey, ephemeralPubKey, header, tag)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap CEK: %w", err)
	}

	// A256CBC-HS512 uses a 64-byte key: first 32 bytes for HMAC, last 32 bytes for AES
	if len(cek) != 64 {
		return nil, fmt.Errorf("%w: A256CBC-HS512 CEK must be 64 bytes, got %d", ErrInvalidKey, len(cek))
	}

	macKey := cek[:32]
	encKey := cek[32:]

	// Decode IV and ciphertext
	iv, err := base64.RawURLEncoding.DecodeString(msg.IV)
	if err != nil {
		return nil, fmt.Errorf("failed to decode IV: %w", err)
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("%w: IV must be %d bytes, got %d", ErrInvalidJWE, aes.BlockSize, len(iv))
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(msg.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	// AAD is the ASCII bytes of the protected header (base64url-encoded)
	aad := []byte(msg.Protected)

	// Verify HMAC-SHA-512 tag
	// Per RFC 7518: MAC_INPUT = AAD || IV || E || AL
	// where AL is the 64-bit big-endian representation of AAD length in bits
	al := make([]byte, 8)
	binary.BigEndian.PutUint64(al, uint64(len(aad)*8))

	macInput := make([]byte, 0, len(aad)+len(iv)+len(ciphertext)+8)
	macInput = append(macInput, aad...)
	macInput = append(macInput, iv...)
	macInput = append(macInput, ciphertext...)
	macInput = append(macInput, al...)

	mac := hmac.New(sha512.New, macKey)
	mac.Write(macInput)
	expectedTag := mac.Sum(nil)[:32] // Use first 32 bytes (256 bits) for A256CBC-HS512

	if !hmac.Equal(tag, expectedTag) {
		return nil, fmt.Errorf("%w: HMAC verification failed", ErrDecryptionFailed)
	}

	// Decrypt using AES-256-CBC (per RFC 7518 A256CBC-HS512)
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("%w: ciphertext length not a multiple of block size", ErrDecryptionFailed)
	}

	//nolint:gosec // RFC 7518 A256CBC-HS512 - HMAC authentication verified above before decryption
	mode := cipher.NewCBCDecrypter(block, iv) //NOSONAR
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS7 padding
	plaintext, err = pkcs7Unpad(plaintext)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid padding: %v", ErrDecryptionFailed, err)
	}

	return plaintext, nil
}

// pkcs7Unpad removes PKCS7 padding from a byte slice.
func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > aes.BlockSize || padLen > len(data) {
		return nil, fmt.Errorf("invalid padding length: %d", padLen)
	}
	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return nil, fmt.Errorf("invalid padding byte at position %d", i)
		}
	}
	return data[:len(data)-padLen], nil
}

// unwrapKeyECDHES unwraps a CEK using ECDH-ES.
func unwrapKeyECDHES(encryptedKey string, recipientPrivKey, ephemeralPubKey jwk.Key, header *JWEHeader) ([]byte, error) {
	// Decode wrapped key
	wrappedKey, err := base64.RawURLEncoding.DecodeString(encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted key: %w", err)
	}

	// Extract keys for ECDH
	recipPriv, err := extractECDHPrivateKey(recipientPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to extract recipient private key: %w", err)
	}

	ephPub, err := extractECDHPublicKey(ephemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to extract ephemeral public key: %w", err)
	}

	// Compute ECDH shared secret
	z, err := recipPriv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("failed to compute ECDH: %w", err)
	}

	// For ECDH-ES with key wrapping, the algorithm for Concat KDF is the full "alg" header value
	// Per RFC 7518 Section 4.6.2: "the AlgorithmID value is the 'alg' (algorithm) Header Parameter
	// value when using Key Agreement with Key Wrapping"
	kdfAlgorithm := header.Algorithm

	// Decode APU and APV from header (they're base64url-encoded)
	var apu, apv []byte
	if header.AgreementPartyUInfo != "" {
		apu, err = base64.RawURLEncoding.DecodeString(header.AgreementPartyUInfo)
		if err != nil {
			return nil, fmt.Errorf("failed to decode APU: %w", err)
		}
	}
	if header.AgreementPartyVInfo != "" {
		apv, err = base64.RawURLEncoding.DecodeString(header.AgreementPartyVInfo)
		if err != nil {
			return nil, fmt.Errorf("failed to decode APV: %w", err)
		}
	}

	// Derive key wrapping key using Concat KDF
	keySize := 32 // 256 bits for A256KW
	wrappingKey, err := concatKDF(z, kdfAlgorithm, apu, apv, keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to derive wrapping key: %w", err)
	}

	// Unwrap the CEK using AES-KW
	return unwrapKeyAES(wrappedKey, wrappingKey)
}

// unwrapKeyECDH1PU unwraps a CEK using ECDH-1PU.
// The ccTag parameter is the content ciphertext authentication tag, which is included
// in the KDF for key commitment per draft-madden-jose-ecdh-1pu.
func unwrapKeyECDH1PU(encryptedKey string, recipientPrivKey, senderPubKey, ephemeralPubKey jwk.Key, header *JWEHeader, ccTag []byte) ([]byte, error) {
	// Decode wrapped key
	wrappedKey, err := base64.RawURLEncoding.DecodeString(encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted key: %w", err)
	}

	// Create ECDH-1PU key agreement for decryption
	agreement, err := NewECDH1PU(nil, recipientPrivKey, header.Algorithm, header.Encryption)
	if err != nil {
		return nil, fmt.Errorf("failed to create ECDH-1PU: %w", err)
	}

	// Set APU and APV from header (these are already base64url-encoded in header,
	// we need to decode them to raw bytes for the KDF)
	if header.AgreementPartyUInfo != "" {
		apu, err := base64.RawURLEncoding.DecodeString(header.AgreementPartyUInfo)
		if err != nil {
			return nil, fmt.Errorf("failed to decode APU: %w", err)
		}
		agreement.APU = apu
	}
	if header.AgreementPartyVInfo != "" {
		apv, err := base64.RawURLEncoding.DecodeString(header.AgreementPartyVInfo)
		if err != nil {
			return nil, fmt.Errorf("failed to decode APV: %w", err)
		}
		agreement.APV = apv
	}

	// Set the content ciphertext tag for ECDH-1PU key commitment
	agreement.CCTag = ccTag

	// Derive the key wrapping key
	wrappingKey, err := agreement.DeriveKeyForDecryption(ephemeralPubKey, senderPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive wrapping key: %w", err)
	}

	// Unwrap the CEK
	return unwrapKeyAES(wrappedKey, wrappingKey)
}

// unwrapKeyAES unwraps a key using AES Key Wrap (RFC 3394).
func unwrapKeyAES(wrappedKey, wrappingKey []byte) ([]byte, error) {
	if len(wrappingKey) != 16 && len(wrappingKey) != 24 && len(wrappingKey) != 32 {
		return nil, fmt.Errorf("wrapping key must be 16, 24, or 32 bytes")
	}

	if len(wrappedKey) < 24 || len(wrappedKey)%8 != 0 {
		return nil, fmt.Errorf("wrapped key length invalid")
	}

	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// RFC 3394 AES Key Unwrap
	n := len(wrappedKey)/8 - 1

	// Initialize A
	a := make([]byte, 8)
	copy(a, wrappedKey[:8])

	// Initialize R[1]..R[n]
	r := make([][]byte, n+1)
	for i := 1; i <= n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], wrappedKey[i*8:(i+1)*8])
	}

	// Unwrap
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			// A ^ t
			t := uint64(n*j + i)
			a[7] ^= byte(t)
			a[6] ^= byte(t >> 8)
			a[5] ^= byte(t >> 16)
			a[4] ^= byte(t >> 24)
			a[3] ^= byte(t >> 32)
			a[2] ^= byte(t >> 40)
			a[1] ^= byte(t >> 48)
			a[0] ^= byte(t >> 56)

			// B = AES^-1(K, (A ^ t) | R[i])
			b := make([]byte, 16)
			copy(b[:8], a)
			copy(b[8:], r[i])
			//nolint:gosec // RFC 3394 AES Key Unwrap - integrity check validates after unwrap
			block.Decrypt(b, b) //NOSONAR

			// A = MSB(64, B)
			copy(a, b[:8])

			// R[i] = LSB(64, B)
			copy(r[i], b[8:])
		}
	}

	// Verify integrity check value
	defaultIV := []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	for i := 0; i < 8; i++ {
		if a[i] != defaultIV[i] {
			return nil, fmt.Errorf("key unwrap integrity check failed")
		}
	}

	// Output: R[1] | ... | R[n]
	cek := make([]byte, n*8)
	for i := 1; i <= n; i++ {
		copy(cek[(i-1)*8:i*8], r[i])
	}

	return cek, nil
}

// DecryptWithKeyStore decrypts a JWE using a key store to find the appropriate key.
func DecryptWithKeyStore(ctx context.Context, encrypted []byte, keyStore KeyStore) ([]byte, error) {
	// Parse the JWE to get recipient information
	msg, err := jwe.Parse(encrypted)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse JWE: %v", ErrInvalidJWE, err)
	}

	// Try each recipient
	for _, recipient := range msg.Recipients() {
		headers := recipient.Headers()
		var kid string
		if err := headers.Get("kid", &kid); err != nil {
			continue
		}

		privateKey, err := keyStore.GetPrivateKey(ctx, kid)
		if err != nil {
			continue
		}

		plaintext, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.ECDH_ES_A256KW(), privateKey))
		if err == nil {
			return plaintext, nil
		}
	}

	return nil, fmt.Errorf("%w: no matching key found", ErrRecipientNotFound)
}

// EncryptedMessage represents a DIDComm encrypted message (JWE).
type EncryptedMessage struct {
	// Protected is the base64url-encoded protected header
	Protected string `json:"protected"`

	// Recipients contains per-recipient encrypted key material
	Recipients []Recipient `json:"recipients"`

	// IV is the initialization vector (base64url-encoded)
	IV string `json:"iv"`

	// Ciphertext is the encrypted content (base64url-encoded)
	Ciphertext string `json:"ciphertext"`

	// Tag is the authentication tag (base64url-encoded)
	Tag string `json:"tag"`

	// AAD is additional authenticated data (base64url-encoded), optional
	AAD string `json:"aad,omitempty"`
}

// Recipient represents a JWE recipient.
type Recipient struct {
	// Header contains per-recipient unprotected header
	Header RecipientHeader `json:"header"`

	// EncryptedKey is the encrypted content encryption key (base64url-encoded)
	EncryptedKey string `json:"encrypted_key"`
}

// RecipientHeader contains per-recipient JWE header parameters.
type RecipientHeader struct {
	// KeyID identifies the recipient's key
	KeyID string `json:"kid"`

	// EphemeralPublicKey is the sender's ephemeral public key
	EphemeralPublicKey json.RawMessage `json:"epk,omitempty"`
}

// KeyStore provides access to private keys for decryption.
type KeyStore interface {
	// GetPrivateKey retrieves a private key by key ID
	GetPrivateKey(ctx context.Context, kid string) (jwk.Key, error)

	// ListKeyIDs returns all available key IDs
	ListKeyIDs(ctx context.Context) ([]string, error)
}

// parseKeyAlgorithm converts a string algorithm name to jwa.KeyAlgorithm.
func parseKeyAlgorithm(alg string) (jwa.KeyEncryptionAlgorithm, error) {
	switch alg {
	case "ECDH-ES", AlgECDHESA256KW:
		return jwa.ECDH_ES_A256KW(), nil
	case AlgECDHESA128KW:
		return jwa.ECDH_ES_A128KW(), nil
	case "ECDH-1PU", AlgECDH1PUA256KW:
		// ECDH-1PU uses custom implementation, but return ECDH-ES for fallback
		return jwa.ECDH_ES_A256KW(), nil
	default:
		return jwa.ECDH_ES_A256KW(), fmt.Errorf("unknown algorithm: %s", alg)
	}
}

// parseContentAlgorithm converts a string algorithm name to jwa.ContentEncryptionAlgorithm.
func parseContentAlgorithm(enc string) (jwa.ContentEncryptionAlgorithm, error) {
	switch enc {
	case EncA256GCM:
		return jwa.A256GCM(), nil
	case EncA256CBCHS512:
		return jwa.A256CBC_HS512(), nil
	case EncA128GCM:
		return jwa.A128GCM(), nil
	case EncXC20P:
		// XC20P uses custom implementation, return A256GCM as fallback indicator
		return jwa.A256GCM(), fmt.Errorf("XC20P requires custom implementation")
	default:
		return jwa.A256GCM(), fmt.Errorf("unknown encryption: %s", enc)
	}
}
