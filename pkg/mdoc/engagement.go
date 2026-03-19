// Package mdoc provides device engagement and session establishment structures
// per ISO/IEC 18013-5:2021 sections 8.2 and 9.1.1.
package mdoc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/url"
)

// EngagementVersion is the device engagement version.
const EngagementVersion = "1.0"

// DeviceRetrievalMethod identifies how the mdoc reader connects to the device.
type DeviceRetrievalMethod uint

const (
	// RetrievalMethodNFC indicates NFC connection.
	RetrievalMethodNFC DeviceRetrievalMethod = 1
	// RetrievalMethodBLE indicates Bluetooth Low Energy.
	RetrievalMethodBLE DeviceRetrievalMethod = 2
	// RetrievalMethodWiFiAware indicates Wi-Fi Aware.
	RetrievalMethodWiFiAware DeviceRetrievalMethod = 3
)

// BLERole indicates the BLE role.
type BLERole uint

const (
	// BLERoleCentral indicates the device is BLE central.
	BLERoleCentral BLERole = 0
	// BLERolePeripheral indicates the device is BLE peripheral.
	BLERolePeripheral BLERole = 1
	// BLERoleBoth indicates the device supports both roles.
	BLERoleBoth BLERole = 2
)

// DeviceEngagement is the structure for device engagement.
// Per ISO 18013-5 section 8.2.1.
type DeviceEngagement struct {
	Version                string            `cbor:"0,keyasint"`
	Security               Security          `cbor:"1,keyasint"`
	DeviceRetrievalMethods []RetrievalMethod `cbor:"2,keyasint,omitempty"`
	ServerRetrievalMethods *ServerRetrieval  `cbor:"3,keyasint,omitempty"`
	ProtocolInfo           any               `cbor:"4,keyasint,omitempty"`
	OriginInfos            []OriginInfo      `cbor:"5,keyasint,omitempty"`
}

// Security contains the security information for device engagement.
type Security struct {
	_               struct{} `cbor:",toarray"`
	CipherSuiteID   int      // 1 = ECDH with AES-256-GCM
	EDeviceKeyBytes []byte   // Tagged CBOR-encoded COSE_Key
}

// RetrievalMethod describes a device retrieval method.
type RetrievalMethod struct {
	_       struct{} `cbor:",toarray"`
	Type    DeviceRetrievalMethod
	Version uint
	Options any // BLEOptions, NFCOptions, or WiFiAwareOptions
}

// BLEOptions contains BLE-specific options.
type BLEOptions struct {
	SupportsCentralMode           bool    `cbor:"0,keyasint,omitempty"`
	SupportsPeripheralMode        bool    `cbor:"1,keyasint,omitempty"`
	PeripheralServerUUID          *string `cbor:"10,keyasint,omitempty"`
	CentralClientUUID             *string `cbor:"11,keyasint,omitempty"`
	PeripheralServerDeviceAddress *[]byte `cbor:"20,keyasint,omitempty"`
}

// NFCOptions contains NFC-specific options.
type NFCOptions struct {
	MaxLenCommandData  uint `cbor:"0,keyasint"`
	MaxLenResponseData uint `cbor:"1,keyasint"`
}

// WiFiAwareOptions contains Wi-Fi Aware options.
type WiFiAwareOptions struct {
	PassphraseInfo *string `cbor:"0,keyasint,omitempty"`
	ChannelInfo    *uint   `cbor:"1,keyasint,omitempty"`
	BandInfo       *uint   `cbor:"2,keyasint,omitempty"`
}

// ServerRetrieval contains server retrieval information.
type ServerRetrieval struct {
	WebAPI *WebAPIRetrieval `cbor:"0,keyasint,omitempty"`
	OIDC   *OIDCRetrieval   `cbor:"1,keyasint,omitempty"`
}

// WebAPIRetrieval contains Web API retrieval info.
type WebAPIRetrieval struct {
	Version uint   `cbor:"0,keyasint"`
	URL     string `cbor:"1,keyasint"`
	Token   string `cbor:"2,keyasint,omitempty"`
}

// OIDCRetrieval contains OIDC retrieval info.
type OIDCRetrieval struct {
	Version uint   `cbor:"0,keyasint"`
	URL     string `cbor:"1,keyasint"`
	Token   string `cbor:"2,keyasint,omitempty"`
}

// OriginInfo contains origin information.
type OriginInfo struct {
	Cat     uint   `cbor:"0,keyasint"` // 0=Delivery, 1=Receive
	Type    uint   `cbor:"1,keyasint"` // 1=Website
	Details string `cbor:"2,keyasint"` // e.g., referrer URL
}

// ReaderEngagement is the structure for reader engagement (mdoc reader to device).
// Per ISO 18013-5 section 8.2.2.
type ReaderEngagement struct {
	Version     string       `cbor:"0,keyasint"`
	Security    Security     `cbor:"1,keyasint"`
	OriginInfos []OriginInfo `cbor:"5,keyasint,omitempty"`
}

// SessionEstablishment is used to establish a secure session.
// Per ISO 18013-5 section 9.1.1.4.
type SessionEstablishment struct {
	_               struct{} `cbor:",toarray"`
	EReaderKeyBytes []byte   // Tagged CBOR-encoded COSE_Key
	Data            []byte   // Encrypted mdoc request (when sent by reader)
}

// SessionData contains encrypted session data.
type SessionData struct {
	Data   []byte `cbor:"data,omitempty"`
	Status *uint  `cbor:"status,omitempty"`
}

// SessionStatus values per ISO 18013-5.
const (
	SessionStatusEncryptionError   uint = 10
	SessionStatusDecodingError     uint = 11
	SessionStatusSessionTerminated uint = 20
)

// EngagementBuilder builds a DeviceEngagement structure.
type EngagementBuilder struct {
	engagement    *DeviceEngagement
	eDeviceKey    *ecdsa.PrivateKey
	eDeviceKeyPub *COSEKey
}

// NewEngagementBuilder creates a new engagement builder.
func NewEngagementBuilder() *EngagementBuilder {
	builder := &EngagementBuilder{
		engagement: &DeviceEngagement{
			Version: EngagementVersion,
		},
	}
	return builder
}

// WithEphemeralKey sets the ephemeral device key.
func (b *EngagementBuilder) WithEphemeralKey(key *ecdsa.PrivateKey) (*EngagementBuilder, error) {
	coseKey, err := NewCOSEKeyFromECDSAPublic(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert key: %w", err)
	}

	b.eDeviceKey = key
	b.eDeviceKeyPub = coseKey

	// Encode the COSE key
	keyBytes, err := coseKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to encode key: %w", err)
	}

	// Wrap in tag 24
	taggedKeyBytes, err := WrapInEncodedCBOR(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap key: %w", err)
	}

	b.engagement.Security = Security{
		CipherSuiteID:   1, // ECDH with AES-256-GCM
		EDeviceKeyBytes: taggedKeyBytes,
	}

	return b, nil
}

// GenerateEphemeralKey generates a new ephemeral P-256 key.
func (b *EngagementBuilder) GenerateEphemeralKey() (*EngagementBuilder, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return b.WithEphemeralKey(key)
}

// WithBLE adds BLE as a device retrieval method.
func (b *EngagementBuilder) WithBLE(opts BLEOptions) *EngagementBuilder {
	method := RetrievalMethod{
		Type:    RetrievalMethodBLE,
		Version: 1,
		Options: opts,
	}
	b.engagement.DeviceRetrievalMethods = append(b.engagement.DeviceRetrievalMethods, method)
	return b
}

// WithNFC adds NFC as a device retrieval method.
func (b *EngagementBuilder) WithNFC(maxCommand, maxResponse uint) *EngagementBuilder {
	method := RetrievalMethod{
		Type:    RetrievalMethodNFC,
		Version: 1,
		Options: NFCOptions{
			MaxLenCommandData:  maxCommand,
			MaxLenResponseData: maxResponse,
		},
	}
	b.engagement.DeviceRetrievalMethods = append(b.engagement.DeviceRetrievalMethods, method)
	return b
}

// WithWiFiAware adds Wi-Fi Aware as a device retrieval method.
func (b *EngagementBuilder) WithWiFiAware(opts WiFiAwareOptions) *EngagementBuilder {
	method := RetrievalMethod{
		Type:    RetrievalMethodWiFiAware,
		Version: 1,
		Options: opts,
	}
	b.engagement.DeviceRetrievalMethods = append(b.engagement.DeviceRetrievalMethods, method)
	return b
}

// WithOriginInfo adds origin information.
func (b *EngagementBuilder) WithOriginInfo(cat, typ uint, details string) *EngagementBuilder {
	b.engagement.OriginInfos = append(b.engagement.OriginInfos, OriginInfo{
		Cat:     cat,
		Type:    typ,
		Details: details,
	})
	return b
}

// Build creates the DeviceEngagement and returns it along with the private key.
func (b *EngagementBuilder) Build() (*DeviceEngagement, *ecdsa.PrivateKey, error) {
	if b.eDeviceKey == nil {
		return nil, nil, fmt.Errorf("ephemeral key is required")
	}
	if len(b.engagement.DeviceRetrievalMethods) == 0 {
		return nil, nil, fmt.Errorf("at least one retrieval method is required")
	}
	return b.engagement, b.eDeviceKey, nil
}

// EncodeDeviceEngagement encodes device engagement to CBOR bytes.
func EncodeDeviceEngagement(de *DeviceEngagement) ([]byte, error) {
	encoder, err := NewCBOREncoder()
	if err != nil {
		return nil, fmt.Errorf("failed to create CBOR encoder: %w", err)
	}
	return encoder.Marshal(de)
}

// DecodeDeviceEngagement decodes device engagement from CBOR bytes.
func DecodeDeviceEngagement(data []byte) (*DeviceEngagement, error) {
	encoder, err := NewCBOREncoder()
	if err != nil {
		return nil, fmt.Errorf("failed to create CBOR encoder: %w", err)
	}
	var de DeviceEngagement
	if err := encoder.Unmarshal(data, &de); err != nil {
		return nil, fmt.Errorf("failed to decode device engagement: %w", err)
	}
	return &de, nil
}

// DeviceEngagementToQRCode generates QR code data from device engagement.
// The QR code contains "mdoc:" followed by the base64url-encoded device engagement.
func DeviceEngagementToQRCode(de *DeviceEngagement) (string, error) {
	data, err := EncodeDeviceEngagement(de)
	if err != nil {
		return "", err
	}

	// Base64URL encode
	encoded := base64URLEncode(data)
	return "mdoc:" + encoded, nil
}

// ParseQRCode parses a device engagement QR code.
func ParseQRCode(qrData string) (*DeviceEngagement, error) {
	if len(qrData) < 6 || qrData[:5] != "mdoc:" {
		return nil, fmt.Errorf("invalid QR code format")
	}

	decoded, err := base64URLDecode(qrData[5:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode QR data: %w", err)
	}

	return DecodeDeviceEngagement(decoded)
}

// base64URLEncode encodes bytes to base64url without padding.
func base64URLEncode(data []byte) string {
	const encodeURL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

	result := make([]byte, ((len(data)+2)/3)*4)
	di, si := 0, 0
	n := (len(data) / 3) * 3

	for si < n {
		val := uint(data[si+0])<<16 | uint(data[si+1])<<8 | uint(data[si+2])
		result[di+0] = encodeURL[val>>18&0x3F]
		result[di+1] = encodeURL[val>>12&0x3F]
		result[di+2] = encodeURL[val>>6&0x3F]
		result[di+3] = encodeURL[val&0x3F]
		si += 3
		di += 4
	}

	remain := len(data) - si
	if remain > 0 {
		val := uint(data[si+0]) << 16
		if remain == 2 {
			val |= uint(data[si+1]) << 8
		}
		result[di+0] = encodeURL[val>>18&0x3F]
		result[di+1] = encodeURL[val>>12&0x3F]
		if remain == 2 {
			result[di+2] = encodeURL[val>>6&0x3F]
			return string(result[:di+3])
		}
		return string(result[:di+2])
	}

	return string(result[:di])
}

// base64URLDecode decodes base64url-encoded string.
func base64URLDecode(s string) ([]byte, error) {
	const decodeURL = "" +
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x3e\xff\xff" +
		"\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\xff\xff\xff\xff\xff\xff" +
		"\xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e" +
		"\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\xff\xff\xff\xff\x3f" +
		"\xff\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28" +
		"\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\xff\xff\xff\xff\xff"

	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}

	result := make([]byte, len(s)/4*3)
	di := 0

	for i := 0; i < len(s); i += 4 {
		var val uint
		for j := range 4 {
			c := s[i+j]
			if c == '=' {
				// Handle padding
				switch j {
				case 2:
					val = (val << 12)
					result[di] = byte(val >> 16)
					return result[:di+1], nil
				case 3:
					val = (val << 6)
					result[di] = byte(val >> 16)
					result[di+1] = byte(val >> 8)
					return result[:di+2], nil
				}
			}
			if int(c) >= len(decodeURL) || decodeURL[c] == 0xff {
				return nil, fmt.Errorf("invalid base64url character: %c", c)
			}
			val = (val << 6) | uint(decodeURL[c])
		}
		result[di+0] = byte(val >> 16)
		result[di+1] = byte(val >> 8)
		result[di+2] = byte(val)
		di += 3
	}

	return result[:di], nil
}

// SessionEncryption handles the encryption/decryption for mdoc sessions.
// Per ISO 18013-5 section 9.1.1.5.
type SessionEncryption struct {
	sharedSecret []byte
	skReader     []byte // Session key for reader
	skDevice     []byte // Session key for device
	readerNonce  uint32
	deviceNonce  uint32
	isReader     bool
}

// NewSessionEncryptionDevice creates session encryption from the device's perspective.
func NewSessionEncryptionDevice(eDevicePriv *ecdsa.PrivateKey, eReaderPub *ecdsa.PublicKey, sessionTranscript []byte) (*SessionEncryption, error) {
	return newSessionEncryption(eDevicePriv, eReaderPub, sessionTranscript, false)
}

// NewSessionEncryptionReader creates session encryption from the reader's perspective.
func NewSessionEncryptionReader(eReaderPriv *ecdsa.PrivateKey, eDevicePub *ecdsa.PublicKey, sessionTranscript []byte) (*SessionEncryption, error) {
	return newSessionEncryption(eReaderPriv, eDevicePub, sessionTranscript, true)
}

func newSessionEncryption(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey, sessionTranscript []byte, isReader bool) (*SessionEncryption, error) {
	// Perform ECDH
	x, _ := priv.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	sharedSecret := x.Bytes()

	// Derive session keys using HKDF-SHA256
	// Per ISO 18013-5 section 9.1.1.5
	skReader, err := hkdfDerive(sharedSecret, sessionTranscript, []byte("SKReader"), 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive SKReader: %w", err)
	}

	skDevice, err := hkdfDerive(sharedSecret, sessionTranscript, []byte("SKDevice"), 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive SKDevice: %w", err)
	}

	session := &SessionEncryption{
		sharedSecret: sharedSecret,
		skReader:     skReader,
		skDevice:     skDevice,
		readerNonce:  1,
		deviceNonce:  1,
		isReader:     isReader,
	}
	return session, nil
}

// hkdfDerive derives a key using HKDF-SHA256.
func hkdfDerive(secret, salt, info []byte, length int) ([]byte, error) {
	// HKDF-Extract
	prk := hmacSHA256(salt, secret)

	// HKDF-Expand
	hashLen := 32
	n := (length + hashLen - 1) / hashLen
	okm := make([]byte, 0, n*hashLen)
	prev := []byte{}

	for i := 1; i <= n; i++ {
		data := append(prev, info...)
		data = append(data, byte(i))
		prev = hmacSHA256(prk, data)
		okm = append(okm, prev...)
	}

	return okm[:length], nil
}

// hmacSHA256 computes HMAC-SHA256.
func hmacSHA256(key, data []byte) []byte {
	const blockSize = 64

	// Pad key
	if len(key) > blockSize {
		h := sha256.Sum256(key)
		key = h[:]
	}
	if len(key) < blockSize {
		padded := make([]byte, blockSize)
		copy(padded, key)
		key = padded
	}

	// ipad and opad
	ipad := make([]byte, blockSize)
	opad := make([]byte, blockSize)
	for i := range blockSize {
		ipad[i] = key[i] ^ 0x36
		opad[i] = key[i] ^ 0x5c
	}

	// Inner hash
	innerData := append(ipad, data...)
	innerHash := sha256.Sum256(innerData)

	// Outer hash
	outerData := append(opad, innerHash[:]...)
	outerHash := sha256.Sum256(outerData)

	return outerHash[:]
}

// Encrypt encrypts data for transmission.
func (s *SessionEncryption) Encrypt(plaintext []byte) ([]byte, error) {
	var sk []byte
	var nonce *uint32

	if s.isReader {
		sk = s.skReader
		nonce = &s.readerNonce
	} else {
		sk = s.skDevice
		nonce = &s.deviceNonce
	}

	// Build nonce (12 bytes)
	nonceBytes := make([]byte, 12)
	binary.BigEndian.PutUint32(nonceBytes[8:], *nonce)
	*nonce++

	// AES-256-GCM encryption
	ciphertext, err := aes256GCMEncrypt(sk, nonceBytes, plaintext, nil)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// Decrypt decrypts received data.
func (s *SessionEncryption) Decrypt(ciphertext []byte) ([]byte, error) {
	var sk []byte
	var nonce *uint32

	// Decrypt with the other party's key
	if s.isReader {
		sk = s.skDevice
		nonce = &s.deviceNonce
	} else {
		sk = s.skReader
		nonce = &s.readerNonce
	}

	// Build nonce (12 bytes)
	nonceBytes := make([]byte, 12)
	binary.BigEndian.PutUint32(nonceBytes[8:], *nonce)
	*nonce++

	// AES-256-GCM decryption
	plaintext, err := aes256GCMDecrypt(sk, nonceBytes, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// aes256GCMEncrypt encrypts plaintext using AES-256-GCM.
// Per ISO 18013-5 section 9.1.1.5, uses AES-256-GCM with 12-byte nonce.
func aes256GCMEncrypt(key, nonce, plaintext, additionalData []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: expected 32 bytes, got %d", len(key))
	}
	if len(nonce) != 12 {
		return nil, fmt.Errorf("invalid nonce length: expected 12 bytes, got %d", len(nonce))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Seal appends the ciphertext and authentication tag to dst
	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
	return ciphertext, nil
}

// aes256GCMDecrypt decrypts ciphertext using AES-256-GCM.
// Per ISO 18013-5 section 9.1.1.5, uses AES-256-GCM with 12-byte nonce.
func aes256GCMDecrypt(key, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: expected 32 bytes, got %d", len(key))
	}
	if len(nonce) != 12 {
		return nil, fmt.Errorf("invalid nonce length: expected 12 bytes, got %d", len(nonce))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// BuildSessionTranscript creates the session transcript for key derivation.
// Per ISO 18013-5 section 9.1.5.1.
func BuildSessionTranscript(deviceEngagement, eReaderKeyBytes, handover []byte) ([]byte, error) {
	encoder, err := NewCBOREncoder()
	if err != nil {
		return nil, fmt.Errorf("failed to create CBOR encoder: %w", err)
	}

	// Session transcript is: [DeviceEngagementBytes, EReaderKeyBytes, Handover]
	transcript := []any{
		TaggedCBOR{Data: deviceEngagement},
		TaggedCBOR{Data: eReaderKeyBytes},
		handover,
	}

	return encoder.Marshal(transcript)
}

// ExtractEDeviceKey extracts the ephemeral device key from device engagement.
func ExtractEDeviceKey(de *DeviceEngagement) (*ecdsa.PublicKey, error) {
	// Unwrap tag 24 - the bytes are the raw CBOR-encoded key
	var keyMap map[int64]any
	if err := UnwrapEncodedCBOR(EncodedCBORBytes(de.Security.EDeviceKeyBytes), &keyMap); err != nil {
		return nil, fmt.Errorf("failed to unwrap key bytes: %w", err)
	}

	coseKey := &COSEKey{}
	if err := coseKey.FromMap(keyMap); err != nil {
		return nil, fmt.Errorf("failed to parse COSE key: %w", err)
	}

	pub, err := coseKey.ToPublicKey()
	if err != nil {
		return nil, err
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected ECDSA public key")
	}

	return ecdsaPub, nil
}

// FromMap populates a COSEKey from a map.
func (k *COSEKey) FromMap(m map[int64]any) error {
	if kty, ok := m[1]; ok {
		if v, ok := kty.(int64); ok {
			k.Kty = v
		}
	}
	if crv, ok := m[-1]; ok {
		if v, ok := crv.(int64); ok {
			k.Crv = v
		}
	}
	if x, ok := m[-2]; ok {
		if v, ok := x.([]byte); ok {
			k.X = v
		}
	}
	if y, ok := m[-3]; ok {
		if v, ok := y.([]byte); ok {
			k.Y = v
		}
	}
	return nil
}

// NFCHandover creates handover data for NFC engagement.
func NFCHandover() []byte {
	// For NFC, handover is null per ISO 18013-5
	return nil
}

// QRHandover creates handover data for QR code engagement.
func QRHandover() []byte {
	// For QR code, handover is null per ISO 18013-5
	return nil
}

// WebsiteHandover creates handover data for website-based engagement.
func WebsiteHandover(referrerURL *url.URL) ([]byte, error) {
	encoder, err := NewCBOREncoder()
	if err != nil {
		return nil, fmt.Errorf("failed to create CBOR encoder: %w", err)
	}

	handover := []any{
		referrerURL.String(),
	}

	return encoder.Marshal(handover)
}
