// Package mdoc implements the ISO/IEC 18013-5:2021 Mobile Driving Licence (mDL) data model.
package mdoc

import (
	"crypto"
	"errors"
	"github.com/fxamacker/cbor/v2"

	"fmt"
)

// DeviceAuthentication represents the structure to be signed/MACed for device authentication.
// Per ISO 18013-5:2021 section 9.1.3.
type DeviceAuthentication struct {
	// SessionTranscript is the session transcript bytes
	SessionTranscript []byte
	// DocType is the document type being authenticated
	DocType string
	// DeviceNameSpacesBytes is the CBOR-encoded device-signed namespaces
	DeviceNameSpacesBytes []byte
}

// DeviceAuthBuilder builds the DeviceSigned structure for mdoc authentication.
type DeviceAuthBuilder struct {
	docType           string
	sessionTranscript []byte
	deviceNameSpaces  map[string]map[string]any
	deviceKey         crypto.Signer
	sessionKey        []byte // For MAC-based authentication
	useMAC            bool
}

// NewDeviceAuthBuilder creates a new DeviceAuthBuilder.
func NewDeviceAuthBuilder(docType string) *DeviceAuthBuilder {
	return &DeviceAuthBuilder{
		docType:          docType,
		deviceNameSpaces: make(map[string]map[string]any),
	}
}

// WithSessionTranscript sets the session transcript.
func (b *DeviceAuthBuilder) WithSessionTranscript(transcript []byte) *DeviceAuthBuilder {
	b.sessionTranscript = transcript
	return b
}

// WithDeviceKey sets the device private key for signature-based authentication.
func (b *DeviceAuthBuilder) WithDeviceKey(key crypto.Signer) *DeviceAuthBuilder {
	b.deviceKey = key
	b.useMAC = false
	return b
}

// WithSessionKey sets the session key for MAC-based authentication.
// This is typically derived from the session encryption keys.
func (b *DeviceAuthBuilder) WithSessionKey(key []byte) *DeviceAuthBuilder {
	b.sessionKey = key
	b.useMAC = true
	return b
}

// AddDeviceNameSpace adds device-signed data elements.
func (b *DeviceAuthBuilder) AddDeviceNameSpace(namespace string, elements map[string]any) *DeviceAuthBuilder {
	b.deviceNameSpaces[namespace] = elements
	return b
}

// Build creates the DeviceSigned structure.
func (b *DeviceAuthBuilder) Build() (*DeviceSignedMdoc, error) {
	if b.sessionTranscript == nil {
		return nil, errors.New("session transcript is required")
	}

	if !b.useMAC && b.deviceKey == nil {
		return nil, errors.New("device key or session key is required")
	}

	if b.useMAC && len(b.sessionKey) == 0 {
		return nil, errors.New("session key is required for MAC authentication")
	}

	encoder, err := NewCBOREncoder()
	if err != nil {
		return nil, fmt.Errorf("failed to create CBOR encoder: %w", err)
	}

	// Encode device namespaces
	var deviceNameSpacesBytes []byte
	if len(b.deviceNameSpaces) > 0 {
		deviceNameSpacesBytes, err = encoder.Marshal(b.deviceNameSpaces)
		if err != nil {
			return nil, fmt.Errorf("failed to encode device namespaces: %w", err)
		}
	} else {
		// Empty map per spec
		deviceNameSpacesBytes, err = encoder.Marshal(map[string]any{})
		if err != nil {
			return nil, fmt.Errorf("failed to encode empty device namespaces: %w", err)
		}
	}

	// Build DeviceAuthentication structure
	// Per ISO 18013-5: DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes]
	deviceAuth := []any{
		"DeviceAuthentication",
		b.sessionTranscript,
		b.docType,
		deviceNameSpacesBytes,
	}

	deviceAuthBytes, err := encoder.Marshal(deviceAuth)
	if err != nil {
		return nil, fmt.Errorf("failed to encode device authentication: %w", err)
	}

	var deviceSigned DeviceSignedMdoc
	deviceSigned.NameSpaces = deviceNameSpacesBytes

	if b.useMAC {
		// MAC-based authentication using session key
		mac0, err := b.createDeviceMAC(deviceAuthBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to create device MAC: %w", err)
		}

		macBytes, err := encoder.Marshal(mac0)
		if err != nil {
			return nil, fmt.Errorf("failed to encode device MAC: %w", err)
		}
		deviceSigned.DeviceAuth.DeviceMac = macBytes
	} else {
		// Signature-based authentication using device key
		sign1, err := b.createDeviceSignature(deviceAuthBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to create device signature: %w", err)
		}

		sigBytes, err := encoder.Marshal(sign1)
		if err != nil {
			return nil, fmt.Errorf("failed to encode device signature: %w", err)
		}
		deviceSigned.DeviceAuth.DeviceSignature = sigBytes
	}

	return &deviceSigned, nil
}

// createDeviceSignature creates a COSE_Sign1 for device authentication.
func (b *DeviceAuthBuilder) createDeviceSignature(payload []byte) (*COSESign1, error) {
	algorithm, err := AlgorithmForKey(b.deviceKey)
	if err != nil {
		return nil, fmt.Errorf("failed to determine algorithm: %w", err)
	}

	// Detached signature - payload is external
	return Sign1Detached(payload, b.deviceKey, algorithm, nil, nil)
}

// createDeviceMAC creates a COSE_Mac0 for device authentication.
func (b *DeviceAuthBuilder) createDeviceMAC(payload []byte) (*COSEMac0, error) {
	// Use HMAC-SHA256 for MAC authentication
	return Mac0(payload, b.sessionKey, AlgorithmHMAC256, nil)
}

// DeviceAuthVerifier verifies device authentication.
type DeviceAuthVerifier struct {
	sessionTranscript []byte
	docType           string
}

// NewDeviceAuthVerifier creates a new DeviceAuthVerifier.
func NewDeviceAuthVerifier(sessionTranscript []byte, docType string) *DeviceAuthVerifier {
	return &DeviceAuthVerifier{
		sessionTranscript: sessionTranscript,
		docType:           docType,
	}
}

func (v *DeviceAuthVerifier) VerifySignature(deviceSigned *DeviceSignedMdoc, deviceKey crypto.PublicKey) error {
    if deviceSigned.DeviceAuth.DeviceSignature == nil {
        return errors.New("no device signature present")
    }

    encoder, err := NewCBOREncoder()
    if err != nil {
        return fmt.Errorf("failed to create CBOR encoder: %w", err)
    }

    var sign1 COSESign1
    sigRaw := deviceSigned.DeviceAuth.DeviceSignature
    switch val := sigRaw.(type) {
    case []byte:
        if len(val) == 0 {
            return errors.New("device signature byte slice is empty")
        }
        if err := encoder.Unmarshal(val, &sign1); err != nil {
            return fmt.Errorf("failed to parse device signature bytes: %w", err)
        }
    case []any:
        sigBytes, err := encoder.Marshal(val)
        if err != nil {
            return fmt.Errorf("failed to re-encode device signature array: %w", err)
        }
        if err := encoder.Unmarshal(sigBytes, &sign1); err != nil {
            return fmt.Errorf("failed to map device signature array to COSESign1: %w", err)
        }
    case cbor.Tag:
        if b, ok := val.Content.([]byte); ok {
            if err := encoder.Unmarshal(b, &sign1); err != nil {
                return fmt.Errorf("failed to parse device signature tag content: %w", err)
            }
        } else {
            return errors.New("device signature tag content is not bytes")
        }
    default:
        return fmt.Errorf("unexpected type for DeviceSignature: %T", val)
    }

    var nameSpacesBytes []byte
    switch ns := deviceSigned.NameSpaces.(type) {
    case []byte:
        nameSpacesBytes = ns
    case cbor.Tag:
        if b, ok := ns.Content.([]byte); ok {
            nameSpacesBytes = b
        }
    case nil:
        nameSpacesBytes = nil
    default:
        b, err := encoder.Marshal(ns)
        if err != nil {
            return fmt.Errorf("failed to marshal NameSpaces for signature verification: %w", err)
        }
        nameSpacesBytes = b
    }

    deviceAuthBytes, err := v.buildDeviceAuthBytes(nameSpacesBytes)
    if err != nil {
        return fmt.Errorf("failed to build device auth bytes: %w", err)
    }
    if err := Verify1(&sign1, deviceAuthBytes, deviceKey, nil); err != nil {
        return fmt.Errorf("device signature verification failed: %w", err)
    }

    return nil
}

// VerifyMAC verifies a MAC-based device authentication.
func (v *DeviceAuthVerifier) VerifyMAC(deviceSigned *DeviceSignedMdoc, sessionKey []byte) error {
	if len(deviceSigned.DeviceAuth.DeviceMac) == 0 {
		return errors.New("no device MAC present")
	}

	encoder, err := NewCBOREncoder()
	if err != nil {
		return fmt.Errorf("failed to create CBOR encoder: %w", err)
	}

	// Parse the COSE_Mac0
	var mac0 COSEMac0
	if err := encoder.Unmarshal(deviceSigned.DeviceAuth.DeviceMac, &mac0); err != nil {
		return fmt.Errorf("failed to parse device MAC: %w", err)
	}

	var nameSpacesBytes []byte

	switch v := deviceSigned.NameSpaces.(type) {
	case []byte:
		nameSpacesBytes = v
	case cbor.Tag:
		// If it's a Tag 24, the content is the byte slice
		if b, ok := v.Content.([]byte); ok {
			nameSpacesBytes = b
		}
	case nil:
		nameSpacesBytes = nil
	default:
		return fmt.Errorf("unexpected type for NameSpaces: %T", v)
	}

	// Reconstruct DeviceAuthentication
	deviceAuthBytes, err := v.buildDeviceAuthBytes(nameSpacesBytes)
	if err != nil {
		return fmt.Errorf("failed to build device auth bytes: %w", err)
	}

	// Verify the MAC
	if err := VerifyCOSEMac0(&mac0, sessionKey, nil); err != nil {
		return fmt.Errorf("device MAC verification failed: %w", err)
	}

	// Also verify the payload matches
	if len(mac0.Payload) > 0 {
		// If payload is included, verify it matches expected
		if string(mac0.Payload) != string(deviceAuthBytes) {
			return errors.New("device auth payload mismatch")
		}
	}

	return nil
}

// buildDeviceAuthBytes reconstructs the DeviceAuthentication bytes for verification.
func (v *DeviceAuthVerifier) buildDeviceAuthBytes(deviceNameSpacesBytes []byte) ([]byte, error) {
	encoder, err := NewCBOREncoder()
	if err != nil {
		return nil, err
	}

	// Ensure we have device namespaces bytes
	if deviceNameSpacesBytes == nil {
		deviceNameSpacesBytes, err = encoder.Marshal(map[string]any{})
		if err != nil {
			return nil, err
		}
	}

	// Build DeviceAuthentication structure
	deviceAuth := []any{
		"DeviceAuthentication",
		v.sessionTranscript,
		v.docType,
		deviceNameSpacesBytes,
	}

	return encoder.Marshal(deviceAuth)
}

// ExtractDeviceKeyFromMSO extracts the device public key from the MSO.
func ExtractDeviceKeyFromMSO(mso *MobileSecurityObject) (crypto.PublicKey, error) {
	if mso == nil {
		return nil, errors.New("MSO is nil")
	}

	if len(mso.DeviceKeyInfo.DeviceKey) == 0 {
		return nil, errors.New("device key not present in MSO")
	}

	encoder, err := NewCBOREncoder()
	if err != nil {
		return nil, err
	}

	// Parse the COSE_Key
	var coseKey COSEKey
	if err := encoder.Unmarshal(mso.DeviceKeyInfo.DeviceKey, &coseKey); err != nil {
		return nil, fmt.Errorf("failed to parse device COSE key: %w", err)
	}

	return coseKey.ToPublicKey()
}

// VerifyDeviceAuth verifies device authentication as part of document verification.
// This should be called after verifying the issuer signature.
func (v *Verifier) VerifyDeviceAuth(doc *DocumentMdoc, mso *MobileSecurityObject, sessionTranscript []byte) error {
	sig, ok := doc.DeviceSigned.DeviceAuth.DeviceSignature.([]any)
	hasNoSignature := !ok || len(sig) == 0
	hasNoMac := len(doc.DeviceSigned.DeviceAuth.DeviceMac) == 0
	if hasNoSignature && hasNoMac {
		// No device auth - this may be acceptable in some contexts
		return nil
	}

	// Extract device key from MSO
	deviceKey, err := ExtractDeviceKeyFromMSO(mso)
	if err != nil {
		return fmt.Errorf("failed to extract device key: %w", err)
	}

	verifier := NewDeviceAuthVerifier(sessionTranscript, doc.DocType)

	// Verify based on auth type
	if len(sig) > 0 {
		return verifier.VerifySignature(&doc.DeviceSigned, deviceKey)
	}

	// For MAC verification, we would need the session key
	// This is typically derived from session encryption
	return errors.New("MAC verification requires session key - use VerifyDeviceAuthWithSessionKey")
}

// VerifyDeviceAuthWithSessionKey verifies MAC-based device authentication.
func (v *Verifier) VerifyDeviceAuthWithSessionKey(doc *DocumentMdoc, sessionTranscript []byte, sessionKey []byte) error {
	if len(doc.DeviceSigned.DeviceAuth.DeviceMac) == 0 {
		return errors.New("no device MAC present")
	}

	verifier := NewDeviceAuthVerifier(sessionTranscript, doc.DocType)
	return verifier.VerifyMAC(&doc.DeviceSigned, sessionKey)
}

// DeriveDeviceAuthenticationKey derives the key used for device MAC authentication.
// Per ISO 18013-5, this is derived from the session encryption keys.
func DeriveDeviceAuthenticationKey(sessionEncryption *SessionEncryption) ([]byte, error) {
	if sessionEncryption == nil {
		return nil, errors.New("session encryption is nil")
	}

	// The device authentication key is typically the same as or derived from
	// the session encryption key. For simplicity, we use the device session key
	// which is derived during session establishment.
	//
	// Per ISO 18013-5, the EMacKey is:
	// HKDF-SHA256(SessionKey, salt="EMacKey", info=SessionTranscript, L=32)

	// We'll derive a separate key for device auth from the shared secret
	return hkdfDerive(
		sessionEncryption.sharedSecret, // Use shared secret as base
		nil,                            // No salt
		[]byte("EMacKey"),              // Info per ISO 18013-5
		32,                             // 256 bits
	)
}
