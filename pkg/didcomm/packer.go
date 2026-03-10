package didcomm

import (
	"context"
	"encoding/json"
	"fmt"

	"vc/pkg/didcomm/crypto"
	"vc/pkg/didcomm/message"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// PackOptions configures message packing behavior.
type PackOptions struct {
	// EncryptionMode specifies the encryption mode.
	// "anoncrypt" for anonymous encryption (ECDH-ES)
	// "authcrypt" for authenticated encryption (ECDH-1PU)
	// Empty string for no encryption
	EncryptionMode string

	// SignBeforeEncrypt signs the message before encrypting.
	// Creates a signed-then-encrypted message.
	SignBeforeEncrypt bool

	// SignerKey is the private key for signing (required if SignBeforeEncrypt is true)
	SignerKey jwk.Key

	// SenderKey is the private key for authcrypt (required if EncryptionMode is "authcrypt")
	SenderKey jwk.Key

	// RecipientKeys are the public keys of the recipients
	RecipientKeys []jwk.Key

	// Forward wraps the message for routing through mediators
	Forward bool

	// RoutingKeys are the mediator keys for forwarding
	RoutingKeys []jwk.Key
}

// PackResult contains the packed message and metadata.
type PackResult struct {
	// Message is the packed message bytes (JWE, JWS, or plaintext JSON)
	Message []byte

	// MediaType is the content type of the packed message
	MediaType string

	// FromKID is the key ID of the sender (if authenticated)
	FromKID string

	// ToKIDs are the key IDs of the recipients
	ToKIDs []string
}

// Pack packs a DIDComm message according to the specified options.
// It can produce plaintext, signed, or encrypted messages.
func Pack(ctx context.Context, msg *message.Message, opts PackOptions) (*PackResult, error) {
	if err := msg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid message: %w", err)
	}

	// Serialize the plaintext message
	plaintext, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize message: %w", err)
	}

	result := &PackResult{
		Message:   plaintext,
		MediaType: MediaTypePlaintext,
	}

	// Step 1: Sign if requested
	if opts.SignBeforeEncrypt {
		if opts.SignerKey == nil {
			return nil, fmt.Errorf("SignBeforeEncrypt requires SignerKey to be set")
		}
		signedMsg, err := crypto.Sign(ctx, plaintext, opts.SignerKey, crypto.SignOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to sign message: %w", err)
		}
		result.Message = signedMsg
		result.MediaType = MediaTypeSigned

		// Extract the key ID
		var kid string
		if err := opts.SignerKey.Get("kid", &kid); err == nil {
			result.FromKID = kid
		}
	}

	// Step 2: Encrypt if requested
	if opts.EncryptionMode != "" && len(opts.RecipientKeys) > 0 {
		var encOpts crypto.EncryptionOptions

		switch opts.EncryptionMode {
		case "anoncrypt":
			encOpts = crypto.DefaultEncryptionOptions()
		case "authcrypt":
			if opts.SenderKey == nil {
				return nil, fmt.Errorf("authcrypt requires sender key")
			}
			var senderDID string
			if msg.From != "" {
				senderDID = msg.From
			}
			encOpts = crypto.AuthcryptOptions(opts.SenderKey, senderDID)
		default:
			return nil, fmt.Errorf("unknown encryption mode: %s", opts.EncryptionMode)
		}

		encryptedMsg, err := crypto.Encrypt(ctx, result.Message, opts.RecipientKeys, encOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt message: %w", err)
		}
		result.Message = encryptedMsg
		result.MediaType = MediaTypeEncrypted

		// Extract recipient key IDs
		for _, key := range opts.RecipientKeys {
			var kid string
			if err := key.Get("kid", &kid); err == nil {
				result.ToKIDs = append(result.ToKIDs, kid)
			}
		}
	}

	return result, nil
}

// UnpackOptions configures message unpacking behavior.
type UnpackOptions struct {
	// KeyStore provides private keys for decryption
	KeyStore crypto.KeyStore

	// KeyResolver provides public keys for signature verification
	KeyResolver crypto.KeyResolver

	// ExpectEncrypted requires the message to be encrypted
	ExpectEncrypted bool

	// ExpectSigned requires the message to be signed
	ExpectSigned bool
}

// UnpackResult contains the unpacked message and metadata.
type UnpackResult struct {
	// Message is the unpacked plaintext message
	Message *message.Message

	// WasEncrypted indicates if the message was encrypted
	WasEncrypted bool

	// WasSigned indicates if the message was signed
	WasSigned bool

	// SignerKID is the key ID of the signer (if signed)
	SignerKID string

	// RecipientKID is the key ID used for decryption (if encrypted)
	RecipientKID string

	// EncryptionAlgorithm is the algorithm used for encryption
	EncryptionAlgorithm string

	// SignatureAlgorithm is the algorithm used for signing
	SignatureAlgorithm string
}

// Unpack unpacks a DIDComm message, decrypting and/or verifying as needed.
func Unpack(ctx context.Context, data []byte, opts UnpackOptions) (*UnpackResult, error) {
	result := &UnpackResult{}

	// Detect the message type
	mediaType := detectMediaType(data)

	currentData := data

	// Step 1: Decrypt if encrypted
	if mediaType == MediaTypeEncrypted {
		if opts.KeyStore == nil {
			return nil, fmt.Errorf("encrypted message requires key store")
		}

		decrypted, err := crypto.DecryptWithKeyStore(ctx, currentData, opts.KeyStore)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt message: %w", err)
		}

		currentData = decrypted
		result.WasEncrypted = true
		mediaType = detectMediaType(currentData)
	} else if opts.ExpectEncrypted {
		return nil, fmt.Errorf("expected encrypted message")
	}

	// Step 2: Verify signature if signed
	if mediaType == MediaTypeSigned {
		if opts.KeyResolver == nil {
			return nil, fmt.Errorf("signed message requires key resolver")
		}

		verified, err := crypto.VerifyWithResolver(ctx, currentData, opts.KeyResolver)
		if err != nil {
			return nil, fmt.Errorf("failed to verify signature: %w", err)
		}

		currentData = verified
		result.WasSigned = true
	} else if opts.ExpectSigned {
		return nil, fmt.Errorf("expected signed message")
	}

	// Step 3: Parse the plaintext message
	msg, err := message.Parse(currentData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse message: %w", err)
	}

	result.Message = msg
	return result, nil
}

// detectMediaType attempts to determine the media type of a message.
func detectMediaType(data []byte) string {
	// Try to parse as JSON to detect the structure
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		// Not valid JSON, could be compact JWS/JWE
		return detectCompactFormat(data)
	}

	// Check for JWE structure (has "protected", "recipients", "ciphertext")
	if _, hasProtected := raw["protected"]; hasProtected {
		if _, hasCiphertext := raw["ciphertext"]; hasCiphertext {
			return MediaTypeEncrypted
		}
	}

	// Check for JWS structure (has "payload", "signatures")
	if _, hasPayload := raw["payload"]; hasPayload {
		if _, hasSignatures := raw["signatures"]; hasSignatures {
			return MediaTypeSigned
		}
	}

	// Check for plaintext DIDComm message (has "id" and "type")
	if _, hasID := raw["id"]; hasID {
		if _, hasType := raw["type"]; hasType {
			return MediaTypePlaintext
		}
	}

	return ""
}

// detectCompactFormat detects compact JWS or JWE format.
func detectCompactFormat(data []byte) string {
	str := string(data)

	// Count the number of dots
	dots := 0
	for _, c := range str {
		if c == '.' {
			dots++
		}
	}

	// Compact JWS has 2 dots (header.payload.signature)
	if dots == 2 {
		return MediaTypeSigned
	}

	// Compact JWE has 4 dots (header.encrypted_key.iv.ciphertext.tag)
	if dots == 4 {
		return MediaTypeEncrypted
	}

	return ""
}

// PackPlaintext packs a message as plaintext JSON (no encryption or signing).
func PackPlaintext(msg *message.Message) (*PackResult, error) {
	if err := msg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid message: %w", err)
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize message: %w", err)
	}

	return &PackResult{
		Message:   data,
		MediaType: MediaTypePlaintext,
	}, nil
}

// PackSigned packs a message as a signed JWS.
func PackSigned(ctx context.Context, msg *message.Message, signerKey jwk.Key) (*PackResult, error) {
	return Pack(ctx, msg, PackOptions{
		SignBeforeEncrypt: true,
		SignerKey:         signerKey,
	})
}

// PackAnoncrypt packs a message with anonymous encryption (ECDH-ES).
func PackAnoncrypt(ctx context.Context, msg *message.Message, recipientKeys []jwk.Key) (*PackResult, error) {
	return Pack(ctx, msg, PackOptions{
		EncryptionMode: "anoncrypt",
		RecipientKeys:  recipientKeys,
	})
}

// PackAuthcrypt packs a message with authenticated encryption (ECDH-1PU).
func PackAuthcrypt(ctx context.Context, msg *message.Message, senderKey jwk.Key, recipientKeys []jwk.Key) (*PackResult, error) {
	return Pack(ctx, msg, PackOptions{
		EncryptionMode: "authcrypt",
		SenderKey:      senderKey,
		RecipientKeys:  recipientKeys,
	})
}
