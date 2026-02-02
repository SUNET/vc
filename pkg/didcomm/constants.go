//go:build didcomm && vc20

package didcomm

// MediaType constants for DIDComm message formats.
// Per DIDComm v2.1 spec Section 2.4.
const (
	// MediaTypePlaintext is the media type for plaintext DIDComm messages
	MediaTypePlaintext = "application/didcomm-plain+json"

	// MediaTypeSigned is the media type for signed DIDComm messages (JWS)
	MediaTypeSigned = "application/didcomm-signed+json"

	// MediaTypeEncrypted is the media type for encrypted DIDComm messages (JWE)
	MediaTypeEncrypted = "application/didcomm-encrypted+json"
)

// Protocol URIs for built-in DIDComm protocols.
const (
	// Trust Ping 2.0
	ProtocolTrustPing         = "https://didcomm.org/trust-ping/2.0"
	MessageTypePing           = "https://didcomm.org/trust-ping/2.0/ping"
	MessageTypePingResponse   = "https://didcomm.org/trust-ping/2.0/ping-response"

	// Discover Features 2.0
	ProtocolDiscoverFeatures  = "https://didcomm.org/discover-features/2.0"
	MessageTypeQuery          = "https://didcomm.org/discover-features/2.0/queries"
	MessageTypeDisclose       = "https://didcomm.org/discover-features/2.0/disclose"

	// Out-of-Band 2.0
	ProtocolOutOfBand         = "https://didcomm.org/out-of-band/2.0"
	MessageTypeInvitation     = "https://didcomm.org/out-of-band/2.0/invitation"

	// Routing 2.0
	ProtocolRouting           = "https://didcomm.org/routing/2.0"
	MessageTypeForward        = "https://didcomm.org/routing/2.0/forward"
)

// Algorithm identifiers per DIDComm v2.1 spec.
const (
	// Key Agreement Algorithms (for encryption)
	AlgECDHES       = "ECDH-ES"        // Anonymous encryption
	AlgECDH1PU      = "ECDH-1PU"       // Authenticated encryption

	// Content Encryption Algorithms
	EncA256GCM       = "A256GCM"        // Recommended for anoncrypt
	EncA256CBCHS512  = "A256CBC-HS512"  // Required for authcrypt

	// Signing Algorithms
	AlgEdDSA  = "EdDSA"   // Ed25519 (Required)
	AlgES256  = "ES256"   // P-256 (Required)
	AlgES256K = "ES256K"  // secp256k1 (Required)
	AlgES384  = "ES384"   // P-384

	// Key Agreement Curves
	CurveX25519 = "X25519"  // Required
	CurveP256   = "P-256"   // Required
	CurveP384   = "P-384"   // Required

	// Signing Curves
	CurveEd25519   = "Ed25519"    // Required
	CurveSecp256k1 = "secp256k1"  // Required
)

// DIDCommMessaging service type for DID document service entries.
const ServiceTypeDIDComm = "DIDCommMessaging"

// OOB URL parameter name for Out-of-Band invitations.
const OOBQueryParam = "_oob"
