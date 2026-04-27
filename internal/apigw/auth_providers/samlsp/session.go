package samlsp

import (
	"time"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
)

// Session represents an active SAML authentication session
type Session struct {
	ID             string
	CredentialType string // Credential type identifier (e.g., "pid")
	IDPEntityID    string
	JWK            *apiv1_issuer.Jwk // Uses protobuf type to avoid conversion when calling issuer gRPC
	CreatedAt      time.Time
	ExpiresAt      time.Time

	// VCI flow integration fields (set when initiated from OpenID4VCI consent)
	VCISessionID string // Links back to the VCI AuthorizationContext session
}
