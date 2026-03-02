package samlsp

import (
	"time"

	apiv1_issuer "vc/internal/gen/issuer/apiv1_issuer"
)

// Session represents an active SAML authentication session
type Session struct {
	ID                 string
	CredentialType     string // Credential type identifier (e.g., "pid")
	CredentialConfigID string // OpenID4VCI credential configuration ID
	IDPEntityID        string
	JWK                *apiv1_issuer.Jwk // Uses protobuf type to avoid conversion when calling issuer gRPC
	CreatedAt          time.Time
	ExpiresAt          time.Time
}
