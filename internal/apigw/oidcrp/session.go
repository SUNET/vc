package oidcrp

import (
	"time"
)

// Session represents an OIDC authentication session
type Session struct {
	ID             string    `json:"id" bson:"id"`
	State          string    `json:"state" bson:"state"`                     // OAuth2 state parameter (CSRF protection)
	Nonce          string    `json:"nonce" bson:"nonce"`                     // OIDC nonce for ID token validation
	CodeVerifier   string    `json:"code_verifier" bson:"code_verifier"`     // PKCE code_verifier
	CredentialType string    `json:"credential_type" bson:"credential_type"` // Requested credential type
	IssuerURL      string    `json:"issuer_url" bson:"issuer_url"`           // OIDC Provider issuer URL
	CreatedAt      time.Time `json:"created_at" bson:"created_at"`
	ExpiresAt      time.Time `json:"expires_at" bson:"expires_at"`

	// VCI flow integration fields (set when initiated from OpenID4VCI consent)
	VCISessionID  string `json:"vci_session_id" bson:"vci_session_id"`   // Links back to the VCI AuthorizationContext session
	VCIRequestURI string `json:"vci_request_uri" bson:"vci_request_uri"` // The VCI request_uri for resuming the flow
}
