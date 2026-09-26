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
	VCISessionID string `json:"vci_session_id" bson:"vci_session_id"` // Links back to the VCI AuthorizationContext session

	// DynamicParams holds key-value parameters propagated from
	// AuthorizationContext.DynamicParams. Nothing reads this field today -
	// the templating it was stored for happens inside InitiateAuth, from
	// its own argument, before this session is ever loaded again.
	//
	// Unverified caller input: they arrive in the PAR request body, nominally
	// from the authentic source business system, but nothing here checks
	// that. Templating is the intended use. They must never satisfy a policy
	// dimension - see the note in apiv1.handlers_oidcrp on why letting them
	// stand in for an OIDC-asserted claim would let a caller forge any
	// dimension the OP did not assert.
	DynamicParams map[string]string `json:"dynamic_params,omitempty" bson:"dynamic_params,omitempty"`
}
