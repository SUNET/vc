package oidcrp

import (
	"time"
)

// Session represents an OIDC authentication session
type Session struct {
	ID             string `json:"id" bson:"id"`
	State          string `json:"state" bson:"state"`                     // OAuth2 state parameter (CSRF protection)
	Nonce          string `json:"nonce" bson:"nonce"`                     // OIDC nonce for ID token validation
	CodeVerifier   string `json:"code_verifier" bson:"code_verifier"`     // PKCE code_verifier
	CredentialType string `json:"credential_type" bson:"credential_type"` // Requested credential type
	IssuerURL      string `json:"issuer_url" bson:"issuer_url"`           // OIDC Provider issuer URL

	// ClientID records which client registration built this flow's
	// authorization URL. An authorization code is issued to a specific
	// client, so a re-registration between the authorization request and
	// the callback must not change which client redeems it. Empty on a
	// session created before this field existed, which falls back to the
	// current registration - the behaviour before it was recorded at all.
	ClientID  string    `json:"client_id" bson:"client_id"`
	CreatedAt time.Time `json:"created_at" bson:"created_at"`
	ExpiresAt time.Time `json:"expires_at" bson:"expires_at"`

	// VCI flow integration fields (set when initiated from OpenID4VCI consent)
	VCISessionID string `json:"vci_session_id" bson:"vci_session_id"` // Links back to the VCI AuthorizationContext session

	// No DynamicParams here. They were persisted onto the session and never
	// read back: the templating they exist for runs inside InitiateAuth,
	// from its own argument, before the session is loaded again. Storing
	// them bought nothing and cost something - they are unverified caller
	// input from the PAR request body, nominally from the authentic source
	// business system though nothing checks that, so keeping a copy in the
	// session store left a later reader free to reach for them as if the OP
	// had asserted them. See AuthorizationContext.DynamicParams, which is
	// where they legitimately live and where the VCI consent flow reads
	// them, and the note in apiv1.handlers_oidcrp on why they must never
	// satisfy a policy dimension.
}
