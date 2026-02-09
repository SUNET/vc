package cache

import (
	"time"

	"vc/pkg/model"
	"vc/pkg/openid4vp"
)

// SessionStatus represents the status of an OIDC session
type SessionStatus string

const (
	SessionStatusPending              SessionStatus = "pending"
	SessionStatusAwaitingPresentation SessionStatus = "awaiting_presentation"
	SessionStatusCodeIssued           SessionStatus = "code_issued"
	SessionStatusTokenIssued          SessionStatus = "token_issued"
	SessionStatusCompleted            SessionStatus = "completed"
	SessionStatusExpired              SessionStatus = "expired"
	SessionStatusError                SessionStatus = "error"
)

// Token represents an access token with expiration
type Token struct {
	AccessToken string `json:"access_token" bson:"access_token" validate:"required"`
	ExpiresAt   int64  `json:"expires_at" bson:"expires_at" validate:"required"`
}

// AuthorizationContext is the unified model for OIDC/OpenID4VP sessions
// It supports both issuer credential issuance flows and verifier presentation/RP flows
type AuthorizationContext struct {
	// Core session fields
	SessionID string        `json:"session_id" bson:"session_id" validate:"required"`
	Status    SessionStatus `json:"status,omitempty" bson:"status,omitempty"`
	CreatedAt time.Time     `json:"created_at,omitempty" bson:"created_at,omitempty"`
	ExpiresAt int64         `json:"expires_at" bson:"expires_at"`

	// Client and authorization fields
	ClientID            string   `json:"client_id" bson:"client_id"`
	Scopes              []string `json:"scopes,omitempty" bson:"scopes,omitempty"`
	State               string   `json:"state,omitempty" bson:"state,omitempty"`
	Nonce               string   `json:"nonce,omitempty" bson:"nonce,omitempty"`
	CodeChallenge       string   `json:"code_challenge,omitempty" bson:"code_challenge,omitempty"`
	CodeChallengeMethod string   `json:"code_challenge_method,omitempty" bson:"code_challenge_method,omitempty"`

	// Authorization code fields
	Code      string `json:"code,omitempty" bson:"code,omitempty"`
	Forfeited bool   `json:"forfeited,omitempty" bson:"forfeited,omitempty"`

	// Token fields
	Token       *Token `json:"token,omitempty" bson:"token,omitempty"`
	AccessToken string `json:"access_token,omitempty" bson:"access_token,omitempty"`
	IDToken     string `json:"id_token,omitempty" bson:"id_token,omitempty"`

	// Issuer-specific fields (credential issuance)
	RequestURI      string          `json:"request_uri,omitempty" bson:"request_uri,omitempty"`
	WalletURI       string          `json:"redirect_url,omitempty" bson:"redirect_url,omitempty"`
	Consent         bool            `json:"consent,omitempty" bson:"consent,omitempty"`
	AuthenticSource string          `json:"authentic_source,omitempty" bson:"authentic_source,omitempty"`
	VCT             string          `json:"vct,omitempty" bson:"vct,omitempty"`
	Identity        *model.Identity `json:"identity,omitempty" bson:"identity,omitempty"`

	// Verifier-specific fields (presentation/RP flows)
	RedirectURI             string         `json:"redirect_uri,omitempty" bson:"redirect_uri,omitempty"`
	ResponseType            string         `json:"response_type,omitempty" bson:"response_type,omitempty"`
	ResponseMode            string         `json:"response_mode,omitempty" bson:"response_mode,omitempty"`
	ShowCredentialDetails   bool           `json:"show_credential_details,omitempty" bson:"show_credential_details,omitempty"`
	CodeExpiresAt           int64          `json:"code_expires_at,omitempty" bson:"code_expires_at,omitempty"`          // Unix timestamp
	AccessTokenExpiresAt    int64          `json:"access_token_expires_at,omitempty" bson:"access_token_expires_at,omitempty"` // Unix timestamp
	RefreshToken            string         `json:"refresh_token,omitempty" bson:"refresh_token,omitempty"`
	RefreshTokenExpiresAt   int64          `json:"refresh_token_expires_at,omitempty" bson:"refresh_token_expires_at,omitempty"` // Unix timestamp
	VerifiedClaims          map[string]any `json:"verified_claims,omitempty" bson:"verified_claims,omitempty"`
	VPToken                 string         `json:"vp_token,omitempty" bson:"vp_token,omitempty"`
	PresentationSubmission  any            `json:"presentation_submission,omitempty" bson:"presentation_submission,omitempty"`

	// OpenID4VP fields (wallet interaction)
	EphemeralEncryptionKeyID string          `json:"ephemeral_encryption_key_id,omitempty" bson:"ephemeral_encryption_key_id,omitempty"`
	VerifierResponseCode     string          `json:"verifier_response_code,omitempty" bson:"verifier_response_code,omitempty"`
	RequestObjectID          string          `json:"request_object_id,omitempty" bson:"request_object_id,omitempty"`
	RequestObjectNonce       string          `json:"request_object_nonce,omitempty" bson:"request_object_nonce,omitempty"`
	DCQLQuery                *openid4vp.DCQL `json:"dcql_query,omitempty" bson:"dcql_query,omitempty"`
	WalletID                 string          `json:"wallet_id,omitempty" bson:"wallet_id,omitempty"`
}
