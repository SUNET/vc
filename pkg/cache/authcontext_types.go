package cache

import (
	"reflect"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/go-playground/validator/v10"
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

	// MaxPreAuthRedeemers is the maximum number of distinct clients that can
	// redeem a single pre-authorized code. This prevents unbounded growth of
	// the RedeemedBy array and child sessions if a code leaks.
	MaxPreAuthRedeemers = 10
)

// Token represents an access token with expiration
type Token struct {
	AccessToken    string `json:"access_token" bson:"access_token" validate:"required,max=4096,printascii"`
	ExpiresAt      int64  `json:"expires_at" bson:"expires_at" validate:"required"`
	DPoPThumbprint string `json:"dpop_thumbprint,omitempty" bson:"dpop_thumbprint,omitempty" validate:"omitempty,max=128,printascii"`
}

// AuthorizationContext is the unified model for OIDC/OpenID4VP sessions
// It supports both issuer credential issuance flows and verifier presentation/RP flows
type AuthorizationContext struct {
	// Core session fields
	SessionID string        `json:"session_id" bson:"session_id" validate:"required,max=128,printascii"`
	Status    SessionStatus `json:"status,omitempty" bson:"status,omitempty" validate:"omitempty,max=32,printascii"`
	CreatedAt time.Time     `json:"created_at" bson:"created_at,omitempty"`
	ExpiresAt int64         `json:"expires_at" bson:"expires_at"`

	// SourceSessionID references the parent session from which this session was
	// derived. Used in the pre-authorized code flow where each client redemption
	// creates a new child session that still needs access to the original
	// session's credential documents.
	SourceSessionID string `json:"source_session_id,omitempty" bson:"source_session_id,omitempty" validate:"omitempty,max=128,printascii"`

	// Client and authorization fields
	ClientID            string   `json:"client_id" bson:"client_id" validate:"omitempty,max=128,printascii"`
	WalletClientID      string   `json:"wallet_client_id,omitempty" bson:"wallet_client_id,omitempty" validate:"omitempty,max=128,printascii"`
	Scopes              []string `json:"scopes,omitempty" bson:"scopes,omitempty"`
	State               string   `json:"state,omitempty" bson:"state,omitempty" validate:"omitempty,max=500,printascii"`
	Nonce               string   `json:"nonce,omitempty" bson:"nonce,omitempty" validate:"omitempty,max=128,printascii"`
	CodeChallenge       string   `json:"code_challenge,omitempty" bson:"code_challenge,omitempty" validate:"omitempty,max=128,printascii"`
	CodeChallengeMethod string   `json:"code_challenge_method,omitempty" bson:"code_challenge_method,omitempty" validate:"omitempty,max=16,printascii"`

	// Authorization code fields
	Code      string `json:"code,omitempty" bson:"code,omitempty" validate:"omitempty,max=128,printascii"`
	Forfeited bool   `json:"forfeited,omitempty" bson:"forfeited,omitempty"`

	// RedeemedBy tracks DPoP thumbprints that have redeemed a pre-authorized code.
	// Pre-authorized codes may be redeemed by multiple distinct clients (each
	// identified by a unique DPoP key), but a given client must not redeem
	// the same code twice.
	RedeemedBy []string `json:"redeemed_by,omitempty" bson:"redeemed_by,omitempty"`

	// Token fields
	Token       *Token `json:"token,omitempty" bson:"token,omitempty"`
	AccessToken string `json:"access_token,omitempty" bson:"access_token,omitempty" validate:"omitempty,max=4096,printascii"`
	IDToken     string `json:"id_token,omitempty" bson:"id_token,omitempty" validate:"omitempty,max=8192,printascii"`

	// Issuer-specific fields (credential issuance)
	AuthorizationDetails []openid4vci.AuthorizationDetailsParameter `json:"authorization_details,omitempty" bson:"authorization_details,omitempty"`
	RequestURI           string                                     `json:"request_uri,omitempty" bson:"request_uri,omitempty" validate:"omitempty,max=2048,printascii"`
	WalletURI            string                                     `json:"redirect_url,omitempty" bson:"redirect_url,omitempty" validate:"omitempty,max=2048,printascii"`
	Consent              bool                                       `json:"consent,omitempty" bson:"consent,omitempty"`
	AuthenticSource      string                                     `json:"authentic_source,omitempty" bson:"authentic_source,omitempty" validate:"omitempty,max=128,printascii"`
	Scope                string                                     `json:"scope,omitempty" bson:"scope,omitempty" validate:"omitempty,max=128,printascii"`
	Identifier           string                                     `json:"identifier,omitempty" bson:"identifier,omitempty" validate:"omitempty,max=256,printascii"`
	AuthProvider         string                                     `json:"auth_provider,omitempty" bson:"auth_provider,omitempty" validate:"omitempty,max=32,printascii"`
	DataSource           string                                     `json:"data_source,omitempty" bson:"data_source,omitempty" validate:"omitempty,max=32,printascii"`
	RemoteName           string                                     `json:"remote_name,omitempty" bson:"remote_name,omitempty" validate:"omitempty,max=128,printascii"`

	// Verifier-specific fields (presentation/RP flows)
	RedirectURI            string         `json:"redirect_uri,omitempty" bson:"redirect_uri,omitempty" validate:"omitempty,max=2048,printascii"`
	ResponseType           string         `json:"response_type,omitempty" bson:"response_type,omitempty" validate:"omitempty,max=32,printascii"`
	ResponseMode           string         `json:"response_mode,omitempty" bson:"response_mode,omitempty" validate:"omitempty,max=32,printascii"`
	ShowCredentialDetails  bool           `json:"show_credential_details,omitempty" bson:"show_credential_details,omitempty"`
	CodeExpiresAt          int64          `json:"code_expires_at,omitempty" bson:"code_expires_at,omitempty"`                 // Unix timestamp
	AccessTokenExpiresAt   int64          `json:"access_token_expires_at,omitempty" bson:"access_token_expires_at,omitempty"` // Unix timestamp
	RefreshToken           string         `json:"refresh_token,omitempty" bson:"refresh_token,omitempty" validate:"omitempty,max=4096,printascii"`
	RefreshTokenExpiresAt  int64          `json:"refresh_token_expires_at,omitempty" bson:"refresh_token_expires_at,omitempty"` // Unix timestamp
	VerifiedClaims         map[string]any `json:"verified_claims,omitempty" bson:"verified_claims,omitempty"`
	VPToken                string         `json:"vp_token,omitempty" bson:"vp_token,omitempty" validate:"omitempty,max=65536,printascii"`
	PresentationSubmission any            `json:"presentation_submission,omitempty" bson:"presentation_submission,omitempty"`

	// OpenID4VP fields (wallet interaction)
	EphemeralEncryptionKeyID string                                 `json:"ephemeral_encryption_key_id,omitempty" bson:"ephemeral_encryption_key_id,omitempty" validate:"omitempty,max=128,printascii"`
	VerifierResponseCode     string                                 `json:"verifier_response_code,omitempty" bson:"verifier_response_code,omitempty" validate:"omitempty,max=128,printascii"`
	RequestObjectID          string                                 `json:"request_object_id,omitempty" bson:"request_object_id,omitempty" validate:"omitempty,max=128,printascii"`
	RequestObjectNonce       string                                 `json:"request_object_nonce,omitempty" bson:"request_object_nonce,omitempty" validate:"omitempty,max=128,printascii"`
	DCQLQuery                *openid4vp.DCQL                        `json:"dcql_query,omitempty" bson:"dcql_query,omitempty"`
	Validations              map[string][]openid4vp.ClaimValidation `json:"validations,omitempty" bson:"validations,omitempty" validate:"omitempty,dive,dive"`
	WalletID                 string                                 `json:"wallet_id,omitempty" bson:"wallet_id,omitempty" validate:"omitempty,max=128,printascii"`
}

// Validate checks the AuthorizationContext against its struct validation tags.
func (a *AuthorizationContext) Validate() error {
	v := validator.New(validator.WithRequiredStructEnabled())
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})
	return v.Struct(a)
}
