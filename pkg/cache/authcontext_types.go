package cache

import (
	"vc/pkg/model"
	"vc/pkg/openid4vp"
)

// Token represents an access token with expiration
type Token struct {
	AccessToken string `json:"access_token" bson:"access_token" validate:"required"`
	ExpiresAt   int64  `json:"expires_at" bson:"expires_at" validate:"required"`
}

// AuthorizationContext is the model for the authorization token stored in cache
type AuthorizationContext struct {
	SessionID                string          `json:"session_id" bson:"session_id" validate:"required"`
	Scope                    []string        `json:"scope" bson:"scope" validate:"required"`
	Code                     string          `json:"code" bson:"code"`
	RequestURI               string          `json:"request_uri" bson:"request_uri" validate:"required"`
	WalletURI                string          `json:"redirect_url" bson:"redirect_url" validate:"required"`
	Forfeited                bool            `json:"is_used" bson:"is_used"`
	State                    string          `json:"state"`
	ClientID                 string          `json:"client_id" bson:"client_id" validate:"required"`
	ExpiresAt                int64           `json:"expires_at" bson:"expires_at" validate:"required"`
	CodeChallenge            string          `json:"code_challenge" bson:"code_challenge" validate:"required"`
	CodeChallengeMethod      string          `json:"code_challenge_method" bson:"code_challenge_method" validate:"required,oneof=S256 plain"`
	Consent                  bool            `json:"consent" bson:"consent"`
	AuthenticSource          string          `json:"authentic_source" bson:"authentic_source"`
	VCT                      string          `json:"vct" bson:"vct"`
	Identity                 *model.Identity `json:"identity,omitempty" bson:"identity,omitempty"`
	Token                    *Token          `json:"token,omitempty" bson:"token,omitempty"`
	Nonce                    string          `json:"nonce,omitempty" bson:"nonce,omitempty" validate:"omitempty"`
	EphemeralEncryptionKeyID string          `json:"ephemeral_encryption_key_id,omitempty" bson:"ephemeral_encryption_key_id,omitempty"`
	VerifierResponseCode     string          `json:"verifier_response_code,omitempty" bson:"verifier_response_code,omitempty"`
	RequestObjectID          string          `json:"request_object_id,omitempty" bson:"request_object_id,omitempty"`
	DCQLQuery                *openid4vp.DCQL `json:"dcql_query,omitempty" bson:"dcql_query,omitempty"`
}
