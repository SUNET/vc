package openidfederation

import (
	"encoding/json"

	"github.com/golang-jwt/jwt/v5"
)

// EntityConfiguration represents an OpenID Federation Entity Configuration
// per OpenID Federation 1.0 §5.1.
type EntityConfiguration struct {
	// Issuer is the entity identifier (iss = sub).
	Issuer string `json:"iss"`
	// Subject is the entity identifier (must equal Issuer for entity configurations).
	Subject string `json:"sub"`
	// IssuedAt is the time the configuration was created.
	IssuedAt *jwt.NumericDate `json:"iat"`
	// ExpiresAt is the expiration time of this configuration.
	ExpiresAt *jwt.NumericDate `json:"exp"`
	// JWKS contains the entity's signing key(s) in JWK Set format.
	JWKS json.RawMessage `json:"jwks"`
	// AuthorityHints lists the entity identifiers of superior authorities.
	AuthorityHints []string `json:"authority_hints,omitempty"`
	// Metadata contains the entity's typed metadata.
	Metadata *EntityMetadata `json:"metadata,omitempty"`
	// TrustMarks contains trust marks issued to this entity.
	TrustMarks []TrustMark `json:"trust_marks,omitempty"`
}

// EntityMetadata contains metadata for each entity type per OpenID Federation 1.0 §4.8.
type EntityMetadata struct {
	// OpenIDCredentialIssuer contains OID4VCI issuer metadata.
	OpenIDCredentialIssuer map[string]any `json:"openid_credential_issuer,omitempty"`
	// OAuthAuthorizationServer contains OAuth2 AS metadata (RFC 8414).
	OAuthAuthorizationServer map[string]any `json:"oauth_authorization_server,omitempty"`
	// OpenIDRelyingParty contains verifier (RP) metadata.
	OpenIDRelyingParty map[string]any `json:"openid_relying_party,omitempty"`
	// FederationEntity contains federation-level metadata.
	FederationEntity map[string]any `json:"federation_entity,omitempty"`
}

// TrustMark represents a trust mark issued to an entity.
type TrustMark struct {
	// ID is the trust mark identifier.
	ID string `json:"id"`
	// TrustMark is the trust mark JWT.
	TrustMark string `json:"trust_mark"`
}

// Config holds configuration for OpenID Federation participation.
type Config struct {
	// Enabled enables the federation entity configuration endpoint.
	Enabled bool `yaml:"enabled" default:"false"`
	// EntityID is the entity identifier (defaults to PublicURL if empty).
	EntityID string `yaml:"entity_id,omitempty"`
	// AuthorityHints lists superior authority entity identifiers.
	AuthorityHints []string `yaml:"authority_hints,omitempty"`
	// OrganizationName is the human-readable organization name.
	OrganizationName string `yaml:"organization_name,omitempty"`
	// LogoURI is the organization logo URL.
	LogoURI string `yaml:"logo_uri,omitempty"`
	// TrustMarks contains pre-issued trust mark JWTs.
	TrustMarks []TrustMarkConfig `yaml:"trust_marks,omitempty" validate:"omitempty,dive"`
	// TTL is the validity period of the entity configuration in seconds.
	// Default: 86400 (24 hours).
	TTL int64 `yaml:"ttl" default:"86400"`
}

// TrustMarkConfig holds a configured trust mark.
type TrustMarkConfig struct {
	// ID is the trust mark identifier.
	ID string `yaml:"id" validate:"required"`
	// JWT is the trust mark JWT string.
	JWT string `yaml:"jwt" validate:"required"`
}
