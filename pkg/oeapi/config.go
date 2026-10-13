package oeapi

import "time"

// Config holds the full Open Education API (OEAPI v6.0) data source configuration
// for credential issuance.
type Config struct {
	// Enable turns on OEAPI data source support (default: false)
	Enable bool `yaml:"enable" default:"false"`

	// CredentialTypes lists credential types that can be issued via OEAPI data
	CredentialTypes []string `yaml:"credential_types" validate:"required_if=Enable true,omitempty,min=1"`

	// BaseURL is the host root of the OEAPI endpoint (the "/v6" version path is appended automatically)
	BaseURL string `yaml:"base_url" validate:"required_if=Enable true" doc_example:"\"https://demo01.eduapi.nl\""`

	// TokenURL is the OAuth 2.0 token endpoint for Client Credentials Grant
	TokenURL string `yaml:"token_url" validate:"required_if=Enable true" doc_example:"\"https://demo01.eduapi.nl/oauth2/token\""`

	// ClientID is the OAuth 2.0 client identifier
	ClientID string `yaml:"client_id" validate:"required_if=Enable true"`

	// ClientSecret is the OAuth 2.0 client secret
	ClientSecret string `yaml:"client_secret" validate:"required_if=Enable true"`

	// Scopes are the OAuth 2.0 scopes to request for the OEAPI
	Scopes []string `yaml:"scopes,omitempty"`

	// Timeout is the HTTP client timeout for OEAPI requests
	Timeout time.Duration `yaml:"timeout" default:"10s"`

	// AttributeMappings defines how to map OEAPI data to credential claims.
	// Key: credential type identifier (must match a credential_metadata key).
	AttributeMappings map[string]AttributeMapping `yaml:"attribute_mappings,omitempty"`
}

// AttributeMapping maps external attribute names to claim configurations.
// Mirrors model.AttributeMapping to avoid circular imports between oeapi and model.
type AttributeMapping map[string]AttributeConfig

// AttributeConfig defines how a single external attribute maps to a credential claim.
// Mirrors model.AttributeConfig to avoid circular imports. Value transformation
// (canonicalisation, case folding, date reformatting) is expressed as
// derivations on the target scope.
type AttributeConfig struct {
	// Claim is the target claim name (supports dot-notation for nesting)
	Claim string `yaml:"claim" validate:"required"`

	// Required indicates if this attribute must be present
	Required bool `yaml:"required" default:"false"`

	// Default is an optional default value if attribute is missing
	Default string `yaml:"default,omitempty"`
}

// ClientConfig returns the subset of Config needed by NewClient.
func (c *Config) ClientConfig() ClientConfig {
	return ClientConfig{
		BaseURL:      c.BaseURL,
		TokenURL:     c.TokenURL,
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Scopes:       c.Scopes,
		Timeout:      c.Timeout,
	}
}
