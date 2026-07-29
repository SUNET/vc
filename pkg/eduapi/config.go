package eduapi

import "time"

// Config holds the full Edu-API (1EdTech) data source configuration for credential issuance.
type Config struct {
	// Enable turns on Edu-API data source support (default: false)
	Enable bool `yaml:"enable" default:"false"`

	// CredentialTypes lists credential types that can be issued via Edu-API data
	CredentialTypes []string `yaml:"credential_types" validate:"required_if=Enable true,omitempty,min=1"`

	// BaseURL is the base URL of the Edu-API endpoint (e.g. Ladok's Edu-API gateway)
	BaseURL string `yaml:"base_url" validate:"required_if=Enable true" doc_example:"\"https://api.ladok.se/eduapi\""`

	// TokenURL is the OAuth 2.0 token endpoint for Client Credentials Grant
	TokenURL string `yaml:"token_url" validate:"required_if=Enable true" doc_example:"\"https://api.ladok.se/oauth2/token\""`

	// ClientID is the OAuth 2.0 client identifier
	ClientID string `yaml:"client_id" validate:"required_if=Enable true"`

	// ClientSecret is the OAuth 2.0 client secret
	ClientSecret string `yaml:"client_secret" validate:"required_if=Enable true"`

	// Scopes are the OAuth 2.0 scopes to request for the Edu-API
	Scopes []string `yaml:"scopes,omitempty" default:"[\"https://purl.imsglobal.org/spec/or/v1p2/scope/roster-core.readonly\"]"`

	// Timeout is the HTTP client timeout for Edu-API requests
	Timeout time.Duration `yaml:"timeout" default:"10s"`

	// AttributeMappings defines how to map Edu-API data to credential claims.
	// Key: credential type identifier (must match a credential_metadata key).
	AttributeMappings map[string]AttributeMapping `yaml:"attribute_mappings,omitempty"`
}

// AttributeMapping maps external attribute names to claim configurations.
// Mirrors model.AttributeMapping to avoid circular imports between eduapi and model.
type AttributeMapping map[string]AttributeConfig

// AttributeConfig defines how a single external attribute maps to a credential claim.
// Mirrors model.AttributeConfig to avoid circular imports.
type AttributeConfig struct {
	// Claim is the target claim name (supports dot-notation for nesting)
	Claim string `yaml:"claim" validate:"required"`

	// Required indicates if this attribute must be present
	Required bool `yaml:"required" default:"false"`

	// Transform is an optional transformation to apply
	Transform string `yaml:"transform,omitempty" validate:"omitempty,oneof=lowercase uppercase trim country_alpha2 country_alpha3"`

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
