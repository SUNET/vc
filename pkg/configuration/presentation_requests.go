package configuration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/SUNET/vc/pkg/openid4vp"

	"gopkg.in/yaml.v2"
)

// PresentationRequestTemplate defines a configurable presentation request
// that maps OIDC scopes to DCQL queries and VP claims to OIDC claims
type PresentationRequestTemplate struct {
	// ID uniquely identifies this template
	ID string `yaml:"id" json:"id" validate:"required"`

	// Name is a human-readable name for this template
	Name string `yaml:"name" json:"name" validate:"required"`

	// Description explains the purpose of this presentation request
	Description string `yaml:"description" json:"description"`

	// Version of this template (for tracking changes)
	Version string `yaml:"version" json:"version"`

	// OIDCScopes that trigger this presentation request
	// When an RP requests these scopes, this template is used
	OIDCScopes []string `yaml:"oidc_scopes" json:"oidc_scopes" validate:"required,min=1"`

	// DCQLQuery is the Digital Credentials Query Language query
	// This defines what credentials and claims to request from the wallet
	DCQLQuery *openid4vp.DCQL `yaml:"dcql" json:"dcql" validate:"required"`

	// ClaimMappings maps VP claim paths to OIDC claim names
	// Key: VP claim path (e.g., "given_name" or "place_of_birth.country")
	// Value: OIDC claim name (e.g., "given_name" or "birth_country")
	// Special value "*" means map all claims through unchanged
	ClaimMappings map[string]string `yaml:"claim_mappings" json:"claim_mappings" validate:"required"`

	// ClaimTransforms defines optional transformations for claims
	ClaimTransforms map[string]ClaimTransform `yaml:"claim_transforms,omitempty" json:"claim_transforms,omitempty"`

	// Enabled indicates whether this template is active
	Enabled bool `yaml:"enabled" json:"enabled"`
}

// GetID returns the template ID (implements openid4vp.PresentationRequestTemplate)
func (t *PresentationRequestTemplate) GetID() string {
	return t.ID
}

// GetOIDCScopes returns the OIDC scopes (implements openid4vp.PresentationRequestTemplate)
func (t *PresentationRequestTemplate) GetOIDCScopes() []string {
	return t.OIDCScopes
}

// GetDCQLQuery returns the DCQL query (implements openid4vp.PresentationRequestTemplate)
func (t *PresentationRequestTemplate) GetDCQLQuery() *openid4vp.DCQL {
	return t.DCQLQuery
}

// GetClaimMappings returns the claim mappings (for claims extraction)
func (t *PresentationRequestTemplate) GetClaimMappings() map[string]string {
	return t.ClaimMappings
}

// GetClaimTransforms returns the claim transforms (for claims extraction)
func (t *PresentationRequestTemplate) GetClaimTransforms() map[string]ClaimTransform {
	return t.ClaimTransforms
}

// ClaimTransform defines how to transform a claim value
type ClaimTransform struct {
	// Type of transformation (e.g., "date_format", "uppercase", "concat")
	Type string `yaml:"type" json:"type" validate:"required"`

	// Parameters for the transformation (type-specific)
	Params map[string]string `yaml:"params,omitempty" json:"params,omitempty"`
}

// PresentationRequestConfig holds all presentation request templates
type PresentationRequestConfig struct {
	// Templates is a list of all available presentation request templates
	Templates []*PresentationRequestTemplate `yaml:"templates" json:"templates" validate:"required,dive"`

	// DefaultTemplate is the ID of the template to use when no scope matches
	DefaultTemplate string `yaml:"default_template,omitempty" json:"default_template,omitempty"`
}

// GetEnabledTemplates returns only the enabled templates as a generic slice
// This is used when creating a PresentationBuilder
func (c *PresentationRequestConfig) GetEnabledTemplates() []*PresentationRequestTemplate {
	enabled := make([]*PresentationRequestTemplate, 0, len(c.Templates))
	for _, t := range c.Templates {
		if t.Enabled {
			enabled = append(enabled, t)
		}
	}
	return enabled
}

// LoadPresentationRequests loads presentation request templates from a directory
// It reads all YAML files in the directory and merges them into a single config
func LoadPresentationRequests(ctx context.Context, dirPath string) (*PresentationRequestConfig, error) {
	if dirPath == "" {
		return nil, fmt.Errorf("presentation requests directory path is empty")
	}

	// Check if directory exists
	info, err := os.Stat(dirPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("presentation requests directory does not exist: %s", dirPath)
		}
		return nil, fmt.Errorf("failed to stat directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("path is not a directory: %s", dirPath)
	}

	config := &PresentationRequestConfig{
		Templates: make([]*PresentationRequestTemplate, 0),
	}

	// Read all YAML files in directory
	files, err := filepath.Glob(filepath.Join(dirPath, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("failed to glob yaml files: %w", err)
	}

	yamlFiles, err := filepath.Glob(filepath.Join(dirPath, "*.yml"))
	if err != nil {
		return nil, fmt.Errorf("failed to glob yml files: %w", err)
	}
	files = append(files, yamlFiles...)

	if len(files) == 0 {
		return nil, fmt.Errorf("no YAML files found in directory: %s", dirPath)
	}

	// Load each file
	for _, filePath := range files {
		templates, err := loadTemplateFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load %s: %w", filePath, err)
		}
		config.Templates = append(config.Templates, templates...)
	}

	// Validate no duplicate IDs
	if err := config.validateUniqueIDs(); err != nil {
		return nil, err
	}

	// Validate no duplicate scopes (same scope in multiple templates)
	if err := config.validateNoDuplicateScopes(); err != nil {
		return nil, err
	}

	return config, nil
}

// LoadPresentationRequestsFromFile loads presentation request config from a single file
func LoadPresentationRequestsFromFile(ctx context.Context, filePath string) (*PresentationRequestConfig, error) {
	if filePath == "" {
		return nil, fmt.Errorf("presentation requests file path is empty")
	}

	fileBytes, err := os.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	var config PresentationRequestConfig
	if err := yaml.Unmarshal(fileBytes, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	// Validate
	if err := config.validateUniqueIDs(); err != nil {
		return nil, err
	}
	if err := config.validateNoDuplicateScopes(); err != nil {
		return nil, err
	}

	return &config, nil
}

// loadTemplateFile loads templates from a YAML file.
// Each file may contain a single template (top-level fields) or multiple
// templates wrapped in a "templates:" list.
func loadTemplateFile(filePath string) ([]*PresentationRequestTemplate, error) {
	fileBytes, err := os.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Try loading as a config with a "templates:" list first
	var cfg PresentationRequestConfig
	if err := yaml.Unmarshal(fileBytes, &cfg); err == nil && len(cfg.Templates) > 0 {
		hasID := false
		for _, t := range cfg.Templates {
			if t.ID != "" {
				hasID = true
			}
			if !t.Enabled {
				t.Enabled = true
			}
		}
		if hasID {
			return cfg.Templates, nil
		}
		return nil, fmt.Errorf("invalid templates configuration in %s: templates list present but all entries missing id", filePath)
	}

	// Fall back to a single template
	var template PresentationRequestTemplate
	if err := yaml.Unmarshal(fileBytes, &template); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	// Set enabled to true by default if not specified
	if !template.Enabled {
		template.Enabled = true
	}

	return []*PresentationRequestTemplate{&template}, nil
}

// validateUniqueIDs checks that all template IDs are unique
func (c *PresentationRequestConfig) validateUniqueIDs() error {
	seen := make(map[string]bool)
	for _, template := range c.Templates {
		if seen[template.ID] {
			return fmt.Errorf("duplicate template ID: %s", template.ID)
		}
		seen[template.ID] = true
	}
	return nil
}

// validateNoDuplicateScopes checks that no scope appears in multiple templates
func (c *PresentationRequestConfig) validateNoDuplicateScopes() error {
	scopeToTemplate := make(map[string]string)
	for _, template := range c.Templates {
		for _, scope := range template.OIDCScopes {
			if existingTemplate, exists := scopeToTemplate[scope]; exists {
				return fmt.Errorf("scope %s is defined in both template %s and %s", scope, existingTemplate, template.ID)
			}
			scopeToTemplate[scope] = template.ID
		}
	}
	return nil
}

// GetTemplateByID returns a template by its ID
func (c *PresentationRequestConfig) GetTemplateByID(id string) (*PresentationRequestTemplate, error) {
	for _, template := range c.Templates {
		if template.ID == id && template.Enabled {
			return template, nil
		}
	}
	return nil, fmt.Errorf("template not found: %s", id)
}

// GetTemplateByScope returns the template that handles the given OIDC scope
func (c *PresentationRequestConfig) GetTemplateByScope(scope string) (*PresentationRequestTemplate, error) {
	for _, template := range c.Templates {
		if !template.Enabled {
			continue
		}
		if slices.Contains(template.OIDCScopes, scope) {
			return template, nil
		}
	}
	return nil, fmt.Errorf("no template found for scope: %s", scope)
}

// GetTemplateByScopes returns the template that handles the given OIDC scopes
// If multiple templates match, returns the first enabled one
func (c *PresentationRequestConfig) GetTemplateByScopes(scopes []string) (*PresentationRequestTemplate, error) {
	for _, scope := range scopes {
		template, err := c.GetTemplateByScope(scope)
		if err == nil {
			return template, nil
		}
	}

	// If no match and default template is set, return it
	if c.DefaultTemplate != "" {
		return c.GetTemplateByID(c.DefaultTemplate)
	}

	return nil, fmt.Errorf("no template found for scopes: %v", scopes)
}

// ListEnabledTemplates returns all enabled templates
func (c *PresentationRequestConfig) ListEnabledTemplates() []*PresentationRequestTemplate {
	enabled := make([]*PresentationRequestTemplate, 0)
	for _, template := range c.Templates {
		if template.Enabled {
			enabled = append(enabled, template)
		}
	}
	return enabled
}
