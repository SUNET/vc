package configuration

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/SUNET/vc/pkg/openid4vp"

	"gopkg.in/yaml.v2"
)

// PresentationRequestTemplate defines a configurable presentation request
// that maps OIDC scopes to DCQL queries and VP claims to OIDC claims.
//
// TODO(refactor): This type and its interface methods belong in pkg/openid4vp (or a dedicated package).
// Only the YAML loading/parsing logic (LoadPresentationRequests, loadTemplateFile) is configuration concern.
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

	// Enabled indicates whether this template is active. Absent means
	// enabled, which is why it is a POINTER: with a plain bool,
	// "enabled: false" and "no enabled key" are the same value, so
	// loadTemplateFile's default-to-true could not tell them apart and
	// forced every file-loaded template on (SUNET/vc#754). Use
	// IsEnabled rather than reading this directly.
	Enabled *bool `yaml:"enabled" json:"enabled"`
}

// IsEnabled reports whether this template should be used. A template that
// says nothing is enabled; only an explicit "enabled: false" turns it off.
func (t *PresentationRequestTemplate) IsEnabled() bool {
	return t.Enabled == nil || *t.Enabled
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
		if t.IsEnabled() {
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

	// Mirror loadTemplateFile: reject configs that still carry removed
	// transformation keys so this public single-file loader cannot silently
	// drop them via yaml.v2's unknown-field tolerance.
	if err := rejectRemovedTemplateKeys(filePath, fileBytes); err != nil {
		return nil, err
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

	// Reject configs that still carry the removed presentation-request
	// transformation keys. gopkg.in/yaml.v2 silently ignores unknown
	// fields, so without this check an old template with
	// claim_transforms: would be loaded and the configured
	// transformations would silently stop taking effect. There is no
	// equivalent downstream pipeline for this path (data_sources
	// derivations never run in the verifier here), so reject rather
	// than mis-apply.
	if err := rejectRemovedTemplateKeys(filePath, fileBytes); err != nil {
		return nil, err
	}

	// Try loading as a config with a "templates:" list first
	var cfg PresentationRequestConfig
	if err := yaml.Unmarshal(fileBytes, &cfg); err == nil && len(cfg.Templates) > 0 {
		hasID := false
		for _, t := range cfg.Templates {
			if t.ID != "" {
				hasID = true
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

	// No defaulting here any more: Enabled is a pointer, so nil already
	// means "not specified", and IsEnabled reads it that way. Writing true
	// over it was what made "enabled: false" unusable in a file.
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

// removedTemplateKeys lists top-level/claim-level YAML keys whose
// semantics no longer exist on a presentation-request template. Loading a
// config that still carries one of them must fail loudly rather than
// silently drop the field.
var removedTemplateKeys = []string{
	"claim_transforms",
}

// rejectRemovedTemplateKeys returns an error when the raw YAML contains a
// removed top-level or in-template key. The scan is a line-oriented
// best-effort check: it ignores lines inside # comments and only matches
// the key when it appears as the first non-space token followed by ":".
func rejectRemovedTemplateKeys(filePath string, data []byte) error {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := scanner.Text()
		trimmed := strings.TrimLeft(line, " \t-")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, key := range removedTemplateKeys {
			if strings.HasPrefix(trimmed, key+":") {
				return fmt.Errorf("presentation request %s line %d: field %q has been removed; migrate the normalisation into a data_sources derivation or drop the entry", filePath, lineNo, key)
			}
		}
	}
	return scanner.Err()
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
		if template.ID == id && template.IsEnabled() {
			return template, nil
		}
	}
	return nil, fmt.Errorf("template not found: %s", id)
}

// GetTemplateByScope returns the template that handles the given OIDC scope
func (c *PresentationRequestConfig) GetTemplateByScope(scope string) (*PresentationRequestTemplate, error) {
	for _, template := range c.Templates {
		if !template.IsEnabled() {
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
		if template.IsEnabled() {
			enabled = append(enabled, template)
		}
	}
	return enabled
}
