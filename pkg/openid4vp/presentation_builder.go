package openid4vp

import (
	"context"
	"fmt"
	"slices"
)

// PresentationRequestTemplate represents a template for creating presentation requests.
// This is a minimal interface to avoid import cycles with pkg/configuration.
type PresentationRequestTemplate interface {
	GetID() string
	GetOIDCScopes() []string
	GetDCQLQuery() *DCQL
}

// PresentationBuilder builds OpenID4VP presentation requests from templates
type PresentationBuilder struct {
	templates  map[string]PresentationRequestTemplate // ID -> template
	scopeIndex map[string]string                      // scope -> template ID
}

// NewPresentationBuilder creates a new PresentationBuilder with the given templates
// The templates parameter accepts any slice of types that implement PresentationRequestTemplate
func NewPresentationBuilder[T PresentationRequestTemplate](templates []T) *PresentationBuilder {
	builder := &PresentationBuilder{
		templates:  make(map[string]PresentationRequestTemplate),
		scopeIndex: make(map[string]string),
	}

	// Index templates by ID and scopes
	for _, template := range templates {
		id := template.GetID()
		builder.templates[id] = template

		// Index by each scope
		for _, scope := range template.GetOIDCScopes() {
			builder.scopeIndex[scope] = id
		}
	}

	return builder
}

// BuildFromScopes creates a DCQL query from OIDC scopes using configured templates
// Returns the DCQL query and the template that was used
func (pb *PresentationBuilder) BuildFromScopes(ctx context.Context, scopes []string) (*DCQL, PresentationRequestTemplate, error) {
	if len(scopes) == 0 {
		return nil, nil, fmt.Errorf("no scopes provided")
	}

	// Find first matching template by scope
	var templateID string
	for _, scope := range scopes {
		if id, ok := pb.scopeIndex[scope]; ok {
			templateID = id
			break
		}
	}

	if templateID == "" {
		return nil, nil, fmt.Errorf("no template found for scopes %v", scopes)
	}

	template := pb.templates[templateID]
	dcql := template.GetDCQLQuery()
	if dcql == nil {
		return nil, nil, fmt.Errorf("template %s has no DCQL query", template.GetID())
	}

	return dcql, template, nil
}

// BuildFromTemplate creates a DCQL query from a specific template ID
func (pb *PresentationBuilder) BuildFromTemplate(ctx context.Context, templateID string) (*DCQL, PresentationRequestTemplate, error) {
	template, ok := pb.templates[templateID]
	if !ok {
		return nil, nil, fmt.Errorf("template %s not found", templateID)
	}

	dcql := template.GetDCQLQuery()
	if dcql == nil {
		return nil, nil, fmt.Errorf("template %s has no DCQL query", template.GetID())
	}

	return dcql, template, nil
}

// BuildDCQLQuery creates a DCQL query from OIDC scopes.
// This attempts to find matching templates, and falls back to a generic DCQL query if none are found.
// All scopes are considered for matching, including standard OIDC scopes like "openid".
// This allows standard OIDC scopes to optionally map to credentials if configured.
// Non-standard scopes are prioritized over standard scopes to prevent "openid" from
// always being selected when it appears first in the request.
func (pb *PresentationBuilder) BuildDCQLQuery(ctx context.Context, scopes []string) (*DCQL, error) {
	if len(scopes) == 0 {
		// Return a generic DCQL query when no scopes provided
		return pb.createGenericDCQL(), nil
	}

	// Prioritize non-standard scopes over standard OIDC scopes.
	// This prevents "openid" (which typically appears first) from always being selected.
	// First, try non-standard scopes
	for _, scope := range scopes {
		if StandardOIDCScopes[scope] {
			continue // Skip standard scopes in first pass
		}
		if templateID, ok := pb.scopeIndex[scope]; ok {
			template := pb.templates[templateID]
			dcql := template.GetDCQLQuery()
			if dcql != nil {
				// Return a copy to avoid modifications to the template
				return copyDCQL(dcql), nil
			}
		}
	}

	// Then, try standard OIDC scopes (if configured with a template)
	for _, scope := range scopes {
		if !StandardOIDCScopes[scope] {
			continue // Already tried non-standard scopes
		}
		if templateID, ok := pb.scopeIndex[scope]; ok {
			template := pb.templates[templateID]
			dcql := template.GetDCQLQuery()
			if dcql != nil {
				// Return a copy to avoid modifications to the template
				return copyDCQL(dcql), nil
			}
		}
	}

	// No template found, return generic DCQL
	return pb.createGenericDCQL(), nil
}

// copyDCQL creates a deep copy of a DCQL query
func copyDCQL(src *DCQL) *DCQL {
	if src == nil {
		return nil
	}

	dst := &DCQL{
		Credentials: make([]CredentialQuery, len(src.Credentials)),
		// CredentialSets is only set if source has elements.
		// We use nil (not empty slice) to ensure consistent behavior:
		// nil is unambiguous for both JSON omitempty and validator omitempty.
	}

	// Only create CredentialSets if source has elements
	if len(src.CredentialSets) > 0 {
		dst.CredentialSets = make([]CredentialSetQuery, len(src.CredentialSets))
	}

	// Copy credentials
	for i, cred := range src.Credentials {
		dst.Credentials[i] = CredentialQuery{
			ID:       cred.ID,
			Format:   cred.Format,
			Multiple: cred.Multiple,
			Meta: MetaQuery{
				VCTValues: append([]string{}, cred.Meta.VCTValues...),
			},
			RequireCryptographicHolderBinding: cred.RequireCryptographicHolderBinding,
		}

		// Copy trusted authorities
		if len(cred.TrustedAuthorities) > 0 {
			dst.Credentials[i].TrustedAuthorities = make([]TrustedAuthority, len(cred.TrustedAuthorities))
			for j, ta := range cred.TrustedAuthorities {
				dst.Credentials[i].TrustedAuthorities[j] = TrustedAuthority{
					Type:   ta.Type,
					Values: append([]string{}, ta.Values...),
				}
			}
		}

		// Copy claims
		if len(cred.Claims) > 0 {
			dst.Credentials[i].Claims = make([]ClaimQuery, len(cred.Claims))
			for j, claim := range cred.Claims {
				pathCopy := make([]*string, len(claim.Path))
				for k, p := range claim.Path {
					if p != nil {
						s := *p
						pathCopy[k] = &s
					}
				}
				dst.Credentials[i].Claims[j] = ClaimQuery{
					Path: pathCopy,
				}
			}
		}

		// Copy claim sets
		if len(cred.ClaimSet) > 0 {
			dst.Credentials[i].ClaimSet = append([]string{}, cred.ClaimSet...)
		}
	}

	// Copy credential sets
	for i, cs := range src.CredentialSets {
		dst.CredentialSets[i] = CredentialSetQuery{
			Required: cs.Required,
			Purpose:  cs.Purpose,
			Options:  make([][]string, len(cs.Options)),
		}
		for j, opt := range cs.Options {
			dst.CredentialSets[i].Options[j] = append([]string{}, opt...)
		}
	}

	return dst
}

// createGenericDCQL creates a generic DCQL query when no specific templates match
func (pb *PresentationBuilder) createGenericDCQL() *DCQL {
	return &DCQL{
		Credentials: []CredentialQuery{
			{
				ID:     "credential_generic",
				Format: "vc+sd-jwt",
				Meta: MetaQuery{
					VCTValues: []string{}, // Empty - accept any VCT
				},
			},
		},
	}
}

// StandardOIDCScopes contains scopes defined by OpenID Connect Core.
// These are protocol-level scopes that are optional for credential matching.
// The "openid" scope is REQUIRED by the OIDC specification and will always
// be present, but it does not need to be mapped to a credential.
var StandardOIDCScopes = map[string]bool{
	"openid":         true,
	"profile":        true,
	"email":          true,
	"address":        true,
	"phone":          true,
	"offline_access": true,
}

// FilterStandardScopes removes standard OIDC scopes from the list.
// This is a utility function that can be used when you specifically need
// to identify scopes that are not standard OIDC scopes. Note that credential
// matching logic does NOT use this - all scopes (including standard ones)
// are considered for matching to allow optional credential mappings.
func FilterStandardScopes(scopes []string) []string {
	filtered := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if !StandardOIDCScopes[scope] {
			filtered = append(filtered, scope)
		}
	}
	return filtered
}

// FindTemplateByScopes finds a template that matches the given OIDC scopes
// Returns the first template where all requested scopes are present in the template's scopes
func (pb *PresentationBuilder) FindTemplateByScopes(scopes []string) PresentationRequestTemplate {
	if len(scopes) == 0 {
		return nil
	}

	// Try to find a template where all requested scopes match
	for _, template := range pb.templates {
		templateScopes := template.GetOIDCScopes()
		if scopesMatch(scopes, templateScopes) {
			return template
		}
	}

	return nil
}

// scopesMatch checks if the requested scopes match the template scopes.
// A template matches if it contains at least one of the requested scopes.
// All scopes are considered for matching, including standard OIDC scopes like "openid".
// This allows standard OIDC scopes to optionally map to credentials if configured.
func scopesMatch(requestedScopes []string, templateScopes []string) bool {
	if len(requestedScopes) == 0 {
		return false
	}

	// Check if template contains any of the requested scopes
	for _, requestedScope := range requestedScopes {
		if slices.Contains(templateScopes, requestedScope) {
			return true // Match found
		}
	}

	return false
}

// GetClaimMappings is a helper to extract claim mappings from a template
// Returns nil if the template doesn't implement this method
func GetClaimMappings(template PresentationRequestTemplate) map[string]string {
	if t, ok := template.(interface {
		GetClaimMappings() map[string]string
	}); ok {
		return t.GetClaimMappings()
	}
	return nil
}

// ListTemplates returns all templates
func (pb *PresentationBuilder) ListTemplates() []PresentationRequestTemplate {
	templates := make([]PresentationRequestTemplate, 0, len(pb.templates))
	for _, template := range pb.templates {
		templates = append(templates, template)
	}
	return templates
}

// GetTemplate returns a specific template by ID
func (pb *PresentationBuilder) GetTemplate(templateID string) (PresentationRequestTemplate, error) {
	template, ok := pb.templates[templateID]
	if !ok {
		return nil, fmt.Errorf("template %s not found", templateID)
	}
	return template, nil
}
