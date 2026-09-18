package openid4vp

import (
	"context"
	"fmt"
	"maps"
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
//
// A caller with a better fallback than the generic query - building from
// credential_metadata, say - wants TemplateDCQLQuery instead, which reports the
// no-match case instead of standing in for it.
func (pb *PresentationBuilder) BuildDCQLQuery(ctx context.Context, scopes []string) (*DCQL, error) {
	if dcql, _, matched := pb.TemplateDCQLQuery(ctx, scopes); matched {
		return dcql, nil
	}
	return pb.createGenericDCQL(), nil
}

// TemplateDCQLQuery returns a copy of the DCQL query of the template matching
// scopes, and whether one matched at all. All scopes are considered, including
// standard OIDC scopes like "openid", so a standard scope can map to a
// credential when configured; non-standard scopes are tried first so "openid"
// does not win merely by appearing first in the request.
//
// The template's declared oidc_scopes come back alongside the query.
//
// matched is the part BuildDCQLQuery cannot express: it answers "no template"
// with the generic placeholder, which constrains nothing and reads to a caller
// exactly like success. Inferring that case back out of the returned query is
// not possible either - a DCQL credential id is arbitrary, nothing reserves the
// placeholder's, and a template using the same id would be discarded. So the
// builder says so directly.
func (pb *PresentationBuilder) TemplateDCQLQuery(_ context.Context, scopes []string) (*DCQL, []string, bool) {
	if len(scopes) == 0 {
		return nil, nil, false
	}

	// Prioritize non-standard scopes over standard OIDC scopes.
	// This prevents "openid" (which typically appears first) from always being selected.
	for _, standard := range []bool{false, true} {
		for _, scope := range scopes {
			if StandardOIDCScopes[scope] != standard {
				continue
			}
			templateID, ok := pb.scopeIndex[scope]
			if !ok {
				continue
			}
			template := pb.templates[templateID]
			if dcql := template.GetDCQLQuery(); dcql != nil {
				// A copy, so a caller completing the query in place (see the
				// verifier's augmentVCTValuesFromConfig) cannot edit the
				// template every later request is built from.
				//
				// The template's own oidc_scopes come back with it: they are
				// the only record of which requested scopes this query is meant
				// to answer, and a caller pairing scopes to queries has nothing
				// else to go on for a scope that configures no credential.
				return copyDCQL(dcql), slices.Clone(template.GetOIDCScopes()), true
			}
		}
	}

	return nil, nil, false
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
		meta := MetaQuery{
			DoctypeValue: cred.Meta.DoctypeValue,
			PPIDContext:  cred.Meta.PPIDContext,
		}
		if len(cred.Meta.VCTValues) > 0 {
			meta.VCTValues = append([]string{}, cred.Meta.VCTValues...)
		}
		if len(cred.Meta.TypeValues) > 0 {
			meta.TypeValues = make([][]string, len(cred.Meta.TypeValues))
			for j, tv := range cred.Meta.TypeValues {
				meta.TypeValues[j] = append([]string{}, tv...)
			}
		}
		if len(cred.Meta.ZKSystemType) > 0 {
			meta.ZKSystemType = make([]ZKSystemTypeSpec, len(cred.Meta.ZKSystemType))
			for j, spec := range cred.Meta.ZKSystemType {
				params := make(map[string]string, len(spec.Params))
				maps.Copy(params, spec.Params)
				meta.ZKSystemType[j] = ZKSystemTypeSpec{
					ID:     spec.ID,
					System: spec.System,
					Params: params,
				}
			}
		}
		dst.Credentials[i] = CredentialQuery{
			ID:       cred.ID,
			Format:   cred.Format,
			Multiple: cred.Multiple,
			Meta:     meta,
		}
		if cred.RequireCryptographicHolderBinding != nil {
			v := *cred.RequireCryptographicHolderBinding
			dst.Credentials[i].RequireCryptographicHolderBinding = &v
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
				var valuesCopy []any
				if claim.Values != nil {
					valuesCopy = append([]any{}, claim.Values...)
				}
				dst.Credentials[i].Claims[j] = ClaimQuery{
					ID:     claim.ID,
					Path:   pathCopy,
					Values: valuesCopy,
				}
			}
		}

		// Copy claim sets
		if len(cred.ClaimSet) > 0 {
			dst.Credentials[i].ClaimSet = make([][]string, len(cred.ClaimSet))
			for j, cs := range cred.ClaimSet {
				dst.Credentials[i].ClaimSet[j] = append([]string{}, cs...)
			}
		}
	}

	// Copy credential sets
	for i, cs := range src.CredentialSets {
		dst.CredentialSets[i] = CredentialSetQuery{
			Options: make([][]string, len(cs.Options)),
		}
		if cs.Required != nil {
			v := *cs.Required
			dst.CredentialSets[i].Required = &v
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
