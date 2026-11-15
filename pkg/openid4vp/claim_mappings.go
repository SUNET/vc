package openid4vp

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"

	"github.com/SUNET/vc/pkg/claimpath"
)

// passThrough is the claim_mappings value, and the entry of the earlier
// release's map, that maps every claim under its own name.
const passThrough = "*"

// ClaimMappings maps the claims of the presented credentials to OIDC
// claims. YAML writes one of three forms:
//
//   - "*" maps every claim under its own name.
//   - A map from DCQL credential query id to a list of {path, claim}
//     entries maps each presentation through the entries of its query.
//   - The earlier release's map from dotted claim names to OIDC claims,
//     with "*": "*" for every claim, maps the claims of all presentations
//     merged in query id order, as that release did.
type ClaimMappings struct {
	form mappingForm
}

// ClaimMapping maps the claim at Path to the OIDC claim Claim.
type ClaimMapping struct {
	// Path is the claim of the presented credential.
	Path claimpath.Pointer `yaml:"path" json:"path"`
	// Claim is the OIDC claim.
	Claim string `yaml:"claim" json:"claim"`
}

// mappingForm is one form of claim mappings.
type mappingForm interface {
	// bind checks the form against the template's dcql.
	bind(dcql *DCQL) (boundForm, error)
	// value returns the form as YAML and JSON write it.
	value() any
}

// boundForm is a form checked against its template's dcql.
type boundForm interface {
	mapClaims(presentations []Presentation) (map[string]any, error)
}

// PassThroughMappings maps every claim under its own name.
func PassThroughMappings() ClaimMappings { return ClaimMappings{form: passThroughForm{}} }

// QueryMappings maps the claims of each presentation through the mappings
// of its DCQL credential query id.
func QueryMappings(byQuery map[string][]ClaimMapping) ClaimMappings {
	return ClaimMappings{form: queryForm(byQuery)}
}

// NameMappings maps claims by the earlier release's map from dotted claim
// names to OIDC claims.
func NameMappings(byName map[string]string) ClaimMappings {
	return ClaimMappings{form: nameForm(byName)}
}

// IsZero reports whether no form is set.
func (m ClaimMappings) IsZero() bool { return m.form == nil }

// ByName returns the earlier release's map, when the mappings are in that
// form.
func (m ClaimMappings) ByName() (map[string]string, bool) {
	byName, ok := m.form.(nameForm)
	return byName, ok
}

// Bind checks each key of the keyed form against the template's credential
// queries, and locates each path in the shape of its query's format.
func (m ClaimMappings) Bind(dcql *DCQL) (BoundClaimMappings, error) {
	if m.form == nil {
		return BoundClaimMappings{}, nil
	}
	bound, err := m.form.bind(dcql)
	if err != nil {
		return BoundClaimMappings{}, fmt.Errorf("claim_mappings: %w", err)
	}
	return BoundClaimMappings{form: bound}, nil
}

// UnmarshalYAML reads "*", the keyed form, or the earlier release's map. A
// map whose values are all strings is the earlier release's map, and a map
// whose values are all lists is the keyed form.
func (m *ClaimMappings) UnmarshalYAML(unmarshal func(any) error) error {
	var scalar string
	if err := unmarshal(&scalar); err == nil {
		if scalar != passThrough {
			return fmt.Errorf("claim_mappings is %q or a map, not %q", passThrough, scalar)
		}
		*m = PassThroughMappings()
		return nil
	}
	var raw map[string]any
	if err := unmarshal(&raw); err != nil {
		return fmt.Errorf("claim_mappings is %q or a map from credential query id to a list of {path, claim} entries: %w", passThrough, err)
	}
	names, lists := 0, 0
	for _, value := range raw {
		switch value.(type) {
		case []any:
			lists++
		case map[any]any, map[string]any:
		default:
			names++
		}
	}
	switch {
	case names == len(raw):
		var byName map[string]string
		if err := unmarshal(&byName); err != nil {
			return err
		}
		*m = NameMappings(byName)
	case lists == len(raw):
		var byQuery map[string][]ClaimMapping
		if err := unmarshal(&byQuery); err != nil {
			return err
		}
		*m = QueryMappings(byQuery)
	default:
		return errors.New("claim_mappings mixes the map from credential query id to a list of {path, claim} entries with the map from dotted claim names to OIDC claims; write one form")
	}
	return nil
}

// MarshalYAML writes the form.
func (m ClaimMappings) MarshalYAML() (any, error) {
	if m.form == nil {
		return nil, nil
	}
	return m.form.value(), nil
}

// MarshalJSON writes the form.
func (m ClaimMappings) MarshalJSON() ([]byte, error) {
	if m.form == nil {
		return []byte("null"), nil
	}
	return json.Marshal(m.form.value())
}

// BoundClaimMappings are claim mappings checked against their template's
// dcql.
type BoundClaimMappings struct {
	form boundForm
}

// IsZero reports whether the mappings map nothing.
func (b BoundClaimMappings) IsZero() bool { return b.form == nil }

// MapClaims maps the claims of the presentations of one vp_token to OIDC
// claims.
func (b BoundClaimMappings) MapClaims(presentations []Presentation) (map[string]any, error) {
	if b.form == nil {
		return nil, errors.New("claim mappings are empty")
	}
	return b.form.mapClaims(presentations)
}

// Presentation is one entry of a vp_token object (OpenID4VP 1.0 section
// 8.1).
type Presentation struct {
	// QueryID is the id of the DCQL credential query the presentation
	// answers, and empty for a vp_token that is one presentation.
	QueryID string
	// Shape is how Claims holds the claims of the presentation.
	Shape claimpath.Shape
	// Claims are the disclosed claims.
	Claims map[string]any
}

// mergedClaims merges the claims of presentations in order: a later claim
// replaces an earlier one, as the earlier release merged them.
func mergedClaims(presentations []Presentation) map[string]any {
	merged := make(map[string]any)
	for _, presentation := range presentations {
		maps.Copy(merged, presentation.Claims)
	}
	return merged
}

// passThroughForm maps every claim under its own name.
type passThroughForm struct{}

func (passThroughForm) bind(*DCQL) (boundForm, error) { return passThroughForm{}, nil }

func (passThroughForm) value() any { return passThrough }

func (passThroughForm) mapClaims(presentations []Presentation) (map[string]any, error) {
	return mapClaimsByName(mergedClaims(presentations), map[string]string{passThrough: passThrough})
}

// nameForm is the earlier release's map from dotted claim names to OIDC
// claims.
type nameForm map[string]string

func (f nameForm) bind(*DCQL) (boundForm, error) { return f, nil }

func (f nameForm) value() any { return map[string]string(f) }

func (f nameForm) mapClaims(presentations []Presentation) (map[string]any, error) {
	return mapClaimsByName(mergedClaims(presentations), f)
}

// queryForm maps the claims of each presentation through the mappings of
// its DCQL credential query id.
type queryForm map[string][]ClaimMapping

func (f queryForm) value() any { return map[string][]ClaimMapping(f) }

func (f queryForm) bind(dcql *DCQL) (boundForm, error) {
	if dcql == nil {
		return nil, errors.New("the template has no dcql whose credential queries the mappings name")
	}
	queries := make(map[string]CredentialQuery, len(dcql.Credentials))
	for _, query := range dcql.Credentials {
		queries[query.ID] = query
	}
	bound := make(boundQueryForm, len(dcql.Credentials))
	for _, query := range dcql.Credentials {
		bound[query.ID] = boundQuery{shape: PresentedShape(query.Format)}
	}
	for _, id := range slices.Sorted(maps.Keys(f)) {
		query, ok := queries[id]
		if !ok {
			return nil, fmt.Errorf("%s names no credential query of the dcql", id)
		}
		shape := PresentedShape(query.Format)
		for i, mapping := range f[id] {
			if mapping.Claim == "" {
				return nil, fmt.Errorf("%s[%d]: claim is empty", id, i)
			}
			if _, err := shape.LocateOne(mapping.Path); err != nil {
				return nil, fmt.Errorf("%s[%d].path: %w", id, i, err)
			}
		}
		bound[id] = boundQuery{shape: shape, mappings: f[id]}
	}
	return bound, nil
}

// boundQuery is the shape of one credential query's presentations and the
// mappings of its claims.
type boundQuery struct {
	shape    claimpath.Shape
	mappings []ClaimMapping
}

// boundQueryForm holds each credential query of the dcql, by id.
type boundQueryForm map[string]boundQuery

func (f boundQueryForm) mapClaims(presentations []Presentation) (map[string]any, error) {
	oidcClaims := make(map[string]any)
	for _, presentation := range presentations {
		if presentation.QueryID == "" {
			return nil, errors.New("the vp_token is no object keyed by credential query ids, which the claim mappings name")
		}
		query, ok := f[presentation.QueryID]
		if !ok {
			return nil, fmt.Errorf("the vp_token answers credential query %q, which the template does not request", presentation.QueryID)
		}
		if !presentation.Shape.Equal(query.shape) {
			return nil, fmt.Errorf("the presentation for credential query %q is in another format than the query requests", presentation.QueryID)
		}
		for _, mapping := range query.mappings {
			if err := mapClaim(oidcClaims, query.shape, presentation, mapping); err != nil {
				return nil, err
			}
		}
	}
	return oidcClaims, nil
}

// mapClaim maps one claim of a presentation into oidcClaims. A claim the
// presentation does not carry is left out. Two different values for one
// OIDC claim are refused.
func mapClaim(oidcClaims map[string]any, shape claimpath.Shape, presentation Presentation, mapping ClaimMapping) error {
	value, present, err := shape.Get(presentation.Claims, mapping.Path)
	if errors.Is(err, claimpath.ErrMismatch) {
		// A claim the presentation holds in another structure is a claim
		// it does not carry where the mapping reads it.
		return nil
	}
	if err != nil {
		return fmt.Errorf("claim mapping %s of credential query %q: %w", mapping.Path, presentation.QueryID, err)
	}
	if !present {
		return nil
	}
	if existing, ok := oidcClaims[mapping.Claim]; ok && !reflect.DeepEqual(existing, value) {
		return fmt.Errorf("the presentations hold two different values for the OIDC claim %q", mapping.Claim)
	}
	oidcClaims[mapping.Claim] = value
	return nil
}
