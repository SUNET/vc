package openid4vp

import (
	"errors"
	"fmt"

	"github.com/SUNET/vc/pkg/claimpath"
)

// passThrough is the claim_mappings value, and the legacy mapping entry,
// that maps every claim under its own name.
const passThrough = "*"

// ClaimMappings maps claims of the presented credentials to OIDC claims.
//
// YAML writes it as a list of {path, claim} entries, or as "*" to map
// every claim under its own name. The legacy mapping form {claim: OIDC
// claim} is read too, with the entry "*": "*" for every claim.
type ClaimMappings struct {
	// PassThrough maps every claim under its own name. It takes the place
	// of Mappings.
	PassThrough bool
	// Mappings maps one claim each.
	Mappings []ClaimMapping
	// shape holds the presented claims; Resolve sets it.
	shape claimpath.Shape
}

// ClaimMapping maps the claim at Path to the OIDC claim Claim.
type ClaimMapping struct {
	// Path is the claim of the presented credential.
	Path claimpath.Pointer `yaml:"path" json:"path"`
	// Claim is the OIDC claim.
	Claim string `yaml:"claim" json:"claim"`
}

// UnmarshalYAML reads "*", the list, or the legacy mapping form.
func (m *ClaimMappings) UnmarshalYAML(unmarshal func(any) error) error {
	var scalar string
	if err := unmarshal(&scalar); err == nil {
		if scalar != passThrough {
			return fmt.Errorf("claim_mappings is a list of {path, claim} entries or %q, not %q", passThrough, scalar)
		}
		*m = ClaimMappings{PassThrough: true}
		return nil
	}
	var entries []ClaimMapping
	if err := claimpath.DecodeList(unmarshal, &entries, func(path claimpath.Pointer, claim string) (ClaimMapping, error) {
		return ClaimMapping{Path: path, Claim: claim}, nil
	}); err != nil {
		return err
	}
	*m = ClaimMappings{}
	for _, entry := range entries {
		if dotted, pending := entry.Path.Pending(); pending && dotted == passThrough && entry.Claim == passThrough {
			m.PassThrough = true
			continue
		}
		m.Mappings = append(m.Mappings, entry)
	}
	return nil
}

// MarshalYAML writes "*" or the list.
func (m ClaimMappings) MarshalYAML() (any, error) {
	if m.PassThrough {
		return passThrough, nil
	}
	return m.Mappings, nil
}

// Resolve reads the dotted claims of the mappings in the shape the
// presented claims are held in, and keeps the shape for MapClaims.
func (m *ClaimMappings) Resolve(shape claimpath.Shape) error {
	for i := range m.Mappings {
		if err := shape.ResolveOne(&m.Mappings[i].Path); err != nil {
			return fmt.Errorf("claim_mappings[%d].path: %w", i, err)
		}
	}
	m.shape = shape
	return nil
}

// IsZero reports whether the mappings map nothing.
func (m ClaimMappings) IsZero() bool {
	return !m.PassThrough && len(m.Mappings) == 0
}

// passThroughClaims returns every claim under its own name, without the
// internal SD-JWT claims.
func passThroughClaims(vpClaims map[string]any) map[string]any {
	oidcClaims := make(map[string]any, len(vpClaims))
	for key, value := range vpClaims {
		if !isInternalClaim(key) {
			oidcClaims[key] = value
		}
	}
	return oidcClaims
}

// MapClaims maps the claims of a presentation to OIDC claims. A mapped
// claim the presentation does not carry is left out.
func (m ClaimMappings) MapClaims(vpClaims map[string]any) (map[string]any, error) {
	if m.PassThrough {
		return passThroughClaims(vpClaims), nil
	}
	oidcClaims := make(map[string]any)
	for _, mapping := range m.Mappings {
		value, present, err := m.shape.Get(vpClaims, mapping.Path)
		if errors.Is(err, claimpath.ErrMismatch) {
			// A claim the presentation holds in another structure is a
			// claim it does not carry where the mapping reads it.
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("claim mapping %s: %w", mapping.Path, err)
		}
		if present {
			oidcClaims[mapping.Claim] = value
		}
	}
	return oidcClaims, nil
}
