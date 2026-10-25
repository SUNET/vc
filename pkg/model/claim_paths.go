package model

import (
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/credential/primitives"
)

// ResolveClaimPaths reads every dotted claim of the apigw configuration as
// a claims path pointer, by the credential the claim belongs to, and checks
// each claim against the shape that holds it.
//
//   - A claim of a presented credential: an mdoc claim splits at its last
//     dot into [namespace, element], and a name without one is an element
//     of org.iso.18013.5.1. A JSON-based claim splits on dots.
//   - A claim of the issued credential's document: a JSON-based claim
//     splits on dots. An mdoc claim is the element the MDDL declares in one
//     namespace, or a document key the MDDL does not declare.
//   - An auth provider's attribute mapping writes a JSON object, so its
//     claims split on dots.
//
// A derivation reads its source data and writes the issued document; see
// primitives.ResolveDerivations. The credential metadata schemas must be
// loaded.
func (c *Cfg) ResolveClaimPaths() error {
	if c.APIGW == nil {
		return nil
	}
	if err := resolveAttributeMapping(c.APIGW.AuthProviders.SAML.AttributeMapping, claimpath.Nested()); err != nil {
		return fmt.Errorf("apigw.auth_providers.saml.attribute_mapping.%w", err)
	}
	if err := resolveAttributeMapping(c.APIGW.AuthProviders.OIDC.AttributeMapping, claimpath.Nested()); err != nil {
		return fmt.Errorf("apigw.auth_providers.oidc.attribute_mapping.%w", err)
	}
	ds := &c.APIGW.DataSources
	for _, resolve := range []func(*Cfg, *DataSources) error{resolveDatastore, resolveAssertion, resolveExternalAPI, resolvePresentation} {
		if err := resolve(c, ds); err != nil {
			return err
		}
	}
	return nil
}

// DocumentShape returns how the document data of the scope's credential
// holds its claims.
func (c *Cfg) DocumentShape(scope string) (claimpath.Shape, error) {
	meta := c.GetCredentialMetadata(scope)
	if meta == nil {
		return claimpath.Shape{}, fmt.Errorf("scope %q has no credential_metadata", scope)
	}
	return meta.DocumentShape()
}

// PresentedShape returns how the verified claims of a presented credential
// of the scope are held.
func (c *Cfg) PresentedShape(scope string) (claimpath.Shape, error) {
	meta := c.GetCredentialMetadata(scope)
	if meta == nil {
		return claimpath.Shape{}, fmt.Errorf("scope %q has no credential_metadata", scope)
	}
	return meta.PresentedShape(), nil
}

// DerivationShapes returns the shapes the derivations of a source scope
// read and write: the presented credential and the issued document for a
// presentation source, the issued document for the others.
func (c *Cfg) DerivationShapes(src SourceScope) (primitives.Shapes, error) {
	issued, err := c.DocumentShape(src.Scope)
	if err != nil {
		return primitives.Shapes{}, err
	}
	if src.Presented == "" {
		return primitives.Shapes{Source: issued, Issued: issued}, nil
	}
	presented, err := c.PresentedShape(src.Presented)
	if err != nil {
		return primitives.Shapes{}, err
	}
	return primitives.Shapes{Source: presented, Issued: issued}, nil
}

func resolveDatastore(c *Cfg, ds *DataSources) error {
	for _, scope := range slices.Sorted(maps.Keys(ds.Datastore.Scopes)) {
		where := fmt.Sprintf("apigw.data_sources.datastore.scopes.%s", scope)
		entries := ds.Datastore.Scopes[scope].AuthScopes
		for _, authScope := range slices.Sorted(maps.Keys(entries)) {
			entry := entries[authScope]
			if err := c.resolveAuthScope(&entry, scope, authScope); err != nil {
				return fmt.Errorf("%s.auth_scopes.%s.%w", where, authScope, err)
			}
			entries[authScope] = entry
		}
		if err := c.resolveDerivations(SourceScope{Source: DataSourceDatastore, Scope: scope, Derivations: ds.Datastore.Scopes[scope].Derivations}); err != nil {
			return fmt.Errorf("%s.%w", where, err)
		}
	}
	return nil
}

func resolveAssertion(c *Cfg, ds *DataSources) error {
	for _, scope := range slices.Sorted(maps.Keys(ds.Assertion.Scopes)) {
		where := fmt.Sprintf("apigw.data_sources.assertion.scopes.%s", scope)
		s := ds.Assertion.Scopes[scope]
		if err := c.resolveDefaults(s.Defaults, scope, s.ExpiryDuration); err != nil {
			return fmt.Errorf("%s.%w", where, err)
		}
		if err := c.resolveDerivations(SourceScope{Source: DataSourceAssertion, Scope: scope, Derivations: s.Derivations}); err != nil {
			return fmt.Errorf("%s.%w", where, err)
		}
	}
	return nil
}

func resolveExternalAPI(c *Cfg, ds *DataSources) error {
	for _, scope := range slices.Sorted(maps.Keys(ds.ExternalAPI.Scopes)) {
		where := fmt.Sprintf("apigw.data_sources.external_api.scopes.%s", scope)
		s := ds.ExternalAPI.Scopes[scope]
		if err := c.resolveScopeAttributeMapping(s.AttributeMapping, scope); err != nil {
			return fmt.Errorf("%s.attribute_mapping.%w", where, err)
		}
		if err := c.resolveDerivations(SourceScope{Source: DataSourceExternalAPI, Scope: scope, Derivations: s.Derivations}); err != nil {
			return fmt.Errorf("%s.%w", where, err)
		}
	}
	return nil
}

func resolvePresentation(c *Cfg, ds *DataSources) error {
	for _, scope := range slices.Sorted(maps.Keys(ds.Presentation.Scopes)) {
		where := fmt.Sprintf("apigw.data_sources.presentation.scopes.%s", scope)
		s := ds.Presentation.Scopes[scope]
		for _, presented := range slices.Sorted(maps.Keys(s.From)) {
			if err := c.resolvePresentedCredential(s.From[presented], scope, presented); err != nil {
				return fmt.Errorf("%s.from.%s.%w", where, presented, err)
			}
		}
		if err := c.resolveDefaults(s.Defaults, scope, s.ExpiryDuration); err != nil {
			return fmt.Errorf("%s.%w", where, err)
		}
	}
	return nil
}

// resolveAuthScope reads the claims of an auth scope: the auth claims,
// identity attributes and copy sources in the presented credential, and
// the copy targets in the issued document.
func (c *Cfg) resolveAuthScope(entry *AuthScopeEntry, scope, authScope string) error {
	if len(entry.AuthClaims) == 0 && len(entry.IdentityAttributes) == 0 && len(entry.DocumentClaims) == 0 {
		return nil
	}
	presented, err := c.PresentedShape(authScope)
	if err != nil {
		return err
	}
	if err := resolveIdentityClaims(entry, presented); err != nil {
		return err
	}
	if len(entry.DocumentClaims) == 0 {
		return nil
	}
	document, err := c.DocumentShape(scope)
	if err != nil {
		return err
	}
	for i := range entry.DocumentClaims {
		if err := resolveDocumentClaim(&entry.DocumentClaims[i], presented, document); err != nil {
			return fmt.Errorf("document_claims[%d].%w", i, err)
		}
	}
	return nil
}

// resolveIdentityClaims reads the auth claims and identity attribute
// renames in the presented credential, and requires each auth claim to
// name an identity attribute.
func resolveIdentityClaims(entry *AuthScopeEntry, presented claimpath.Shape) error {
	for i := range entry.AuthClaims {
		if err := presented.ResolveOne(&entry.AuthClaims[i]); err != nil {
			return fmt.Errorf("auth_claims[%d]: %w", i, err)
		}
	}
	for i := range entry.IdentityAttributes {
		if err := presented.ResolveOne(&entry.IdentityAttributes[i].Path); err != nil {
			return fmt.Errorf("identity_attributes[%d].path: %w", i, err)
		}
	}
	for i, claim := range entry.AuthClaims {
		if _, ok := entry.IdentityAttributes.For(claim); !ok {
			return fmt.Errorf("auth_claims[%d]: %s ends in no key, so it needs an identity_attributes entry", i, claim)
		}
	}
	return nil
}

// resolveDocumentClaim reads a copy's source in the presented credential
// and its target, one top-level document key, in the issued document.
func resolveDocumentClaim(claim *DocumentClaim, presented, document claimpath.Shape) error {
	if err := presented.ResolveOne(&claim.From); err != nil {
		return fmt.Errorf("from: %w", err)
	}
	if err := document.ResolveOne(&claim.To); err != nil {
		return fmt.Errorf("to: %w", err)
	}
	location, err := document.Locate(claim.To)
	if err != nil {
		return fmt.Errorf("to: %w", err)
	}
	if location.Len() != 1 {
		return fmt.Errorf("to: %s is no top-level claim of the issued document", claim.To)
	}
	return nil
}

// resolvePresentedCredential reads the required claims in the presented
// credential, and the derivations from it into the issued document.
func (c *Cfg) resolvePresentedCredential(accepted PresentedCredential, scope, presented string) error {
	if err := c.resolveRequiredClaims(accepted.RequiredClaims, presented); err != nil {
		return err
	}
	return c.resolveDerivations(SourceScope{Source: DataSourcePresentation, Scope: scope, Presented: presented, Derivations: accepted.Derivations})
}

// resolveRequiredClaims reads the required claims in the presented
// credential. A required claim may select every element of an array.
func (c *Cfg) resolveRequiredClaims(claims RequiredClaims, presented string) error {
	if len(claims) == 0 {
		return nil
	}
	shape, err := c.PresentedShape(presented)
	if err != nil {
		return err
	}
	for i := range claims {
		claim := &claims[i].Path
		if err := claim.Resolve(shape.Dotted); err != nil {
			return fmt.Errorf("required_claims[%d].path: %w", i, err)
		}
		if _, err := shape.Locate(*claim); err != nil {
			return fmt.Errorf("required_claims[%d].path: %w", i, err)
		}
	}
	return nil
}

// resolveDefaults reads the default claims in the issued document, and
// checks them against the claims MergeDefaults computes.
func (c *Cfg) resolveDefaults(defaults ClaimDefaults, scope, expiryDuration string) error {
	if len(defaults) == 0 {
		return nil
	}
	document, err := c.DocumentShape(scope)
	if err != nil {
		return err
	}
	for i := range defaults {
		if err := document.ResolveOne(&defaults[i].Path); err != nil {
			return fmt.Errorf("defaults[%d].path: %w", i, err)
		}
	}
	resolved, err := defaults.resolve(time.Time{}, expiryDuration, document)
	if err != nil {
		return fmt.Errorf("defaults: %w", err)
	}
	if err := resolved.CheckDistinct(); err != nil {
		return fmt.Errorf("defaults: %w", err)
	}
	return nil
}

func (c *Cfg) resolveDerivations(src SourceScope) error {
	if len(src.Derivations) == 0 {
		return nil
	}
	shapes, err := c.DerivationShapes(src)
	if err != nil {
		return err
	}
	return primitives.ResolveDerivations(src.Derivations, shapes)
}

// resolveScopeAttributeMapping reads the claims of an external API
// attribute mapping in the document of the scope's credential.
func (c *Cfg) resolveScopeAttributeMapping(mapping AttributeMapping, scope string) error {
	if len(mapping) == 0 {
		return nil
	}
	document, err := c.DocumentShape(scope)
	if err != nil {
		return err
	}
	return resolveAttributeMapping(mapping, document)
}

// resolveAttributeMapping reads the claim of each attribute in shape.
func resolveAttributeMapping(mapping AttributeMapping, shape claimpath.Shape) error {
	for _, attribute := range slices.Sorted(maps.Keys(mapping)) {
		config := mapping[attribute]
		if err := shape.ResolveOne(&config.Claim); err != nil {
			return fmt.Errorf("%s.claim: %w", attribute, err)
		}
		mapping[attribute] = config
	}
	return nil
}
