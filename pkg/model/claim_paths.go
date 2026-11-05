package model

import (
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/credential/primitives"
)

// CheckClaimPaths checks each claim of the apigw configuration against the
// shape of the credential the claim belongs to.
//
//   - A claim of a presented credential is located in its presented shape.
//   - A claim of the issued credential's document is located in the
//     document shape.
//   - An auth provider's attribute mapping writes a JSON object.
//
// A derivation reads its source data and writes the issued document; see
// primitives.CheckDerivations. The credential metadata schemas must be
// loaded.
func (c *Cfg) CheckClaimPaths() error {
	if c.APIGW == nil {
		return nil
	}
	if err := checkAttributeMapping(c.APIGW.AuthProviders.SAML.AttributeMapping, claimpath.Nested()); err != nil {
		return fmt.Errorf("apigw.auth_providers.saml.attribute_mapping.%w", err)
	}
	if err := checkAttributeMapping(c.APIGW.AuthProviders.OIDC.AttributeMapping, claimpath.Nested()); err != nil {
		return fmt.Errorf("apigw.auth_providers.oidc.attribute_mapping.%w", err)
	}
	ds := &c.APIGW.DataSources
	for _, check := range []func(*Cfg, *DataSources) error{checkDatastore, checkAssertion, checkExternalAPI, checkPresentation} {
		if err := check(c, ds); err != nil {
			return err
		}
	}
	return nil
}

// DocumentShape returns how the document data of the scope's credential
// holds its claims. A scope without credential_metadata holds them as a
// JSON object.
func (c *Cfg) DocumentShape(scope string) (claimpath.Shape, error) {
	meta := c.GetCredentialMetadata(scope)
	if meta == nil {
		return claimpath.Nested(), nil
	}
	return meta.DocumentShape()
}

// PresentedShape returns how the verified claims of a presented credential
// of the scope are held. A scope without credential_metadata holds them as
// a JSON object.
func (c *Cfg) PresentedShape(scope string) (claimpath.Shape, error) {
	meta := c.GetCredentialMetadata(scope)
	if meta == nil {
		return claimpath.Nested(), nil
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

func checkDatastore(c *Cfg, ds *DataSources) error {
	for _, scope := range slices.Sorted(maps.Keys(ds.Datastore.Scopes)) {
		where := fmt.Sprintf("apigw.data_sources.datastore.scopes.%s", scope)
		entries := ds.Datastore.Scopes[scope].AuthScopes
		for _, authScope := range slices.Sorted(maps.Keys(entries)) {
			if err := c.checkAuthScope(entries[authScope], scope, authScope); err != nil {
				return fmt.Errorf("%s.auth_scopes.%s.%w", where, authScope, err)
			}
		}
		if err := c.checkDerivations(SourceScope{Source: DataSourceDatastore, Scope: scope, Derivations: ds.Datastore.Scopes[scope].Derivations}); err != nil {
			return fmt.Errorf("%s.%w", where, err)
		}
	}
	return nil
}

func checkAssertion(c *Cfg, ds *DataSources) error {
	for _, scope := range slices.Sorted(maps.Keys(ds.Assertion.Scopes)) {
		where := fmt.Sprintf("apigw.data_sources.assertion.scopes.%s", scope)
		s := ds.Assertion.Scopes[scope]
		if err := c.checkDefaults(s.Defaults, scope, s.ExpiryDuration); err != nil {
			return fmt.Errorf("%s.%w", where, err)
		}
		if err := c.checkDerivations(SourceScope{Source: DataSourceAssertion, Scope: scope, Derivations: s.Derivations}); err != nil {
			return fmt.Errorf("%s.%w", where, err)
		}
	}
	return nil
}

func checkExternalAPI(c *Cfg, ds *DataSources) error {
	for _, scope := range slices.Sorted(maps.Keys(ds.ExternalAPI.Scopes)) {
		where := fmt.Sprintf("apigw.data_sources.external_api.scopes.%s", scope)
		s := ds.ExternalAPI.Scopes[scope]
		if err := c.checkScopeAttributeMapping(s.AttributeMapping, scope); err != nil {
			return fmt.Errorf("%s.attribute_mapping.%w", where, err)
		}
		if err := c.checkDerivations(SourceScope{Source: DataSourceExternalAPI, Scope: scope, Derivations: s.Derivations}); err != nil {
			return fmt.Errorf("%s.%w", where, err)
		}
	}
	return nil
}

func checkPresentation(c *Cfg, ds *DataSources) error {
	for _, scope := range slices.Sorted(maps.Keys(ds.Presentation.Scopes)) {
		where := fmt.Sprintf("apigw.data_sources.presentation.scopes.%s", scope)
		s := ds.Presentation.Scopes[scope]
		for _, presented := range slices.Sorted(maps.Keys(s.From)) {
			if err := c.checkPresentedCredential(s.From[presented], scope, presented); err != nil {
				return fmt.Errorf("%s.from.%s.%w", where, presented, err)
			}
		}
		if err := c.checkDefaults(s.Defaults, scope, s.ExpiryDuration); err != nil {
			return fmt.Errorf("%s.%w", where, err)
		}
	}
	return nil
}

// checkAuthScope locates the claims of an auth scope: the auth claims,
// identity attributes and copy sources in the presented credential, and
// the copy targets in the issued document.
func (c *Cfg) checkAuthScope(entry AuthScopeEntry, scope, authScope string) error {
	if len(entry.AuthClaims) == 0 && len(entry.IdentityAttributes) == 0 && len(entry.DocumentClaims) == 0 {
		return nil
	}
	presented, err := c.PresentedShape(authScope)
	if err != nil {
		return err
	}
	if err := checkIdentityClaims(entry, presented); err != nil {
		return err
	}
	if len(entry.DocumentClaims) == 0 {
		return nil
	}
	document, err := c.DocumentShape(scope)
	if err != nil {
		return err
	}
	for i, claim := range entry.DocumentClaims {
		if err := checkDocumentClaim(claim, presented, document); err != nil {
			return fmt.Errorf("document_claims[%d].%w", i, err)
		}
	}
	return nil
}

// checkIdentityClaims locates the auth claims and identity attribute
// renames in the presented credential.
func checkIdentityClaims(entry AuthScopeEntry, presented claimpath.Shape) error {
	for i, claim := range entry.AuthClaims {
		if _, err := presented.LocateOne(claim); err != nil {
			return fmt.Errorf("auth_claims[%d]: %w", i, err)
		}
	}
	for i, rename := range entry.IdentityAttributes {
		if _, err := presented.LocateOne(rename.Path); err != nil {
			return fmt.Errorf("identity_attributes[%d].path: %w", i, err)
		}
	}
	return nil
}

// checkDocumentClaim locates a copy's source in the presented credential
// and its target, one top-level document key, in the issued document.
func checkDocumentClaim(claim DocumentClaim, presented, document claimpath.Shape) error {
	if _, err := presented.LocateOne(claim.From); err != nil {
		return fmt.Errorf("from: %w", err)
	}
	location, err := document.LocateOne(claim.To)
	if err != nil {
		return fmt.Errorf("to: %w", err)
	}
	if location.Len() != 1 {
		return fmt.Errorf("to: %s is no top-level claim of the issued document", claim.To)
	}
	return nil
}

// checkPresentedCredential checks the required claims in the presented
// credential, and the derivations from it into the issued document.
func (c *Cfg) checkPresentedCredential(accepted PresentedCredential, scope, presented string) error {
	if err := c.checkRequiredClaims(accepted.RequiredClaims, presented); err != nil {
		return err
	}
	return c.checkDerivations(SourceScope{Source: DataSourcePresentation, Scope: scope, Presented: presented, Derivations: accepted.Derivations})
}

// checkRequiredClaims locates the required claims in the presented
// credential. A required claim may select every element of an array.
func (c *Cfg) checkRequiredClaims(claims RequiredClaims, presented string) error {
	if len(claims) == 0 {
		return nil
	}
	shape, err := c.PresentedShape(presented)
	if err != nil {
		return err
	}
	for i, claim := range claims {
		if _, err := shape.Locate(claim.Path); err != nil {
			return fmt.Errorf("required_claims[%d].path: %w", i, err)
		}
	}
	return nil
}

// checkDefaults locates the default claims in the issued document, and
// checks them against the claims MergeDefaults computes.
func (c *Cfg) checkDefaults(defaults ClaimDefaults, scope, expiryDuration string) error {
	if len(defaults) == 0 {
		return nil
	}
	document, err := c.DocumentShape(scope)
	if err != nil {
		return err
	}
	for i, claim := range defaults {
		if _, err := document.LocateOne(claim.Path); err != nil {
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

func (c *Cfg) checkDerivations(src SourceScope) error {
	if len(src.Derivations) == 0 {
		return nil
	}
	shapes, err := c.DerivationShapes(src)
	if err != nil {
		return err
	}
	return primitives.CheckDerivations(src.Derivations, shapes)
}

// checkScopeAttributeMapping locates the claims of an external API
// attribute mapping in the document of the scope's credential.
func (c *Cfg) checkScopeAttributeMapping(mapping AttributeMapping, scope string) error {
	if len(mapping) == 0 {
		return nil
	}
	document, err := c.DocumentShape(scope)
	if err != nil {
		return err
	}
	return checkAttributeMapping(mapping, document)
}

// checkAttributeMapping locates the claim of each attribute in shape.
func checkAttributeMapping(mapping AttributeMapping, shape claimpath.Shape) error {
	for _, attribute := range slices.Sorted(maps.Keys(mapping)) {
		if _, err := shape.LocateOne(mapping[attribute].Claim); err != nil {
			return fmt.Errorf("%s.claim: %w", attribute, err)
		}
	}
	return nil
}
