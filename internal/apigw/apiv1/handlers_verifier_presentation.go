package apiv1

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/credential"
	"github.com/SUNET/vc/pkg/credential/primitives"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
)

// finalisePresentationVerification stores the required claims from a
// presented credential onto authCtx.VerifiedClaims, records which accepted
// credential it is in authCtx.PresentedScope, and validates its per-claim
// allow-lists. The datastore lookup step is intentionally
// skipped: presentation-source credentials derive their whole document from
// the presented credential's own claims (see handlers_issuer.go's
// VCICredential presentation branch). A preview document is cached so the
// consent/preview UI (which calls UserLookup unconditionally) can render
// the credential-to-be-issued before final consent.
// Errors from here are classified the same way the rest of the
// issuance-auth pipeline classifies them: a credential that does not carry
// what was asked for is the wallet's, while a store that would not write
// or a deployment whose derivations do not resolve is ours and carries
// ErrIssuanceAuthServerFault. The Authorization Challenge Endpoint turns
// the two into different HTTP answers, and telling a wallet its
// presentation was rejected when the datastore was down invites a retry
// that cannot succeed.
func (c *Client) finalisePresentationVerification(ctx context.Context, authCtx *cache.AuthorizationContext, scope string, pScope model.PresentationScope, presentedScope string, presented map[string]any) error {
	accepted, ok := pScope.From[presentedScope]
	if !ok {
		return helpers.NewErrorDetailsWithStatus("presentation_scope_mismatch",
			fmt.Sprintf("a %q credential is not one this scope accepts", presentedScope),
			400)
	}
	// VPTokenValidator.validateAgainstDCQL is currently a no-op, so a
	// wallet could return a credential of the wrong type that happens to
	// carry the required claim keys. Enforce the presented type against
	// presentedScope before minting anything from it.
	if err := c.enforceScopeCredentialType(presentedScope, presented); err != nil {
		return err
	}

	// The format of presentedScope decides the shape the claims are read
	// in. SD-JWT VC nests a path under real objects, so a literal
	// top-level "identity.birthdate" key does NOT satisfy the required
	// path ["identity", "birthdate"] — otherwise a wallet could smuggle a
	// flat key in and have it accepted. mdoc keeps the opposite
	// convention: namespace-qualified claims live as one literal key
	// (e.g. "org.iso.18013.5.1.birth_date").
	shapes, err := c.cfg.DerivationShapes(model.SourceScope{Source: model.DataSourcePresentation, Scope: scope, Presented: presentedScope})
	if err != nil {
		return serverFault(err)
	}
	verified, err := verifiedClaims(shapes.Source, presented, accepted.RequiredClaims)
	if err != nil {
		return err
	}
	authCtx.VerifiedClaims = verified
	authCtx.PresentedScope = presentedScope
	if err := c.cacheService.AuthContext.Update(ctx, authCtx); err != nil {
		return serverFault(fmt.Errorf("failed to persist verified claims: %w", err))
	}

	// Cache a preview document keyed by session so UserLookup (called by the
	// consent flow before VCICredential runs) has something to render. The
	// authoritative document is rebuilt from VerifiedClaims in VCICredential.
	// Mirror buildPresentationDocument's derivation + defaults steps so the
	// consent UI sees the same claims (e.g. age_over_*, over_*_this_year)
	// that will actually be issued — walking the target VCTM against only
	// the raw verified claims would otherwise render an empty preview.
	// Deep clone, not maps.Copy: MergeNestedClaims below writes INTO an
	// existing nested map, so a shallow copy shares e.g. the "identity"
	// sub-map with verified - and verified is authCtx.VerifiedClaims, which
	// was just persisted and which issuance rebuilds the real document from.
	// A derivation targeting a nested claim would otherwise write its result
	// into the holder's verified claims. buildPresentationDocument already
	// clones for the same reason.
	previewData := credential.CloneNestedClaims(verified)
	now := time.Now()
	derived, err := credential.ApplyDerivations(accepted.Derivations, verified, now, shapes)
	if err != nil {
		// Not every derivation failure is ours. A scope deriving age from
		// a required birthdate gets whatever the credential carried, and a
		// birthdate that is empty, malformed or in the future is the
		// Holder's data - it passes every check above and then fails here.
		// Reporting server_error for that tells the wallet to try again
		// when nothing it can do will help, and by this point the
		// auth_session has been consumed so there is nothing to try again
		// with. Anything else - a misconfigured derivation, a broken
		// primitive - really is ours.
		if errors.Is(err, primitives.ErrInvalidClaimInput) {
			return fmt.Errorf("the presented claims cannot satisfy this scope: %w", err)
		}
		return serverFault(fmt.Errorf("failed to apply derivations for preview: %w", err))
	}
	credential.MergeNestedClaims(previewData, derived)
	if err := pScope.MergeDefaults(previewData, now, shapes.Issued); err != nil {
		return serverFault(fmt.Errorf("failed to merge defaults for preview: %w", err))
	}

	previewDoc := &model.CompleteDocument{
		Meta: &model.MetaData{
			AuthenticSource: presentedScope,
		},
		DocumentData: previewData,
	}
	c.cacheService.Document.Set(ctx, authCtx.SessionID, map[string]*model.CompleteDocument{
		presentedScope: previewDoc,
	})
	return nil
}

// verifiedClaims returns the required claims of a presented credential,
// each checked against its allow-list, in the shape the presented
// credential used.
func verifiedClaims(shape claimpath.Shape, presented map[string]any, required model.RequiredClaims) (map[string]any, error) {
	verified := make(map[string]any, len(required))
	for _, claim := range required {
		if err := verifyRequiredClaim(shape, presented, claim); err != nil {
			return nil, err
		}
		if err := copyPresentedClaim(shape, verified, presented, claim.Path); err != nil {
			return nil, serverFault(err)
		}
	}
	return verified, nil
}

// verifyRequiredClaim refuses a presentation that does not carry a required
// claim, or none of whose values is in the claim's allow-list.
func verifyRequiredClaim(shape claimpath.Shape, presented map[string]any, claim model.RequiredClaim) error {
	values, err := shape.Select(presented, claim.Path)
	if errors.Is(err, claimpath.ErrNoClaim) || errors.Is(err, claimpath.ErrMismatch) {
		return helpers.NewErrorDetailsWithStatus("missing_required_claim",
			fmt.Sprintf("claim %s not present on presented credential", claim.Path),
			400)
	}
	if err != nil {
		return serverFault(err)
	}
	if len(claim.Values) > 0 && !slices.ContainsFunc(values, func(v any) bool { return claimValueMatches(v, claim.Values) }) {
		return helpers.NewErrorDetailsWithStatus("claim_value_not_allowed",
			fmt.Sprintf("claim %s value not in allow-list", claim.Path),
			403)
	}
	return nil
}

// copyPresentedClaim copies the claim at path, up to its first null or
// index, from presented into verified, in the same shape. The downstream
// VCTM filter (which walks nested maps) then sees it under the shape the
// presented credential used, and a claim's array keeps its positions.
func copyPresentedClaim(shape claimpath.Shape, verified, presented map[string]any, path claimpath.Pointer) error {
	keys, ok := path.KeyPrefix()
	if !ok {
		return fmt.Errorf("claim %s starts with no key", path)
	}
	value, present, err := shape.Get(presented, keys)
	if err != nil {
		return fmt.Errorf("claim %s: %w", path, err)
	}
	if !present {
		return fmt.Errorf("claim %s: the presentation holds no claim at %s", path, keys)
	}
	return shape.Set(verified, keys, value)
}

// isMDocLikeFormat returns true for every DCQL mdoc format variant whose
// claims are stored as namespace-qualified literal keys. Keeping ZK
// alongside plain mdoc here matches claims_extractor's own
// mdocClaimsFromResult / zk_verifier flattening conventions and
// openid4vp.PresentedShape.
func isMDocLikeFormat(format string) bool {
	return format == openid4vp.FormatMsoMdoc || format == openid4vp.FormatMsoMdocZk
}

// enforceScopeCredentialType refuses a presented credential whose type does
// not match the credential_metadata for the given scope. For SD-JWT VC the
// top-level `vct` claim carries the canonical type identifier and is
// compared against the configured credential metadata's vct. For mso_mdoc
// the doctype (surfaced as a synthetic top-level `docType` claim by
// extractMDocClaimsFromToken) is compared against the configured MDDL
// doctype (falling back to the scope's `doctype` field).
func (c *Client) enforceScopeCredentialType(scope string, presented map[string]any) error {
	meta := c.cfg.GetCredentialMetadata(scope)
	if meta == nil {
		return helpers.NewErrorDetailsWithStatus("presentation_scope_misconfigured",
			fmt.Sprintf("scope %q has no credential_metadata entry", scope),
			500)
	}
	switch {
	case isSDJWTFormat(meta.Format):
		return c.enforceSDJWTType(scope, meta, presented)
	case isMDocFormat(meta.Format):
		return c.enforceMDocType(scope, meta, presented)
	case meta.Format == openid4vp.FormatMsoMdocZk:
		// openid4vp.PresentedShape already reads mso_mdoc_zk claims, but
		// the dispatch below (VPTokenValidator and
		// MDocHandler.VerifyAndExtractBound) has no ZK path yet. Rather
		// than advertise partial support that fails later with a
		// confusing error, refuse the configuration here.
		return helpers.NewErrorDetailsWithStatus("presentation_scope_unsupported_format",
			fmt.Sprintf("scope %q uses mso_mdoc_zk, which a presentation scope cannot accept; use the ZK verifier directly", scope),
			500)
	default:
		return helpers.NewErrorDetailsWithStatus("presentation_scope_misconfigured",
			fmt.Sprintf("scope %q has unsupported format %q for presentation type enforcement", scope, meta.Format),
			500)
	}
}

func (c *Client) enforceSDJWTType(scope string, meta *model.CredentialMetadata, presented map[string]any) error {
	vctRaw, ok := presented["vct"]
	if !ok {
		return helpers.NewErrorDetailsWithStatus("presentation_type_unverifiable",
			fmt.Sprintf("presented credential carries no vct; cannot enforce scope %q", scope),
			400)
	}
	vct, ok := vctRaw.(string)
	if !ok || vct == "" {
		return helpers.NewErrorDetailsWithStatus("presentation_type_unverifiable",
			"presented credential vct is not a non-empty string",
			400)
	}
	expected := ""
	if vctm := meta.GetVCTM(); vctm != nil {
		expected = vctm.VCT
	}
	if expected == "" {
		expected = meta.GetVCTURL()
	}
	if expected == "" {
		return helpers.NewErrorDetailsWithStatus("presentation_scope_misconfigured",
			fmt.Sprintf("scope %q has no canonical vct", scope),
			500)
	}
	if vct != expected {
		return helpers.NewErrorDetailsWithStatus("presentation_type_mismatch",
			fmt.Sprintf("presented credential vct %q does not match scope %q (expected %q)", vct, scope, expected),
			403)
	}
	return nil
}

func (c *Client) enforceMDocType(scope string, meta *model.CredentialMetadata, presented map[string]any) error {
	docTypeRaw, ok := presented["docType"]
	if !ok {
		return helpers.NewErrorDetailsWithStatus("presentation_type_unverifiable",
			fmt.Sprintf("presented credential carries no docType; cannot enforce scope %q", scope),
			400)
	}
	docType, ok := docTypeRaw.(string)
	if !ok || docType == "" {
		return helpers.NewErrorDetailsWithStatus("presentation_type_unverifiable",
			"presented credential docType is not a non-empty string",
			400)
	}
	expected := ""
	if mddl := meta.GetMDDL(); mddl != nil && mddl.DocType != "" {
		expected = mddl.DocType
	}
	if expected == "" {
		expected = meta.Doctype
	}
	if expected == "" {
		return helpers.NewErrorDetailsWithStatus("presentation_scope_misconfigured",
			fmt.Sprintf("scope %q has no canonical doctype", scope),
			500)
	}
	if docType != expected {
		return helpers.NewErrorDetailsWithStatus("presentation_type_mismatch",
			fmt.Sprintf("presented credential docType %q does not match scope %q (expected %q)", docType, scope, expected),
			403)
	}
	return nil
}

func isSDJWTFormat(format string) bool {
	return format == "dc+sd-jwt" || format == "vc+sd-jwt"
}

// isMDocFormat intentionally matches only plain mso_mdoc. mso_mdoc_zk is
// handled on a separate branch of enforceScopeCredentialType with a clear
// unsupported-format error, since the ZK presentation path (zkDocuments +
// native proof verification) is not wired into this handler and silently
// treating it as plain mdoc would route a valid ZK presentation to
// MDocHandler, which only decodes DeviceResponse.Documents.
func isMDocFormat(format string) bool {
	return format == openid4vp.FormatMsoMdoc
}

// mdocClaimsFromResult flattens an MDocHandler result into the claim map
// shape enforceMDocType and finalisePresentationVerification expect:
// namespace-qualified keys, unqualified keys for the primary ISO namespace,
// and a synthetic top-level `docType`. Mixed doctypes are rejected because
// downstream enforcement compares a single expected doctype against the map.
func mdocClaimsFromResult(result *mdoc.MDocVerificationResult) (map[string]any, error) {
	if result == nil || len(result.Documents) == 0 {
		return nil, errors.New("mdoc verification produced no documents")
	}
	if len(result.Documents) > 1 {
		types := make([]string, 0, len(result.Documents))
		for dt := range result.Documents {
			types = append(types, dt)
		}
		return nil, fmt.Errorf("mdoc DeviceResponse contains multiple docTypes (%v); refuse rather than merge", types)
	}
	claims := make(map[string]any)
	var synthDocType string
	for docType, doc := range result.Documents {
		synthDocType = docType
		for ns, items := range doc.Namespaces {
			for k, v := range items {
				claims[fmt.Sprintf("%s.%s", ns, k)] = v
				if ns == mdoc.Namespace {
					claims[k] = v
				}
			}
		}
	}
	// Assign the synthetic doctype AFTER namespace flattening so a mdoc
	// element literally named "docType" in the primary namespace cannot
	// overwrite the canonical document type that enforceMDocType compares.
	claims["docType"] = synthDocType
	return claims, nil
}

// claimValueMatches returns true if val (a scalar string or a list of them)
// contains at least one entry that appears in the allow-list.
func claimValueMatches(val any, allowed []string) bool {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		allowedSet[a] = struct{}{}
	}
	switch v := val.(type) {
	case string:
		_, ok := allowedSet[v]
		return ok
	case []string:
		for _, s := range v {
			if _, ok := allowedSet[s]; ok {
				return true
			}
		}
	case []any:
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				continue
			}
			if _, ok := allowedSet[s]; ok {
				return true
			}
		}
	}
	return false
}
