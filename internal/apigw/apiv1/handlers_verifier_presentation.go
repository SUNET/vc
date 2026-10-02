package apiv1

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
)

// finalisePresentationVerification stores the required claims from a
// presented credential onto authCtx.VerifiedClaims and validates the
// scope's per-claim allow-lists. The datastore lookup step is intentionally
// skipped: presentation-source credentials derive their whole document from
// the presented credential's own claims (see handlers_issuer.go's
// VCICredential presentation branch). A preview document is cached so the
// consent/preview UI (which calls UserLookup unconditionally) can render
// the credential-to-be-issued before final consent.
func (c *Client) finalisePresentationVerification(ctx context.Context, authCtx *cache.AuthorizationContext, pScope model.PresentationScope, presented map[string]any) error {
	// VPTokenValidator.validateAgainstDCQL is currently a no-op, so a
	// wallet could return a credential of the wrong type that happens to
	// carry the required claim keys. Enforce the presented type against
	// pScope.FromScope before minting anything from it.
	if err := c.enforceFromScopeType(pScope, presented); err != nil {
		return err
	}

	// Format of pScope.FromScope decides what counts as a valid claim
	// shape. SD-JWT VC nests dotted paths under real objects, so a literal
	// top-level "identity.birthdate" key must NOT satisfy the required
	// nested path "identity.birthdate" — otherwise a wallet could smuggle
	// a flat key in and have it accepted. mdoc keeps the opposite
	// convention: namespace-qualified claims live as one literal dotted
	// key (e.g. "org.iso.18013.5.1.birth_date"), so literal lookup is the
	// only one that works.
	sourceFormat := c.cfg.GetFormatForScope(pScope.FromScope)
	verified := make(map[string]any, len(pScope.RequiredClaims))
	for claim, allowed := range pScope.RequiredClaims {
		val, present := lookupClaimPath(sourceFormat, presented, claim)
		if !present {
			return helpers.NewErrorDetailsWithStatus("missing_required_claim",
				fmt.Sprintf("claim %q not present on presented credential", claim),
				400)
		}
		if len(allowed) > 0 && !claimValueMatches(val, allowed) {
			return helpers.NewErrorDetailsWithStatus("claim_value_not_allowed",
				fmt.Sprintf("claim %q value not in allow-list", claim),
				403)
		}
		// Materialise dotted claim paths as nested map structures so the
		// downstream VCTM filter (which walks nested maps) can see them
		// under the same shape the presented credential used. mdoc keeps
		// its namespace-qualified literal key; SD-JWT always nests.
		setClaimPath(sourceFormat, verified, presented, claim, val)
	}
	authCtx.VerifiedClaims = verified
	if err := c.cacheService.AuthContext.Update(ctx, authCtx); err != nil {
		return fmt.Errorf("failed to persist verified claims: %w", err)
	}

	// Cache a preview document keyed by session so UserLookup (called by the
	// consent flow before VCICredential runs) has something to render. The
	// authoritative document is rebuilt from VerifiedClaims in VCICredential.
	previewDoc := &model.CompleteDocument{
		Meta: &model.MetaData{
			AuthenticSource: pScope.FromScope,
		},
		DocumentData: verified,
	}
	c.cacheService.Document.Set(ctx, authCtx.SessionID, map[string]*model.CompleteDocument{
		pScope.FromScope: previewDoc,
	})
	return nil
}

// lookupClaimPath resolves a claim path against a nested claims map in a
// format-aware way. For mdoc formats (plain or ZK) a literal-key match is
// tried first so namespace-qualified keys stored as one flat
// "org.iso.18013.5.1.birth_date" entry resolve to their value, then the
// path falls back to splitting on "." and walking nested maps. For
// SD-JWT VC the literal fallback is intentionally skipped so a flat
// "identity.birthdate" key on the presented credential cannot satisfy a
// nested path "identity.birthdate" the scope required. Returns the value
// and true when the path resolves; false when any intermediate segment is
// missing or is not a map.
func lookupClaimPath(sourceFormat string, claims map[string]any, path string) (any, bool) {
	if isMDocLikeFormat(sourceFormat) {
		if v, ok := claims[path]; ok {
			return v, true
		}
	}
	if !strings.Contains(path, ".") {
		if v, ok := claims[path]; ok {
			return v, true
		}
		return nil, false
	}
	segments := strings.Split(path, ".")
	var cur any = claims
	for _, seg := range segments {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		v, present := m[seg]
		if !present {
			return nil, false
		}
		cur = v
	}
	return cur, true
}

// setClaimPath writes val at a claim path in dst, mirroring how the path
// resolved on src in a format-aware way: for mdoc, when src carries the
// path as a flat literal key (e.g. "org.iso.18013.5.1.birth_date") it is
// stored literally; otherwise the path is split on "." and intermediate
// maps are created as needed so multiple required claims sharing a prefix
// (e.g. "identity.given_name" and "identity.family_name") produce a single
// nested object rather than overwriting siblings. For SD-JWT the literal
// shortcut is intentionally skipped so flat dotted keys never leak into
// the issued document.
func setClaimPath(sourceFormat string, dst, src map[string]any, path string, val any) {
	if isMDocLikeFormat(sourceFormat) {
		if _, ok := src[path]; ok {
			dst[path] = val
			return
		}
	}
	if !strings.Contains(path, ".") {
		dst[path] = val
		return
	}
	segments := strings.Split(path, ".")
	cur := dst
	for _, seg := range segments[:len(segments)-1] {
		next, ok := cur[seg].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[seg] = next
		}
		cur = next
	}
	cur[segments[len(segments)-1]] = val
}

// isMDocLikeFormat returns true for every DCQL mdoc format variant whose
// claims are stored as namespace-qualified literal keys. Keeping ZK
// alongside plain mdoc here matches claims_extractor's own
// mdocClaimsFromResult / zk_verifier flattening conventions and matches
// authClaimPathSegments' DCQL-side treatment of both formats.
func isMDocLikeFormat(format string) bool {
	return format == openid4vp.FormatMsoMdoc || format == openid4vp.FormatMsoMdocZk
}

// enforceFromScopeType refuses a presented credential whose type does not
// match pScope.FromScope. Delegates to enforceScopeCredentialType keyed by
// FromScope.
func (c *Client) enforceFromScopeType(pScope model.PresentationScope, presented map[string]any) error {
	return c.enforceScopeCredentialType(pScope.FromScope, presented)
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
		// authClaimPathSegments already produces DCQL paths for
		// mso_mdoc_zk, but the dispatch below (VPTokenValidator and
		// MDocHandler.VerifyAndExtractBound) has no ZK path yet. Rather
		// than advertise partial support that fails later with a
		// confusing error, refuse the configuration here.
		return helpers.NewErrorDetailsWithStatus("presentation_scope_unsupported_format",
			fmt.Sprintf("scope %q uses mso_mdoc_zk, which is not supported as a presentation from_scope; use the ZK verifier directly", scope),
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
	for docType, doc := range result.Documents {
		claims["docType"] = docType
		for ns, items := range doc.Namespaces {
			for k, v := range items {
				claims[fmt.Sprintf("%s.%s", ns, k)] = v
				if ns == mdoc.Namespace {
					claims[k] = v
				}
			}
		}
	}
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
