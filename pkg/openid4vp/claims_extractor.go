package openid4vp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/sdjwtvc"
	"github.com/SUNET/vc/pkg/vc20/credential"

	"github.com/fxamacker/cbor/v2"
	"github.com/piprate/json-gold/ld"
)

// ClaimsExtractor extracts and maps claims from VP tokens to OIDC claims
type ClaimsExtractor struct {
	// templates holds the presentation request templates for claim mapping
	templates map[string]*presentationRequestTemplate
}

// presentationRequestTemplate is an internal interface for accessing template data
type presentationRequestTemplate interface {
	GetID() string
	GetOIDCScopes() []string
	GetClaimMappings() map[string]string
	GetClaimTransforms() map[string]any
}

// NewClaimsExtractor creates a new claims extractor
func NewClaimsExtractor() *ClaimsExtractor {
	return &ClaimsExtractor{
		templates: make(map[string]*presentationRequestTemplate),
	}
}

// ExtractClaimsFromVPToken extracts claims from a VP token.
// Automatically detects the format:
//   - DCQL response: JSON object mapping credential query IDs to individual tokens
//   - W3C VC 2.0: a JSON-LD credential or presentation
//   - mdoc: CBOR-based mobile document
//   - SD-JWT: dot-separated JWT with selective disclosures
//
// Returns a merged map of disclosed claims from all credentials.
func (ce *ClaimsExtractor) ExtractClaimsFromVPToken(ctx context.Context, vpToken string) (map[string]any, error) {
	if vpToken == "" {
		return nil, fmt.Errorf("VP token is empty")
	}

	// A leading '{' is not enough to say "DCQL response": a W3C VC 2.0
	// credential or presentation is also a JSON object, and routing one to
	// the DCQL parser failed it as "cannot parse as map[string][]string".
	// That is how W3C scopes came to work on the UI direct-post path and
	// not on the OIDC one, which extracts claims through here.
	// A leading '[' is expanded JSON-LD, which detectCredentialFormat
	// accepts as a W3C credential - it falls through to
	// extractClaimsFromSingleToken below, which handles both JSON shapes.
	trimmed := strings.TrimSpace(vpToken)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		if isW3CDocument(trimmed) {
			return extractW3CClaims(trimmed)
		}
		return ce.extractClaimsFromDCQLResponse(ctx, trimmed)
	}

	return ce.extractClaimsFromSingleToken(vpToken)
}

// extractClaimsFromDCQLResponse parses a DCQL vp_token response where the value
// is a JSON object mapping credential query IDs to arrays of VP token strings
// (per OID4VP §6.3). Claims from all credentials are merged into a single map;
// credential query IDs are processed in sorted order for deterministic output.
func (ce *ClaimsExtractor) extractClaimsFromDCQLResponse(ctx context.Context, vpToken string) (map[string]any, error) {
	var dcqlResponse map[string][]string
	if err := json.Unmarshal([]byte(vpToken), &dcqlResponse); err != nil {
		return nil, fmt.Errorf("failed to parse DCQL vp_token as map[string][]string: %w", err)
	}

	if len(dcqlResponse) == 0 {
		return nil, fmt.Errorf("DCQL vp_token contains no credentials")
	}

	merged := make(map[string]any)
	credIDs := make([]string, 0, len(dcqlResponse))
	for credID := range dcqlResponse {
		credIDs = append(credIDs, credID)
	}
	slices.Sort(credIDs)
	for _, credID := range credIDs {
		tokens := dcqlResponse[credID]
		if len(tokens) == 0 {
			return nil, fmt.Errorf("DCQL vp_token contains empty array for credential %q", credID)
		}
		for _, token := range tokens {
			claims, err := ce.extractClaimsFromSingleToken(token)
			if err != nil {
				return nil, fmt.Errorf("failed to extract claims from credential %q: %w", credID, err)
			}
			maps.Copy(merged, claims)
		}
	}

	return merged, nil
}

// extractClaimsFromSingleToken extracts claims from a single VP token
// (W3C JSON-LD, SD-JWT or mdoc).
func (ce *ClaimsExtractor) extractClaimsFromSingleToken(vpToken string) (map[string]any, error) {
	// A W3C VC 2.0 credential or presentation travels as JSON-LD, so it is
	// a JSON document rather than a dot-separated token - an object when
	// compact, an array when expanded. Inside a DCQL response this is where
	// each one arrives.
	if document, ok := jsonDocumentToken(vpToken); ok {
		return extractW3CClaims(document)
	}

	// Check if this is an mdoc format token
	if isMDocFormatToken(vpToken) {
		return extractMDocClaimsFromToken(vpToken)
	}

	// Default to SD-JWT format
	parsed, err := sdjwtvc.Token(vpToken).Parse()
	if err != nil {
		return nil, fmt.Errorf("failed to parse VP token: %w", err)
	}

	return parsed.Claims, nil
}

// isMDocFormatToken checks if the VP token appears to be in mdoc format.
func isMDocFormatToken(vpToken string) bool {
	if strings.Count(vpToken, ".") >= 2 {
		return false
	}
	data, err := base64.RawURLEncoding.DecodeString(vpToken)
	if err != nil {
		data, err = base64.StdEncoding.DecodeString(vpToken)
		if err != nil {
			return false
		}
	}
	if len(data) > 0 {
		firstByte := data[0]
		return (firstByte >= 0x80 && firstByte <= 0x9f) ||
			(firstByte >= 0xa0 && firstByte <= 0xbf)
	}
	return false
}

// mdocDeviceResponse is a minimal struct for decoding mdoc DeviceResponse CBOR.
type mdocDeviceResponse struct {
	Documents []mdocDocument `cbor:"documents"`
}

type mdocDocument struct {
	DocType      string           `cbor:"docType"`
	IssuerSigned mdocIssuerSigned `cbor:"issuerSigned"`
}

type mdocIssuerSigned struct {
	NameSpaces map[string][]mdocIssuerSignedItem `cbor:"nameSpaces"`
}

type mdocIssuerSignedItem struct {
	ElementIdentifier string `cbor:"elementIdentifier"`
	ElementValue      any    `cbor:"elementValue"`
}

const mdocNamespace = "org.iso.18013.5.1"

// extractMDocClaimsFromToken extracts claims from an mdoc VP token without full verification.
func extractMDocClaimsFromToken(vpToken string) (map[string]any, error) {
	data, err := base64.RawURLEncoding.DecodeString(vpToken)
	if err != nil {
		data, err = base64.StdEncoding.DecodeString(vpToken)
		if err != nil {
			return nil, fmt.Errorf("failed to decode mdoc VP token: %w", err)
		}
	}

	// Local anonymous structural schema definition matching your production format
	var deviceResponse struct {
		Documents []struct {
			DocType      string `cbor:"docType"`
			IssuerSigned struct {
				NameSpaces map[string][]any `cbor:"nameSpaces"`
			} `cbor:"issuerSigned"`
		} `cbor:"documents"`
		// A "mso_mdoc_zk" presentation (multipaz's zkDocuments extension,
		// see pkg/mdoc/zk.go) carries its documents here instead of
		// "documents" - checked only to distinguish "genuinely empty
		// DeviceResponse" from "a ZK-proof response this best-effort,
		// pre-verification preview extractor doesn't understand yet".
		// Real claim extraction+verification for these happens in the
		// dedicated pkg/mdoc/zk_verifier.go path elsewhere in the pipeline
		// (can't import it directly here - it already imports this
		// package). Confirmed live: without this check, every ZK mdoc
		// presentation failed the whole /verification/direct_post
		// submission with "no documents in DeviceResponse", even though
		// the proof itself was valid and never got a chance to verify.
		ZkDocuments []cbor.RawMessage `cbor:"zkDocuments,omitempty"`
	}

	if err := cbor.Unmarshal(data, &deviceResponse); err != nil {
		return nil, fmt.Errorf("failed to parse DeviceResponse: %w", err)
	}

	if len(deviceResponse.Documents) == 0 {
		if len(deviceResponse.ZkDocuments) > 0 {
			return make(map[string]any), nil
		}
		return nil, fmt.Errorf("no documents in DeviceResponse")
	}

	claims := make(map[string]any)
	for _, doc := range deviceResponse.Documents {
		for ns, items := range doc.IssuerSigned.NameSpaces {
			for _, anyItem := range items {
				var elementID string
				var elementVal any
				found := false

				// Dynamically unpack based on how the item is wrapped on the wire
				switch v := anyItem.(type) {
				case cbor.Tag:
					// If it's a Tag 24 item, extract the nested serialized byte slice
					if content, ok := v.Content.([]byte); ok {
						var item struct {
							ElementIdentifier string `cbor:"elementIdentifier"`
							ElementValue      any    `cbor:"elementValue"`
						}
						if err := cbor.Unmarshal(content, &item); err == nil {
							elementID = item.ElementIdentifier
							elementVal = item.ElementValue
							found = true
						}
					}
				case map[any]any:
					// Fallback if the map is already unmarshaled into generic maps
					if id, ok := v["elementIdentifier"].(string); ok {
						elementID = id
						elementVal = v["elementValue"]
						found = true
					}
				}

				if found {
					qualifiedKey := fmt.Sprintf("%s.%s", ns, elementID)
					claims[qualifiedKey] = elementVal

					if ns == mdocNamespace {
						claims[elementID] = elementVal
					}
				}
			}
		}
	}

	return claims, nil
}

// MapClaimsToOIDC maps VP claims to OIDC claims using the template's claim mappings
// claimMappings: Key = VP claim path, Value = OIDC claim name
// Special mapping "*" : "*" means pass all claims through unchanged
func (ce *ClaimsExtractor) MapClaimsToOIDC(vpClaims map[string]any, claimMappings map[string]string) (map[string]any, error) {
	if vpClaims == nil {
		return nil, fmt.Errorf("VP claims are nil")
	}
	if claimMappings == nil {
		return nil, fmt.Errorf("claim mappings are nil")
	}

	oidcClaims := make(map[string]any)

	// Check for wildcard mapping first
	if wildcardTarget, hasWildcard := claimMappings["*"]; hasWildcard && wildcardTarget == "*" {
		// Map all claims through unchanged
		for key, value := range vpClaims {
			// Skip internal SD-JWT claims
			if !isInternalClaim(key) {
				oidcClaims[key] = value
			}
		}
		return oidcClaims, nil
	}

	// Map specific claims according to the mapping
	for vpPath, oidcName := range claimMappings {
		if vpPath == "*" {
			continue // Already handled above
		}

		value, err := ce.extractNestedClaim(vpClaims, vpPath)
		if err != nil {
			// Claim not found - this is acceptable, not all claims may be present
			continue
		}

		oidcClaims[oidcName] = value
	}

	return oidcClaims, nil
}

// extractNestedClaim extracts a claim value from a nested path
// Supports paths like "given_name" or "place_of_birth.country"
func (ce *ClaimsExtractor) extractNestedClaim(claims map[string]any, path string) (any, error) {
	if path == "" {
		return nil, fmt.Errorf("empty claim path")
	}

	// Split path by dots for nested access
	parts := strings.Split(path, ".")

	current := claims
	for i, part := range parts {
		value, ok := current[part]
		if !ok {
			return nil, fmt.Errorf("claim '%s' not found at path '%s'", part, path)
		}

		// If this is the last part, return the value
		if i == len(parts)-1 {
			return value, nil
		}

		// Otherwise, value must be a map to continue traversing
		nextMap, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("claim '%s' is not an object, cannot traverse further in path '%s'", part, path)
		}
		current = nextMap
	}

	return nil, fmt.Errorf("unexpected error extracting claim at path '%s'", path)
}

// ApplyClaimTransforms applies transformations to claim values
// transformDefs: Map of OIDC claim name to transform definition
func (ce *ClaimsExtractor) ApplyClaimTransforms(claims map[string]any, transformDefs map[string]ClaimTransformDef) (map[string]any, error) {
	if len(transformDefs) == 0 {
		return claims, nil // No transforms to apply
	}

	transformedClaims := make(map[string]any)

	// Copy all claims first
	maps.Copy(transformedClaims, claims)

	// Apply transforms
	for claimName, transformDef := range transformDefs {
		value, exists := transformedClaims[claimName]
		if !exists {
			continue // Claim not present, skip transform
		}

		transformed, err := ce.applyTransform(value, transformDef)
		if err != nil {
			return nil, fmt.Errorf("failed to transform claim '%s': %w", claimName, err)
		}

		transformedClaims[claimName] = transformed
	}

	return transformedClaims, nil
}

// ClaimTransformDef defines a claim transformation
type ClaimTransformDef struct {
	Type   string            // Transform type: date_format, boolean_string, uppercase, lowercase, etc.
	Params map[string]string // Transform parameters
}

// applyTransform applies a specific transformation to a claim value
func (ce *ClaimsExtractor) applyTransform(value any, transform ClaimTransformDef) (any, error) {
	switch transform.Type {
	case "date_format":
		return ce.transformDateFormat(value, transform.Params)
	case "boolean_string":
		return ce.transformBooleanString(value, transform.Params)
	case "uppercase":
		return ce.transformUppercase(value)
	case "lowercase":
		return ce.transformLowercase(value)
	default:
		return nil, fmt.Errorf("unknown transform type: %s", transform.Type)
	}
}

// transformDateFormat converts a date from one format to another
// Params: "from" (source format), "to" (target format)
// Formats use Go's time format strings
func (ce *ClaimsExtractor) transformDateFormat(value any, params map[string]string) (any, error) {
	dateStr, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("date value is not a string: %T", value)
	}

	fromFormat := params["from"]
	toFormat := params["to"]

	if fromFormat == "" || toFormat == "" {
		return nil, fmt.Errorf("date_format transform requires 'from' and 'to' parameters")
	}

	// Parse the date string
	parsedDate, err := time.Parse(fromFormat, dateStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse date '%s' with format '%s': %w", dateStr, fromFormat, err)
	}

	// Format to target format
	return parsedDate.Format(toFormat), nil
}

// transformBooleanString converts boolean to "yes"/"no" strings
// Params: "true_value" (default "yes"), "false_value" (default "no")
func (ce *ClaimsExtractor) transformBooleanString(value any, params map[string]string) (any, error) {
	boolVal, ok := value.(bool)
	if !ok {
		return nil, fmt.Errorf("boolean value is not a bool: %T", value)
	}

	trueValue := params["true_value"]
	if trueValue == "" {
		trueValue = "yes"
	}

	falseValue := params["false_value"]
	if falseValue == "" {
		falseValue = "no"
	}

	if boolVal {
		return trueValue, nil
	}
	return falseValue, nil
}

// transformUppercase converts string to uppercase
func (ce *ClaimsExtractor) transformUppercase(value any) (any, error) {
	str, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("uppercase value is not a string: %T", value)
	}
	return strings.ToUpper(str), nil
}

// transformLowercase converts string to lowercase
func (ce *ClaimsExtractor) transformLowercase(value any) (any, error) {
	str, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("lowercase value is not a string: %T", value)
	}
	return strings.ToLower(str), nil
}

// isInternalClaim checks if a claim is an internal SD-JWT structural claim that should
// never be forwarded to relying parties. Only filters SD-JWT mechanics — standard JWT
// claims (iss, iat, exp, nbf) are passed through since RPs may need them.
func isInternalClaim(key string) bool {
	internalClaims := []string{
		"_sd",     // Selective disclosure digests
		"_sd_alg", // Selective disclosure hash algorithm
		"cnf",     // Confirmation - internal key binding
		"status",  // Token status list reference
		"vct",     // Verifiable credential type - internal metadata
	}

	return slices.Contains(internalClaims, key)
}

// ExtractAndMapClaims is a convenience function that combines extraction, mapping, and transformation
// This is the main entry point for the complete claims processing pipeline
func (ce *ClaimsExtractor) ExtractAndMapClaims(
	ctx context.Context,
	vpToken string,
	claimMappings map[string]string,
	transformDefs map[string]ClaimTransformDef,
) (map[string]any, error) {
	// Step 1: Extract claims from VP token
	vpClaims, err := ce.ExtractClaimsFromVPToken(ctx, vpToken)
	if err != nil {
		return nil, fmt.Errorf("extraction failed: %w", err)
	}

	// Step 2: Map VP claims to OIDC claims
	oidcClaims, err := ce.MapClaimsToOIDC(vpClaims, claimMappings)
	if err != nil {
		return nil, fmt.Errorf("mapping failed: %w", err)
	}

	// Step 3: Apply transformations
	if len(transformDefs) > 0 {
		oidcClaims, err = ce.ApplyClaimTransforms(oidcClaims, transformDefs)
		if err != nil {
			return nil, fmt.Errorf("transformation failed: %w", err)
		}
	}

	return oidcClaims, nil
}

// EmbeddedCredentialCount reports how many credentials a W3C presentation
// carries. A bare credential carries none.
//
// Needed because VC20Handler.VerifyAndExtract verifies the first embedded
// credential only, while claim extraction merges every one - so a caller
// that must not read unverified claims has to know when there is more than
// one.
func EmbeddedCredentialCount(document string) (int, error) {
	var raw any
	if err := json.Unmarshal([]byte(strings.TrimSpace(document)), &raw); err != nil {
		return 0, fmt.Errorf("failed to parse VP token as JSON: %w", err)
	}
	doc, _, err := compactW3CDocument(raw)
	if err != nil {
		return 0, err
	}
	embedded, ok := doc["verifiableCredential"]
	if !ok {
		return 0, nil
	}
	return len(asSlice(embedded)), nil
}

// W3CDocumentsIn returns the W3C VC 2.0 documents carried in a vp_token,
// whether it is one document or a DCQL response keyed by credential query
// id. The map key is the query id for a DCQL response, and "" for a bare
// document.
//
// Callers that must VERIFY a W3C response need this: a DCQL envelope is a
// JSON object too, so "looks like JSON" cannot tell a W3C document from the
// wrapper around one, and treating the wrapper as a credential fails a
// conformant response before its contents are ever looked at.
func W3CDocumentsIn(vpToken string) map[string][]string {
	trimmed := strings.TrimSpace(vpToken)
	if trimmed == "" {
		return nil
	}

	if trimmed[0] == '{' && !isW3CDocument(trimmed) {
		var envelope map[string][]string
		if err := json.Unmarshal([]byte(trimmed), &envelope); err != nil {
			return nil
		}
		out := make(map[string][]string)
		for queryID, tokens := range envelope {
			for _, token := range tokens {
				if inner, ok := jsonDocumentToken(token); ok {
					out[queryID] = append(out[queryID], inner)
				}
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}

	if document, ok := jsonDocumentToken(trimmed); ok {
		return map[string][]string{"": {document}}
	}
	return nil
}

// rawJSONDocument reports whether a token is already a JSON-LD document
// rather than a dot-separated one: an object when compact, an array when
// expanded.
func rawJSONDocument(token string) bool {
	trimmed := strings.TrimSpace(token)
	return len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
}

// decodeBase64Document unwraps a base64url- or standard-base64-encoded
// token, in the same two spellings the format detector accepts.
func decodeBase64Document(token string) (string, bool) {
	if decoded, err := base64.RawURLEncoding.DecodeString(token); err == nil {
		return string(decoded), true
	}
	if decoded, err := base64.StdEncoding.DecodeString(token); err == nil {
		return string(decoded), true
	}
	return "", false
}

// jsonDocumentToken returns the token as raw JSON, unwrapping base64 when
// that is how it arrived. Callers that go on to PARSE the document need the
// decoded form, not just the knowledge that one is in there.
//
// Base64 counts as a JSON-LD document. The VC20 decoder and
// detectCredentialFormat both accept a base64url- or standard-base64-wrapped
// JSON-LD document, so a guard that only looked at raw '{'/'[' could be
// stepped around by encoding the same credential - which is the whole
// surface it was added to cover. An mdoc cannot be mistaken for one: its
// CBOR starts 0x80-0xbf, and '{' and '[' are 0x7b and 0x5b.
func jsonDocumentToken(token string) (string, bool) {
	trimmed := strings.TrimSpace(token)
	if rawJSONDocument(trimmed) {
		return trimmed, true
	}
	if decoded, ok := decodeBase64Document(trimmed); ok && rawJSONDocument(decoded) {
		return strings.TrimSpace(decoded), true
	}
	return "", false
}

// isW3CDocument reports whether a JSON object is a W3C VC 2.0 credential or
// presentation rather than a DCQL vp_token map.
//
// Discriminated on "@context", which every W3C VC 2.0 document carries and
// which is not a credential query id anyone would choose - a DCQL response
// keys by query id and its values are arrays of token strings. Requiring the
// payload member as well keeps a stray "@context" query id from routing a
// real DCQL response into the W3C branch.
//
// A shape that is neither still reports the DCQL parse failure, which is the
// more useful error for the malformed-DCQL case that produced it.
func isW3CDocument(document string) bool {
	var doc map[string]any
	if err := json.Unmarshal([]byte(document), &doc); err != nil {
		return false
	}
	if _, hasContext := doc["@context"]; !hasContext {
		return false
	}
	_, hasSubject := doc["credentialSubject"]
	_, hasEmbedded := doc["verifiableCredential"]
	return hasSubject || hasEmbedded
}

// extractW3CClaims reads the disclosed claims out of a W3C VC 2.0 document:
// a verifiable presentation, whose credentials are unwrapped in turn, or a
// bare credential.
//
// Claims come from credentialSubject, which is where a W3C credential puts
// them - there is no selective disclosure to resolve, so what the document
// says is what was disclosed.
//
// This does NOT verify anything. Neither does the SD-JWT or mdoc path
// through this extractor: ProcessDirectPost performs no signature
// verification for any format, which is a pre-existing gap of its own. What
// this fixes is a W3C response failing to parse at all on that path, so a
// configured W3C scope worked through the UI direct-post flow and nowhere
// else.
func extractW3CClaims(document string) (map[string]any, error) {
	var raw any
	if err := json.Unmarshal([]byte(document), &raw); err != nil {
		return nil, fmt.Errorf("failed to parse VP token as JSON: %w", err)
	}

	doc, byID, err := compactW3CDocument(raw)
	if err != nil {
		return nil, err
	}

	// A presentation: unwrap each credential it carries. Entries are
	// either JSON objects or embedded strings, both of which the builders
	// in this package can produce.
	if embedded, ok := doc["verifiableCredential"]; ok {
		merged := make(map[string]any)
		for _, entry := range asSlice(embedded) {
			claims, err := w3cSubjectClaims(entry, byID)
			if err != nil {
				return nil, err
			}
			maps.Copy(merged, claims)
		}
		if len(merged) == 0 {
			return nil, fmt.Errorf("W3C presentation discloses no credential subject claims")
		}
		return merged, nil
	}

	return w3cSubjectClaims(doc, byID)
}

// asSlice normalises a JSON-LD member that may be a single value or a list.
func asSlice(v any) []any {
	if list, ok := v.([]any); ok {
		return list
	}
	return []any{v}
}

// w3cSubjectClaims reads credentialSubject from one credential, which may
// still be an embedded JSON string, and whose subject may be a NODE
// REFERENCE rather than an inline object - byID resolves those.
func w3cSubjectClaims(entry any, byID map[string]map[string]any) (map[string]any, error) {
	cred, ok := entry.(map[string]any)
	if !ok {
		raw, isString := entry.(string)
		if !isString {
			return nil, fmt.Errorf("W3C credential entry is %T, want an object or an embedded JSON string", entry)
		}
		if node, known := byID[raw]; known {
			cred = node
		} else if err := json.Unmarshal([]byte(raw), &cred); err != nil {
			return nil, fmt.Errorf("failed to parse embedded W3C credential: %w", err)
		}
	}

	subject, ok := cred["credentialSubject"]
	if !ok {
		return nil, fmt.Errorf("W3C credential carries no credentialSubject")
	}

	merged := make(map[string]any)
	for _, s := range asSlice(subject) {
		if claims, ok := s.(map[string]any); ok {
			maps.Copy(merged, claims)
			continue
		}
		// An expanded document is a FLAT graph: the credential names its
		// subject by id and the subject's properties live in a node of
		// their own. Compaction preserves that shape, so a reference here
		// is normal rather than malformed.
		ref, isRef := s.(string)
		if !isRef {
			return nil, fmt.Errorf("W3C credentialSubject is %T, want an object or a node reference", s)
		}
		node, known := byID[ref]
		if !known {
			return nil, fmt.Errorf("W3C credentialSubject references node %q, which the document does not contain", ref)
		}
		maps.Copy(merged, node)
	}
	return merged, nil
}

// compactW3CDocument returns the document in COMPACT form, so one extractor
// reads both serializations.
//
// A W3C credential travels expanded as often as compact: json-gold's
// MarshalJSON emits an array of nodes keyed by full IRIs, and
// detectCredentialFormat accepts a leading "[" as a W3C credential - so the
// verifier and the claim extraction would otherwise disagree about the same
// bytes, accepting a presentation and then failing to read a claim out of
// it.
//
// Compacting against the VC 2.0 context rather than matching expanded IRIs
// by hand: the term definitions live in the context, the context is served
// from the embedded bundle, and this way an expanded document reaches
// exactly the same code path a compact one does.
func compactW3CDocument(raw any) (map[string]any, map[string]map[string]any, error) {
	if doc, ok := raw.(map[string]any); ok && !isExpandedNode(doc) {
		return doc, nil, nil
	}

	compacted, err := ld.NewJsonLdProcessor().Compact(raw,
		map[string]any{"@context": credential.ContextV2}, credential.NewJSONLDOptions(""))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compact W3C document: %w", err)
	}

	graph, ok := compacted["@graph"]
	if !ok {
		return compacted, nil, nil
	}

	// Compacting an expanded document yields a @graph of FLAT nodes: the
	// credential names its subject by id, and the subject's properties are
	// a node of their own. So the graph is both searched for the document
	// node and kept as a lookup, because the claims are not inside it.
	byID := make(map[string]map[string]any)
	var document map[string]any
	for _, node := range asSlice(graph) {
		entry, ok := node.(map[string]any)
		if !ok {
			continue
		}
		if id, ok := entry["id"].(string); ok {
			byID[id] = entry
		}
		if document != nil {
			continue
		}
		if _, isCredential := entry["credentialSubject"]; isCredential {
			document = entry
		} else if _, isPresentation := entry["verifiableCredential"]; isPresentation {
			document = entry
		}
	}
	if document == nil {
		return nil, nil, fmt.Errorf("W3C document contains neither a credential nor a presentation")
	}
	return document, byID, nil
}

// isExpandedNode reports whether a JSON object is in expanded JSON-LD form,
// which names its members by full IRI and carries no "@context".
func isExpandedNode(doc map[string]any) bool {
	if _, hasContext := doc["@context"]; hasContext {
		return false
	}
	for key := range doc {
		if strings.Contains(key, "://") {
			return true
		}
	}
	return false
}
