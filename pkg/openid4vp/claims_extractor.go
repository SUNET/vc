package openid4vp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/fxamacker/cbor/v2"
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
//   - mdoc: CBOR-based mobile document
//   - SD-JWT: dot-separated JWT with selective disclosures
//
// Returns a merged map of disclosed claims from all credentials.
func (ce *ClaimsExtractor) ExtractClaimsFromVPToken(ctx context.Context, vpToken string) (map[string]any, error) {
	if vpToken == "" {
		return nil, fmt.Errorf("VP token is empty")
	}

	// Check if this is a DCQL response (JSON object mapping credential IDs to tokens)
	trimmed := strings.TrimSpace(vpToken)
	if len(trimmed) > 0 && trimmed[0] == '{' {
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

// extractClaimsFromSingleToken extracts claims from a single VP token (SD-JWT or mdoc).
func (ce *ClaimsExtractor) extractClaimsFromSingleToken(vpToken string) (map[string]any, error) {
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

// ExtractAndMapClaims extracts claims from a VP token and maps them to OIDC claims.
// Value normalisation (date reformatting, case folding, etc.) is out of scope;
// it belongs downstream as scope-config derivations.
func (ce *ClaimsExtractor) ExtractAndMapClaims(
	ctx context.Context,
	vpToken string,
	claimMappings map[string]string,
) (map[string]any, error) {
	vpClaims, err := ce.ExtractClaimsFromVPToken(ctx, vpToken)
	if err != nil {
		return nil, fmt.Errorf("extraction failed: %w", err)
	}

	oidcClaims, err := ce.MapClaimsToOIDC(vpClaims, claimMappings)
	if err != nil {
		return nil, fmt.Errorf("mapping failed: %w", err)
	}

	return oidcClaims, nil
}
