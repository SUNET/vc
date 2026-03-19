package openid4vp

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
	"vc/pkg/sdjwtvc"
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
// is a JSON object mapping credential query IDs to their individual VP tokens.
// Claims from all credentials are merged into a single map.
func (ce *ClaimsExtractor) extractClaimsFromDCQLResponse(ctx context.Context, vpToken string) (map[string]any, error) {
	var dcqlResponse map[string]string
	if err := json.Unmarshal([]byte(vpToken), &dcqlResponse); err != nil {
		return nil, fmt.Errorf("failed to parse DCQL vp_token as JSON object: %w", err)
	}

	if len(dcqlResponse) == 0 {
		return nil, fmt.Errorf("DCQL vp_token contains no credentials")
	}

	merged := make(map[string]any)
	for credID, token := range dcqlResponse {
		claims, err := ce.extractClaimsFromSingleToken(token)
		if err != nil {
			return nil, fmt.Errorf("failed to extract claims from credential %q: %w", credID, err)
		}
		maps.Copy(merged, claims)
	}

	return merged, nil
}

// extractClaimsFromSingleToken extracts claims from a single VP token (SD-JWT or mdoc).
func (ce *ClaimsExtractor) extractClaimsFromSingleToken(vpToken string) (map[string]any, error) {
	// Check if this is an mdoc format token
	if IsMDocFormat(vpToken) {
		return ExtractMDocClaims(vpToken)
	}

	// Default to SD-JWT format
	parsed, err := sdjwtvc.Token(vpToken).Parse()
	if err != nil {
		return nil, fmt.Errorf("failed to parse VP token: %w", err)
	}

	return parsed.Claims, nil
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
	if transformDefs == nil || len(transformDefs) == 0 {
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

// isInternalClaim checks if a claim is an internal SD-JWT claim that should be filtered
func isInternalClaim(key string) bool {
	internalClaims := []string{
		"_sd",
		"_sd_alg",
		"iss",    // Issuer - usually not needed in OIDC claims
		"iat",    // Issued at - usually not needed
		"exp",    // Expiration - usually not needed
		"nbf",    // Not before - usually not needed
		"vct",    // Verifiable credential type - internal
		"cnf",    // Confirmation - internal key binding
		"status", // Status - internal
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
	if transformDefs != nil && len(transformDefs) > 0 {
		oidcClaims, err = ce.ApplyClaimTransforms(oidcClaims, transformDefs)
		if err != nil {
			return nil, fmt.Errorf("transformation failed: %w", err)
		}
	}

	return oidcClaims, nil
}
