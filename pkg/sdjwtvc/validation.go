package sdjwtvc

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ValidationError represents a validation error with details
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("validation error for field '%s': %s", e.Field, e.Message)
	}
	return fmt.Sprintf("validation error: %s", e.Message)
}

// ValidationErrors represents multiple validation errors
type ValidationErrors struct {
	Errors []ValidationError
}

func (e *ValidationErrors) Error() string {
	if len(e.Errors) == 0 {
		return "no validation errors"
	}
	if len(e.Errors) == 1 {
		return e.Errors[0].Error()
	}

	var msgs []string
	for _, err := range e.Errors {
		msgs = append(msgs, err.Error())
	}
	return fmt.Sprintf("multiple validation errors: %s", strings.Join(msgs, "; "))
}

// AddError adds a validation error
func (e *ValidationErrors) AddError(field, message string) {
	e.Errors = append(e.Errors, ValidationError{
		Field:   field,
		Message: message,
	})
}

// HasErrors returns true if there are validation errors
func (e *ValidationErrors) HasErrors() bool {
	return len(e.Errors) > 0
}

// ValidateDocument validates document data against VCTM metadata.
// documentData should be JSON-encoded document claims as supplied by the data
// source — i.e. the input to the issuer pipeline before JWT/SD-JWT envelope
// claims (iss, exp, cnf, vct, iat, ...) are added at signing time. Those
// envelope claims are not expected to be present here even when the VCTM marks
// them mandatory; see isIssuerSuppliedClaim.
func ValidateDocument(documentData []byte, vctm *VCTM) error {
	if vctm == nil {
		return fmt.Errorf("VCTM is nil")
	}

	var claims map[string]any
	if err := json.Unmarshal(documentData, &claims); err != nil {
		return fmt.Errorf("invalid document data: %w", err)
	}

	return validateClaims(claims, vctm, true)
}

// ValidateClaims validates a fully assembled claims set against VCTM metadata.
// All mandatory claims declared by the VCTM must be present, including JWT/
// SD-JWT envelope claims such as iss, exp, cnf, vct, and iat. Use this when
// validating an assembled credential payload. To validate document-data prior
// to issuance — where envelope claims are filled in later by the issuer
// pipeline — use ValidateDocument instead.
func ValidateClaims(claims map[string]any, vctm *VCTM) error {
	return validateClaims(claims, vctm, false)
}

// validateClaims is the shared implementation behind ValidateClaims and
// ValidateDocument. When skipIssuerSupplied is true, VCTM mandatory entries
// for JWT/SD-JWT envelope claims that the issuer pipeline supplies at signing
// time are not required to be present (see isIssuerSuppliedClaim).
func validateClaims(claims map[string]any, vctm *VCTM, skipIssuerSupplied bool) error {
	if vctm == nil {
		return fmt.Errorf("VCTM is nil")
	}

	if claims == nil {
		return fmt.Errorf("claims are nil")
	}

	errors := &ValidationErrors{}

	// Check mandatory claims are present
	for _, claim := range vctm.Claims {
		if claim.Mandatory {
			if skipIssuerSupplied && isIssuerSuppliedClaim(claim.Path) {
				continue
			}
			claimPath := claim.Path
			if !claimExists(claims, claimPath) {
				errors.AddError(
					claim.JSONPath(),
					"mandatory claim is missing",
				)
			}
		}
	}

	// Validate claim structure and types
	for _, claim := range vctm.Claims {
		if len(claim.Path) == 0 {
			continue
		}

		// Get the value at the path
		value, exists := getClaimValue(claims, claim.Path)
		if !exists {
			// Already handled by mandatory check
			continue
		}

		// Validate based on claim path structure
		if err := validateClaimValue(claim, value); err != nil {
			errors.AddError(claim.JSONPath(), err.Error())
		}
	}

	if errors.HasErrors() {
		return errors
	}

	return nil
}

// claimExists checks if a claim exists at the given path
func claimExists(claims map[string]any, path []*string) bool {
	_, exists := getClaimValue(claims, path)
	return exists
}

// getClaimValue retrieves the value at the given path
func getClaimValue(claims map[string]any, path []*string) (any, bool) {
	if len(path) == 0 {
		return nil, false
	}

	current := any(claims)

	for i, pathElement := range path {
		if pathElement == nil {
			// null in path means "all array elements" - validate this is an array
			arr, ok := current.([]any)
			if !ok {
				return nil, false
			}
			// For validation purposes, we just check the array exists
			// Individual elements will be validated separately
			if i == len(path)-1 {
				return arr, true
			}
			// Can't traverse further with null path element
			return nil, false
		}

		key := *pathElement

		// Try as object
		if obj, ok := current.(map[string]any); ok {
			val, exists := obj[key]
			if !exists {
				return nil, false
			}
			current = val
			continue
		}

		// Not an object, can't navigate further
		return nil, false
	}

	return current, true
}

// validateClaimValue validates a claim value based on basic type checking
func validateClaimValue(claim Claim, value any) error {
	if value == nil {
		// nil is valid for optional claims
		if claim.Mandatory {
			return fmt.Errorf("value is nil but claim is mandatory")
		}
		return nil
	}

	// For now, we do basic type validation
	// More sophisticated validation could be added based on VCTM extensions

	// Check if it's a valid JSON type
	switch value.(type) {
	case string, bool, float64, int, int64:
		// Primitive types are OK
		return nil
	case map[string]any:
		// Objects are OK
		return nil
	case []any:
		// Arrays are OK
		return nil
	default:
		// Unknown type
		return fmt.Errorf("unsupported value type: %T", value)
	}
}

// ValidateClaimPaths validates that all claims in the document have
// corresponding paths in VCTM. This is a stricter validation that ensures no
// extra claims are present. It operates on document-data semantics, matching
// ValidateDocument: VCTM-mandatory envelope claims supplied by the issuer
// pipeline are not required, and the extras check ignores standard JWT/SD-JWT
// claims (see isStandardClaim).
func ValidateClaimPaths(claims map[string]any, vctm *VCTM, strict bool) error {
	if !strict {
		// Non-strict mode: just validate mandatory claims and known claims
		return validateClaims(claims, vctm, true)
	}

	// Strict mode: ensure all claims in document are defined in VCTM
	errors := &ValidationErrors{}

	// First do standard validation
	if err := validateClaims(claims, vctm, true); err != nil {
		if validationErrs, ok := err.(*ValidationErrors); ok {
			errors.Errors = append(errors.Errors, validationErrs.Errors...)
		} else {
			return err
		}
	}

	// Build a map of allowed claim paths
	allowedPaths := make(map[string]bool)
	for _, claim := range vctm.Claims {
		if len(claim.Path) > 0 {
			// Add the top-level key
			if claim.Path[0] != nil {
				allowedPaths[*claim.Path[0]] = true
			}
		}
	}

	// Check all top-level claims in document
	for key := range claims {
		// Skip standard JWT claims
		if isStandardClaim(key) {
			continue
		}

		if !allowedPaths[key] {
			errors.AddError(key, "claim not defined in VCTM")
		}
	}

	if errors.HasErrors() {
		return errors
	}

	return nil
}

// isIssuerSuppliedClaim reports whether a VCTM claim path refers to a
// JWT/SD-JWT VC envelope claim that the issuer pipeline (BuildCredentialWithSigner
// and friends) fills in at signing time, rather than something the data source
// must provide in documentData. VCTMs commonly mark these mandatory:true for
// verifier-side conformance, but document-data validation must skip them.
// This exemption is only applied in document-data paths (ValidateDocument,
// ValidateClaimPaths) — ValidateClaims validates strictly, since a fully
// assembled credential must carry these envelope claims.
func isIssuerSuppliedClaim(path []*string) bool {
	if len(path) != 1 || path[0] == nil {
		return false
	}
	switch *path[0] {
	case "iss", "nbf", "exp", "cnf", "vct", "status", "iat":
		return true
	}
	return false
}

// isStandardClaim checks if a claim is a standard JWT/SD-JWT claim
func isStandardClaim(claim string) bool {
	standardClaims := map[string]bool{
		"iss":     true, // Issuer
		"sub":     true, // Subject
		"aud":     true, // Audience
		"exp":     true, // Expiration
		"nbf":     true, // Not Before
		"iat":     true, // Issued At
		"jti":     true, // JWT ID
		"vct":     true, // Verifiable Credential Type
		"cnf":     true, // Confirmation (holder binding)
		"_sd":     true, // Selective Disclosure array
		"_sd_alg": true, // SD hash algorithm
		"...":     true, // Recursive disclosure (reserved)
	}
	return standardClaims[claim]
}
