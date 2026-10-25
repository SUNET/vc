package sdjwtvc

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/SUNET/vc/pkg/claimpath"
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
	for _, claim := range vctm.Claims {
		validateClaim(errors, claims, claim, skipIssuerSupplied)
	}

	if errors.HasErrors() {
		return errors
	}

	return nil
}

// validateClaim checks that a mandatory claim is present and that every
// value the claim's path selects has a JSON type.
func validateClaim(errors *ValidationErrors, claims map[string]any, claim Claim, skipIssuerSupplied bool) {
	values, err := claim.Path.Select(claims)
	if err != nil {
		if claim.Mandatory && !(skipIssuerSupplied && isIssuerSuppliedClaim(claim.Path)) {
			errors.AddError(claim.JSONPath(), "mandatory claim is missing")
		}
		return
	}
	for _, value := range values {
		if err := validateClaimValue(claim, value); err != nil {
			errors.AddError(claim.JSONPath(), err.Error())
		}
	}
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

	allowedPaths, err := topLevelClaims(vctm)
	if err != nil {
		return err
	}
	addUndeclaredClaims(errors, claims, allowedPaths)

	if errors.HasErrors() {
		return errors
	}

	return nil
}

// addUndeclaredClaims reports each top-level claim of the document that is
// neither allowed nor a standard JWT claim.
func addUndeclaredClaims(errors *ValidationErrors, claims map[string]any, allowed map[string]bool) {
	for key := range claims {
		if !isStandardClaim(key) && !allowed[key] {
			errors.AddError(key, "claim not defined in VCTM")
		}
	}
}

// topLevelClaims returns the keys the VCTM's claim paths start with.
func topLevelClaims(vctm *VCTM) (map[string]bool, error) {
	keys := make(map[string]bool)
	for _, claim := range vctm.Claims {
		components, err := claim.Path.Components()
		if err != nil {
			return nil, err
		}
		if key, ok := components[0].KeyName(); ok {
			keys[key] = true
		}
	}
	return keys, nil
}

// isIssuerSuppliedClaim reports whether a VCTM claim path refers to a
// JWT/SD-JWT VC envelope claim that the issuer pipeline (BuildCredentialWithSigner
// and friends) fills in at signing time, rather than something the data source
// must provide in documentData. VCTMs commonly mark these mandatory:true for
// verifier-side conformance, but document-data validation must skip them.
// This exemption is only applied in document-data paths (ValidateDocument,
// ValidateClaimPaths) — ValidateClaims validates strictly, since a fully
// assembled credential must carry these envelope claims.
func isIssuerSuppliedClaim(path claimpath.Pointer) bool {
	keys, ok := path.KeyNames()
	if !ok || len(keys) != 1 {
		return false
	}
	switch keys[0] {
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
