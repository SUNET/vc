package openid4vp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// BindingMethod represents a method used to verify combined presentation binding.
type BindingMethod string

const (
	// BindingMethodSession indicates binding via session context (all credentials
	// arrived in the same VP response). This is the baseline assumption per ARF 3.0 §3.2.
	BindingMethodSession BindingMethod = "session_based"

	// BindingMethodKey indicates binding via holder key comparison (same cnf.jwk
	// or device key across multiple credentials = same WSCD).
	BindingMethodKey BindingMethod = "key_based"

	// BindingMethodAttribute indicates binding via shared identifier attributes
	// (e.g., sub, pid_number, or compound name+DOB matching).
	BindingMethodAttribute BindingMethod = "attribute_based"
)

// BindingConfidence represents the level of assurance from a binding check.
type BindingConfidence string

const (
	BindingConfidenceHigh   BindingConfidence = "high"
	BindingConfidenceMedium BindingConfidence = "medium"
	BindingConfidenceLow    BindingConfidence = "low"
	BindingConfidenceNone   BindingConfidence = "none"
)

// BindingEnforcement configures how binding verification results are handled.
type BindingEnforcement string

const (
	// BindingEnforcementEnforce rejects the presentation if binding cannot be established.
	BindingEnforcementEnforce BindingEnforcement = "enforce"
	// BindingEnforcementWarn logs a warning but allows the presentation through.
	BindingEnforcementWarn BindingEnforcement = "warn"
	// BindingEnforcementDisabled skips binding verification entirely.
	BindingEnforcementDisabled BindingEnforcement = "disabled"
)

// BindingResult holds the outcome of a single binding method check.
type BindingResult struct {
	Method     BindingMethod     `json:"method"`
	Confidence BindingConfidence `json:"confidence"`
	Details    string            `json:"details,omitempty"`
	Error      string            `json:"error,omitempty"`
}

// CombinedBindingResult aggregates results from all binding methods.
type CombinedBindingResult struct {
	// Bound indicates whether the verifier considers the credentials bound to the same holder.
	Bound bool `json:"bound"`
	// HighestConfidence is the best confidence level achieved across all methods.
	HighestConfidence BindingConfidence `json:"highest_confidence"`
	// Results contains individual results per method.
	Results []BindingResult `json:"results"`
}

// Err returns a combined error if any binding method produced an error, or nil if all methods succeeded.
func (r *CombinedBindingResult) Err() error {
	var errs []error
	for _, res := range r.Results {
		if res.Error != "" {
			errs = append(errs, errors.New(res.Error))
		}
	}
	return errors.Join(errs...)
}

// Valid returns true if binding was established without any method errors.
func (r *CombinedBindingResult) Valid() bool {
	return r.Bound && r.Err() == nil
}

// VerifiedCredentialBinding holds the binding-relevant data extracted from a verified credential.
type VerifiedCredentialBinding struct {
	// Scope is the credential query ID / scope this credential was presented for.
	Scope string
	// HolderKeyThumbprint is the RFC 7638 SHA-256 thumbprint of the holder's public key
	// (from cnf.jwk for SD-JWT, or device key for mDoc). Empty if no key binding.
	HolderKeyThumbprint string
	// Claims is the verified credential claims map for attribute-based binding.
	Claims map[string]any
}

// CombinedPresentationConfig configures combined presentation verification.
type CombinedPresentationConfig struct {
	// Enabled activates combined presentation binding verification.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Enforcement determines how binding verification results are handled:
	//   - "enforce": reject the presentation if binding cannot be established
	//   - "warn": log a warning but allow the presentation through (per ARF 3.0 ACP_08)
	//   - "disabled": skip binding verification entirely
	Enforcement BindingEnforcement `yaml:"enforcement" json:"enforcement" validate:"omitempty,oneof=enforce warn disabled" default:"warn"`
	// BindingAttributes configures attribute-based binding checks.
	BindingAttributes []BindingAttributeConfig `yaml:"binding_attributes,omitempty" json:"binding_attributes,omitempty" validate:"omitempty,dive"`
	// KeyBinding configures key-based binding checks.
	KeyBinding KeyBindingConfig `yaml:"key_binding" json:"key_binding"`
}

// BindingAttributeConfig defines a set of attribute paths to compare across credentials.
type BindingAttributeConfig struct {
	// Paths lists claim paths that must ALL match across credentials (AND semantics).
	Paths []string `yaml:"paths" json:"paths" validate:"required,min=1,dive,required" doc_example:"[\"family_name\", \"birth_date\", \"place_of_birth.locality\"]"`
}

// KeyBindingConfig configures key-based binding verification.
type KeyBindingConfig struct {
	// Enabled activates key-based binding (cnf.jwk / device key comparison).
	Enabled bool `yaml:"enabled" json:"enabled"`
	// CrossFormat enables comparing keys across credential formats
	// (e.g., SD-JWT cnf.jwk vs mDoc device key).
	CrossFormat bool `yaml:"cross_format" json:"cross_format"`
}

// CombinedBindingVerifier verifies that multiple credentials in a combined
// presentation belong to the same holder.
type CombinedBindingVerifier struct {
	Config CombinedPresentationConfig
}

// Verify checks binding across the provided verified credentials.
// Returns nil result and nil error if fewer than 2 credentials are provided (no binding needed).
func (v *CombinedBindingVerifier) Verify(credentials []VerifiedCredentialBinding) (*CombinedBindingResult, error) {
	if len(credentials) < 2 {
		return nil, nil
	}

	result := &CombinedBindingResult{
		Results: make([]BindingResult, 0, 3),
	}

	// Always include session-based binding as baseline
	result.Results = append(result.Results, BindingResult{
		Method:     BindingMethodSession,
		Confidence: BindingConfidenceLow,
		Details:    "all credentials received in same VP response",
	})
	result.HighestConfidence = BindingConfidenceLow
	result.Bound = true

	// Key-based binding
	if v.Config.KeyBinding.Enabled {
		keyResult := v.verifyKeyBinding(credentials)
		result.Results = append(result.Results, keyResult)
		if keyResult.Confidence == BindingConfidenceHigh {
			result.HighestConfidence = BindingConfidenceHigh
		}
		if keyResult.Error != "" && v.Config.Enforcement == BindingEnforcementEnforce {
			result.Bound = false
		}
	}

	// Attribute-based binding
	if len(v.Config.BindingAttributes) > 0 {
		attrResult := v.verifyAttributeBinding(credentials)
		result.Results = append(result.Results, attrResult)
		if attrResult.Confidence == BindingConfidenceMedium && result.HighestConfidence != BindingConfidenceHigh {
			result.HighestConfidence = BindingConfidenceMedium
		}
		if attrResult.Error != "" && v.Config.Enforcement == BindingEnforcementEnforce {
			result.Bound = false
		}
	}

	// If enforcement is "enforce" and we only achieved session-based (low) confidence,
	// and at least one higher-confidence method was configured but couldn't establish binding,
	// mark as unbound.
	if v.Config.Enforcement == BindingEnforcementEnforce {
		higherMethodConfigured := v.Config.KeyBinding.Enabled || len(v.Config.BindingAttributes) > 0
		if higherMethodConfigured && result.HighestConfidence == BindingConfidenceLow {
			result.Bound = false
		}
	}

	return result, nil
}

// verifyKeyBinding compares holder key thumbprints across all credentials.
func (v *CombinedBindingVerifier) verifyKeyBinding(credentials []VerifiedCredentialBinding) BindingResult {
	thumbprints := make([]string, 0, len(credentials))
	for _, cred := range credentials {
		if cred.HolderKeyThumbprint != "" {
			thumbprints = append(thumbprints, cred.HolderKeyThumbprint)
		}
	}

	if len(thumbprints) < 2 {
		return BindingResult{
			Method:     BindingMethodKey,
			Confidence: BindingConfidenceNone,
			Details:    fmt.Sprintf("insufficient key material: %d of %d credentials have holder keys", len(thumbprints), len(credentials)),
		}
	}

	// Check all thumbprints match
	first := thumbprints[0]
	for i := 1; i < len(thumbprints); i++ {
		if thumbprints[i] != first {
			return BindingResult{
				Method:     BindingMethodKey,
				Confidence: BindingConfidenceNone,
				Error:      "holder key mismatch: credentials are bound to different keys",
			}
		}
	}

	return BindingResult{
		Method:     BindingMethodKey,
		Confidence: BindingConfidenceHigh,
		Details:    fmt.Sprintf("all %d credentials share the same holder key", len(thumbprints)),
	}
}

// verifyAttributeBinding compares configured attributes across all credentials.
func (v *CombinedBindingVerifier) verifyAttributeBinding(credentials []VerifiedCredentialBinding) BindingResult {
	matchedPaths := 0
	totalPaths := 0

	for _, attrConfig := range v.Config.BindingAttributes {
		allMatch := true
		for _, path := range attrConfig.Paths {
			totalPaths++
			values := make([]any, 0, len(credentials))
			for _, cred := range credentials {
				val := resolveSimplePath(cred.Claims, path)
				if val != nil {
					values = append(values, val)
				}
			}

			// Need at least 2 values to compare
			if len(values) < 2 {
				allMatch = false
				break
			}

			// Check all values are equal
			firstStr := fmt.Sprintf("%v", values[0])
			for i := 1; i < len(values); i++ {
				if fmt.Sprintf("%v", values[i]) != firstStr {
					allMatch = false
					break
				}
			}
			if !allMatch {
				break
			}
		}

		if allMatch && len(attrConfig.Paths) > 0 {
			matchedPaths += len(attrConfig.Paths)
		}
	}

	if matchedPaths == 0 {
		if totalPaths == 0 {
			return BindingResult{
				Method:     BindingMethodAttribute,
				Confidence: BindingConfidenceNone,
				Details:    "no binding attributes configured",
			}
		}
		return BindingResult{
			Method:     BindingMethodAttribute,
			Confidence: BindingConfidenceNone,
			Error:      "attribute binding failed: no matching attributes found across credentials",
		}
	}

	return BindingResult{
		Method:     BindingMethodAttribute,
		Confidence: BindingConfidenceMedium,
		Details:    fmt.Sprintf("matched %d attribute paths across credentials", matchedPaths),
	}
}

// resolveSimplePath resolves a dot-separated path against a claims map.
// For example "address.country" resolves claims["address"]["country"].
func resolveSimplePath(claims map[string]any, path string) any {
	parts := strings.Split(path, ".")
	var current any = claims
	for _, part := range parts {
		m, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current, ok = m[part]
		if !ok {
			return nil
		}
	}
	return current
}

// ExtractHolderKeyThumbprint extracts the RFC 7638 SHA-256 thumbprint from
// a cnf.jwk claim map (as found in SD-JWT credentials).
func ExtractHolderKeyThumbprint(claims map[string]any) (string, error) {
	cnf, ok := claims["cnf"].(map[string]any)
	if !ok {
		return "", nil // No cnf claim — no key binding
	}

	jwkMap, ok := cnf["jwk"].(map[string]any)
	if !ok {
		return "", nil // No jwk in cnf — no key binding
	}

	return ComputeJWKThumbprint(jwkMap)
}

// ComputeJWKThumbprint computes an RFC 7638 thumbprint of a JWK map.
// Only includes the required members for the key type (kty, crv, x, y for EC;
// kty, e, n for RSA) in lexicographic order.
func ComputeJWKThumbprint(jwkMap map[string]any) (string, error) {
	kty, _ := jwkMap["kty"].(string)
	if kty == "" {
		return "", fmt.Errorf("JWK missing kty field")
	}

	var canonical map[string]string
	switch kty {
	case "EC":
		crv, _ := jwkMap["crv"].(string)
		x, _ := jwkMap["x"].(string)
		y, _ := jwkMap["y"].(string)
		if crv == "" || x == "" || y == "" {
			return "", fmt.Errorf("EC JWK missing required fields (crv, x, y)")
		}
		canonical = map[string]string{"crv": crv, "kty": kty, "x": x, "y": y}
	case "RSA":
		e, _ := jwkMap["e"].(string)
		n, _ := jwkMap["n"].(string)
		if e == "" || n == "" {
			return "", fmt.Errorf("RSA JWK missing required fields (e, n)")
		}
		canonical = map[string]string{"e": e, "kty": kty, "n": n}
	case "OKP":
		crv, _ := jwkMap["crv"].(string)
		x, _ := jwkMap["x"].(string)
		if crv == "" || x == "" {
			return "", fmt.Errorf("OKP JWK missing required fields (crv, x)")
		}
		canonical = map[string]string{"crv": crv, "kty": kty, "x": x}
	default:
		return "", fmt.Errorf("unsupported key type: %s", kty)
	}

	// RFC 7638: JSON serialization with members in lexicographic order
	canonicalJSON, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("failed to marshal canonical JWK: %w", err)
	}

	hash := sha256.Sum256(canonicalJSON)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// ECPublicKeyToJWKThumbprint converts an *ecdsa.PublicKey to its RFC 7638 thumbprint.
// Used for mDoc device keys.
func ECPublicKeyToJWKThumbprint(key *ecdsa.PublicKey) (string, error) {
	if key == nil {
		return "", fmt.Errorf("nil public key")
	}

	crv := ""
	switch key.Curve {
	case elliptic.P256():
		crv = "P-256"
	case elliptic.P384():
		crv = "P-384"
	case elliptic.P521():
		crv = "P-521"
	default:
		return "", fmt.Errorf("unsupported curve")
	}

	// Encode coordinates as base64url with proper padding to curve byte length
	byteLen := (key.Curve.Params().BitSize + 7) / 8
	xBytes := key.X.FillBytes(make([]byte, byteLen))
	yBytes := key.Y.FillBytes(make([]byte, byteLen))

	jwkMap := map[string]any{
		"kty": "EC",
		"crv": crv,
		"x":   base64.RawURLEncoding.EncodeToString(xBytes),
		"y":   base64.RawURLEncoding.EncodeToString(yBytes),
	}

	return ComputeJWKThumbprint(jwkMap)
}

// PublicKeyToJWKThumbprint converts a crypto.PublicKey to its RFC 7638 thumbprint.
// Supports *ecdsa.PublicKey. Returns empty string for unsupported key types.
func PublicKeyToJWKThumbprint(key crypto.PublicKey) (string, error) {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		return ECPublicKeyToJWKThumbprint(k)
	default:
		return "", fmt.Errorf("unsupported public key type: %T", key)
	}
}

// ECPublicKeyFromJWKMap extracts an *ecdsa.PublicKey from a JWK map.
func ECPublicKeyFromJWKMap(jwkMap map[string]any) (*ecdsa.PublicKey, error) {
	kty, _ := jwkMap["kty"].(string)
	if kty != "EC" {
		return nil, fmt.Errorf("not an EC key: kty=%s", kty)
	}

	crv, _ := jwkMap["crv"].(string)
	x, _ := jwkMap["x"].(string)
	y, _ := jwkMap["y"].(string)

	if crv == "" || x == "" || y == "" {
		return nil, fmt.Errorf("EC JWK missing required fields")
	}

	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode y: %w", err)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}
