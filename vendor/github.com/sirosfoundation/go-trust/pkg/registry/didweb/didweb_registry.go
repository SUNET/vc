// Package didweb implements a TrustRegistry using the did:web method specification.
//
// The did:web method allows DIDs to be resolved via HTTPS from domain names,
// as specified in https://w3c-ccg.github.io/did-method-web/
package didweb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// DIDWebRegistry implements a trust registry using the did:web method.
// It resolves DID documents via HTTPS and validates key bindings.
type DIDWebRegistry struct {
	httpClient  registry.HTTPClientInterface
	timeout     time.Duration
	description string
	allowHTTP   bool // For testing only
}

// Config holds configuration for creating a DIDWebRegistry.
type Config struct {
	// Timeout for HTTP requests (default: 30 seconds)
	Timeout time.Duration `json:"timeout,omitempty"`

	// Description of this registry instance
	Description string `json:"description,omitempty"`

	// InsecureSkipVerify disables TLS certificate verification (NOT RECOMMENDED for production)
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`

	// AllowHTTP allows using HTTP instead of HTTPS for DID resolution.
	// WARNING: This should only be used for testing. The did:web spec requires HTTPS.
	AllowHTTP bool `json:"allow_http,omitempty"`

	// AllowPrivateIPs permits requests to private/internal networks (RFC 1918).
	// WARNING: This should only be used for testing or internal deployments.
	AllowPrivateIPs bool `json:"allow_private_ips,omitempty"`
}

// DIDDocument represents a W3C DID Document.
// See https://www.w3.org/TR/did-core/
type DIDDocument struct {
	Context            interface{}          `json:"@context,omitempty"`
	ID                 string               `json:"id"`
	Controller         interface{}          `json:"controller,omitempty"`
	VerificationMethod []VerificationMethod `json:"verificationMethod,omitempty"`
	Authentication     interface{}          `json:"authentication,omitempty"`
	AssertionMethod    interface{}          `json:"assertionMethod,omitempty"`
	KeyAgreement       interface{}          `json:"keyAgreement,omitempty"`
	Service            interface{}          `json:"service,omitempty"`
}

// VerificationMethod represents a verification method in a DID document.
type VerificationMethod struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`
	Controller   string                 `json:"controller"`
	PublicKeyJwk map[string]interface{} `json:"publicKeyJwk,omitempty"`
	PublicKeyHex string                 `json:"publicKeyHex,omitempty"`
}

// NewDIDWebRegistry creates a new did:web trust registry.
//
// The registry uses SafeHTTPClient with SSRF protection that blocks requests
// to private/internal IP addresses by default. This can be overridden with
// AllowPrivateIPs for testing or internal deployments.
func NewDIDWebRegistry(config Config) (*DIDWebRegistry, error) {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	description := config.Description
	if description == "" {
		description = "DID Web Method (did:web) Registry"
	}

	// Use SafeHTTPClient with SSRF protection
	// See ADR 0012: SSRF Mitigation Strategy
	httpClient := registry.NewSafeHTTPClient(registry.SafeClientConfig{
		Timeout:            timeout,
		AllowHTTP:          config.AllowHTTP,
		AllowPrivateIPs:    config.AllowPrivateIPs,
		InsecureSkipVerify: config.InsecureSkipVerify,
	})

	return &DIDWebRegistry{
		httpClient:  httpClient,
		timeout:     timeout,
		description: description,
		allowHTTP:   config.AllowHTTP,
	}, nil
}

// Evaluate implements TrustRegistry.Evaluate by resolving did:web DIDs and validating key bindings.
//
// For resolution-only requests (where IsResolutionOnlyRequest() returns true), the method
// returns decision=true with the resolved DID document in trust_metadata, without validating
// a specific key binding.
//
// For full trust evaluation requests, the method validates that the provided key matches
// one of the verification methods in the resolved DID document.
func (r *DIDWebRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	startTime := time.Now()

	// Validate that subject.id is a did:web identifier
	if !strings.HasPrefix(req.Subject.ID, "did:web:") {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error": fmt.Sprintf("subject.id must be a did:web identifier, got: %s", req.Subject.ID),
				},
			},
		}, nil
	}

	// Extract the base DID without fragment (e.g., "did:web:example.com#key-1" -> "did:web:example.com")
	// The fragment identifies a specific verification method within the DID document
	baseDID := req.Subject.ID
	if idx := strings.Index(baseDID, "#"); idx != -1 {
		baseDID = baseDID[:idx]
	}

	// Resolve the DID document using the base DID
	didDoc, err := r.resolveDID(ctx, baseDID)
	if err != nil {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error":         fmt.Sprintf("failed to resolve DID: %v", err),
					"resolution_ms": time.Since(startTime).Milliseconds(),
				},
			},
		}, nil
	}

	// Verify that the DID document ID matches the base DID (without fragment)
	if didDoc.ID != baseDID {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error":       "DID document ID does not match requested DID",
					"requested":   baseDID,
					"document_id": didDoc.ID,
				},
			},
		}, nil
	}

	// Check policy constraints from request context (set by policy mapper)
	if denial := r.checkPolicyConstraints(req, didDoc, baseDID, startTime); denial != nil {
		return denial, nil
	}

	// Check if this is a resolution-only request
	if req.IsResolutionOnlyRequest() {
		// For resolution-only requests, return the DID document in trust_metadata
		return r.buildResolutionOnlyResponse(didDoc, startTime), nil
	}

	// For full trust evaluation, validate the key binding
	matched, matchedMethod, err := r.verifyKeyBinding(req, didDoc)
	if err != nil {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error":         err.Error(),
					"resolution_ms": time.Since(startTime).Milliseconds(),
				},
			},
		}, nil
	}

	if !matched {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error":                "no matching verification method found in DID document",
					"verification_methods": len(didDoc.VerificationMethod),
					"resolution_ms":        time.Since(startTime).Milliseconds(),
				},
			},
		}, nil
	}

	// Success - key binding is valid
	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"did":                  didDoc.ID,
				"verification_method":  matchedMethod.ID,
				"key_type":             matchedMethod.Type,
				"resolution_ms":        time.Since(startTime).Milliseconds(),
				"verification_methods": len(didDoc.VerificationMethod),
			},
			TrustMetadata: r.didDocumentToTrustMetadata(didDoc),
		},
	}, nil
}

// buildResolutionOnlyResponse creates an EvaluationResponse for resolution-only requests.
// The response includes decision=true and the DID document in trust_metadata.
func (r *DIDWebRegistry) buildResolutionOnlyResponse(didDoc *DIDDocument, startTime time.Time) *authzen.EvaluationResponse {
	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"did":                  didDoc.ID,
				"resolution_only":      true,
				"resolution_ms":        time.Since(startTime).Milliseconds(),
				"verification_methods": len(didDoc.VerificationMethod),
			},
			TrustMetadata: r.didDocumentToTrustMetadata(didDoc),
		},
	}
}

// didDocumentToTrustMetadata converts a DIDDocument to the trust_metadata format.
// Returns the full DID document structure as specified in W3C DID Core.
func (r *DIDWebRegistry) didDocumentToTrustMetadata(didDoc *DIDDocument) map[string]interface{} {
	trustMeta := map[string]interface{}{
		"@context": didDoc.Context,
		"id":       didDoc.ID,
	}

	if didDoc.Controller != nil {
		trustMeta["controller"] = didDoc.Controller
	}

	if len(didDoc.VerificationMethod) > 0 {
		verificationMethods := make([]map[string]interface{}, len(didDoc.VerificationMethod))
		for i, vm := range didDoc.VerificationMethod {
			method := map[string]interface{}{
				"id":         vm.ID,
				"type":       vm.Type,
				"controller": vm.Controller,
			}
			if vm.PublicKeyJwk != nil {
				method["publicKeyJwk"] = vm.PublicKeyJwk
			}
			if vm.PublicKeyHex != "" {
				method["publicKeyHex"] = vm.PublicKeyHex
			}
			verificationMethods[i] = method
		}
		trustMeta["verificationMethod"] = verificationMethods
	}

	if didDoc.Authentication != nil {
		trustMeta["authentication"] = didDoc.Authentication
	}
	if didDoc.AssertionMethod != nil {
		trustMeta["assertionMethod"] = didDoc.AssertionMethod
	}
	if didDoc.KeyAgreement != nil {
		trustMeta["keyAgreement"] = didDoc.KeyAgreement
	}
	if didDoc.Service != nil {
		trustMeta["service"] = didDoc.Service
	}

	return trustMeta
}

// resolveDID resolves a did:web identifier to a DID document.
// Implements the resolution algorithm from https://w3c-ccg.github.io/did-method-web/#read-resolve
func (r *DIDWebRegistry) resolveDID(ctx context.Context, did string) (*DIDDocument, error) {
	// Parse the DID to extract the domain and path
	httpURL, err := didToHTTPURL(did)
	if err != nil {
		return nil, fmt.Errorf("invalid did:web identifier: %w", err)
	}

	// For testing: allow HTTP instead of HTTPS
	if r.allowHTTP {
		httpURL = strings.Replace(httpURL, "https://", "http://", 1)
	}

	// Create HTTP request with context
	req, err := http.NewRequestWithContext(ctx, "GET", httpURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	req.Header.Set("Accept", "application/did+json, application/json")
	req.Header.Set("User-Agent", "go-trust/1.0")

	// Perform the HTTP GET request
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // Body close error is not actionable

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP request returned status %d", resp.StatusCode)
	}

	// Read and parse the response body (limited to prevent unbounded memory use)
	body, err := registry.ReadLimitedBody(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var didDoc DIDDocument
	if err := json.Unmarshal(body, &didDoc); err != nil {
		return nil, fmt.Errorf("failed to parse DID document: %w", err)
	}

	return &didDoc, nil
}

// didToHTTPURL converts a did:web identifier to an HTTPS URL.
// Implements the conversion algorithm from the spec:
// 1. Replace ":" with "/" in the method-specific identifier
// 2. Percent-decode any port specifications
// 3. Prepend "https://"
// 4. Append "/.well-known" if no path specified
// 5. Append "/did.json"
func didToHTTPURL(did string) (string, error) {
	// Remove "did:web:" prefix
	if !strings.HasPrefix(did, "did:web:") {
		return "", fmt.Errorf("not a did:web identifier")
	}
	methodSpecificID := strings.TrimPrefix(did, "did:web:")

	// Step 1: Handle percent-encoded port colons
	// Replace %3A with a temporary placeholder before splitting
	methodSpecificID = strings.ReplaceAll(methodSpecificID, "%3A", "___PORT___")
	methodSpecificID = strings.ReplaceAll(methodSpecificID, "%3a", "___PORT___")

	// Step 2: Split by colon to separate domain and path components
	parts := strings.Split(methodSpecificID, ":")

	// Step 3: First part is the domain name
	// Replace the port placeholder back to a colon
	domain := strings.ReplaceAll(parts[0], "___PORT___", ":")

	// Step 4: Build the path from remaining parts
	var path string
	if len(parts) > 1 {
		// Join remaining parts with "/" to form the path
		// Also handle any placeholders in the path parts
		pathParts := []string{}
		for _, part := range parts[1:] {
			cleaned := strings.ReplaceAll(part, "___PORT___", ":")
			if cleaned != "" {
				pathParts = append(pathParts, cleaned)
			}
		}
		if len(pathParts) > 0 {
			path = "/" + strings.Join(pathParts, "/")
		} else {
			path = "/.well-known"
		}
	} else {
		// No path specified, use .well-known
		path = "/.well-known"
	}

	// Step 5: Construct the HTTPS URL
	httpURL := fmt.Sprintf("https://%s%s/did.json", domain, path)

	// Validate the URL
	if _, err := url.Parse(httpURL); err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	return httpURL, nil
}

// verifyKeyBinding checks if the key in the request matches a verification method in the DID document.
func (r *DIDWebRegistry) verifyKeyBinding(req *authzen.EvaluationRequest, didDoc *DIDDocument) (bool, *VerificationMethod, error) {
	// For JWK resource type, compare the JWK directly
	if req.Resource.Type == "jwk" {
		return r.matchJWK(req.Resource.Key, didDoc)
	}

	// For x5c, we would need to extract the public key and compare
	// This is more complex and could be added later
	return false, nil, fmt.Errorf("resource type %s not yet supported for did:web", req.Resource.Type)
}

// matchJWK attempts to match a JWK from the request against verification methods in the DID document.
func (r *DIDWebRegistry) matchJWK(keyArray []interface{}, didDoc *DIDDocument) (bool, *VerificationMethod, error) {
	if len(keyArray) == 0 {
		return false, nil, fmt.Errorf("empty key array")
	}

	// The key should be a JWK object
	requestJWK, ok := keyArray[0].(map[string]interface{})
	if !ok {
		return false, nil, fmt.Errorf("invalid JWK format")
	}

	// Compare against each verification method
	for i := range didDoc.VerificationMethod {
		vm := &didDoc.VerificationMethod[i]
		if vm.PublicKeyJwk == nil {
			continue
		}

		// Compare key fields
		if registry.JWKsMatch(requestJWK, vm.PublicKeyJwk) {
			return true, vm, nil
		}
	}

	return false, nil, nil
}

// checkPolicyConstraints validates DID policy constraints from request context.
// These constraints are injected by the policy mapper based on role (action.name).
func (r *DIDWebRegistry) checkPolicyConstraints(req *authzen.EvaluationRequest, didDoc *DIDDocument, baseDID string, startTime time.Time) *authzen.EvaluationResponse {
	if req.Context == nil {
		return nil
	}

	// Check allowed_domains: restrict DIDs to specific domains
	if allowedDomains := extractStringSlice(req.Context, "allowed_domains"); len(allowedDomains) > 0 {
		domain := extractDomainFromDIDWeb(baseDID)
		if !matchesDomain(domain, allowedDomains) {
			return &authzen.EvaluationResponse{
				Decision: false,
				Context: &authzen.EvaluationResponseContext{
					Reason: map[string]interface{}{
						"error":           "DID domain not in allowed domains for this role",
						"domain":          domain,
						"allowed_domains": allowedDomains,
						"resolution_ms":   time.Since(startTime).Milliseconds(),
					},
				},
			}
		}
	}

	// Check required_services: DID document must have specific service types
	if requiredServices := extractStringSlice(req.Context, "required_services"); len(requiredServices) > 0 {
		if !hasRequiredServices(didDoc.Service, requiredServices) {
			return &authzen.EvaluationResponse{
				Decision: false,
				Context: &authzen.EvaluationResponseContext{
					Reason: map[string]interface{}{
						"error":             "DID document missing required services for this role",
						"required_services": requiredServices,
						"resolution_ms":     time.Since(startTime).Milliseconds(),
					},
				},
			}
		}
	}

	return nil
}

// extractStringSlice extracts a []string from a context map value.
func extractStringSlice(ctx map[string]interface{}, key string) []string {
	v, ok := ctx[key]
	if !ok {
		return nil
	}
	switch s := v.(type) {
	case []string:
		return s
	case []interface{}:
		result := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}
	return nil
}

// extractDomainFromDIDWeb extracts the domain from a did:web identifier.
func extractDomainFromDIDWeb(did string) string {
	// Remove "did:web:" prefix
	if !strings.HasPrefix(did, "did:web:") {
		return ""
	}
	rest := strings.TrimPrefix(did, "did:web:")
	// Split by colon - first part is the domain (with %3A for port)
	parts := strings.SplitN(rest, ":", 2)
	domain := parts[0]
	// Decode percent-encoded port
	domain = strings.ReplaceAll(domain, "%3A", ":")
	domain = strings.ReplaceAll(domain, "%3a", ":")
	return domain
}

// matchesDomain checks if a domain matches any of the allowed domains.
// Supports wildcards: "*.example.com" matches "sub.example.com".
func matchesDomain(domain string, allowedDomains []string) bool {
	for _, allowed := range allowedDomains {
		if allowed == domain {
			return true
		}
		// Wildcard matching: *.example.com matches sub.example.com
		if strings.HasPrefix(allowed, "*.") {
			suffix := allowed[1:] // ".example.com"
			if strings.HasSuffix(domain, suffix) && domain != suffix[1:] {
				return true
			}
		}
	}
	return false
}

// hasRequiredServices checks if the DID document services include all required service types.
func hasRequiredServices(service interface{}, requiredTypes []string) bool {
	if service == nil {
		return false
	}

	// Services can be an array of service entries
	services, ok := service.([]interface{})
	if !ok {
		return false
	}

	// Build set of present service types
	presentTypes := make(map[string]bool)
	for _, svc := range services {
		if svcMap, ok := svc.(map[string]interface{}); ok {
			if svcType, ok := svcMap["type"].(string); ok {
				presentTypes[svcType] = true
			}
		}
	}

	// Check all required types are present
	for _, required := range requiredTypes {
		if !presentTypes[required] {
			return false
		}
	}
	return true
}

// SupportedResourceTypes returns the resource types this registry can handle.
func (r *DIDWebRegistry) SupportedResourceTypes() []string {
	return []string{"jwk"} // x5c support could be added later
}

// SupportsResolutionOnly returns true for did:web registry.
// The did:web method supports resolution-only requests where clients can
// retrieve DID documents without validating a specific key binding.
// This enables use as a DID resolver via the AuthZEN protocol.
func (r *DIDWebRegistry) SupportsResolutionOnly() bool {
	return true
}

// Info returns metadata about this registry.
func (r *DIDWebRegistry) Info() registry.RegistryInfo {
	return registry.RegistryInfo{
		Name:        "didweb-registry",
		Type:        "did:web",
		Description: r.description,
		Version:     "1.0.0",
		TrustAnchors: []string{
			"HTTPS/TLS certificate validation",
			"Domain-based trust (did:web method)",
		},
	}
}

// Healthy returns true if the registry is operational.
func (r *DIDWebRegistry) Healthy() bool {
	return r.httpClient != nil
}

// Refresh is a no-op for did:web since DIDs are resolved on-demand.
func (r *DIDWebRegistry) Refresh(ctx context.Context) error {
	// No cached data to refresh for did:web
	return nil
}

// SetHTTPClient sets a custom HTTP client for the registry.
// This is useful for testing with mock servers or custom transport configurations.
func (r *DIDWebRegistry) SetHTTPClient(client *http.Client) {
	r.httpClient = client
}
