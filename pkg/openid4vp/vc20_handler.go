package openid4vp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/vc20/credential"
	ecdsaSuite "github.com/SUNET/vc/pkg/vc20/crypto/ecdsa"
	eddsaSuite "github.com/SUNET/vc/pkg/vc20/crypto/eddsa"
)

// VC20Format identifiers per OpenID4VC spec Appendix A
const (
	FormatLdpVC    = "ldp_vc"     // VC Data Model 1.1 with Data Integrity
	FormatVC20JSON = "vc+ld+json" // VC Data Model 2.0 with Data Integrity
)

// Supported cryptosuites
const (
	CryptosuiteECDSA2019 = "ecdsa-rdfc-2019"
	CryptosuiteECDSASd   = "ecdsa-sd-2023"
	CryptosuiteEdDSA2022 = "eddsa-rdfc-2022"
)

// VC20KeyResolver resolves verification method URIs to public keys.
// Implementations can resolve DIDs (did:key, did:web, did:jwk, etc.),
// fetch JWKS, or use go-trust for policy-based resolution.
type VC20KeyResolver interface {
	// ResolveKey resolves a verification method to a public key.
	// verificationMethod can be:
	//   - Full DID URL: "did:key:z6Mk...#key-1"
	//   - DID with fragment: "did:web:example.com#keys-1"
	//   - HTTP URL: "https://example.com/keys/1"
	// Returns crypto.PublicKey which can be *ecdsa.PublicKey or ed25519.PublicKey
	ResolveKey(ctx context.Context, verificationMethod string) (crypto.PublicKey, error)
}

// StaticVC20KeyResolver is a simple key resolver that returns a fixed key.
type StaticVC20KeyResolver struct {
	Key crypto.PublicKey
}

// ResolveKey returns the static key regardless of verification method.
func (r *StaticVC20KeyResolver) ResolveKey(ctx context.Context, verificationMethod string) (crypto.PublicKey, error) {
	if r.Key == nil {
		return nil, errors.New("no key configured")
	}
	return r.Key, nil
}

// VC20Handler handles W3C VC 2.0 Data Integrity credentials in OpenID4VP flows.
type VC20Handler struct {
	keyResolver     VC20KeyResolver
	trustedIssuers  map[string]bool
	checkRevocation bool
	clock           func() time.Time
	allowedSkew     time.Duration
	signerConfig    *VC20SignerConfig
}

// VC20HandlerOption configures a VC20Handler.
type VC20HandlerOption func(*VC20Handler)

// WithVC20KeyResolver sets the key resolver for VC20 verification.
func WithVC20KeyResolver(resolver VC20KeyResolver) VC20HandlerOption {
	return func(h *VC20Handler) {
		h.keyResolver = resolver
	}
}

// WithVC20StaticKey sets a static public key for VC20 verification.
func WithVC20StaticKey(key crypto.PublicKey) VC20HandlerOption {
	return func(h *VC20Handler) {
		h.keyResolver = &StaticVC20KeyResolver{Key: key}
	}
}

// WithVC20TrustedIssuers sets the list of trusted issuers.
func WithVC20TrustedIssuers(issuers []string) VC20HandlerOption {
	return func(h *VC20Handler) {
		for _, iss := range issuers {
			h.trustedIssuers[iss] = true
		}
	}
}

// WithVC20RevocationCheck enables credential status checking.
func WithVC20RevocationCheck(check bool) VC20HandlerOption {
	return func(h *VC20Handler) {
		h.checkRevocation = check
	}
}

// WithVC20Clock sets the clock function for time validation.
func WithVC20Clock(clock func() time.Time) VC20HandlerOption {
	return func(h *VC20Handler) {
		h.clock = clock
	}
}

// WithVC20AllowedSkew sets the allowed clock skew for time validation.
func WithVC20AllowedSkew(skew time.Duration) VC20HandlerOption {
	return func(h *VC20Handler) {
		h.allowedSkew = skew
	}
}

// NewVC20Handler creates a new W3C VC 2.0 handler for OpenID4VP.
func NewVC20Handler(opts ...VC20HandlerOption) (*VC20Handler, error) {
	h := &VC20Handler{
		trustedIssuers: make(map[string]bool),
		clock:          time.Now,
		allowedSkew:    5 * time.Minute,
	}

	for _, opt := range opts {
		opt(h)
	}

	return h, nil
}

// VC20VerificationResult contains the result of W3C VC verification.
type VC20VerificationResult struct {
	// Credential metadata
	ID             string     `json:"id,omitempty"`
	Issuer         string     `json:"issuer"`
	Subject        string     `json:"subject,omitempty"`
	Types          []string   `json:"type"`
	IssuanceDate   time.Time  `json:"validFrom"`
	ExpirationDate *time.Time `json:"validUntil,omitempty"`

	// Credential content
	CredentialSubject map[string]any `json:"credentialSubject"`

	// Proof metadata
	ProofType          string    `json:"proofType"`
	Cryptosuite        string    `json:"cryptosuite"`
	VerificationMethod string    `json:"verificationMethod"`
	ProofPurpose       string    `json:"proofPurpose"`
	ProofCreated       time.Time `json:"proofCreated"`

	// Selective disclosure info (for ecdsa-sd-2023)
	IsSelectiveDisclosure bool     `json:"isSelectiveDisclosure"`
	DisclosedPaths        []string `json:"disclosedPaths,omitempty"`

	// All claims as map for generic access
	Claims map[string]any `json:"claims"`

	// Raw credential JSON
	RawCredential json.RawMessage `json:"rawCredential"`
}

// VerifyAndExtract verifies a W3C VC VP token and extracts claims.
func (h *VC20Handler) VerifyAndExtract(ctx context.Context, vpToken string) (*VC20VerificationResult, error) {
	if vpToken == "" {
		return nil, errors.New("VP token is empty")
	}

	// 1. Decode VP token (may be base64url encoded or plain JSON)
	originalBytes, err := h.decodeVPToken(vpToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decode VP token: %w", err)
	}

	// Keep original bytes for verification with vc20 library
	credBytes := originalBytes

	// 2. Parse credential JSON - handle both compact and expanded JSON-LD formats
	var credMap map[string]any

	// Try to unmarshal as object first
	if err := json.Unmarshal(credBytes, &credMap); err != nil {
		// Try as expanded JSON-LD (array format)
		var expanded []any
		if err2 := json.Unmarshal(credBytes, &expanded); err2 != nil {
			return nil, fmt.Errorf("failed to parse credential JSON: %w (also tried array: %v)", err, err2)
		}
		// Find the credential node in the expanded format for result extraction
		// Keep original bytes for vc20 library verification
		credMap, err = h.extractCredentialFromExpanded(expanded)
		if err != nil {
			return nil, fmt.Errorf("failed to extract credential from expanded JSON-LD: %w", err)
		}
	}

	// 3. Check if this is a VP or VC
	// If it's a VP, extract the embedded credential
	if types, ok := credMap["type"].([]any); ok {
		for _, t := range types {
			if t == "VerifiablePresentation" {
				credBytes, credMap, err = h.extractCredentialFromVP(credMap)
				if err != nil {
					return nil, fmt.Errorf("failed to extract credential from VP: %w", err)
				}
				break
			}
		}
	}

	// 4. Extract and validate issuer
	issuer, err := h.extractIssuer(credMap)
	if err != nil {
		return nil, err
	}

	// Check trusted issuers if configured
	if len(h.trustedIssuers) > 0 && !h.trustedIssuers[issuer] {
		return nil, fmt.Errorf("issuer %s is not trusted", issuer)
	}

	// 5. Extract proof
	proof, err := h.extractProof(credMap)
	if err != nil {
		return nil, err
	}

	// 6. Resolve verification method to public key
	if h.keyResolver == nil {
		return nil, errors.New("no key resolver configured")
	}

	vm, _ := proof["verificationMethod"].(string)
	if vm == "" {
		return nil, errors.New("proof missing verificationMethod")
	}

	pubKey, err := h.keyResolver.ResolveKey(ctx, vm)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve public key: %w", err)
	}

	// 7. Determine cryptosuite and verify with appropriate key type
	cryptosuite, _ := proof["cryptosuite"].(string)
	if cryptosuite == "" {
		return nil, errors.New("proof missing cryptosuite")
	}

	switch cryptosuite {
	case CryptosuiteECDSA2019:
		ecdsaKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("cryptosuite %s requires ECDSA key, got %T", cryptosuite, pubKey)
		}
		return h.verifyECDSA2019(ctx, credBytes, credMap, proof, ecdsaKey)

	case CryptosuiteECDSASd:
		ecdsaKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("cryptosuite %s requires ECDSA key, got %T", cryptosuite, pubKey)
		}
		return h.verifyECDSASd2023(ctx, credBytes, credMap, proof, ecdsaKey)

	case CryptosuiteEdDSA2022:
		ed25519Key, ok := pubKey.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("cryptosuite %s requires Ed25519 key, got %T", cryptosuite, pubKey)
		}
		return h.verifyEdDSA2022(ctx, credBytes, credMap, proof, ed25519Key)

	default:
		return nil, fmt.Errorf("unsupported cryptosuite: %s", cryptosuite)
	}
}

// decodeVPToken decodes the VP token from base64url or returns plain JSON.
func (h *VC20Handler) decodeVPToken(vpToken string) ([]byte, error) {
	// Check if it looks like JSON (object or array)
	trimmed := strings.TrimSpace(vpToken)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return []byte(vpToken), nil
	}

	// Try base64url decode
	decoded, err := base64.RawURLEncoding.DecodeString(vpToken)
	if err != nil {
		// Try standard base64
		decoded, err = base64.StdEncoding.DecodeString(vpToken)
		if err != nil {
			return nil, fmt.Errorf("failed to base64 decode VP token: %w", err)
		}
	}
	return decoded, nil
}

// extractCredentialFromVP extracts the first credential from a Verifiable Presentation.
func (h *VC20Handler) extractCredentialFromVP(vp map[string]any) ([]byte, map[string]any, error) {
	vc := vp["verifiableCredential"]
	if vc == nil {
		return nil, nil, errors.New("VP missing verifiableCredential")
	}

	// Handle array or single credential
	var credMap map[string]any
	switch v := vc.(type) {
	case []any:
		if len(v) == 0 {
			return nil, nil, errors.New("VP verifiableCredential array is empty")
		}
		var ok bool
		credMap, ok = v[0].(map[string]any)
		if !ok {
			return nil, nil, errors.New("VP verifiableCredential is not a valid credential object")
		}
	case map[string]any:
		credMap = v
	default:
		return nil, nil, fmt.Errorf("VP verifiableCredential has unexpected type: %T", vc)
	}

	credBytes, err := json.Marshal(credMap)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal credential: %w", err)
	}

	return credBytes, credMap, nil
}

// extractCredentialFromExpanded extracts credential data from expanded JSON-LD format.
// Expanded JSON-LD is an array of nodes, we need to find the credential node.
func (h *VC20Handler) extractCredentialFromExpanded(expanded []any) (map[string]any, error) {
	// W3C VC expanded JSON-LD URIs
	const (
		vcType    = "https://www.w3.org/2018/credentials#VerifiableCredential"
		issuerURI = "https://www.w3.org/2018/credentials#issuer"
		proofURI  = "https://w3id.org/security#proof"
	)

	// Find the credential node (one with VerifiableCredential type)
	for _, node := range expanded {
		nodeMap, ok := node.(map[string]any)
		if !ok {
			continue
		}

		// Check if this node has VerifiableCredential type
		types, ok := nodeMap["@type"].([]any)
		if !ok {
			continue
		}

		isVC := false
		for _, t := range types {
			if t == vcType {
				isVC = true
				break
			}
		}

		if !isVC {
			continue
		}

		// Found the credential node - extract and transform to compact form
		result := make(map[string]any)
		result["@context"] = []string{"https://www.w3.org/ns/credentials/v2"}

		// Extract @id
		if id, ok := nodeMap["@id"].(string); ok {
			result["id"] = id
		}

		// Extract types (convert from full URIs to compact)
		var typeList []string
		for _, t := range types {
			ts, ok := t.(string)
			if !ok {
				continue
			}
			// Convert full URIs to common names
			switch ts {
			case vcType:
				typeList = append(typeList, "VerifiableCredential")
			default:
				// Keep as-is or try to extract local name
				typeList = append(typeList, ts)
			}
		}
		result["type"] = typeList

		// Extract issuer
		if issuerData, ok := nodeMap[issuerURI].([]any); ok && len(issuerData) > 0 {
			if issuerNode, ok := issuerData[0].(map[string]any); ok {
				if issuerID, ok := issuerNode["@id"].(string); ok {
					result["issuer"] = issuerID
				}
			}
		}

		// Extract proof
		if proofData, ok := nodeMap[proofURI].([]any); ok && len(proofData) > 0 {
			if proofNode, ok := proofData[0].(map[string]any); ok {
				// Look up the proof in expanded array (it's often a reference)
				if proofRef, ok := proofNode["@id"].(string); ok {
					// Find the proof node
					for _, pn := range expanded {
						proofMap, ok := pn.(map[string]any)
						if !ok {
							continue
						}
						// Look for @graph which contains the actual proof
						if graph, ok := proofMap["@graph"].([]any); ok && len(graph) > 0 {
							if actualProof, ok := graph[0].(map[string]any); ok {
								result["proof"] = h.extractProofFromExpanded(actualProof)
								break
							}
						}
						// Direct proof reference
						if proofMap["@id"] == proofRef {
							result["proof"] = h.extractProofFromExpanded(proofMap)
							break
						}
					}
				}
			}
		}

		// Extract credentialSubject - simplified
		const csURI = "https://www.w3.org/2018/credentials#credentialSubject"
		if csData, ok := nodeMap[csURI].([]any); ok && len(csData) > 0 {
			if csNode, ok := csData[0].(map[string]any); ok {
				cs := make(map[string]any)
				if id, ok := csNode["@id"].(string); ok {
					cs["id"] = id
				}
				result["credentialSubject"] = cs
			}
		}

		// Extract validFrom/validUntil
		const validFromURI = "https://www.w3.org/2018/credentials#validFrom"
		const validUntilURI = "https://www.w3.org/2018/credentials#validUntil"
		if vfData, ok := nodeMap[validFromURI].([]any); ok && len(vfData) > 0 {
			if vfNode, ok := vfData[0].(map[string]any); ok {
				if val, ok := vfNode["@value"].(string); ok {
					result["validFrom"] = val
				}
			}
		}
		if vuData, ok := nodeMap[validUntilURI].([]any); ok && len(vuData) > 0 {
			if vuNode, ok := vuData[0].(map[string]any); ok {
				if val, ok := vuNode["@value"].(string); ok {
					result["validUntil"] = val
				}
			}
		}

		return result, nil
	}

	return nil, errors.New("no VerifiableCredential found in expanded JSON-LD")
}

// extractProofFromExpanded extracts proof data from expanded JSON-LD proof node.
func (h *VC20Handler) extractProofFromExpanded(proofNode map[string]any) map[string]any {
	proof := make(map[string]any)

	// Extract type
	if types, ok := proofNode["@type"].([]any); ok && len(types) > 0 {
		if t, ok := types[0].(string); ok {
			if t == "https://w3id.org/security#DataIntegrityProof" {
				proof["type"] = "DataIntegrityProof"
			} else {
				proof["type"] = t
			}
		}
	}

	// Extract cryptosuite
	const cryptosuiteURI = "https://w3id.org/security#cryptosuite"
	if csData, ok := proofNode[cryptosuiteURI].([]any); ok && len(csData) > 0 {
		if csNode, ok := csData[0].(map[string]any); ok {
			if val, ok := csNode["@value"].(string); ok {
				proof["cryptosuite"] = val
			}
		}
	}

	// Extract verificationMethod
	const vmURI = "https://w3id.org/security#verificationMethod"
	if vmData, ok := proofNode[vmURI].([]any); ok && len(vmData) > 0 {
		if vmNode, ok := vmData[0].(map[string]any); ok {
			if id, ok := vmNode["@id"].(string); ok {
				proof["verificationMethod"] = id
			}
		}
	}

	// Extract proofPurpose
	const ppURI = "https://w3id.org/security#proofPurpose"
	if ppData, ok := proofNode[ppURI].([]any); ok && len(ppData) > 0 {
		if ppNode, ok := ppData[0].(map[string]any); ok {
			if id, ok := ppNode["@id"].(string); ok {
				// Convert full URI to compact form
				if strings.HasSuffix(id, "assertionMethod") {
					proof["proofPurpose"] = "assertionMethod"
				} else {
					proof["proofPurpose"] = id
				}
			}
		}
	}

	// Extract created
	const createdURI = "http://purl.org/dc/terms/created"
	if cData, ok := proofNode[createdURI].([]any); ok && len(cData) > 0 {
		if cNode, ok := cData[0].(map[string]any); ok {
			if val, ok := cNode["@value"].(string); ok {
				proof["created"] = val
			}
		}
	}

	// Extract proofValue
	const pvURI = "https://w3id.org/security#proofValue"
	if pvData, ok := proofNode[pvURI].([]any); ok && len(pvData) > 0 {
		if pvNode, ok := pvData[0].(map[string]any); ok {
			if val, ok := pvNode["@value"].(string); ok {
				proof["proofValue"] = val
			}
		}
	}

	return proof
}

// extractIssuer extracts the issuer from a credential.
func (h *VC20Handler) extractIssuer(cred map[string]any) (string, error) {
	issuer := cred["issuer"]
	if issuer == nil {
		return "", errors.New("credential missing issuer")
	}

	switch v := issuer.(type) {
	case string:
		return v, nil
	case map[string]any:
		if id, ok := v["id"].(string); ok {
			return id, nil
		}
		return "", errors.New("issuer object missing id")
	default:
		return "", fmt.Errorf("issuer has unexpected type: %T", issuer)
	}
}

// extractProof extracts the proof from a credential.
func (h *VC20Handler) extractProof(cred map[string]any) (map[string]any, error) {
	proof := cred["proof"]
	if proof == nil {
		return nil, errors.New("credential missing proof")
	}

	// Handle array of proofs (take first)
	if proofArray, ok := proof.([]any); ok {
		if len(proofArray) == 0 {
			return nil, errors.New("credential proof array is empty")
		}
		proof = proofArray[0]
	}

	proofMap, ok := proof.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("proof has unexpected type: %T", proof)
	}

	return proofMap, nil
}

// verifyECDSA2019 verifies a credential with ecdsa-rdfc-2019 cryptosuite.
func (h *VC20Handler) verifyECDSA2019(
	ctx context.Context,
	credBytes []byte,
	credMap map[string]any,
	proof map[string]any,
	pubKey *ecdsa.PublicKey,
) (*VC20VerificationResult, error) {
	// Create RDF credential
	rdfCred, err := credential.NewRDFCredentialFromJSON(credBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create RDF credential: %w", err)
	}

	// Verify using the standard suite
	suite := ecdsaSuite.NewSuite()
	if err := suite.Verify(rdfCred, pubKey); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Build result
	return h.buildResult(credBytes, credMap, proof, false)
}

// verifyECDSASd2023 verifies a credential with ecdsa-sd-2023 cryptosuite.
func (h *VC20Handler) verifyECDSASd2023(
	ctx context.Context,
	credBytes []byte,
	credMap map[string]any,
	proof map[string]any,
	pubKey *ecdsa.PublicKey,
) (*VC20VerificationResult, error) {
	// Create RDF credential
	rdfCred, err := credential.NewRDFCredentialFromJSON(credBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create RDF credential: %w", err)
	}

	// Verify using the SD suite
	sdSuite := ecdsaSuite.NewSdSuite()
	if err := sdSuite.Verify(rdfCred, pubKey); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Build result
	return h.buildResult(credBytes, credMap, proof, true)
}

// verifyEdDSA2022 verifies a credential with eddsa-rdfc-2022 cryptosuite.
func (h *VC20Handler) verifyEdDSA2022(
	ctx context.Context,
	credBytes []byte,
	credMap map[string]any,
	proof map[string]any,
	pubKey ed25519.PublicKey,
) (*VC20VerificationResult, error) {
	// Create RDF credential
	rdfCred, err := credential.NewRDFCredentialFromJSON(credBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create RDF credential: %w", err)
	}

	// Verify using the EdDSA suite
	suite := eddsaSuite.NewSuite()
	if err := suite.Verify(rdfCred, pubKey); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Build result
	return h.buildResult(credBytes, credMap, proof, false)
}

// buildResult builds the verification result from credential data.
func (h *VC20Handler) buildResult(
	credBytes []byte,
	credMap map[string]any,
	proof map[string]any,
	isSD bool,
) (*VC20VerificationResult, error) {
	result := &VC20VerificationResult{
		Claims:                credMap,
		RawCredential:         credBytes,
		IsSelectiveDisclosure: isSD,
	}

	// Extract credential ID
	if id, ok := credMap["id"].(string); ok {
		result.ID = id
	}

	// Extract issuer
	result.Issuer, _ = h.extractIssuer(credMap)

	// Extract types
	if types, ok := credMap["type"].([]any); ok {
		for _, t := range types {
			if ts, ok := t.(string); ok {
				result.Types = append(result.Types, ts)
			}
		}
	}

	// Extract credential subject
	if cs, ok := credMap["credentialSubject"].(map[string]any); ok {
		result.CredentialSubject = cs
		if id, ok := cs["id"].(string); ok {
			result.Subject = id
		}
	}

	// Extract dates
	if validFrom, ok := credMap["validFrom"].(string); ok {
		if t, err := time.Parse(time.RFC3339, validFrom); err == nil {
			result.IssuanceDate = t
		}
	} else if issuanceDate, ok := credMap["issuanceDate"].(string); ok {
		// VC 1.1 compatibility
		if t, err := time.Parse(time.RFC3339, issuanceDate); err == nil {
			result.IssuanceDate = t
		}
	}

	if validUntil, ok := credMap["validUntil"].(string); ok {
		if t, err := time.Parse(time.RFC3339, validUntil); err == nil {
			result.ExpirationDate = &t
		}
	} else if expirationDate, ok := credMap["expirationDate"].(string); ok {
		// VC 1.1 compatibility
		if t, err := time.Parse(time.RFC3339, expirationDate); err == nil {
			result.ExpirationDate = &t
		}
	}

	// Extract proof metadata
	result.ProofType, _ = proof["type"].(string)
	result.Cryptosuite, _ = proof["cryptosuite"].(string)
	result.VerificationMethod, _ = proof["verificationMethod"].(string)
	result.ProofPurpose, _ = proof["proofPurpose"].(string)

	if created, ok := proof["created"].(string); ok {
		if t, err := time.Parse(time.RFC3339, created); err == nil {
			result.ProofCreated = t
		}
	}

	// Validate time constraints
	now := h.clock()
	if !result.IssuanceDate.IsZero() {
		if now.Add(h.allowedSkew).Before(result.IssuanceDate) {
			return nil, fmt.Errorf("credential not yet valid (validFrom: %s)", result.IssuanceDate)
		}
	}
	if result.ExpirationDate != nil {
		if now.Add(-h.allowedSkew).After(*result.ExpirationDate) {
			return nil, fmt.Errorf("credential has expired (validUntil: %s)", *result.ExpirationDate)
		}
	}

	return result, nil
}

// GetClaims returns all claims from the credential.
func (r *VC20VerificationResult) GetClaims() map[string]any {
	return r.Claims
}

// GetCredentialSubject returns the credential subject claims.
func (r *VC20VerificationResult) GetCredentialSubject() map[string]any {
	return r.CredentialSubject
}

// VC20SignerConfig holds issuer signing configuration.
type VC20SignerConfig struct {
	// PrivateKey is the signing key (ecdsa.PrivateKey or ed25519.PrivateKey)
	PrivateKey crypto.PrivateKey
	// IssuerID is the DID or URI of the issuer (e.g., "did:web:example.com")
	IssuerID string
	// VerificationMethod is the full verification method URI (e.g., "did:web:example.com#key-1")
	VerificationMethod string
	// Cryptosuite specifies which suite to use: ecdsa-rdfc-2019, ecdsa-sd-2023, eddsa-rdfc-2022
	Cryptosuite string
}

// VC20CreateRequest contains parameters for creating a credential.
type VC20CreateRequest struct {
	// CredentialID is the unique ID for the credential (optional, generated if empty)
	CredentialID string
	// Types are the credential types (e.g., ["VerifiableCredential", "UniversityDegreeCredential"])
	Types []string
	// Subject is the credential subject (the entity the credential is about)
	Subject map[string]any
	// AdditionalContexts are extra JSON-LD contexts to include
	AdditionalContexts []string
	// ValidFrom is when the credential becomes valid (defaults to now)
	ValidFrom time.Time
	// ValidUntil is when the credential expires (optional)
	ValidUntil *time.Time
	// CredentialStatus for revocation (optional)
	CredentialStatus map[string]any
}

// VC20CreateResult contains the signed credential and metadata.
type VC20CreateResult struct {
	// CredentialJSON is the signed credential as JSON bytes
	CredentialJSON []byte
	// CredentialID is the credential's unique ID
	CredentialID string
	// Issuer is the issuer DID
	Issuer string
	// ValidFrom is when the credential is valid from
	ValidFrom time.Time
	// ValidUntil is when the credential expires (nil if no expiration)
	ValidUntil *time.Time
}

// WithVC20SignerConfig sets the signing configuration for credential issuance.
func WithVC20SignerConfig(config *VC20SignerConfig) VC20HandlerOption {
	return func(h *VC20Handler) {
		h.signerConfig = config
	}
}

// CreateCredential creates and signs a new W3C VC 2.0 Data Integrity credential.
func (h *VC20Handler) CreateCredential(ctx context.Context, req *VC20CreateRequest) (*VC20CreateResult, error) {
	if h.signerConfig == nil {
		return nil, errors.New("signer config not configured, use WithVC20SignerConfig")
	}
	if h.signerConfig.PrivateKey == nil {
		return nil, errors.New("private key not configured")
	}
	if h.signerConfig.IssuerID == "" {
		return nil, errors.New("issuer ID not configured")
	}
	if h.signerConfig.VerificationMethod == "" {
		return nil, errors.New("verification method not configured")
	}

	// Build credential JSON
	credJSON, err := h.buildCredentialJSON(req)
	if err != nil {
		return nil, fmt.Errorf("failed to build credential JSON: %w", err)
	}

	// Parse into RDFCredential
	cred, err := credential.NewRDFCredentialFromJSON(credJSON, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	// Sign based on cryptosuite
	var signedCred *credential.RDFCredential
	switch h.signerConfig.Cryptosuite {
	case CryptosuiteECDSA2019:
		signedCred, err = h.signECDSA2019(cred)
	case CryptosuiteECDSASd:
		signedCred, err = h.signECDSASd2023(cred)
	case CryptosuiteEdDSA2022:
		signedCred, err = h.signEdDSA2022(cred)
	default:
		return nil, fmt.Errorf("unsupported cryptosuite: %s", h.signerConfig.Cryptosuite)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to sign credential: %w", err)
	}

	// Get signed credential JSON
	signedJSON, err := signedCred.ToCompactJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize signed credential: %w", err)
	}

	// Build result
	result := &VC20CreateResult{
		CredentialJSON: signedJSON,
		CredentialID:   req.CredentialID,
		Issuer:         h.signerConfig.IssuerID,
		ValidFrom:      req.ValidFrom,
		ValidUntil:     req.ValidUntil,
	}

	return result, nil
}

// buildCredentialJSON builds the credential JSON structure.
func (h *VC20Handler) buildCredentialJSON(req *VC20CreateRequest) ([]byte, error) {
	// Start with W3C VC 2.0 context
	contexts := []any{credential.ContextV2}
	for _, ctx := range req.AdditionalContexts {
		contexts = append(contexts, ctx)
	}

	// Build types array
	types := []any{"VerifiableCredential"}
	for _, t := range req.Types {
		if t != "VerifiableCredential" {
			types = append(types, t)
		}
	}

	// Determine credential ID
	credID := req.CredentialID
	if credID == "" {
		credID = fmt.Sprintf("urn:uuid:%s", generateUUID())
	}

	// Build credential map
	cred := map[string]any{
		"@context":          contexts,
		"id":                credID,
		"type":              types,
		"issuer":            h.signerConfig.IssuerID,
		"credentialSubject": req.Subject,
	}

	// Set validFrom (defaults to now)
	validFrom := req.ValidFrom
	if validFrom.IsZero() {
		validFrom = time.Now().UTC()
	}
	cred["validFrom"] = validFrom.Format(time.RFC3339)

	// Set validUntil if provided
	if req.ValidUntil != nil {
		cred["validUntil"] = req.ValidUntil.Format(time.RFC3339)
	}

	// Add credential status if provided
	if req.CredentialStatus != nil {
		cred["credentialStatus"] = req.CredentialStatus
	}

	return json.Marshal(cred)
}

// signECDSA2019 signs a credential using ecdsa-rdfc-2019.
func (h *VC20Handler) signECDSA2019(cred *credential.RDFCredential) (*credential.RDFCredential, error) {
	key, ok := h.signerConfig.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ecdsa-rdfc-2019 requires ECDSA private key, got %T", h.signerConfig.PrivateKey)
	}

	suite := ecdsaSuite.NewSuite()
	return suite.Sign(context.Background(), cred, key, &ecdsaSuite.SignOptions{
		VerificationMethod: h.signerConfig.VerificationMethod,
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
	})
}

// signECDSASd2023 signs a credential using ecdsa-sd-2023.
func (h *VC20Handler) signECDSASd2023(cred *credential.RDFCredential) (*credential.RDFCredential, error) {
	key, ok := h.signerConfig.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ecdsa-sd-2023 requires ECDSA private key, got %T", h.signerConfig.PrivateKey)
	}

	sdSuite := ecdsaSuite.NewSdSuite()

	// Default to disclosing all mandatory paths (basic signing without selective disclosure)
	return sdSuite.Sign(cred, key, &ecdsaSuite.SdSignOptions{
		VerificationMethod: h.signerConfig.VerificationMethod,
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
		MandatoryPointers:  []string{},
	})
}

// signEdDSA2022 signs a credential using eddsa-rdfc-2022.
func (h *VC20Handler) signEdDSA2022(cred *credential.RDFCredential) (*credential.RDFCredential, error) {
	key, ok := h.signerConfig.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("eddsa-rdfc-2022 requires Ed25519 private key, got %T", h.signerConfig.PrivateKey)
	}

	suite := eddsaSuite.NewSuite()
	return suite.Sign(cred, key, &eddsaSuite.SignOptions{
		VerificationMethod: h.signerConfig.VerificationMethod,
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
	})
}

// generateUUID generates a random UUID v4.
func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Reader.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
