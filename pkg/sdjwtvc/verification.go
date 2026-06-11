package sdjwtvc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/trust"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirosfoundation/go-cryptoutil"
	"github.com/sirosfoundation/go-trust/pkg/trustapi"
)

// VerificationResult contains the result of SD-JWT verification
type VerificationResult struct {
	Valid            bool           // Overall validity
	Header           map[string]any // JWT header
	Claims           map[string]any // All claims (including disclosed)
	DisclosedClaims  map[string]any // Only the selectively disclosed claims
	Disclosures      []Disclosure   // Parsed disclosures
	VCTM             *VCTM          // Verifiable Credential Type Metadata
	KeyBindingValid  bool           // Whether KB-JWT is valid (if present)
	KeyBindingClaims map[string]any // KB-JWT claims (if present)
	Errors           []error        // Any validation errors
}

// Disclosure represents a parsed disclosure
type Disclosure struct {
	Salt  string // Random salt for privacy
	Claim string // Claim name
	Value any    // Claim value
	Raw   string // Raw disclosure string
	Hash  string // Base64url-encoded hash
}

// VerificationOptions contains options for verification
type VerificationOptions struct {
	// RequireKeyBinding: whether KB-JWT must be present
	RequireKeyBinding bool
	// ExpectedNonce: nonce to validate in KB-JWT (required if KB-JWT present)
	ExpectedNonce string
	// ExpectedAudience: audience to validate in KB-JWT (required if KB-JWT present)
	ExpectedAudience string
	// AllowedClockSkew: allowed time skew for exp/iat validation (default: 5 minutes)
	AllowedClockSkew time.Duration
	// ValidateTime: whether to validate exp/iat claims (default: true)
	ValidateTime bool
	// TrustEvaluator: optional trust evaluator for validating issuer's key
	// When set and x5c header is present, the certificate chain will be validated
	// against the trust framework. If not set, the provided public key is used directly.
	TrustEvaluator trust.TrustEvaluator
	// TrustContext: context for trust evaluation (optional, defaults to context.Background())
	TrustContext context.Context
	// CredentialType: credential type for policy routing (e.g., "PID", "mDL")
	// If set, this is passed to the TrustEvaluator for policy-based routing.
	// If not set, it will be extracted from the 'vct' claim if present.
	CredentialType string
	// CryptoExt provides extended algorithm and certificate support
	// (e.g. brainpool curves).
	CryptoExt *cryptoutil.Extensions
}

// ParseAndVerify parses and verifies an SD-JWT credential
// Per draft-13 Section 3.4 (Verification and Processing) and draft-22 Section 6 (Verification)
// Parameters:
//   - sdJWT: the SD-JWT string (format: <Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~[<KB-JWT>])
//   - publicKey: issuer's public key for signature verification
//   - opts: verification options (can be nil for defaults)
func (c *Client) ParseAndVerify(sdJWT string, publicKey any, opts *VerificationOptions) (*VerificationResult, error) {
	result := &VerificationResult{
		Valid:  false,
		Errors: []error{},
	}

	if opts == nil {
		opts = &VerificationOptions{
			ValidateTime:     true,
			AllowedClockSkew: 5 * time.Minute,
		}
	}

	// Step 1: Split the SD-JWT into components (§6.1)
	parts := strings.Split(sdJWT, "~")
	if len(parts) < 1 {
		err := fmt.Errorf("invalid SD-JWT format: must contain at least issuer-signed JWT")
		result.Errors = append(result.Errors, err)
		return result, err
	}

	issuerJWT := parts[0]
	var kbJWT string
	var disclosureParts []string

	// Check if last part is a KB-JWT (non-empty after last ~)
	if len(parts) > 1 {
		lastPart := parts[len(parts)-1]
		if lastPart != "" && strings.Count(lastPart, ".") == 2 {
			// Last part looks like a JWT (has 2 dots) - it's a KB-JWT
			kbJWT = lastPart
			disclosureParts = parts[1 : len(parts)-1]
		} else {
			// No KB-JWT, all parts after first are disclosures
			disclosureParts = parts[1:]
		}
	}

	// Step 2: Parse JWT header to check for x5c (before signature verification)
	// If x5c is present and TrustEvaluator is configured, extract the public key
	// from the certificate chain and validate trust
	verificationKey := publicKey
	var certChain []*x509.Certificate

	// Pre-parse to get header without verification
	preParser := jwt.NewParser(jwt.WithoutClaimsValidation())
	preToken, _, _ := preParser.ParseUnverified(issuerJWT, jwt.MapClaims{})

	if preToken != nil {
		// Check for x5c header
		if x5cRaw, ok := preToken.Header["x5c"]; ok && opts.TrustEvaluator != nil {
			chain, err := jose.ParseX5CHeader(x5cRaw, opts.CryptoExt)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Errorf("failed to parse x5c header: %w", err))
				return result, err
			}
			certChain = chain

			// Extract issuer identifier for trust evaluation
			// Priority: 1. iss claim (if parseable), 2. leaf certificate CN
			issuerID := ""
			credentialType := opts.CredentialType
			if preToken.Claims != nil {
				if claims, ok := preToken.Claims.(jwt.MapClaims); ok {
					if iss, ok := claims["iss"].(string); ok {
						issuerID = iss
					}
					// Extract vct for credential type if not explicitly set
					if credentialType == "" {
						if vct, ok := claims["vct"].(string); ok {
							credentialType = vct
						}
					}
				}
			}
			if issuerID == "" && len(chain) > 0 {
				issuerID = chain[0].Subject.CommonName
			}

			// Evaluate trust
			ctx := opts.TrustContext
			if ctx == nil {
				ctx = context.Background()
			}

			trustDecision, err := opts.TrustEvaluator.Evaluate(ctx, &trust.EvaluationRequest{
				EvaluationRequest: trustapi.EvaluationRequest{
					SubjectID:      issuerID,
					KeyType:        trust.KeyTypeX5C,
					Key:            chain,
					Role:           trust.RoleCredentialIssuer,
					CredentialType: credentialType,
				},
			})
			if err != nil {
				result.Errors = append(result.Errors, fmt.Errorf("trust evaluation failed: %w", err))
				return result, err
			}

			if !trustDecision.Trusted {
				result.Errors = append(result.Errors, fmt.Errorf("issuer not trusted: %s", trustDecision.Reason))
				return result, fmt.Errorf("issuer not trusted: %s", trustDecision.Reason)
			}

			// Use the public key from the leaf certificate
			if len(chain) > 0 {
				verificationKey = chain[0].PublicKey
			}
		}
	}

	// Step 3: Verify issuer-signed JWT signature (§6.2)
	token, err := c.verifyJWTSignature(issuerJWT, verificationKey)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("signature verification failed: %w", err))
		return result, err
	}

	// Extract header
	result.Header = token.Header

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		err := fmt.Errorf("invalid claims type")
		result.Errors = append(result.Errors, err)
		return result, err
	}
	result.Claims = claims

	// Store certificate chain if present (for later inspection)
	if certChain != nil {
		result.Header["_certChain"] = certChain
	}

	// Step 4: Validate SD-JWT VC structure (draft-13 §3.2.2)
	if err := c.validateSDJWTVCStructure(result.Header, claims, opts); err != nil {
		result.Errors = append(result.Errors, err)
		return result, err
	}

	// Step 5: Extract VCTM from header (draft-13 §6)
	// VCTM decoding is optional and errors are non-fatal (don't add to Errors)
	if vctmEncoded, ok := result.Header["vctm"]; ok {
		vctm, _ := decodeVCTM(vctmEncoded)
		if vctm != nil {
			result.VCTM = vctm
		}
	}

	// Step 5: Parse and validate disclosures (§6.3)
	sdAlg, _ := claims["_sd_alg"].(string)
	if sdAlg == "" {
		sdAlg = "sha-256" // Default per spec
	}

	hashMethod, err := getHashFromAlgorithm(sdAlg)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("unsupported hash algorithm %s: %w", sdAlg, err))
		return result, err
	}

	result.DisclosedClaims = make(map[string]any)
	for _, disclosurePart := range disclosureParts {
		if disclosurePart == "" {
			continue // Empty disclosure (trailing ~)
		}

		disclosure, err := c.parseDisclosure(disclosurePart, hashMethod)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("failed to parse disclosure: %w", err))
			continue
		}

		result.Disclosures = append(result.Disclosures, *disclosure)
		if disclosure.Claim != "" {
			result.DisclosedClaims[disclosure.Claim] = disclosure.Value
		}
	}

	// Verify disclosure hashes: only hashes reachable from the issuer-signed
	// claims tree (transitively, via values of already-anchored disclosures)
	// are considered valid. This prevents mutually-referencing attacker-controlled
	// disclosures from passing verification.
	anchoredHashes := collectAnchoredHashes(map[string]any(claims), result.Disclosures)
	for i := range result.Disclosures {
		if !anchoredHashes[result.Disclosures[i].Hash] {
			result.Errors = append(result.Errors, fmt.Errorf("disclosure hash %s not found in _sd array", result.Disclosures[i].Hash))
		}
	}

	// Step 6: Reconstruct full claims with disclosed values
	if err := c.reconstructClaims(result.Claims, result.Disclosures); err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("failed to reconstruct claims: %w", err))
	}

	// Step 7: Verify Key Binding JWT if present (§4.3)
	if kbJWT != "" {
		kbResult, err := c.verifyKeyBindingJWT(kbJWT, issuerJWT, disclosureParts, claims, opts, hashMethod)
		if err != nil {
			kbErr := fmt.Errorf("KB-JWT verification failed: %w", err)
			result.Errors = append(result.Errors, kbErr)
			// KB-JWT verification failure is fatal
			return result, kbErr
		}
		result.KeyBindingValid = true
		result.KeyBindingClaims = kbResult
	} else if opts.RequireKeyBinding {
		err := fmt.Errorf("key binding JWT required but not present")
		result.Errors = append(result.Errors, err)
		return result, err
	}

	// Overall validity: no errors
	result.Valid = len(result.Errors) == 0
	return result, nil
}

// verifyJWTSignature verifies the signature of a JWT
func (c *Client) verifyJWTSignature(tokenString string, publicKey any) (*jwt.Token, error) {
	// Parse without validation first to avoid time-based errors
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, err := parser.Parse(tokenString, func(token *jwt.Token) (any, error) {
		// Verify algorithm matches key type
		switch publicKey.(type) {
		case *ecdsa.PublicKey:
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v (expected ECDSA)", token.Header["alg"])
			}
		case *rsa.PublicKey:
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v (expected RSA)", token.Header["alg"])
			}
		default:
			return nil, fmt.Errorf("unsupported key type: %T", publicKey)
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	return token, nil
}

// validateSDJWTVCStructure validates SD-JWT VC required structure per draft-13 §3.2.2
// Per draft-13: iss is OPTIONAL, vct is REQUIRED, typ MUST be dc+sd-jwt
// (vc+sd-jwt is accepted during transition period per §3.2.1)
func (c *Client) validateSDJWTVCStructure(header map[string]any, claims jwt.MapClaims, opts *VerificationOptions) error {
	// Validate typ header (§3.2.1)
	typ, _ := header["typ"].(string)
	if typ != "dc+sd-jwt" && typ != "vc+sd-jwt" {
		return fmt.Errorf("invalid typ header: %s (must be dc+sd-jwt or vc+sd-jwt)", typ)
	}

	// Validate required claims (§3.2.2)
	vct, ok := claims["vct"].(string)
	if !ok || vct == "" {
		return fmt.Errorf("missing required claim: vct")
	}

	// Validate time claims if enabled
	if opts.ValidateTime {
		now := time.Now()

		// Check exp (expiration time)
		if expFloat, ok := claims["exp"].(float64); ok {
			exp := time.Unix(int64(expFloat), 0)
			if now.After(exp.Add(opts.AllowedClockSkew)) {
				return fmt.Errorf("credential expired at %s", exp)
			}
		}

		// Check iat (issued at time) - shouldn't be in the future
		if iatFloat, ok := claims["iat"].(float64); ok {
			iat := time.Unix(int64(iatFloat), 0)
			if now.Before(iat.Add(-opts.AllowedClockSkew)) {
				return fmt.Errorf("credential issued in the future: %s", iat)
			}
		}

		// Check nbf (not before time)
		if nbfFloat, ok := claims["nbf"].(float64); ok {
			nbf := time.Unix(int64(nbfFloat), 0)
			if now.Before(nbf.Add(-opts.AllowedClockSkew)) {
				return fmt.Errorf("credential not yet valid (nbf: %s)", nbf)
			}
		}
	}

	return nil
}

// parseDisclosure parses a disclosure string into a Disclosure struct
// Per draft-22 §4.2: Object property disclosures have format [<salt>, <claim_name>, <claim_value>]
// Per draft-22 §4.2.2: Array element disclosures have format [<salt>, <value>]
func (c *Client) parseDisclosure(disclosureStr string, hashMethod hash.Hash) (*Disclosure, error) {
	// Base64url decode
	decoded, err := base64.RawURLEncoding.DecodeString(disclosureStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode disclosure: %w", err)
	}

	// Parse JSON array
	var parts []any
	if err := json.Unmarshal(decoded, &parts); err != nil {
		return nil, fmt.Errorf("failed to unmarshal disclosure: %w", err)
	}

	var salt, claim string
	var value any

	switch len(parts) {
	case 3:
		// Object property disclosure: [salt, claim_name, claim_value]
		s, ok := parts[0].(string)
		if !ok {
			return nil, fmt.Errorf("invalid disclosure: salt must be string")
		}
		salt = s
		c, ok := parts[1].(string)
		if !ok {
			return nil, fmt.Errorf("invalid disclosure: claim name must be string")
		}
		claim = c
		value = parts[2]
	case 2:
		// Array element disclosure: [salt, value]
		s, ok := parts[0].(string)
		if !ok {
			return nil, fmt.Errorf("invalid disclosure: salt must be string")
		}
		salt = s
		value = parts[1]
	default:
		return nil, fmt.Errorf("invalid disclosure format: expected 2 or 3 elements, got %d", len(parts))
	}

	// Calculate hash
	hashMethod.Reset()
	hashMethod.Write([]byte(disclosureStr))
	hash := base64.RawURLEncoding.EncodeToString(hashMethod.Sum(nil))

	return &Disclosure{
		Salt:  salt,
		Claim: claim,
		Value: value,
		Raw:   disclosureStr,
		Hash:  hash,
	}, nil
}

// collectAnchoredHashes returns the set of disclosure hashes that are
// transitively reachable from the issuer-signed claims tree. A hash is
// anchored if it appears in an _sd array or as an array-element marker
// ({"...": hash}) in the signed claims, OR in the value of a disclosure
// whose own hash is already anchored. This prevents mutually-referencing
// attacker-crafted disclosures from being accepted.
func collectAnchoredHashes(claims map[string]any, disclosures []Disclosure) map[string]bool {
	// Build hash -> disclosure lookup
	byHash := make(map[string]*Disclosure, len(disclosures))
	for i := range disclosures {
		byHash[disclosures[i].Hash] = &disclosures[i]
	}

	anchored := make(map[string]bool, len(disclosures))

	// Collect all hashes directly referenced in the issuer-signed claims tree
	directHashes := collectHashesFromNode(claims)

	// BFS/iterative expansion: anchor direct hashes, then transitively
	// anchor hashes found inside anchored disclosure values.
	queue := make([]string, 0, len(directHashes))
	for h := range directHashes {
		anchored[h] = true
		queue = append(queue, h)
	}

	for len(queue) > 0 {
		h := queue[0]
		queue = queue[1:]

		d, ok := byHash[h]
		if !ok {
			continue
		}
		// Find hashes inside this disclosure's value
		childHashes := collectHashesFromValue(d.Value)
		for ch := range childHashes {
			if !anchored[ch] {
				anchored[ch] = true
				queue = append(queue, ch)
			}
		}
	}

	return anchored
}

// collectHashesFromNode collects all disclosure hashes referenced in _sd arrays
// and array-element markers ({"...": hash}) throughout a claims tree.
func collectHashesFromNode(node map[string]any) map[string]bool {
	hashes := make(map[string]bool)
	collectHashesFromNodeInto(node, hashes)
	return hashes
}

func collectHashesFromNodeInto(node map[string]any, hashes map[string]bool) {
	// Collect from _sd array
	if sdField, ok := node["_sd"]; ok {
		if sdArray, ok := sdField.([]any); ok {
			for _, h := range sdArray {
				if hashStr, ok := h.(string); ok {
					hashes[hashStr] = true
				}
			}
		}
	}

	// Recurse into nested objects and arrays
	for k, v := range node {
		if k == "_sd" {
			continue
		}
		switch val := v.(type) {
		case map[string]any:
			collectHashesFromNodeInto(val, hashes)
		case []any:
			collectHashesFromArrayInto(val, hashes)
		}
	}
}

func collectHashesFromArrayInto(arr []any, hashes map[string]bool) {
	for _, elem := range arr {
		switch v := elem.(type) {
		case map[string]any:
			if len(v) == 1 {
				if hashVal, ok := v["..."]; ok {
					if hashStr, ok := hashVal.(string); ok {
						hashes[hashStr] = true
						continue
					}
				}
			}
			collectHashesFromNodeInto(v, hashes)
		case []any:
			collectHashesFromArrayInto(v, hashes)
		}
	}
}

// collectHashesFromValue collects disclosure hashes from a disclosure's value.
func collectHashesFromValue(value any) map[string]bool {
	hashes := make(map[string]bool)
	switch v := value.(type) {
	case []any:
		collectHashesFromArrayInto(v, hashes)
	case map[string]any:
		collectHashesFromNodeInto(v, hashes)
	}
	return hashes
}

// reconstructClaims adds disclosed claims back into the claims map, including nested _sd arrays.
func (c *Client) reconstructClaims(claims map[string]any, disclosures []Disclosure) error {
	// Build a hash -> Disclosure lookup
	disclosureMap := make(map[string]*Disclosure, len(disclosures))
	for i := range disclosures {
		disclosureMap[disclosures[i].Hash] = &disclosures[i]
	}

	reconstructNode(claims, disclosureMap)
	return nil
}

// reconstructNode resolves _sd arrays at this level and recurses into nested maps.
func reconstructNode(node map[string]any, disclosureMap map[string]*Disclosure) {
	if sdField, ok := node["_sd"]; ok {
		if sdArray, ok := sdField.([]any); ok {
			for _, h := range sdArray {
				hashStr, ok := h.(string)
				if !ok {
					continue
				}
				if d, found := disclosureMap[hashStr]; found && d.Claim != "" {
					node[d.Claim] = d.Value
				}
			}
		}
	}

	delete(node, "_sd")
	delete(node, "_sd_alg")

	// Collect keys first to ensure newly-added claims from _sd resolution are included.
	keys := make([]string, 0, len(node))
	for k := range node {
		keys = append(keys, k)
	}

	for _, key := range keys {
		value := node[key]
		switch v := value.(type) {
		case map[string]any:
			reconstructNode(v, disclosureMap)
		case []any:
			node[key] = reconstructArrayNode(v, disclosureMap)
		}
	}
}

// reconstructArrayNode resolves array element disclosures ({"...": hash}) and recurses.
func reconstructArrayNode(arr []any, disclosureMap map[string]*Disclosure) []any {
	result := make([]any, 0, len(arr))
	for _, elem := range arr {
		switch v := elem.(type) {
		case map[string]any:
			if len(v) == 1 {
				if hashVal, ok := v["..."]; ok {
					if hashStr, ok := hashVal.(string); ok {
						if d, found := disclosureMap[hashStr]; found {
							// Recurse into the disclosed value in case it
							// contains nested _sd or array markers.
							switch dv := d.Value.(type) {
							case map[string]any:
								reconstructNode(dv, disclosureMap)
								result = append(result, dv)
							case []any:
								result = append(result, reconstructArrayNode(dv, disclosureMap))
							default:
								result = append(result, d.Value)
							}
							continue
						}
					}
				}
			}
			reconstructNode(v, disclosureMap)
			result = append(result, v)
		case []any:
			result = append(result, reconstructArrayNode(v, disclosureMap))
		default:
			result = append(result, elem)
		}
	}
	return result
}

// verifyKeyBindingJWT verifies a Key Binding JWT per draft-22 §4.3
func (c *Client) verifyKeyBindingJWT(
	kbJWT string,
	issuerJWT string,
	disclosures []string,
	issuerClaims jwt.MapClaims,
	opts *VerificationOptions,
	hashMethod hash.Hash,
) (map[string]any, error) {
	// Extract holder's public key from cnf claim in issuer JWT
	cnf, ok := issuerClaims["cnf"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("missing cnf claim in issuer JWT (required for key binding)")
	}

	jwkMap, ok := cnf["jwk"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("missing jwk in cnf claim")
	}

	// Convert JWK map to public key
	holderPublicKey, err := jwkToPublicKey(jwkMap)
	if err != nil {
		return nil, fmt.Errorf("failed to parse holder's public key: %w", err)
	}

	// Verify KB-JWT signature
	kbToken, err := c.verifyJWTSignature(kbJWT, holderPublicKey)
	if err != nil {
		return nil, fmt.Errorf("KB-JWT signature verification failed: %w", err)
	}

	// Verify KB-JWT header
	kbHeader := kbToken.Header

	if typ, _ := kbHeader["typ"].(string); typ != "kb+jwt" {
		return nil, fmt.Errorf("invalid KB-JWT typ header: %s (must be kb+jwt)", typ)
	}

	// Verify KB-JWT claims
	kbClaims, ok := kbToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid KB-JWT claims")
	}

	// Verify nonce (only if expected nonce is provided)
	nonce, _ := kbClaims["nonce"].(string)
	if opts.ExpectedNonce != "" && nonce != opts.ExpectedNonce {
		return nil, fmt.Errorf("nonce mismatch: expected %s, got %s", opts.ExpectedNonce, nonce)
	}

	// Verify audience (only if expected audience is provided)
	aud, _ := kbClaims["aud"].(string)
	if opts.ExpectedAudience != "" && aud != opts.ExpectedAudience {
		return nil, fmt.Errorf("audience mismatch: expected %s, got %s", opts.ExpectedAudience, aud)
	}

	// Verify sd_hash
	expectedSDHash, err := c.calculateSDHashForVerification(issuerJWT, disclosures, hashMethod)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate sd_hash: %w", err)
	}

	actualSDHash, _ := kbClaims["sd_hash"].(string)
	if actualSDHash != expectedSDHash {
		return nil, fmt.Errorf("sd_hash mismatch")
	}

	return kbClaims, nil
}

// calculateSDHashForVerification calculates sd_hash for verification
func (c *Client) calculateSDHashForVerification(issuerJWT string, disclosures []string, hashMethod hash.Hash) (string, error) {
	// Reconstruct the SD-JWT without KB-JWT: <Issuer-signed JWT>~<Disclosure 1>~...~
	var sdJWT strings.Builder
	sdJWT.WriteString(issuerJWT)
	for _, disclosure := range disclosures {
		sdJWT.WriteByte('~')
		sdJWT.WriteString(disclosure)
	}
	sdJWT.WriteString("~") // Trailing ~

	hashMethod.Reset()
	hashMethod.Write([]byte(sdJWT.String()))
	return base64.RawURLEncoding.EncodeToString(hashMethod.Sum(nil)), nil
}

// jwkToPublicKey converts a JWK map to a public key
func jwkToPublicKey(jwkMap map[string]any) (any, error) {
	kty, _ := jwkMap["kty"].(string)

	switch kty {
	case "EC":
		// ECDSA key
		crv, _ := jwkMap["crv"].(string)
		xStr, _ := jwkMap["x"].(string)
		yStr, _ := jwkMap["y"].(string)

		if xStr == "" || yStr == "" {
			return nil, fmt.Errorf("missing x or y coordinate in EC key")
		}

		xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode x coordinate: %w", err)
		}

		yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode y coordinate: %w", err)
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

		pubKey := &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}
		return pubKey, nil

	case "RSA":
		// RSA key - not implemented yet
		return nil, fmt.Errorf("RSA key type not yet implemented for verification")

	default:
		return nil, fmt.Errorf("unsupported key type: %s", kty)
	}
}

// decodeVCTM decodes VCTM from header
func decodeVCTM(vctmEncoded any) (*VCTM, error) {
	// VCTM can be either a string (URL) or an object
	switch v := vctmEncoded.(type) {
	case string:
		// It's a URL reference - we don't fetch it, just store the URL
		return &VCTM{VCT: v}, nil
	case map[string]any:
		// It's an embedded object - marshal and unmarshal to VCTM struct
		vctmJSON, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		var vctm VCTM
		if err := json.Unmarshal(vctmJSON, &vctm); err != nil {
			return nil, err
		}
		return &vctm, nil
	case []any:
		// VCTM was encoded as an array (from base64 decoding) - try to decode it
		vctmJSON, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		var vctm VCTM
		if err := json.Unmarshal(vctmJSON, &vctm); err != nil {
			return nil, err
		}
		return &vctm, nil
	default:
		// Just skip VCTM if it's in an unexpected format
		return nil, nil
	}
}
