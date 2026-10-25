package sdjwtvc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	sha30 "crypto/sha3"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"slices"
	"sort"
	"time"

	"github.com/SUNET/vc/pkg/claimpath"

	"github.com/google/uuid"
)

// CredentialOptions contains optional parameters for credential building
type CredentialOptions struct {
	// DecoyDigests: number of decoy digests to add per _sd array (§4.2.5)
	DecoyDigests int
	// ExpirationDays: number of days until credential expires (default: 365)
	ExpirationDays int
	// TokenStatusList contains the Token Status List reference for credential revocation per draft-ietf-oauth-status-list
	TokenStatusList *TokenStatusListReference
	// Integrity is the pre-computed SRI hash of the VCTM document (e.g. "sha256-...").
	// When non-empty it is set as the "vct#integrity" claim in the issued credential
	// per SD-JWT VC draft-14 Section 6.
	Integrity string
}

// TokenStatusListReference contains the status list reference to embed in a credential
// per draft-ietf-oauth-status-list Section 5 (Referenced Token)
type TokenStatusListReference struct {
	// Index is the index within the section for this credential's status
	Index int64
	// URI is the full Status List Token URI (e.g., https://example.com/statuslists/0)
	URI string
}

// parseVCTM parses raw VCTM JSON bytes supplied by a trusted caller (e.g. APIGW)
// and performs a basic sanity check (non-empty vct field). Integrity is NOT
// re-verified here because the caller already verified it at load time and the
// gRPC transport is internal/mTLS-protected.
func (c *Client) parseVCTM(rawBytes []byte) (*VCTM, error) {
	var vctm VCTM
	if err := json.Unmarshal(rawBytes, &vctm); err != nil {
		return nil, fmt.Errorf("failed to parse inline VCTM: %w", err)
	}
	if vctm.VCT == "" {
		return nil, fmt.Errorf("inline VCTM has empty vct field")
	}
	return &vctm, nil
}

// fetchVCTM fetches and parses a VCTM document from the given URL.
// It verifies the fetched document's SRI integrity hash matches the expected
// value per SD-JWT VC draft-14 Section 6.
// Returns the parsed VCTM on success.
func (c *Client) fetchVCTM(ctx context.Context, vctURL string, expectedIntegrity string) (*VCTM, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, vctURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for VCT URL %s: %w", vctURL, err)
	}

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch VCTM from %s: %w", vctURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d fetching VCTM from %s", resp.StatusCode, vctURL)
	}

	// Read at most maxVCTMSize+1 bytes so we can detect oversized responses.
	limitedReader := io.LimitReader(resp.Body, maxVCTMSize+1)
	rawBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read VCTM response from %s: %w", vctURL, err)
	}
	if int64(len(rawBytes)) > maxVCTMSize {
		return nil, fmt.Errorf("VCTM response from %s exceeds maximum allowed size of %d bytes", vctURL, maxVCTMSize)
	}

	var vctm VCTM
	if err := json.Unmarshal(rawBytes, &vctm); err != nil {
		return nil, fmt.Errorf("failed to parse VCTM from %s: %w", vctURL, err)
	}

	// Verify SRI integrity (required per SD-JWT VC draft-14 Section 6)
	if expectedIntegrity == "" {
		return nil, fmt.Errorf("integrity is required when fetching VCTM from %s", vctURL)
	}
	actualIntegrity, err := vctm.SRIIntegrity(rawBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to compute VCTM integrity: %w", err)
	}
	if actualIntegrity != expectedIntegrity {
		return nil, fmt.Errorf("VCTM integrity mismatch: expected %s, got %s", expectedIntegrity, actualIntegrity)
	}

	return &vctm, nil
}

// BuildCredentialWithSigner creates a complete SD-JWT credential using a Signer interface.
// This allows signing with HSMs via PKCS#11 or other external signing services.
// The caller provides the raw VCTM bytes directly, eliminating SSRF risk.
// The vct claim is derived from the VCTM's VCT field.
func (c *Client) BuildCredentialWithSigner(ctx context.Context, issuer string, signer Signer, vctmRaw []byte, documentData []byte, holderJWK any, opts *CredentialOptions) (string, error) {
	// Set defaults
	if opts == nil {
		opts = &CredentialOptions{
			DecoyDigests:   0,
			ExpirationDays: 365,
		}
	}
	if opts.ExpirationDays == 0 {
		opts.ExpirationDays = 365
	}

	// Parse document data as generic map
	body := map[string]any{}
	if err := json.Unmarshal(documentData, &body); err != nil {
		return "", fmt.Errorf("failed to unmarshal document data: %w", err)
	}

	// Add standard JWT claims
	// Per SD-JWT VC draft-13 section 3.2.2.2:
	// - iss: OPTIONAL (set when provided)
	// - nbf, exp: OPTIONAL
	// - vct: REQUIRED
	now := time.Now()
	body["iat"] = now.Unix()
	body["nbf"] = now.Unix()
	body["exp"] = now.Add(time.Duration(opts.ExpirationDays) * 24 * time.Hour).Unix()
	if issuer != "" {
		body["iss"] = issuer
	}
	body["jti"] = uuid.NewString()

	// Parse the VCTM and derive the vct claim from it (authoritative source).
	vctm, err := c.parseVCTM(vctmRaw)
	if err != nil {
		return "", fmt.Errorf("failed to parse VCTM: %w", err)
	}
	body["vct"] = vctm.VCT

	// Add vct#integrity if provided (SD-JWT VC draft-14 Section 6)
	if opts.Integrity != "" {
		body["vct#integrity"] = opts.Integrity
	}

	// Add confirmation claim with holder's public key
	body["cnf"] = map[string]any{
		"jwk": holderJWK,
	}

	// Add status claim if provided (per draft-ietf-oauth-status-list Section 5)
	if opts.TokenStatusList != nil && opts.TokenStatusList.URI != "" {
		body["status"] = map[string]any{
			"status_list": map[string]any{
				"idx": opts.TokenStatusList.Index,
				"uri": opts.TokenStatusList.URI,
			},
		}
	}

	// Validate document data against the fetched VCTM
	if err := ValidateDocument(documentData, vctm); err != nil {
		return "", fmt.Errorf("document validation failed: %w", err)
	}

	// Create JWT header using signer's algorithm and key ID
	header := map[string]any{
		"typ": "dc+sd-jwt",
		"kid": signer.KeyID(),
		"alg": signer.Algorithm(),
	}

	// Create selective disclosures using the fetched VCTM
	token, disclosures, err := c.MakeCredential(sha256.New(), body, vctm, opts.DecoyDigests)
	if err != nil {
		return "", fmt.Errorf("failed to create selective disclosures: %w", err)
	}

	// Sign the JWT using the signer interface
	signedToken, err := SignWithSigner(ctx, header, token, signer)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	// Combine signed JWT with disclosures
	signedToken = Combine(signedToken, disclosures, "")

	return signedToken, nil
}

// MakeCredential creates a SD-JWT credential with optional decoy digests.
// It implements recursive selective disclosure per oauth-selective-disclosure-jwt-22.
// Per section 4.2.5: decoy digests obscure the actual number of claims.
// Use decoyCount = 0 for no decoy digests (standard behavior).
func (c *Client) MakeCredential(hashMethod hash.Hash, data map[string]any, vctm *VCTM, decoyCount int) (map[string]any, []string, error) {
	disclosures := []string{}

	// Set hash algorithm claim (section 4.1.1)
	// Determine algorithm name from the hash interface
	algName, err := getHashAlgorithmName(hashMethod)
	if err != nil {
		return nil, nil, fmt.Errorf("unsupported hash algorithm: %w", err)
	}
	data["_sd_alg"] = algName

	// Sort claims by depth (deepest first) to ensure child claims are processed
	// before parent claims in recursive selective disclosure scenarios
	sortedClaims := sortClaimsByDepth(vctm.Claims)

	// Process claims recursively
	for _, claim := range sortedClaims {
		if claim.SD != "always" {
			continue
		}
		claimDisclosures, err := c.discloseClaim(data, claim.Path, hashMethod)
		if err != nil {
			return nil, nil, err
		}
		disclosures = append(disclosures, claimDisclosures...)
	}

	// Add decoy digests if requested (section 4.2.5)
	if decoyCount > 0 {
		if err := c.addDecoyDigests(data, hashMethod, decoyCount); err != nil {
			return nil, nil, fmt.Errorf("failed to add decoy digests: %w", err)
		}
	}

	// Shuffle all _sd arrays to hide original claim order (section 4.2.4.1)
	// "The Issuer MUST hide the original order of the claims in the array"
	shuffleSDArrays(data)

	return data, disclosures, nil
}

// discloseClaim makes the claims at path selectively disclosable and
// returns their disclosures. A path that ends in a key discloses that
// object property (section 4.2.1); one that ends in null or an index
// discloses the array elements it selects (section 4.2.2). A null or an
// index before the end selects the objects or arrays in every element
// they name. A path the data does not carry discloses nothing.
func (c *Client) discloseClaim(data map[string]any, path claimpath.Pointer, hashMethod hash.Hash) ([]string, error) {
	last, ok := path.Last()
	if !ok {
		return nil, fmt.Errorf("claim path %s is unset or unresolved", path)
	}
	containers := []any{data}
	if parent, ok := path.Parent(); ok {
		selected, err := parent.Select(data)
		if errors.Is(err, claimpath.ErrNoClaim) {
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("invalid path %s: %w", path, err)
		}
		containers = selected
	}
	var disclosures []string
	for _, container := range containers {
		disclosed, err := c.discloseIn(container, last, hashMethod)
		if err != nil {
			return nil, fmt.Errorf("path %s: %w", path, err)
		}
		disclosures = append(disclosures, disclosed...)
	}
	return disclosures, nil
}

// discloseIn discloses what the last path component selects in its
// container.
func (c *Client) discloseIn(container any, last claimpath.Component, hashMethod hash.Hash) ([]string, error) {
	if name, ok := last.KeyName(); ok {
		object, ok := container.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid path: non-object %T holds claim %q", container, name)
		}
		return c.discloseProperty(object, name, hashMethod)
	}
	array, ok := container.([]any)
	if !ok {
		return nil, fmt.Errorf("path with null or an index must point to an array, got %T", container)
	}
	return discloseElements(array, last, hashMethod)
}

// discloseElements discloses the array elements null or an index selects.
func discloseElements(array []any, last claimpath.Component, hashMethod hash.Hash) ([]string, error) {
	first, end := 0, len(array)
	if index, ok := last.IndexValue(); ok {
		if index >= uint(len(array)) {
			return nil, nil
		}
		first, end = int(index), int(index)+1
	}
	disclosures := make([]string, 0, end-first)
	for i := first; i < end; i++ {
		disclosure, err := discloseElement(array, i, hashMethod)
		if err != nil {
			return nil, err
		}
		disclosures = append(disclosures, disclosure)
	}
	return disclosures, nil
}

// discloseProperty makes an object property selectively disclosable per
// section 4.2.1: the claim leaves the object, and the digest of its
// disclosure joins the object's _sd array (section 4.2.4.1).
func (c *Client) discloseProperty(object map[string]any, name string, hashMethod hash.Hash) ([]string, error) {
	// Per section 4.2.1.1: claim name MUST NOT be _sd, ..., or an existing permanently disclosed claim
	if name == "_sd" || name == "..." {
		return nil, fmt.Errorf("claim name cannot be '_sd' or '...'")
	}

	// For nested objects that should be selectively disclosed recursively,
	// the value might already be processed (contain _sd arrays): this
	// handles recursive disclosures as per section 4.2.6. An array
	// processed with array element disclosure is an SD array like
	// [{"...": hash1}, {"...": hash2}, ...], disclosed here as a whole.
	value, exists := object[name]
	if !exists {
		return nil, nil
	}

	// Create disclosure with cryptographically secure random salt
	// Per section 4.2.1: salt MUST be a string with recommended 128-bit entropy
	salt, err := generateSalt()
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Create Disclosure for object property: [salt, claim_name, value]
	discloser := Discloser{
		Salt:      salt,
		ClaimName: name,
		Value:     value,
		IsArray:   false,
	}

	// Hash the disclosure per section 4.2.3
	// "The input to the hash function MUST be the base64url-encoded Disclosure"
	sdHash, sdB64, _, err := discloser.Hash(hashMethod)
	if err != nil {
		return nil, fmt.Errorf("failed to hash disclosure: %w", err)
	}

	if err := addDigest(object, sdHash); err != nil {
		return nil, err
	}
	delete(object, name)
	return []string{sdB64}, nil
}

// discloseElement makes one array element selectively disclosable per
// section 4.2.2: the element is replaced with {"...": digest}.
func discloseElement(array []any, i int, hashMethod hash.Hash) (string, error) {
	// Create disclosure with cryptographically secure random salt
	salt, err := generateSalt()
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Create Disclosure for array element: [salt, value]
	discloser := Discloser{
		Salt:    salt,
		Value:   array[i],
		IsArray: true,
	}

	sdHash, sdB64, _, err := discloser.Hash(hashMethod)
	if err != nil {
		return "", fmt.Errorf("failed to hash disclosure: %w", err)
	}

	// Per section 4.2.2.2: the element is replaced with an object holding its digest
	array[i] = map[string]any{"...": sdHash}
	return sdB64, nil
}

// addDigest adds a digest to the _sd array of an object.
// Per section 4.2.4.1: "Digests of Disclosures for object properties are added
// to an array under the new key _sd in the object"
func addDigest(object map[string]any, digest string) error {
	// Ensure _sd key exists and is an array
	// Per section 4.2.4.1: "The _sd key MUST refer to an array of strings"
	if _, ok := object["_sd"]; !ok {
		object["_sd"] = []any{}
	}

	sdArray, ok := object["_sd"].([]any)
	if !ok {
		return fmt.Errorf("_sd is not an array")
	}

	// Check for duplicate digests (section 7.1 step 4)
	// "If any digest value is encountered more than once in the Issuer-signed JWT
	// payload (directly or recursively via other Disclosures), the SD-JWT MUST be rejected"
	if slices.Contains(sdArray, any(digest)) {
		return fmt.Errorf("duplicate digest detected: %s", digest)
	}

	object["_sd"] = append(sdArray, digest)
	return nil
}

// addDecoyDigests adds decoy digests to _sd arrays to obscure the actual number of claims
// Per section 4.2.5: "An Issuer MAY add additional digests to the SD-JWT payload that are
// not associated with any claim. The purpose of such 'decoy' digests is to make it more
// difficult for an adversarial Verifier to see the original number of claims"
func (c *Client) addDecoyDigests(data map[string]any, hashMethod hash.Hash, decoyCount int) error {
	// Recursively add decoy digests to all _sd arrays
	return addDecoyDigestsRecursive(data, hashMethod, decoyCount)
}

// addDecoyDigestsRecursive recursively adds decoy digests to nested structures
func addDecoyDigestsRecursive(data map[string]any, hashMethod hash.Hash, decoyCount int) error {
	for key, value := range data {
		// Process nested objects
		if nested, ok := value.(map[string]any); ok {
			if err := addDecoyDigestsRecursive(nested, hashMethod, decoyCount); err != nil {
				return err
			}
		}

		// Add decoy digests to _sd arrays
		if key == "_sd" {
			if sdArray, ok := value.([]any); ok {
				// Generate decoy digests
				for range decoyCount {
					decoy, err := generateDecoyDigest(hashMethod)
					if err != nil {
						return fmt.Errorf("failed to generate decoy digest: %w", err)
					}
					sdArray = append(sdArray, decoy)
				}
				data[key] = sdArray
			}
		}
	}
	return nil
}

// generateDecoyDigest generates a decoy digest by hashing a random value
// Per section 4.2.5: "It is RECOMMENDED to create the decoy digests by hashing over
// a cryptographically secure random number"
func generateDecoyDigest(hashMethod hash.Hash) (string, error) {
	// Generate 32 bytes of random data
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	// Hash the random bytes
	hashMethod.Reset()
	_, err = hashMethod.Write(randomBytes)
	if err != nil {
		return "", err
	}

	// Base64url-encode the hash
	digest := base64.RawURLEncoding.EncodeToString(hashMethod.Sum(nil))
	return digest, nil
}

// shuffleSDArrays recursively shuffles all _sd arrays in the data structure
// Per section 4.2.4.1: "The Issuer MUST hide the original order of the claims in the array.
// To ensure this, it is RECOMMENDED to shuffle the array of hashes, e.g., by sorting it
// alphanumerically or randomly"
func shuffleSDArrays(data map[string]any) {
	for key, value := range data {
		switch v := value.(type) {
		case map[string]any:
			// Recursively process nested objects
			shuffleSDArrays(v)
		case []any:
			// Process array elements
			for _, elem := range v {
				if m, ok := elem.(map[string]any); ok {
					shuffleSDArrays(m)
				}
			}
		}

		// If this is an _sd array, shuffle it
		if key == "_sd" {
			if arr, ok := value.([]any); ok {
				// Sort alphanumerically as recommended in the spec
				sortSDArray(arr)
				data[key] = arr
			}
		}
	}
}

// sortSDArray sorts an _sd array alphanumerically
func sortSDArray(arr []any) {
	sort.Slice(arr, func(i, j int) bool {
		si, oki := arr[i].(string)
		sj, okj := arr[j].(string)
		if oki && okj {
			return si < sj
		}
		return false
	})
}

// generateSalt generates a cryptographically secure random salt
// Per spec section 4.2.1: "To achieve the recommended entropy of the salt,
// the Issuer can base64url-encode 128 bits of cryptographically secure random data"
func generateSalt() (string, error) {
	// 128 bits = 16 bytes
	saltBytes := make([]byte, 16)
	_, err := rand.Read(saltBytes)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(saltBytes), nil
}

// getHashAlgorithmName determines the hash algorithm name from a hash.Hash interface
// Returns the algorithm name as specified in IANA Named Information Hash Algorithm registry
// Per section 4.1.1, the _sd_alg value should use the hash algorithm name from this registry
func getHashAlgorithmName(h hash.Hash) (string, error) {
	// Determine algorithm by size, which is the most reliable method
	// since we can't directly inspect the concrete type without reflection
	size := h.Size()

	switch size {
	case 32: // 256 bits
		// Could be SHA-256 or SHA3-256
		// We'll default to SHA-256 as it's most common
		// To distinguish, we'd need to check the type, so we create reference hashes
		if isSHA256(h) {
			return "sha-256", nil
		}
		if isSHA3_256(h) {
			return "sha3-256", nil
		}
		return "sha-256", nil // default to SHA-256 for 32-byte hashes

	case 48: // 384 bits
		return "sha-384", nil

	case 64: // 512 bits
		// Could be SHA-512 or SHA3-512
		if isSHA512(h) {
			return "sha-512", nil
		}
		if isSHA3_512(h) {
			return "sha3-512", nil
		}
		return "sha-512", nil // default to SHA-512 for 64-byte hashes

	case 28: // 224 bits
		return "sha-224", nil

	default:
		return "", fmt.Errorf("unsupported hash size: %d bytes", size)
	}
}

// isSHA256 checks if the hash is SHA-256 by comparing behavior
func isSHA256(h hash.Hash) bool {
	h.Reset()
	testData := []byte("test")
	h.Write(testData)
	result := h.Sum(nil)
	h.Reset()

	// Compare with known SHA-256 hash
	ref := sha256.New()
	ref.Write(testData)
	expected := ref.Sum(nil)

	if len(result) != len(expected) {
		return false
	}
	for i := range result {
		if result[i] != expected[i] {
			return false
		}
	}
	return true
}

// isSHA3_256 checks if the hash is SHA3-256
func isSHA3_256(h hash.Hash) bool {
	h.Reset()
	testData := []byte("test")
	h.Write(testData)
	result := h.Sum(nil)
	h.Reset()

	// Compare with known SHA3-256 hash
	ref := hash.Hash(sha30.New256())
	ref.Write(testData)
	expected := ref.Sum(nil)

	if len(result) != len(expected) {
		return false
	}
	for i := range result {
		if result[i] != expected[i] {
			return false
		}
	}
	return true
}

// isSHA512 checks if the hash is SHA-512
func isSHA512(h hash.Hash) bool {
	h.Reset()
	testData := []byte("test")
	h.Write(testData)
	result := h.Sum(nil)
	h.Reset()

	// Compare with known SHA-512 hash
	ref := sha512.New()
	ref.Write(testData)
	expected := ref.Sum(nil)

	if len(result) != len(expected) {
		return false
	}
	for i := range result {
		if result[i] != expected[i] {
			return false
		}
	}
	return true
}

// isSHA3_512 checks if the hash is SHA3-512
func isSHA3_512(h hash.Hash) bool {
	h.Reset()
	testData := []byte("test")
	h.Write(testData)
	result := h.Sum(nil)
	h.Reset()

	// Compare with known SHA3-512 hash
	ref := hash.Hash(sha30.New512())
	ref.Write(testData)
	expected := ref.Sum(nil)

	if len(result) != len(expected) {
		return false
	}
	for i := range result {
		if result[i] != expected[i] {
			return false
		}
	}
	return true
}

// sortClaimsByDepth sorts claims by path depth (deepest first) to ensure
// child claims are processed before parent claims in recursive selective disclosure.
// This makes the VCTM claim order independent - users can specify claims in any order.
func sortClaimsByDepth(claims []Claim) []Claim {
	if len(claims) == 0 {
		return claims
	}

	// Create a copy to avoid modifying the original
	sorted := make([]Claim, len(claims))
	copy(sorted, claims)

	// Sort by path length (descending - deepest first)
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i].Path.Len() < sorted[j].Path.Len() {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	return sorted
}
