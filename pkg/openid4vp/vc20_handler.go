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
	"maps"
	"net/url"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/vc20/credential"

	ecdsaSuite "github.com/SUNET/vc/pkg/vc20/crypto/ecdsa"
	eddsaSuite "github.com/SUNET/vc/pkg/vc20/crypto/eddsa"
	"github.com/piprate/json-gold/ld"
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

// VC20IssuerAuthorizer answers the question a key resolver cannot: may THIS
// issuer assert with THIS key, for this proof purpose.
//
// Resolution and authorization are different questions. A resolver says the
// trust framework knows a verification method, which in a framework holding
// many issuers is true of all of their keys - so a credential naming issuer A
// could be signed with issuer B's key and accepted. A resolver that also
// implements this interface is asked, and its answer is final.
//
// Implement it wherever the trust decision lives. pkg/trust's TrustEvaluator
// already asks this shape of question - subject, key, action - so an adapter
// over it is a few lines; this interface exists so the handler does not have
// to depend on that package.
//
// Without it the handler falls back to a lexical test, which is weaker in
// both directions: see issuerControlsMethod.
type VC20IssuerAuthorizer interface {
	AuthorizeIssuerKey(ctx context.Context, issuer string, key crypto.PublicKey, proofPurpose string) error
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
		// A presentation at the ROOT is refused, not unwrapped.
		//
		// credBytes stays the whole document here, so verification below
		// checks the proofs the DOCUMENT attaches to itself - the holder's,
		// for a presentation. extractCredentialFromExpanded meanwhile
		// returns the first VerifiableCredential node, which for a
		// presentation is the credential it carries. The step 3 unwrap
		// cannot see it either, since the map that function builds never
		// says VerifiablePresentation. So a holder-signed presentation
		// passed while the issuer, subject and trust decision all came from
		// an embedded credential whose own proof was never checked.
		//
		// Carving that credential, and the proof graphs beside it, out of a
		// flattened array is exactly the kind of reconstruction that goes
		// quietly wrong, and getting it wrong here means authenticating the
		// wrong node. The compact form is unwrapped correctly at step 3, so
		// that is what this asks for.
		//
		// Only the ROOT. A credential may carry a presentation as evidence,
		// or under any other property, and refusing the whole document for
		// that rejects something perfectly verifiable - root selection
		// already says which node the proofs belong to.
		if expandedRootIsAPresentation(expanded) {
			return nil, errors.New("a verifiable presentation in expanded JSON-LD is not accepted: send it in compact form, where the credential it carries is what gets verified")
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
	// EXPANDED, like the verification method it is compared against. A
	// compact-IRI issuer - "ex:issuer" under a document that defines the
	// prefix - was being matched against an absolute method IRI and handed
	// to the authorizer as written, so a valid credential was refused and
	// authorization asked about an identifier nobody has.
	issuer, err = h.expandDocumentIdentifier(credMap, issuer)
	if err != nil {
		return nil, err
	}

	// Check trusted issuers if configured
	if len(h.trustedIssuers) > 0 && !h.trustedIssuers[issuer] {
		return nil, fmt.Errorf("issuer %s is not trusted", issuer)
	}

	// 5. The proofs the document attaches to ITSELF, in the order it
	// carries them.
	//
	// EVERY candidate, not just the first. Sign appends rather than
	// replaces, so a document signed by two parties carries two root
	// proofs - and each names its own verification method and may name its
	// own cryptosuite. Resolving the first one's key and dispatching on the
	// first one's suite meant a valid later proof was always checked with
	// the wrong key, and a second cryptosuite was never dispatched at all.
	if h.keyResolver == nil {
		return nil, errors.New("no key resolver configured")
	}
	// ONE parse, and one secured-document answer, for every candidate. Each
	// candidate used to get its own: a reparse, a JSON-LD expansion, an RDF
	// serialization and a URDNA2015 canonicalization, all before anything
	// about the document had been authenticated. The answer is identical
	// for every proof in a set - that is what a proof set means.
	rdfCred, err := credential.NewRDFCredentialFromJSON(credBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create RDF credential: %w", err)
	}

	candidates, err := h.rootProofCandidates(rdfCred)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, proof := range candidates {
		result, err := h.verifyOneRootProof(ctx, rdfCred, credBytes, credMap, proof, issuer)
		if err != nil {
			lastErr = err
			continue
		}
		return result, nil
	}
	if lastErr == nil {
		lastErr = errors.New("credential missing proof")
	}

	return nil, lastErr
}

// rootProofCandidates lists the proofs the document attaches to itself, in
// the short-keyed form the rest of this handler reads.
func (h *VC20Handler) rootProofCandidates(rdfCred *credential.RDFCredential) ([]map[string]any, error) {
	// The MEMOIZED compaction. Compacting here and letting the suites
	// compact the same set again on the way to matching a candidate doubled
	// the JSON-LD work on unauthenticated input, and bypassed the
	// memoization that exists to stop exactly that.
	//
	// Skipping a proof that will not compact, reporting why when none
	// survive, and the proof-count cap all live in that one step now,
	// rather than being repeated here.
	candidates, err := credential.CompactedRootProofs(rdfCred)
	if err != nil {
		return nil, err
	}
	if len(candidates) > credential.MaxRootProofs {
		return nil, fmt.Errorf("the document attaches %d proofs to itself, more than the %d this will verify", len(candidates), credential.MaxRootProofs)
	}

	return candidates, nil
}

// verifyOneRootProof resolves the key this proof names and dispatches on the
// cryptosuite it declares.
func (h *VC20Handler) verifyOneRootProof(
	ctx context.Context,
	rdfCred *credential.RDFCredential,
	credBytes []byte,
	credMap map[string]any,
	proof map[string]any,
	issuer string,
) (*VC20VerificationResult, error) {
	vm, _ := proof["verificationMethod"].(string)
	if vm == "" {
		return nil, errors.New("proof missing verificationMethod")
	}

	// EXPANDED, because that is the identifier the key belongs to. A
	// compact document may define a prefix and write "ex:key"; the same
	// method read back off the RDF is the absolute IRI it stands for. The
	// resolver was being handed whichever spelling the document happened to
	// use, so two documents naming one key asked for two different keys -
	// and the check that the proof which VERIFIED names the method the key
	// was resolved from could never match for a compact one.
	vm, err := h.expandVerificationMethod(credMap, proof, vm)
	if err != nil {
		return nil, err
	}

	// The key must be the ISSUER's. Resolving it says the trust framework
	// knows that verification method, not that the issuer this credential
	// names may sign with it - so a credential claiming an allowlisted
	// issuer, signed with any key the resolver will hand back, was accepted
	// and reported as that issuer's.
	//
	// ASKED when the resolver can answer, and only approximated when it
	// cannot. The lexical test runs first in that case, before resolution,
	// so an unauthorized method costs no lookup.
	authorizer, canAuthorize := h.keyResolver.(VC20IssuerAuthorizer)
	if !canAuthorize {
		if err := issuerControlsMethod(issuer, vm); err != nil {
			return nil, err
		}
	}

	pubKey, err := h.keyResolver.ResolveKey(ctx, vm)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve public key: %w", err)
	}

	if canAuthorize {
		purpose, _ := proof["proofPurpose"].(string)
		if err := authorizer.AuthorizeIssuerKey(ctx, issuer, pubKey, purpose); err != nil {
			return nil, fmt.Errorf("the issuer %q may not assert with the key %q names: %w", issuer, vm, err)
		}
	}

	// Determine cryptosuite and verify with appropriate key type
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
		return h.verifyECDSA2019(ctx, rdfCred, credBytes, credMap, proof, vm, ecdsaKey)

	case CryptosuiteECDSASd:
		ecdsaKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("cryptosuite %s requires ECDSA key, got %T", cryptosuite, pubKey)
		}
		return h.verifyECDSASd2023(ctx, rdfCred, credBytes, credMap, proof, ecdsaKey)

	case CryptosuiteEdDSA2022:
		ed25519Key, ok := pubKey.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("cryptosuite %s requires Ed25519 key, got %T", cryptosuite, pubKey)
		}
		return h.verifyEdDSA2022(ctx, rdfCred, credBytes, credMap, proof, vm, ed25519Key)

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

// expandedRootIsAPresentation reports whether the node an expanded document is
// ABOUT is a VerifiablePresentation.
//
// The root, not any node. An earlier version refused a document that carried a
// presentation anywhere, on the grounds that refusing cost a caller nothing -
// but a credential may carry one as evidence or under any other property, and
// that refused something perfectly verifiable. Root selection says which node
// the proofs belong to, so that is the node to ask about.
//
// A document whose root cannot be identified is left to the extraction below
// to refuse, with the error that says why.
func expandedRootIsAPresentation(expanded []any) bool {
	const vpType = "https://www.w3.org/2018/credentials#VerifiablePresentation"

	root, err := credential.RootOfExpandedNodes(expanded)
	if err != nil {
		return false
	}
	types, hasTypes := root["@type"].([]any)
	if !hasTypes {
		return false
	}
	for _, entry := range types {
		if name, isString := entry.(string); isString && name == vpType {
			return true
		}
	}
	return false
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

	// The ROOT node, not the first credential in array order. A flattened
	// document may hold several VerifiableCredential nodes - one nested
	// under credentialSubject, say - and top-level array order is not
	// signed. Taking the first meant reordering a nested credential to the
	// front had the handler report ITS issuer and claims while
	// rootProofCandidates verified the outer credential's proof.
	//
	// credential.RootOfExpandedNodes is the same rule the rest of this
	// change uses: the node nothing else refers to, and a refusal when the
	// document does not say which that is. It also knows the two things a
	// fresh selector loses - a named graph is not a candidate, and a node
	// split across several top-level entries is ONE node.
	root, err := credential.RootOfExpandedNodes(expanded)
	if err != nil {
		return nil, fmt.Errorf("cannot tell which node an expanded document is about: %w", err)
	}

	for _, node := range []any{root} {
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
			return nil, errors.New("the node an expanded document is about is not a VerifiableCredential")
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
					if resolved := h.proofForRef(expanded, proofRef); resolved != nil {
						result["proof"] = resolved
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

	return nil, errors.New("the node an expanded document is about is not a VerifiableCredential")
}

// proofForRef resolves the proof a root's proof reference NAMES, rather than
// whichever named graph the expanded array happens to list first.
//
// A root proof that survived a round trip through RDF is a REFERENCE to a
// graph sitting beside the document, and an expanded credential carrying an
// embedded secured credential has more than one such graph. Accepting the
// first let top-level array ORDER decide which proof was reported - and array
// order is not signed - so a document could be reordered until the claims
// named the NESTED issuer's proof while rootProofCandidates verified the
// root's. Exactly the defect already fixed for the credential node itself.
//
// Nothing matching means no proof is reported. Reporting the wrong one is the
// failure being removed here; saying nothing is not.
func (h *VC20Handler) proofForRef(expanded []any, proofRef string) map[string]any {
	// Fragments of ONE graph, gathered: flattening may split a named graph
	// across several top-level entries, and the proof can be in any of them.
	var members []any
	var direct map[string]any

	for _, entry := range expanded {
		node, isNode := entry.(map[string]any)
		if !isNode {
			continue
		}
		id, isText := node["@id"].(string)
		if !isText || id != proofRef {
			continue
		}
		if graph, isGraph := node["@graph"].([]any); isGraph {
			members = append(members, graph...)
			continue
		}
		// A node bearing the reference's identifier and no graph: the proof
		// written inline rather than as a named graph.
		if direct == nil {
			direct = node
		}
	}

	for _, member := range members {
		if node, isNode := member.(map[string]any); isNode {
			return h.extractProofFromExpanded(node)
		}
	}
	if direct != nil {
		return h.extractProofFromExpanded(direct)
	}
	return nil
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
	rdfCred *credential.RDFCredential,
	credBytes []byte,
	credMap map[string]any,
	proof map[string]any,
	verificationMethod string,
	pubKey *ecdsa.PublicKey,
) (*VC20VerificationResult, error) {
	// Verify using the standard suite, and build the result from the proof
	// that ACTUALLY verified - see verifyEdDSA2022 for the attack this
	// closes; both suites try every proof the root carries.
	suite := ecdsaSuite.NewSuite()
	verifiedProof, err := suite.VerifyRootProof(rdfCred, pubKey, proof)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}
	if err := sameVerificationMethod(verifiedProof, verificationMethod); err != nil {
		return nil, err
	}

	// Build result
	return h.buildResult(credBytes, credMap, verifiedProof, false)
}

// verifyECDSASd2023 verifies a credential with ecdsa-sd-2023 cryptosuite.
func (h *VC20Handler) verifyECDSASd2023(
	ctx context.Context,
	rdfCred *credential.RDFCredential,
	credBytes []byte,
	credMap map[string]any,
	proof map[string]any,
	pubKey *ecdsa.PublicKey,
) (*VC20VerificationResult, error) {
	// Verify THIS candidate, not whichever proof the suite would pick for
	// itself. Verify(cred, key) selects independently, so the proof that
	// verified and the proof whose metadata this result reports could be two
	// different proofs - which is all an attacker needs to have a forged
	// proof described back to the caller.
	sdSuite := ecdsaSuite.NewSdSuite()
	verifiedProof, err := sdSuite.VerifyRootProof(rdfCred, pubKey, proof)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Build result from what VERIFIED, not from what was asked about.
	return h.buildResult(credBytes, credMap, verifiedProof, true)
}

// verifyEdDSA2022 verifies a credential with eddsa-rdfc-2022 cryptosuite.
func (h *VC20Handler) verifyEdDSA2022(
	ctx context.Context,
	rdfCred *credential.RDFCredential,
	credBytes []byte,
	credMap map[string]any,
	proof map[string]any,
	verificationMethod string,
	pubKey ed25519.PublicKey,
) (*VC20VerificationResult, error) {
	// Verify using the EdDSA suite, and build the result from the proof
	// that ACTUALLY verified.
	//
	// A document may carry several root proofs and the suite tries each.
	// extractProof hands back the FIRST one in the array, so describing
	// that one let an attacker prepend an invalid proof naming the real
	// verification method with a forged proofPurpose or created: the suite
	// verified the genuine proof further along, and this result reported
	// the forged one's fields as verified.
	suite := eddsaSuite.NewSuite()
	verifiedProof, err := suite.VerifyRootProof(rdfCred, pubKey, proof)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	if err := sameVerificationMethod(verifiedProof, verificationMethod); err != nil {
		return nil, err
	}

	// Build result
	return h.buildResult(credBytes, credMap, verifiedProof, false)
}

// expandDocumentIdentifier turns an identifier the document spells compactly
// into the absolute IRI it stands for, under the document's own context.
//
// The issuer needs this for the same reason the verification method does: an
// absolute IRI expands to itself, so this changes nothing for the common case,
// while "ex:issuer" under a document defining that prefix becomes the
// identifier a key can belong to and a policy can name.
func (h *VC20Handler) expandDocumentIdentifier(credMap map[string]any, identifier string) (string, error) {
	if identifier == "" {
		return identifier, nil
	}
	// No proof, so no proof-local context: an issuer is a member of the
	// document, not of a proof.
	return h.expandVerificationMethod(credMap, map[string]any{}, identifier)
}

// expandVerificationMethod turns the method as the document spells it into
// the absolute IRI it stands for, using the document's own context.
//
// An absolute IRI expands to itself, so this changes nothing for the common
// case; a compact one ("ex:key", with ex defined in the context) becomes the
// IRI the RDF form carries, which is what the suite reports and what a
// resolver should be keyed on.
//
// The probe NESTS the proof's context inside the document's, exactly as the
// real document does, rather than joining them into one array. Context
// processing is ordered and a nested context may RESET the active one with
// null - so a proof whose context is [null, someURL] means something
// different from [someURL, null], and flattening the two into one list
// (worse, dropping a repeated URL to avoid "recursive context inclusion")
// silently changes which terms are defined. Letting json-gold walk the same
// nesting the document has gets the order, the resets and the repeats right
// without this code knowing the rules.
//
// Reachability: proofs now reach this function from
// rootProofCandidates, which reads them off the EXPANDED document and compacts
// each against the v2 context alone - so the method is already an absolute IRI
// and the proof no longer carries an @context of its own by the time it gets
// here. The proof-local context handling below is therefore inert on that
// path; it is kept because this function must not depend on WHERE its proof
// came from. Changing the source back to the raw JSON, which is what the
// handler used to do, is exactly the mistake it exists to absorb.
func (h *VC20Handler) expandVerificationMethod(credMap map[string]any, proof map[string]any, method string) (string, error) {
	documentContext, hasDocumentContext := credMap["@context"]
	localContext, hasLocalContext := proof["@context"]
	if !hasDocumentContext && !hasLocalContext {
		return method, nil
	}

	const verificationMethodIRI = "https://w3id.org/security#verificationMethod"
	const proofIRI = "https://w3id.org/security#proof"

	probeProof := map[string]any{verificationMethodIRI: map[string]any{"@id": method}}
	// By PRESENCE, not by non-nil. An explicit "@context": null is a
	// context RESET in JSON-LD, not an absent context: it drops the
	// inherited definitions, so a method compacted under a prefix the
	// document defines is not resolvable on that proof. Treating null as
	// absent expanded it anyway, under prefixes the real proof does not
	// have.
	if hasLocalContext {
		probeProof["@context"] = localContext
	}
	// The proof's TYPE goes in too. A type-scoped context - a local context
	// that hangs term definitions off a proof type - is only active on a
	// node carrying that type, so a probe without it expands the method
	// under a different active context than the document does, and resolves
	// the wrong key or none.
	if proofType, present := proof["type"]; present {
		probeProof["@type"] = proofType
	} else if proofType, present := proof["@type"]; present {
		probeProof["@type"] = proofType
	}
	probe := map[string]any{proofIRI: probeProof}
	if hasDocumentContext {
		// json-gold reads a context out of decoded JSON, so a []string
		// built in Go - which this package does in one place - is not one
		// it accepts.
		if typed, isStrings := documentContext.([]string); isStrings {
			entries := make([]any, 0, len(typed))
			for _, entry := range typed {
				entries = append(entries, entry)
			}
			documentContext = entries
		}
		probe["@context"] = documentContext
	}

	expanded, err := ld.NewJsonLdProcessor().Expand(probe, credential.NewJSONLDOptions(""))
	if err != nil {
		return "", fmt.Errorf("cannot expand verificationMethod %q against the document's context: %w", method, err)
	}
	if id := findExpandedID(expanded, verificationMethodIRI); id != "" {
		return id, nil
	}

	// Expansion dropped it, which means it is a relative reference no
	// context defines - not an identifier a key can belong to.
	return "", fmt.Errorf("verificationMethod %q is not an absolute IRI and the document's context does not define it", method)
}

// findExpandedID returns the @id expansion gave the first value of predicate.
func findExpandedID(node any, predicate string) string {
	switch typed := node.(type) {
	case []any:
		for _, entry := range typed {
			if id := findExpandedID(entry, predicate); id != "" {
				return id
			}
		}
	case map[string]any:
		if values, ok := typed[predicate].([]any); ok && len(values) > 0 {
			if entry, ok := values[0].(map[string]any); ok {
				if id, ok := entry["@id"].(string); ok && id != "" {
					return id
				}
			}
		}
		for key, member := range typed {
			if key == "@id" {
				continue
			}
			if id := findExpandedID(member, predicate); id != "" {
				return id
			}
		}
	}
	return ""
}

// proofTypeOf names the proof's type, preferring the Data Integrity one
// when a proof carries several.
func proofTypeOf(proof map[string]any) string {
	switch typed := proof["type"].(type) {
	case string:
		return typed
	case []any:
		first := ""
		for _, entry := range typed {
			name, ok := entry.(string)
			if !ok {
				continue
			}
			if name == dataIntegrityProofType {
				return name
			}
			if first == "" {
				first = name
			}
		}
		return first
	}
	return ""
}

// dataIntegrityProofType is the type every cryptosuite here produces.
const dataIntegrityProofType = "DataIntegrityProof"

// issuerControlsMethod refuses a proof whose verification method does not
// belong to the issuer the credential names.
//
// Resolution is not authorization. The resolver answers "is this a
// verification method the trust framework knows", which in a framework
// holding many issuers is true of every one of their keys - so nothing
// stopped a credential naming issuer A from being signed by issuer B, or by
// anyone else resolvable, and reported as A's.
//
// This is the FALLBACK, used only when the resolver cannot answer the real
// question - see VC20IssuerAuthorizer, which a resolver should implement
// wherever the trust decision actually lives.
//
// It is weaker in both directions, and knowing how is the point of this
// comment. An identifier under the issuer is not proof that the key sits in
// that issuer's assertionMethod relationship, and a key delegated to a
// different identifier may be perfectly well authorized. It is here because
// the alternative, with no authorizer, is no binding at all - and no binding
// means any resolvable key signs for any issuer.
//
// The test is lexical, because a resolved key arrives without its controller:
// the method must BE the issuer, or live under it - a fragment, a path, or a
// query. did:example:issuer#key-1 belongs to did:example:issuer;
// https://issuer.example/keys/1 belongs to https://issuer.example. Anything
// else is refused rather than guessed at.
//
// A deployment that signs with a key outside the issuer's own identifier
// space - delegation to a separate DID - is refused by this and needs the
// authorization asked of the PDP instead, which the KeyResolver interface
// cannot express today.
func issuerControlsMethod(issuer string, verificationMethod string) error {
	if issuer == "" {
		return errors.New("the credential names no issuer, so no proof can be checked against it")
	}
	// A path that climbs back OUT is not under the issuer, whatever the
	// prefix says: https://issuer.example/keys/../other-tenant/key starts
	// with the issuer and resolves somewhere else entirely. Rather than
	// try to normalize it, anything carrying a dot segment is refused -
	// a verification method has no business containing one.
	if err := refuseDotSegments(verificationMethod); err != nil {
		return err
	}

	// The issuer's own trailing delimiter is not a boundary of its own.
	// https://issuer.example/ and https://issuer.example name the same
	// thing, but comparing the first against https://issuer.example/keys/1
	// found "k" where it wanted a delimiter and refused a method in the
	// issuer's own path.
	boundary := strings.TrimRight(issuer, "#/?")
	if boundary == "" {
		return fmt.Errorf("the credential's issuer %q names nothing a proof can belong to", issuer)
	}

	if verificationMethod == boundary {
		return nil
	}
	if strings.HasPrefix(verificationMethod, boundary) {
		switch verificationMethod[len(boundary)] {
		case '#', '/', '?':
			return nil
		}
	}
	return fmt.Errorf("the proof's verification method %q does not belong to the issuer %q", verificationMethod, issuer)
}

// refuseDotSegments rejects an identifier carrying a path segment that climbs
// out of where it appears to sit.
//
// At EVERY decoding depth, not just as written. A prefix test is not
// containment, and https://issuer.example/keys/../other/key is the obvious
// way past it - but so is %2e%2e, which a resolver normalizing the URL reads
// as the same thing, and %252e%252e behind that. Decoding is repeated until
// the identifier stops changing and every stage is checked, so the depth of
// the encoding does not decide the answer.
//
// Refused rather than normalized: a verification method has no business
// carrying a dot segment at all, and refusing is a rule one can read, while
// canonicalizing invites the next disagreement about whose normalization is
// right.
func refuseDotSegments(identifier string) error {
	const maxDecodings = 8

	seen := identifier
	for range maxDecodings {
		for _, segment := range strings.Split(seen, "/") {
			if segment == "." || segment == ".." {
				return fmt.Errorf("the proof's verification method %q contains a path segment that climbs out of it", identifier)
			}
		}

		decoded, err := url.PathUnescape(seen)
		if err != nil {
			// Not decodable, so nothing below this can be a dot segment
			// either - but an identifier this library cannot read is not
			// one it should accept as an issuer's.
			return fmt.Errorf("the proof's verification method %q is not a readable identifier: %w", identifier, err)
		}
		if decoded == seen {
			return nil
		}
		seen = decoded
	}
	return fmt.Errorf("the proof's verification method %q is encoded too deeply to check", identifier)
}

// sameVerificationMethod checks that the proof which verified names the
// method the key was resolved from.
//
// The suites are handed a KEY, not a method, so a proof naming someone
// else's method could otherwise verify with this one and be reported under
// that name.
func sameVerificationMethod(verifiedProof map[string]any, resolvedFrom string) error {
	verifiedMethod, _ := verifiedProof["verificationMethod"].(string)
	if verifiedMethod != resolvedFrom {
		return fmt.Errorf("the proof that verified names verification method %q, but the key was resolved from %q",
			verifiedMethod, resolvedFrom)
	}
	return nil
}

// buildResult builds the verification result from credential data.
func (h *VC20Handler) buildResult(
	credBytes []byte,
	credMap map[string]any,
	proof map[string]any,
	isSD bool,
) (*VC20VerificationResult, error) {
	// The claims report the proof that VERIFIED, not whichever one the
	// document happens to list first. A proof SET may carry a forged proof
	// ahead of a genuine one, and extraction resolves only the first
	// reference - so Claims["proof"] named the proof this package had just
	// REJECTED while every other field on this result described the one it
	// accepted. A COPY, because the caller's map is not ours to rewrite.
	claims := maps.Clone(credMap)
	if claims == nil {
		claims = map[string]any{}
	}
	if proof != nil {
		claims["proof"] = proof
	}

	result := &VC20VerificationResult{
		Claims:                claims,
		RawCredential:         credBytes,
		IsSelectiveDisclosure: isSD,
	}

	// Extract credential ID
	if id, ok := credMap["id"].(string); ok {
		result.ID = id
	}

	// Extract issuer, EXPANDED - the identifier the trust decision was made
	// about, not the spelling the document happened to use. Reporting
	// "ex:one" while having checked https://example.org/issuers/one against
	// the trusted list invites a caller to compare the reported value with
	// its own policy and get a different answer.
	result.Issuer, _ = h.extractIssuer(credMap)
	if expanded, err := h.expandDocumentIdentifier(credMap, result.Issuer); err == nil {
		result.Issuer = expanded
	}

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
	//
	// The type may be a LIST. A document that hangs a type-scoped context
	// off its own alias for DataIntegrityProof has to name both - the alias
	// is not a replacement, since DataIntegrityProof is @protected and
	// carries the VC 2.0 definitions of cryptosuite and proofValue - and
	// reading only a string left the reported type empty for a proof this
	// package had just accepted.
	result.ProofType = proofTypeOf(proof)
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
