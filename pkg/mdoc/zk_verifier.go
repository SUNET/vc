package mdoc

// This file is the verification-side plumbing for "mso_mdoc_zk" OpenID4VP
// presentations - zero-knowledge (Longfellow) proof-of-possession, with an
// optional pairwise pseudonym (PPID), over an mdoc credential.
//
// It implements: decoding the zkDocuments wire structure, matching the
// requested DCQL zk_system_type against what was presented, verifying the
// issuer's certificate chain (msoX5chain) via the same TrustEvaluator used
// for plain "mso_mdoc" presentations, deriving the verifier_context a
// pairwise pseudonym is bound to, and assembling the exact argument shapes
// zk-cred-longfellow's own verify_with_ppid FFI function expects.
//
// The actual cryptographic ZK proof verification
// (nativeVerifyZkProof/nativeVerifyZkProofWithPPID) is implemented in one
// of two build-tag-gated files:
//   - zk_native_cgo.go (build tag "zknative"): a real cgo binding to
//     zk-cred-longfellow, resolving the presented zkSystemId to a circuit
//     via pkg/mdoc/zkcircuit and pkg/mdoc/zknative.
//   - zk_native_stub.go (default, no "zknative" tag): returns
//     ErrNativeZkVerifyNotImplemented.
//
// This mirrors pkg/pki's PKCS#11 support (build tag "pkcs11"): the default
// vc-verifier build stays CGO_ENABLED=0/fully static; native ZK
// verification is opt-in. See docs/ZK_PPID_VERIFICATION_PLAN.md and
// README.md's "Native ZK/PPID proof verification" section for setup.
import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/trust"

	"github.com/sirosfoundation/go-trust/pkg/trustapi"
)

// PseudonymClaimIdentifier is the element identifier a Longfellow V8 PPID
// proof uses for the derived pairwise pseudonym, both in the presented
// ZkDocumentData.IssuerSigned map and as an Attribute passed to the native
// verify_with_ppid call (see zk-cred-longfellow's prover.rs
// verify_with_ppid_wasm, which hardcodes the same identifier).
const PseudonymClaimIdentifier = "pairwise_pseudonym"

// ErrNativeZkVerifyNotImplemented is returned by the (stubbed) native ZK
// proof verification call. Every check that does NOT require the native
// Longfellow library - trust chain, zk_system_type matching, argument
// assembly - has already completed successfully by the time this error is
// produced; it marks specifically the "call into libzk" step that vc
// currently cannot perform. See docs/ZK_PPID_VERIFICATION_PLAN.md.
var ErrNativeZkVerifyNotImplemented = errors.New(
	"native Longfellow ZK proof verification is not implemented: vc-verifier has no Go binding to zk-cred-longfellow yet (see docs/ZK_PPID_VERIFICATION_PLAN.md)",
)

// ZkAttribute mirrors zk-cred-longfellow's own `Attribute` FFI record
// (see zk-cred-longfellow/src/mdoc_zk/verifier.rs): an element identifier
// plus the CBOR encoding of its value - the shape the native
// verify/verify_with_ppid calls expect for each disclosed claim.
type ZkAttribute struct {
	Identifier string
	ValueCBOR  []byte
}

// ZkVerifierConfig configures a ZkHandler. Mirrors VerifierConfig
// (the plain mso_mdoc verifier's config) - the same TrustEvaluator is
// reused since msoX5chain trust evaluation is identical for ZK and non-ZK
// presentations; only the credential digest/signature check differs
// (delegated to the ZK proof instead of a plain COSE_Sign1 + MSO digests).
type ZkVerifierConfig struct {
	// TrustEvaluator is required, same contract as VerifierConfig.TrustEvaluator.
	TrustEvaluator trust.TrustEvaluator

	// IssuerURL, same contract as VerifierConfig.IssuerURL.
	IssuerURL string

	// ZkCircuitSources are zk-circuits catalog mirror base URLs (see
	// pkg/mdoc/zkcircuit.Client), tried in order, used to resolve a
	// presented document's zkSystemId to a circuit for native verification.
	// Only consulted when built with the "zknative" tag; ignored by the
	// default stub. If empty, zkcircuit.DefaultZkCircuitURL is used.
	ZkCircuitSources []string

	// Clock is an optional function that returns the current time. Defaults
	// to time.Now.
	Clock func() time.Time
}

// ZkHandler verifies "mso_mdoc_zk" OpenID4VP presentations - the ZK/PPID
// counterpart to MDocHandler (which handles plain "mso_mdoc").
type ZkHandler struct {
	trustEvaluator   trust.TrustEvaluator
	issuerURL        string
	zkCircuitSources []string
	clock            func() time.Time
}

// NewZkHandler creates a new ZkHandler.
func NewZkHandler(cfg ZkVerifierConfig) (*ZkHandler, error) {
	if cfg.TrustEvaluator == nil {
		return nil, errors.New("TrustEvaluator is required")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	return &ZkHandler{
		trustEvaluator:   cfg.TrustEvaluator,
		issuerURL:        cfg.IssuerURL,
		zkCircuitSources: cfg.ZkCircuitSources,
		clock:            clock,
	}, nil
}

// ZkPresentationContext carries everything about the verifier's own
// request/session that a presented ZK document needs to be checked
// against: which ZK systems were offered (to match zkSystemId), and the
// inputs needed to (eventually) recompute the same verifier_context the
// wallet used to derive a pairwise pseudonym.
type ZkPresentationContext struct {
	// SessionID is this presentation's own session identifier - the REAL
	// verifier_id input for pseudonym derivation (confirmed 2026-08-17 via
	// direct report from zk-cred-longfellow's V8/PPID author: a pseudonym's
	// verifier_context binds to the presentation SESSION, not the
	// verifier's static identity - see ComputeZkVerifierContext). Should be
	// the same session id sent as the OpenID4VP `state` parameter.
	SessionID string

	// ClientID is the verifier's OpenID4VP client_id, used as the
	// verifier_id fallback only when SessionID is empty (e.g. a transport
	// with no server-assigned session id at all, mirroring
	// VerifierIdentity.sessionId's doc comment in siros-sdk-kotlin's
	// ZkProofSystem.kt).
	ClientID string

	// PPIDContext is the DCQL credential query's `meta.ppid_context`
	// string, if the original request had one. Empty if absent - see
	// ComputeZkVerifierContext for the exact absent-vs-present handling
	// (NOT the same as an empty string being hashed).
	PPIDContext string

	// RequestedZkSystems is the DCQL credential query's `meta.zk_system_type`
	// array - what this verifier declared it would accept. A presented
	// document whose ZkSystemID doesn't match one of these is rejected.
	RequestedZkSystems []openid4vp.ZKSystemTypeSpec

	// SessionTranscript is the CBOR-encoded ISO 18013-5 SessionTranscript
	// this presentation is bound to (see BuildOID4VPSessionTranscript for
	// the OpenID4VP redirect-flow construction). Required - the native
	// verify call uses it both as a public input and to seed the Fiat-Shamir
	// transcript the proof itself was built against.
	SessionTranscript []byte

	// RequestedClaimIDs is the DCQL credential query's `claims[].path`
	// leaf identifiers, in the exact order the request specified them -
	// NOT including "pairwise_pseudonym" (see PseudonymClaimIdentifier),
	// which buildZkAttributes always appends last, matching the
	// siros-sdk-kotlin/siros-sdk-swift proving-side convention
	// (`requestedClaims + PSEUDONYM_CLAIM`). This is the sole source of
	// truth for the order attributes are assembled in: zk-cred-longfellow's
	// verifier matches attributes to circuit slots purely by position (see
	// its own docs on this), so a wrong or nondeterministic order here
	// would make native verification of a genuinely valid proof fail. Empty
	// if no DCQL query was cached for this session/scope (best-effort,
	// matching RequestedZkSystems' own fallback) - buildZkAttributes then
	// has no ordering to reconstruct and returns an error rather than
	// silently guessing.
	RequestedClaimIDs []string
}

// ZkDocumentResult is the per-document verification/extraction result for
// one entry of a presented zkDocuments array.
type ZkDocumentResult struct {
	DocType    string
	ZkSystemID string
	// Claims is namespace -> elementIdentifier -> value, same shape as
	// MDocDocumentClaims.Namespaces (issuer-signed only - see
	// ZkDocumentDataMdoc.FlattenIssuerSigned).
	Claims map[string]map[string]any
	// Pseudonym is the presented pairwise_pseudonym bytes, if the document
	// disclosed one (nil otherwise). This is the wallet-computed pseudonym
	// value as presented, NOT independently re-derived here - only the ZK
	// proof itself (once verifiable) attests it was correctly computed from
	// a validly-signed pseudonym_seed and this presentation's
	// verifier_context.
	Pseudonym []byte
}

// ZkVerificationResult is the ZK counterpart of MDocVerificationResult.
type ZkVerificationResult struct {
	Valid     bool
	Documents map[string]*ZkDocumentResult
}

// GetClaims returns a flat map of all claims from all namespaces, using the
// exact same qualification convention as MDocDocumentClaims.GetClaims (so
// callers that already flatten mso_mdoc claims can treat ZK results
// identically).
func (r *ZkDocumentResult) GetClaims() map[string]any {
	claims := make(map[string]any)
	for ns, nsItems := range r.Claims {
		for key, value := range nsItems {
			qualifiedKey := fmt.Sprintf("%s.%s", ns, key)
			claims[qualifiedKey] = value
			if ns == Namespace {
				claims[key] = value
			}
		}
	}
	return claims
}

// VerifyAndExtract verifies a "mso_mdoc_zk" vp_token: it decodes the
// zkDocuments wire structure, matches each document's declared ZK system
// against pctx.RequestedZkSystems, verifies the issuer certificate chain via
// TrustEvaluator, assembles the native verify/verify_with_ppid call's
// arguments (including, for a PPID document, the verifier_context - see
// ComputeZkVerifierContext), and then calls the native ZK verify function.
//
// That last call (see nativeVerifyZkProof / nativeVerifyZkProofWithPPID)
// is real for the PPID path under the "zknative" build tag (see
// zk_native_cgo.go); the non-PPID direction and the default (no
// "zknative" tag) build both still return ErrNativeZkVerifyNotImplemented
// - see those functions' own doc comments for why. Every prior step here
// is always real regardless of the build tag: a document that fails
// trust evaluation or zk_system_type matching is rejected for that
// reason, not because of the native-binding gap, so callers can already
// distinguish "this presentation is malformed/untrusted" from
// "verification isn't fully wired up yet" by checking the returned error.
func (h *ZkHandler) VerifyAndExtract(ctx context.Context, vpToken string, pctx ZkPresentationContext) (*ZkVerificationResult, error) {
	// Decode the VP token (base64url-encoded DeviceResponse) - same
	// convention as MDocHandler.VerifyAndExtract.
	data, err := base64.RawURLEncoding.DecodeString(vpToken)
	if err != nil {
		data, err = base64.StdEncoding.DecodeString(vpToken)
		if err != nil {
			return nil, fmt.Errorf("failed to decode ZK mdoc VP token: %w", err)
		}
	}

	response, err := DecodeDeviceResponse(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ZK device response: %w", err)
	}

	if response.Version != "1.0" {
		return nil, fmt.Errorf("unsupported response version: %s", response.Version)
	}
	if response.Status != 0 {
		return nil, fmt.Errorf("response status indicates error: %d", response.Status)
	}
	if len(response.ZkDocuments) == 0 {
		return nil, errors.New("device response contains no zkDocuments")
	}
	if len(pctx.SessionTranscript) == 0 {
		return nil, errors.New("SessionTranscript is required")
	}

	result := &ZkVerificationResult{
		Valid:     true,
		Documents: make(map[string]*ZkDocumentResult, len(response.ZkDocuments)),
	}

	var errs []error
	for i := range response.ZkDocuments {
		zkDoc := &response.ZkDocuments[i]

		dd, err := zkDoc.ParseZkDocumentData()
		if err != nil {
			errs = append(errs, fmt.Errorf("zkDocuments[%d]: %w", i, err))
			result.Valid = false
			continue
		}

		docResult, err := h.verifyOneDocument(ctx, zkDoc, dd, pctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("zkDocuments[%d] (docType=%s): %w", i, dd.DocType, err))
			result.Valid = false
			continue
		}

		result.Documents[dd.DocType] = docResult
	}

	if len(errs) > 0 {
		return result, errors.Join(errs...)
	}
	return result, nil
}

func (h *ZkHandler) verifyOneDocument(ctx context.Context, zkDoc *ZkDocumentMdoc, dd *ZkDocumentDataMdoc, pctx ZkPresentationContext) (*ZkDocumentResult, error) {
	// 1. Match the declared ZK system against what this verifier requested.
	_, matched := openid4vp.MatchZKSystemType(pctx.RequestedZkSystems, dd.ZkSystemID)
	if !matched {
		return nil, fmt.Errorf("zkSystemId %q was not offered in this request's zk_system_type", dd.ZkSystemID)
	}

	// 2. Extract and trust-evaluate the issuer's certificate chain. This is
	// real, independent of the native ZK library - it's the same trust
	// decision a plain mso_mdoc presentation goes through (see
	// verifyCertificateChainWithContext in verifier.go), just duplicated
	// here rather than shared, since ZkHandler and Verifier are separate
	// types with no common base to hang a shared method off without a
	// larger refactor of the existing (unrelated) Verifier type.
	certs, err := dd.X5ChainCertificates()
	if err != nil {
		return nil, fmt.Errorf("msoX5chain: %w", err)
	}
	dsCert := certs[0]

	now := h.clock()
	if now.Before(dsCert.NotBefore) {
		return nil, fmt.Errorf("certificate not yet valid: valid from %s", dsCert.NotBefore)
	}
	if now.After(dsCert.NotAfter) {
		return nil, fmt.Errorf("certificate expired: valid until %s", dsCert.NotAfter)
	}

	issuerID := h.issuerURL
	if issuerID == "" {
		issuerID = extractMDocIssuerID(dsCert)
	}
	decision, err := h.trustEvaluator.Evaluate(ctx, &trust.EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			SubjectID: issuerID,
			KeyType:   trust.KeyTypeX5C,
			Key:       certs,
			Role:      trust.RoleCredentialIssuer,
			DocType:   dd.DocType,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("trust evaluation failed: %w", err)
	}
	if !decision.Trusted {
		return nil, fmt.Errorf("issuer not trusted: %s", decision.Reason)
	}

	// 3. Assemble the native call's arguments.
	issuerSigned := dd.FlattenIssuerSigned()
	attributes, pseudonym, err := buildZkAttributes(issuerSigned, pctx.RequestedClaimIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to assemble ZK attributes: %w", err)
	}

	// Use the package's canonical (sorted-map-key) CBOR encoder, not the
	// cbor library's plain package-level Marshal: deviceSignedToWireMap
	// returns a genuine Go map (map[string]map[string]any), and Go map
	// iteration order is randomized, so the default (SortNone) encoder
	// would produce non-deterministic bytes across calls whenever there is
	// more than one namespace or element. device_name_spaces_bytes must
	// byte-match the canonical CBOR encoding a real wallet's own canonical
	// encoder produced when it built the ZK proof - every other CBOR
	// encode call site in this package already goes through
	// NewCBOREncoder() for exactly this reason.
	cborEncoder, err := NewCBOREncoder()
	if err != nil {
		return nil, fmt.Errorf("failed to create CBOR encoder: %w", err)
	}
	deviceNameSpacesBytes, err := cborEncoder.Marshal(deviceSignedToWireMap(dd.DeviceSigned))
	if err != nil {
		return nil, fmt.Errorf("failed to encode device_name_spaces_bytes: %w", err)
	}

	issuerPubKeySEC1, err := sec1PublicKeyFromCert(dsCert)
	if err != nil {
		return nil, fmt.Errorf("failed to extract issuer public key: %w", err)
	}

	timeStr := string(dd.Timestamp)

	// 4. Call into the native ZK verifier.
	if pseudonym != nil {
		verifierContext := ComputeZkVerifierContext(pctx.SessionID, pctx.ClientID, pctx.PPIDContext)
		if err := nativeVerifyZkProofWithPPID(
			ctx, dd.ZkSystemID, issuerPubKeySEC1, attributes, dd.DocType,
			deviceNameSpacesBytes, pctx.SessionTranscript, timeStr,
			verifierContext[:], zkDoc.Proof, h.zkCircuitSources,
		); err != nil {
			return nil, err
		}
	} else {
		if err := nativeVerifyZkProof(
			ctx, dd.ZkSystemID, issuerPubKeySEC1, attributes, dd.DocType,
			deviceNameSpacesBytes, pctx.SessionTranscript, timeStr, zkDoc.Proof, h.zkCircuitSources,
		); err != nil {
			return nil, err
		}
	}

	return &ZkDocumentResult{
		DocType:    dd.DocType,
		ZkSystemID: dd.ZkSystemID,
		Claims:     issuerSigned,
		Pseudonym:  pseudonym,
	}, nil
}

// buildZkAttributes converts a flattened issuerSigned claim map into the
// []ZkAttribute shape the native verify call expects, and separately
// returns the pairwise_pseudonym bytes if the document disclosed one (found
// under PseudonymClaimIdentifier in any namespace).
//
// Order is NOT derived from map iteration (Go's map order is randomized,
// and was a real, confirmed nondeterminism bug here before this fix -
// zk-cred-longfellow's verifier matches attributes to circuit slots purely
// by position, so a random order makes native verification of a genuinely
// valid proof fail unpredictably). Instead this reconstructs the exact
// order the original prover used: requestedClaimIDs (the DCQL request's own
// claims[].path order) first, then "pairwise_pseudonym" always LAST if
// present - mirroring siros-sdk-kotlin/siros-sdk-swift's
// `requestedClaims + PSEUDONYM_CLAIM` proving-side convention exactly. See
// ZkPresentationContext.RequestedClaimIDs's doc comment for the full
// rationale.
func buildZkAttributes(issuerSigned map[string]map[string]any, requestedClaimIDs []string) ([]ZkAttribute, []byte, error) {
	if len(requestedClaimIDs) == 0 {
		return nil, nil, fmt.Errorf("no requested claim IDs available to determine attribute order - cannot safely assemble a native ZK verify call")
	}

	// Use the package's canonical (sorted-map-key) CBOR encoder, not the
	// cbor library's plain package-level Marshal: an attribute's value can
	// itself be a map (structured mdoc claims decode as map[string]any),
	// and the default encoder's SortNone mode encodes maps in Go's
	// randomized iteration order - non-deterministic across calls. Each
	// attribute's value_cbor must byte-match the canonical encoding a real
	// wallet's own canonical encoder committed to inside the ZK proof.
	cborEncoder, err := NewCBOREncoder()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CBOR encoder: %w", err)
	}

	// findClaim looks up identifier across every disclosed namespace - the
	// DCQL request only names the leaf identifier (mdoc claim paths are
	// [namespace, elementIdentifier], and buildZkAttributes has never
	// needed the namespace itself: ZkAttribute.Identifier is bare, matching
	// the native verifier's own expectation), so this mirrors the lookup
	// semantics the old (buggy) map-iteration version had, minus the
	// nondeterminism.
	findClaim := func(identifier string) (any, bool) {
		for _, items := range issuerSigned {
			if value, ok := items[identifier]; ok {
				return value, true
			}
		}
		return nil, false
	}

	buildOne := func(identifier string, value any) (ZkAttribute, error) {
		valueCBOR, err := cborEncoder.Marshal(value)
		if err != nil {
			return ZkAttribute{}, fmt.Errorf("failed to encode attribute %q: %w", identifier, err)
		}
		return ZkAttribute{Identifier: identifier, ValueCBOR: valueCBOR}, nil
	}

	attributes := make([]ZkAttribute, 0, len(requestedClaimIDs)+1)
	for _, identifier := range requestedClaimIDs {
		if identifier == PseudonymClaimIdentifier {
			// Kotlin/Swift never include this in requestedClaims itself
			// (it's appended separately, always last) - a DCQL request
			// that somehow did name it explicitly would double it up at
			// the wrong position, so guard against that rather than
			// silently mis-ordering.
			return nil, nil, fmt.Errorf("%s must not appear in RequestedClaimIDs - it is always appended last automatically", PseudonymClaimIdentifier)
		}
		value, ok := findClaim(identifier)
		if !ok {
			return nil, nil, fmt.Errorf("requested claim %q was not disclosed in this presentation", identifier)
		}
		attr, err := buildOne(identifier, value)
		if err != nil {
			return nil, nil, err
		}
		attributes = append(attributes, attr)
	}

	var pseudonym []byte
	if value, ok := findClaim(PseudonymClaimIdentifier); ok {
		b, ok := value.([]byte)
		if !ok {
			// A present-but-wrong-type pairwise_pseudonym claim must not
			// silently fall back to the non-PPID verify path (which is
			// unimplemented even under "zknative" - see
			// nativeVerifyZkProof's doc comment): that would produce a
			// misleading ErrNativeZkVerifyNotImplemented instead of a
			// clear error about the actual malformed claim.
			return nil, nil, fmt.Errorf(
				"%s claim has unexpected CBOR type %T, want []byte",
				PseudonymClaimIdentifier, value,
			)
		}
		attr, err := buildOne(PseudonymClaimIdentifier, value)
		if err != nil {
			return nil, nil, err
		}
		attributes = append(attributes, attr)
		pseudonym = b
	}

	return attributes, pseudonym, nil
}

// deviceSignedToWireMap converts the flattened {namespace: [{elementIdentifier,
// elementValue}]} shape ZkDocumentDataMdoc.DeviceSigned decodes to back into
// the real ISO 18013-5 DeviceNameSpaces CBOR shape ({namespace:
// {elementIdentifier: elementValue}}) that device_name_spaces_bytes must
// encode. Empty/nil input encodes to an empty CBOR map (0xA0), matching
// zk-cred-longfellow's own test vectors for "no device-signed elements".
func deviceSignedToWireMap(deviceSigned map[string][]ZkSignedItemMdoc) map[string]map[string]any {
	out := make(map[string]map[string]any, len(deviceSigned))
	for ns, items := range deviceSigned {
		nsMap := make(map[string]any, len(items))
		for _, item := range items {
			nsMap[item.ElementIdentifier] = item.ElementValue
		}
		out[ns] = nsMap
	}
	return out
}

// ComputeZkVerifierContext derives the 32-byte verifier_context a
// pairwise-pseudonym (PPID) proof binds to, implementing the confirmed
// wire-format formula (siros-sdk-kotlin's ZkProofSystem.kt
// DefaultZkPseudonymDeriver, cross-checked against multipaz's own
// verifier.kt at multipaz-verifier-server, both updated 2026-08-17 after
// direct confirmation from zk-cred-longfellow's V8/PPID author):
//
//	verifier_id_hash    = SHA256(verifier_id_source)
//	ppid_context_hash   = SHA256(ppid_context)   if ppid_context != ""
//	                    = 32 zero bytes           otherwise (NOT SHA256(""))
//	verifier_context    = SHA256(verifier_id_hash || ppid_context_hash)
//
// verifier_id_source is sessionID if non-empty, else clientID - a real
// reference implementation (confirmed against zk-cred-longfellow's own
// author) binds a pseudonym to the presentation SESSION, not the verifier's
// static identity, specifically so a captured proof can't be
// replayed/cached against a different session. clientID is only a fallback
// for transports with no server-assigned session id (e.g. DC API).
//
// The pseudonym itself is then (inside the ZK circuit, not computed here):
// SHA256(pseudonym_seed || verifier_context). This function only produces
// the verifier_context input to that formula, not the pseudonym.
func ComputeZkVerifierContext(sessionID, clientID, ppidContext string) [32]byte {
	verifierIDSource := sessionID
	if verifierIDSource == "" {
		verifierIDSource = clientID
	}
	verifierIDHash := sha256.Sum256([]byte(verifierIDSource))

	var ppidContextHash [32]byte // zero value = 32 zero bytes, the documented no-context default
	if ppidContext != "" {
		ppidContextHash = sha256.Sum256([]byte(ppidContext))
	}

	combined := make([]byte, 0, 64)
	combined = append(combined, verifierIDHash[:]...)
	combined = append(combined, ppidContextHash[:]...)
	return sha256.Sum256(combined)
}

// sec1PublicKeyFromCert extracts a certificate's EC public key in SEC1
// (uncompressed X9.62, 0x04||X||Y) encoding - the format
// zk-cred-longfellow's verify/verify_with_ppid expect for
// issuer_public_key_sec_1 ("as encoded in the public key field of an X.509
// SubjectPublicKeyInfo", which for an EC key IS the SEC1 point encoding).
func sec1PublicKeyFromCert(cert *x509.Certificate) ([]byte, error) {
	ecPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("issuer certificate public key is %T, not *ecdsa.PublicKey", cert.PublicKey)
	}
	ecdhPub, err := ecPub.ECDH()
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key: %w", err)
	}
	return ecdhPub.Bytes(), nil
}

// nativeVerifyZkProof and nativeVerifyZkProofWithPPID are implemented in
// zk_native_cgo.go (build tag "zknative") or zk_native_stub.go (default) -
// see this file's package doc comment above.
