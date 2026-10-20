package registry

import (
	"strings"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// VerifierIDTypesEnabled returns the verifier identifier types the policy
// enabled for this request (context key return_verifier_ids, written only by
// applyPolicyToRequest), narrowed to hint when the client sent the optional
// verifier_id_type context member. A nil result means the feature is off.
//
// A hint naming a type the policy did not enable yields an empty, non-nil
// result: the hint only ever narrows, it can never enable a type.
func VerifierIDTypesEnabled(req *authzen.EvaluationRequest) []string {
	if req == nil || req.Context == nil {
		return nil
	}
	enabled := extractStringSliceFromContext(req.Context, authzen.VerifierIDsPolicyContextKey)
	if len(enabled) == 0 {
		return nil
	}
	hint, hasHint := req.Context[authzen.VerifierIDHintContextKey].(string)
	if !hasHint || hint == "" {
		return enabled
	}
	narrowed := []string{}
	for _, t := range enabled {
		if t == hint {
			narrowed = append(narrowed, t)
		}
	}
	return narrowed
}

// verifierIDEnabled reports whether type t may be emitted for req.
func verifierIDEnabled(req *authzen.EvaluationRequest, t string) bool {
	for _, e := range VerifierIDTypesEnabled(req) {
		if e == t {
			return true
		}
	}
	return false
}

// AddVerifierID appends one verified identifier to resp.Context.VerifierIDs.
// It is the single emission point for registries that derive an identifier
// themselves (DID, OpenID Federation), and fails closed: nothing is added
// unless the decision is true, the policy enabled the type, the hint (if any)
// matches, and id is non-empty. Duplicate (type, id) pairs are not added twice.
func AddVerifierID(resp *authzen.EvaluationResponse, req *authzen.EvaluationRequest, idType, id, basis string) {
	if resp == nil || !resp.Decision || id == "" || !verifierIDEnabled(req, idType) {
		return
	}
	if resp.Context == nil {
		resp.Context = &authzen.EvaluationResponseContext{}
	}
	for _, v := range resp.Context.VerifierIDs {
		if v.Type == idType && v.ID == id {
			return
		}
	}
	resp.Context.VerifierIDs = append(resp.Context.VerifierIDs, authzen.VerifierID{Type: idType, ID: id, Basis: basis})
}

// CanonicalDNSName returns the canonical verifier form of a DNS name for the
// x509_san_dns identifier: the ASCII (A-label) spelling, ASCII lower case, one
// trailing dot removed. ok is false when name is not an identifier, in which
// case no entry is emitted (fail closed).
//
// The value is hashed into a pseudonym, so two spellings of one host must give
// one string and nothing may be rewritten that could be rewritten differently
// elsewhere. In particular U-labels are NOT converted to A-labels: IDNA2003,
// IDNA2008 and UTS #46 disagree for some names, and a conversion difference is a
// different pseudonym. A name containing any non-ASCII byte is therefore not an
// identifier, and an A-label ("xn--...") is passed through verbatim apart from
// case. Also refused: empty labels (including a leading dot or more than one
// trailing dot), labels over 63 and names over 253 octets, whitespace and
// control characters, and a wildcard.
func CanonicalDNSName(name string) (string, bool) {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 {
		return "", false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return "", false
		}
	}
	b := []byte(name)
	for i, c := range b {
		switch {
		case c < 0x21 || c > 0x7e || c == '*':
			return "", false
		case c >= 'A' && c <= 'Z':
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b), true
}

// sanExactlyContains reports whether dnsNames holds clientID, ASCII
// case-insensitively like the binding. A client_id bound only through a
// wildcard SAN (*.example.com) is one of many hosts under one certificate, so it
// does not identify a single verifier.
func sanExactlyContains(dnsNames []string, clientID string) bool {
	for _, n := range dnsNames {
		if equalASCIIFold(n, clientID) {
			return true
		}
	}
	return false
}

// CanonicalDID returns the DID without any fragment, i.e. the DID itself rather
// than a verification method reference. Nothing else is altered: the
// method-specific part can be case-sensitive (did:web path segments).
func CanonicalDID(did string) string {
	if i := strings.IndexByte(did, '#'); i >= 0 {
		return did[:i]
	}
	return did
}

// AddDIDVerifierID emits the "did" verifier identifier for a DID registry's
// successful key-bound decision. docID is the id of the resolved DID document;
// it is emitted only when it equals the DID the request named (fragment
// ignored), so a resolver that returned a different document can never put its
// own identifier in the response. The match is exact.
func AddDIDVerifierID(resp *authzen.EvaluationResponse, req *authzen.EvaluationRequest, docID string) {
	if req == nil || CanonicalDID(docID) != CanonicalDID(req.Subject.ID) {
		return
	}
	AddVerifierID(resp, req, authzen.VerifierIDTypeDID, CanonicalDID(docID), authzen.VerifierIDBasisDIDResolution)
}
