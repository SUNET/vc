package openid4vp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
)

// Reason codes for a refused circuit_zk presentation.
//
// Stable identifiers rather than message text, because they are the
// shared conformance vocabulary: the Rust matcher, the Kotlin and
// Swift SDKs and this verifier all name the same failure the same
// way, and a vector asserts the code and not the sentence.
const (
	ReasonResponseNotParseable          = "response_not_parseable"
	ReasonDuplicateMember               = "duplicate_member"
	ReasonQueryIDMissing                = "query_id_missing"
	ReasonPresentationsNotArray         = "presentations_not_array"
	ReasonPresentationsEmpty            = "presentations_empty"
	ReasonPresentationsMultipleNotAllow = "presentations_multiple_not_allowed"
	ReasonPresentationNotObject         = "presentation_not_object"
	ReasonPresentationErrorMember       = "presentation_error_member"
	ReasonPresentationUnknownMember     = "presentation_unknown_member"
	ReasonPresentationMemberMissing     = "presentation_member_missing"
	ReasonPresentationMemberWrongType   = "presentation_member_wrong_type"
	ReasonCircuitIDNotOffered           = "circuit_id_not_offered"
	ReasonProofSystemNotOffered         = "proof_system_not_offered"
	ReasonProofEmpty                    = "proof_empty"
	ReasonProofNotBase64URL             = "proof_not_base64url"
	ReasonDuplicateHandle               = "duplicate_handle"
	ReasonResultHandleUnexpected        = "result_handle_unexpected"
	ReasonResultHandleMissing           = "result_handle_missing"
	ReasonResultNotObject               = "result_not_object"
	ReasonResultFunctionUnknown         = "result_function_unknown"
	ReasonResultUnknownMember           = "result_unknown_member"
	ReasonResultMemberMissing           = "result_member_missing"
	ReasonResultMemberWrongType         = "result_member_wrong_type"
	ReasonResultNotSatisfied            = "result_not_satisfied"
	ReasonPseudonymNotBase64URL         = "pseudonym_not_base64url"
	ReasonPseudonymWrongLength          = "pseudonym_wrong_length"
)

// CircuitZkResponseError is a refusal, carrying the reason code the
// conformance vectors name.
type CircuitZkResponseError struct {
	Reason string
	Detail string
}

func (e *CircuitZkResponseError) Error() string {
	if e.Detail == "" {
		return "circuit_zk response refused: " + e.Reason
	}
	return "circuit_zk response refused: " + e.Reason + ": " + e.Detail
}

func refuse(reason, format string, args ...any) *CircuitZkResponseError {
	return &CircuitZkResponseError{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// pseudonymBytes is the width of a nym_auth pseudonym.
const pseudonymBytes = 32

// CircuitZkPresentation is one validated presentation.
//
// Nothing in it is trusted beyond its shape and its binding to the
// request. CircuitID and ProofSystem have been checked for membership
// in what the request offered and nothing more; Proof is not decoded;
// a Pseudonym is the holder's CLAIM, which means nothing until a proof
// has been checked against it.
type CircuitZkPresentation struct {
	CircuitID   string
	ProofSystem string
	// Proof is the raw proof bytes, decoded from the canonical
	// unpadded base64url on the wire.
	Proof []byte
	// Pseudonyms are the claimed pseudonyms, by the request handle
	// each answers.
	Pseudonyms map[string][]byte
	// Satisfied names the handles whose predicate the proof asserts.
	Satisfied []string
}

// CircuitZkRequest is what a response is checked against: the
// verifier's own request, and nothing from the response.
type CircuitZkRequest struct {
	// QueryID is the DCQL credential query id the response is keyed
	// by.
	QueryID string
	// Items are the request's req items, in request order.
	Items []ReqItem
	// Multiple is the credential query's DCQL `multiple`. Omitted
	// means false, so more than one presentation is refused.
	Multiple bool
	// Offered are the circuit ids and proof systems the request
	// stated. Empty means nothing was offered, and every response is
	// refused - fail closed, because a response naming a circuit the
	// request never offered is the holder choosing what it is
	// verified against.
	OfferedCircuitIDs   []string
	OfferedProofSystems []string
}

// ValidateCircuitZkResponse checks a vp_token against the request that
// asked for it, and returns the presentations it accepted.
//
// It checks SHAPE and BINDING TO THE REQUEST. It does not verify the
// proof, and nothing it returns is a verified fact: a pseudonym is the
// holder's claim until a proof has been checked against it.
//
// The whole response is refused on the first failure, in the order the
// shared specification fixes. There is no partial acceptance: a
// presentation that breaks a rule is one whose author disagrees with
// this verifier about the format, and accepting its siblings would be
// guessing which half to trust.
//
// vpToken is the RAW TEXT, not a decoded object, because two of the
// rules - a repeated member and a repeated handle - cannot be seen
// after decoding: Go's decoder silently keeps the last of a repeated
// key, so a response carrying two values for one handle would arrive
// here as a response carrying one.
func ValidateCircuitZkResponse(vpToken []byte, request CircuitZkRequest) ([]CircuitZkPresentation, error) {
	if err := refuseDuplicateJSONMembers(vpToken); err != nil {
		return nil, err
	}

	var envelope map[string]json.RawMessage
	if err := strictDecode(vpToken, &envelope); err != nil {
		return nil, refuse(ReasonResponseNotParseable, "%v", err)
	}

	raw, present := envelope[request.QueryID]
	if !present {
		// Entries for other query ids are ignored, but the one this
		// request asked for has to be there.
		return nil, refuse(ReasonQueryIDMissing, "no entry for credential query %q", request.QueryID)
	}

	var elements []json.RawMessage
	if err := strictDecode(raw, &elements); err != nil {
		return nil, refuse(ReasonPresentationsNotArray, "%v", err)
	}
	if len(elements) == 0 {
		// A response with no presentations is a decline in disguise,
		// and a decline is not a presentation.
		return nil, refuse(ReasonPresentationsEmpty, "credential query %q carries no presentations", request.QueryID)
	}
	if len(elements) > 1 && !request.Multiple {
		return nil, refuse(ReasonPresentationsMultipleNotAllow,
			"%d presentations for a query that did not set multiple", len(elements))
	}

	out := make([]CircuitZkPresentation, 0, len(elements))
	for _, element := range elements {
		presentation, err := validateCircuitZkPresentation(element, request)
		if err != nil {
			return nil, err
		}
		out = append(out, presentation)
	}
	return out, nil
}

// presentationMembers are the only members a presentation may carry.
var presentationMembers = []string{"circuit_id", "proof_system", "proof", "results"}

func validateCircuitZkPresentation(raw json.RawMessage, request CircuitZkRequest) (CircuitZkPresentation, error) {
	var members map[string]json.RawMessage
	if err := strictDecode(raw, &members); err != nil {
		return CircuitZkPresentation{}, refuse(ReasonPresentationNotObject, "%v", err)
	}

	// In-band errors first: a presentation that describes a failure is
	// not a presentation, and every rule below would be judging the
	// shape of something that was never meant to be verified.
	for _, name := range []string{"error", "error_description"} {
		if _, found := members[name]; found {
			return CircuitZkPresentation{}, refuse(ReasonPresentationErrorMember,
				"a presentation carries %q; a wallet that cannot satisfy the request declines at the OpenID4VP level", name)
		}
	}
	for name := range members {
		if !slices.Contains(presentationMembers, name) {
			return CircuitZkPresentation{}, refuse(ReasonPresentationUnknownMember, "unknown member %q", name)
		}
	}
	for _, name := range presentationMembers {
		if _, found := members[name]; !found {
			return CircuitZkPresentation{}, refuse(ReasonPresentationMemberMissing, "missing member %q", name)
		}
	}

	presentation := CircuitZkPresentation{Pseudonyms: map[string][]byte{}}
	for _, name := range []string{"circuit_id", "proof_system", "proof"} {
		var value string
		if err := strictDecode(members[name], &value); err != nil {
			return CircuitZkPresentation{}, refuse(ReasonPresentationMemberWrongType, "%q is not a string", name)
		}
		switch name {
		case "circuit_id":
			presentation.CircuitID = value
		case "proof_system":
			presentation.ProofSystem = value
		}
	}

	var results map[string]json.RawMessage
	if err := strictDecode(members["results"], &results); err != nil {
		return CircuitZkPresentation{}, refuse(ReasonPresentationMemberWrongType, "\"results\" is not an object")
	}

	// Binding to the offer. The holder STATES both; this verifier
	// trusts them no further than membership in what it offered. A
	// request that offered no list offered nothing, so there is
	// nothing a response could be a member of - refused rather than
	// waved through, because the alternative is the holder choosing
	// what it is verified against.
	if !slices.Contains(request.OfferedCircuitIDs, presentation.CircuitID) {
		return CircuitZkPresentation{}, refuse(ReasonCircuitIDNotOffered,
			"circuit_id %q is not one this request offered", presentation.CircuitID)
	}
	if !slices.Contains(request.OfferedProofSystems, presentation.ProofSystem) {
		return CircuitZkPresentation{}, refuse(ReasonProofSystemNotOffered,
			"proof_system %q is not one this request offered", presentation.ProofSystem)
	}

	var proof string
	_ = strictDecode(members["proof"], &proof)
	if proof == "" {
		return CircuitZkPresentation{}, refuse(ReasonProofEmpty, "the proof is empty")
	}
	decodedProof, err := decodeCanonicalBase64URL(proof)
	if err != nil {
		return CircuitZkPresentation{}, refuse(ReasonProofNotBase64URL, "%v", err)
	}
	presentation.Proof = decodedProof

	if err := refuseDuplicateHandles(members["results"]); err != nil {
		return CircuitZkPresentation{}, err
	}
	if err := checkCircuitZkHandles(results, request); err != nil {
		return CircuitZkPresentation{}, err
	}
	// Values in REQUEST order, so the reported failure does not depend
	// on how a decoder happened to order a map.
	for _, item := range request.Items {
		if err := readCircuitZkResult(item, results[item.Return], &presentation); err != nil {
			return CircuitZkPresentation{}, err
		}
	}
	return presentation, nil
}

// checkCircuitZkHandles requires the results to be keyed by exactly
// the request's handles.
//
// Extra before missing, and both before any value is looked at: an
// extra handle is a result nobody asked for and a missing one is a
// result that was asked for and not given, and neither is a question
// about what a value contains.
func checkCircuitZkHandles(results map[string]json.RawMessage, request CircuitZkRequest) error {
	wanted := make([]string, 0, len(request.Items))
	for _, item := range request.Items {
		wanted = append(wanted, item.Return)
	}
	for handle := range results {
		if !slices.Contains(wanted, handle) {
			return refuse(ReasonResultHandleUnexpected, "results carry handle %q, which this request did not ask for", handle)
		}
	}
	for _, handle := range wanted {
		if _, found := results[handle]; !found {
			return refuse(ReasonResultHandleMissing, "no result for handle %q", handle)
		}
	}
	return nil
}

// readCircuitZkResult checks one result against the function that
// asked for it.
func readCircuitZkResult(item ReqItem, raw json.RawMessage, presentation *CircuitZkPresentation) error {
	var members map[string]json.RawMessage
	if err := strictDecode(raw, &members); err != nil {
		return refuse(ReasonResultNotObject, "the result for %q is not an object", item.Return)
	}

	member, known := circuitZkResultMembers[item.ID]
	if !known {
		// A request may legally carry a function this build passes
		// through opaquely; a RESULT for one cannot be checked at all,
		// so it is refused rather than accepted unexamined.
		return refuse(ReasonResultFunctionUnknown, "no result shape for function %q", item.ID)
	}
	for name := range members {
		if name != member {
			return refuse(ReasonResultUnknownMember, "the result for %q carries %q, which %q does not return", item.Return, name, item.ID)
		}
	}
	value, found := members[member]
	if !found {
		return refuse(ReasonResultMemberMissing, "the result for %q has no %q", item.Return, member)
	}

	switch item.ID {
	case CircuitZkFunctionPseudonym:
		var encoded string
		if err := strictDecode(value, &encoded); err != nil {
			return refuse(ReasonResultMemberWrongType, "the pseudonym for %q is not a string", item.Return)
		}
		raw, err := decodeCanonicalBase64URL(encoded)
		if err != nil {
			return refuse(ReasonPseudonymNotBase64URL, "%v", err)
		}
		if len(raw) != pseudonymBytes {
			return refuse(ReasonPseudonymWrongLength, "the pseudonym for %q is %d bytes, not %d", item.Return, len(raw), pseudonymBytes)
		}
		presentation.Pseudonyms[item.Return] = raw
	case CircuitZkFunctionAgeCheck:
		var satisfied bool
		if err := strictDecode(value, &satisfied); err != nil {
			return refuse(ReasonResultMemberWrongType, "the result for %q is not a boolean", item.Return)
		}
		if !satisfied {
			// A predicate that does not hold produces NO PROOF; the
			// prover refuses. So "satisfied": false is a wallet
			// asserting something the proof system cannot say, and an
			// unsatisfiable request is a decline rather than a
			// negative result.
			return refuse(ReasonResultNotSatisfied, "the result for %q says the predicate is not satisfied, which is a decline and not a result", item.Return)
		}
		presentation.Satisfied = append(presentation.Satisfied, item.Return)
	}
	return nil
}

// Function identifiers with a result shape this build can check.
const (
	CircuitZkFunctionPseudonym = "pseudonym-v1-sha256"
	CircuitZkFunctionAgeCheck  = "age_check"
)

// circuitZkResultMembers is the single member each known function's
// result carries. Exactly one: a result object with another member, or
// without this one, is refused.
var circuitZkResultMembers = map[string]string{
	CircuitZkFunctionPseudonym: "pseudonym",
	CircuitZkFunctionAgeCheck:  "satisfied",
}

// decodeCanonicalBase64URL decodes unpadded base64url and refuses
// anything that is not the canonical spelling of those bytes.
//
// Decoding is not the same as the wire contract. Go's decoder skips CR
// and LF and accepts a final character whose unused low bits are set,
// so a value with a newline in it and a value differing only in those
// bits both decode - two spellings of one proof, from a contract that
// says there is one.
func decodeCanonicalBase64URL(encoded string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("not unpadded base64url: %w", err)
	}
	if base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return nil, errors.New("not canonical unpadded base64url")
	}
	return raw, nil
}

// strictDecode refuses trailing content as well as a wrong type.
//
// A json.Decoder stops at the end of the first value, so `{"a":1}
// garbage` decodes happily - which is strictly weaker than what a
// response has to be.
func strictDecode(raw []byte, into any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(into); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing content after the JSON value")
	}
	return nil
}
