package openid4vp

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Reason codes for a refused zkp_req presentation.
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
	ReasonPresentationNotString         = "presentation_not_string"
	ReasonPresentationNotBase64URL      = "presentation_not_base64url"
	ReasonCBORMalformed                 = "cbor_malformed"
	ReasonCBORIndefiniteLength          = "cbor_indefinite_length"
	ReasonCBORTrailingBytes             = "cbor_trailing_bytes"
	ReasonCBORDuplicateKey              = "cbor_duplicate_key"
	ReasonPresentationNotMap            = "presentation_not_map"
	ReasonPresentationKeyNotText        = "presentation_key_not_text"
	ReasonPresentationUnknownMember     = "presentation_unknown_member"
	ReasonPresentationMemberMissing     = "presentation_member_missing"
	ReasonPresentationMemberWrongType   = "presentation_member_wrong_type"
	ReasonSystemIDNotOffered            = "system_id_not_offered"
	ReasonProofEmpty                    = "proof_empty"
	ReasonIssuerKeySetEmpty             = "issuer_key_set_empty"
	ReasonIssuerKeySetTooMany           = "issuer_key_set_too_many"
	ReasonIssuerKeyNotBytes             = "issuer_key_not_bytes"
	ReasonIssuerKeyEmpty                = "issuer_key_empty"
	ReasonIssuerKeyTooLarge             = "issuer_key_too_large"
	ReasonProofTimeMissing              = "proof_time_missing"
	ReasonProofTimeNotTDate             = "proof_time_not_tdate"
	ReasonProofTimeForm                 = "proof_time_form"
	ReasonResultKeyNotText              = "result_key_not_text"
	ReasonResultHandleUnexpected        = "result_handle_unexpected"
	ReasonResultHandleMissing           = "result_handle_missing"
	ReasonResultWrongType               = "result_wrong_type"
	ReasonResultNotSatisfied            = "result_not_satisfied"
	ReasonResultFunctionUnknown         = "result_function_unknown"
	ReasonPseudonymWrongLength          = "pseudonym_wrong_length"
	ReasonPseudonymPrfUnknown           = "pseudonym_prf_unknown"
)

// Limits on the issuer key set, normative in zkp_req_response.md rule 7.
//
// They bound attacker-controlled input on its way to an X.509 parser:
// the set arrives from the holder and is parsed before anything about
// it has been judged.
const (
	MaxIssuerKeySetSize  = 8
	MaxIssuerKeyBytes    = 4096
	maxCBORNestingLevels = 16
)

// ZkpReqResponseError is a refusal, carrying the reason code the
// conformance vectors name.
type ZkpReqResponseError struct {
	Reason string
	Detail string
}

func (e *ZkpReqResponseError) Error() string {
	if e.Detail == "" {
		return "zkp_req response refused: " + e.Reason
	}
	return "zkp_req response refused: " + e.Reason + ": " + e.Detail
}

func refuse(reason, format string, args ...any) *ZkpReqResponseError {
	return &ZkpReqResponseError{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// ZkpReqRequest is the verifier-side view of the request a response
// answers.
type ZkpReqRequest struct {
	// QueryID is the DCQL credential query id the response is keyed by.
	QueryID string
	// Items are the request's _req items, in request order.
	Items []ReqItem
	// Multiple is the credential query's DCQL `multiple`. Omitted
	// means false, so more than one presentation is refused.
	Multiple bool
	// SourceFormat is meta.source_format: the stored attestation the
	// proof is made over. "mso_mdoc" makes proof_time required.
	SourceFormat string
	// OfferedSystemIDs is
	// client_metadata.vp_formats_supported.zkp_req.system_id_values.
	// Empty means nothing was offered, and every response is refused.
	OfferedSystemIDs []string
}

// ZkpPresentation is one validated presentation.
//
// Nothing here is a verified fact: a pseudonym is the holder's claim
// until a proof has been checked against it.
type ZkpPresentation struct {
	// SystemID names the approved system, and is one the request
	// offered.
	SystemID string
	// Proof is opaque at this layer.
	Proof []byte
	// IssuerKeySet is the issuer's certificates, leaf first, DER.
	// Bounded and nothing more: this package does not parse X.509.
	IssuerKeySet [][]byte
	// ProofTime is the prover-supplied T, and HasProofTime says
	// whether it was carried at all. T is a public input to the
	// circuit, byte-identical between prover and verifier.
	ProofTime    time.Time
	HasProofTime bool
	// ProofTimeText is T exactly as it arrived, which is what the
	// circuit takes: 20 bytes, YYYY-MM-DDThh:mm:ssZ.
	ProofTimeText string
	// Pseudonyms are the claimed pseudonyms, keyed by handle.
	Pseudonyms map[string][]byte
	// Satisfied names the handles whose predicate the proof asserts.
	Satisfied []string
}

// ValidateZkpReqResponse checks a vp_token against the request that
// asked for it, and returns the presentations it accepted.
//
// SHAPE and BINDING TO THE REQUEST only. It does not verify the proof
// and it does not parse or trust a certificate.
//
// The whole response is refused on the first failure, in the order the
// shared specification fixes. There is no partial acceptance: a
// presentation that breaks a rule is one whose author disagrees with
// this verifier about the format, and accepting its siblings would be
// guessing which half to trust.
//
// vpToken is the RAW TEXT, because a repeated JSON member cannot be
// seen after decoding: Go's decoder silently keeps the last.
func ValidateZkpReqResponse(vpToken []byte, request ZkpReqRequest) ([]ZkpPresentation, error) {
	if err := refuseDuplicateJSONMembers(vpToken); err != nil {
		return nil, err
	}

	var envelope map[string]json.RawMessage
	if err := strictDecode(vpToken, &envelope); err != nil {
		return nil, refuse(ReasonResponseNotParseable, "%v", err)
	}

	raw, present := envelope[request.QueryID]
	if !present {
		// Entries for other query ids are ignored; the one this
		// request asked for has to be there.
		return nil, refuse(ReasonQueryIDMissing, "no entry for credential query %q", request.QueryID)
	}

	var elements []json.RawMessage
	if !isJSONArray(raw) {
		return nil, refuse(ReasonPresentationsNotArray, "the entry for %q is not an array", request.QueryID)
	}
	if err := strictDecode(raw, &elements); err != nil {
		return nil, refuse(ReasonPresentationsNotArray, "%v", err)
	}
	if len(elements) == 0 {
		// A response with no presentations is a decline in disguise,
		// and a decline is an OpenID4VP error response.
		return nil, refuse(ReasonPresentationsEmpty, "credential query %q carries no presentations", request.QueryID)
	}
	if len(elements) > 1 && !request.Multiple {
		return nil, refuse(ReasonPresentationsMultipleNotAllow,
			"%d presentations for a query that did not set multiple", len(elements))
	}

	presentations := make([]ZkpPresentation, 0, len(elements))
	for _, element := range elements {
		presentation, err := validateZkpPresentation(element, request)
		if err != nil {
			return nil, err
		}
		presentations = append(presentations, presentation)
	}
	return presentations, nil
}

// presentationMembers are the only members a presentation may carry.
var presentationMembers = []string{"system_id", "proof", "issuer_key_set", "proof_time", "results"}

// requiredPresentationMembers are the members it must carry.
// proof_time is required only for mso_mdoc, which rule 8 handles.
var requiredPresentationMembers = []string{"system_id", "proof", "issuer_key_set", "results"}

func validateZkpPresentation(element json.RawMessage, request ZkpReqRequest) (ZkpPresentation, error) {
	var encoded string
	if err := strictDecode(element, &encoded); err != nil {
		return ZkpPresentation{}, refuse(ReasonPresentationNotString, "a presentation is not a JSON string")
	}
	decoded, err := decodeCanonicalBase64URL(encoded)
	if err != nil {
		return ZkpPresentation{}, refuse(ReasonPresentationNotBase64URL, "%v", err)
	}

	members, cborErr := decodeZkpPresentationCBOR(decoded)
	if cborErr != nil {
		return ZkpPresentation{}, cborErr
	}

	for name := range members {
		if !slices.Contains(presentationMembers, name) {
			return ZkpPresentation{}, refuse(ReasonPresentationUnknownMember, "unknown member %q", name)
		}
	}
	for _, name := range requiredPresentationMembers {
		if _, found := members[name]; !found {
			return ZkpPresentation{}, refuse(ReasonPresentationMemberMissing, "missing member %q", name)
		}
	}

	presentation := ZkpPresentation{Pseudonyms: map[string][]byte{}}
	if err := cborInto(members["system_id"], &presentation.SystemID); err != nil {
		return ZkpPresentation{}, refuse(ReasonPresentationMemberWrongType, "\"system_id\" is not a text string")
	}
	if err := cborInto(members["proof"], &presentation.Proof); err != nil {
		return ZkpPresentation{}, refuse(ReasonPresentationMemberWrongType, "\"proof\" is not a byte string")
	}
	var rawKeySet []cbor.RawMessage
	if err := cborInto(members["issuer_key_set"], &rawKeySet); err != nil {
		return ZkpPresentation{}, refuse(ReasonPresentationMemberWrongType, "\"issuer_key_set\" is not an array")
	}
	rawResults, resultsErr := cborResultsMap(members["results"])
	if resultsErr != nil {
		return ZkpPresentation{}, resultsErr
	}

	// Binding to the offer. The holder STATES system_id; this verifier
	// trusts it no further than membership in what it offered. A
	// request that offered no list offered nothing, so there is
	// nothing a response could be a member of - refused rather than
	// waved through, because the alternative is the holder choosing
	// what it is verified against.
	if !slices.Contains(request.OfferedSystemIDs, presentation.SystemID) {
		return ZkpPresentation{}, refuse(ReasonSystemIDNotOffered,
			"system_id %q is not one this request offered", presentation.SystemID)
	}

	if len(presentation.Proof) == 0 {
		return ZkpPresentation{}, refuse(ReasonProofEmpty, "the proof is empty")
	}

	keySet, keyErr := decodeIssuerKeySet(rawKeySet)
	if keyErr != nil {
		return ZkpPresentation{}, keyErr
	}
	presentation.IssuerKeySet = keySet

	rawProofTime, carriesProofTime := members["proof_time"]
	if !carriesProofTime {
		if request.SourceFormat == SourceFormatMsoMdoc {
			// Every approved mso_mdoc circuit checks the MSO validity
			// period, so T is not optional there.
			return ZkpPresentation{}, refuse(ReasonProofTimeMissing,
				"proof_time is required for source_format %q", SourceFormatMsoMdoc)
		}
	} else {
		text, err := decodeProofTimeTDate(rawProofTime)
		if err != nil {
			return ZkpPresentation{}, err
		}
		parsed, formErr := ParseProofTime(text)
		if formErr != nil {
			return ZkpPresentation{}, refuse(ReasonProofTimeForm, "%v", formErr)
		}
		presentation.ProofTime = parsed
		presentation.ProofTimeText = text
		presentation.HasProofTime = true
	}

	if err := checkZkpHandles(rawResults, request); err != nil {
		return ZkpPresentation{}, err
	}
	// Values in REQUEST order, so the reported failure does not depend
	// on how a decoder happened to order a map.
	for _, item := range request.Items {
		if err := readZkpResult(item, rawResults[item.Return], &presentation); err != nil {
			return ZkpPresentation{}, err
		}
	}
	return presentation, nil
}

// checkZkpHandles refuses a results map whose keys are not exactly the
// request's return handles.
func checkZkpHandles(results map[string]cbor.RawMessage, request ZkpReqRequest) error {
	expected := make(map[string]bool, len(request.Items))
	for _, item := range request.Items {
		expected[item.Return] = true
	}
	// Unexpected before missing, which is the shared order: a
	// response that is wrong in two ways is reported the same way by
	// every implementation.
	for handle := range results {
		if !expected[handle] {
			return refuse(ReasonResultHandleUnexpected, "the response carries handle %q, which this request did not ask for", handle)
		}
	}
	for _, item := range request.Items {
		if _, found := results[item.Return]; !found {
			return refuse(ReasonResultHandleMissing, "no result for handle %q", item.Return)
		}
	}
	return nil
}

// readZkpResult checks one result against the function that asked for
// it.
func readZkpResult(item ReqItem, raw cbor.RawMessage, presentation *ZkpPresentation) error {
	switch item.FnID {
	case FunctionPseudonym:
		want, known := pseudonymLengthFor(item)
		if !known {
			// No prf, no length to demand - and a pseudonym whose
			// width nobody agreed is not one to accept.
			return refuse(ReasonPseudonymPrfUnknown, "the %q item names no prf this build knows", item.Return)
		}
		var value []byte
		if err := cborInto(raw, &value); err != nil {
			return refuse(ReasonResultWrongType, "the pseudonym for %q is not a byte string", item.Return)
		}
		if len(value) != want {
			return refuse(ReasonPseudonymWrongLength, "the pseudonym for %q is %d bytes, not %d", item.Return, len(value), want)
		}
		presentation.Pseudonyms[item.Return] = value
	case FunctionAgeCheck:
		var satisfied bool
		if err := cborInto(raw, &satisfied); err != nil {
			return refuse(ReasonResultWrongType, "the result for %q is not a boolean", item.Return)
		}
		if !satisfied {
			// A predicate that does not hold produces NO PROOF; the
			// prover refuses. So false is a wallet asserting something
			// the proof system cannot say, and an unsatisfiable
			// request is a decline rather than a negative result.
			return refuse(ReasonResultNotSatisfied, "the result for %q says the predicate is not satisfied, which is a decline and not a result", item.Return)
		}
		presentation.Satisfied = append(presentation.Satisfied, item.Return)
	default:
		// A request may legally carry a function this build passes
		// through opaquely; a RESULT for one cannot be checked at all,
		// so it is refused rather than accepted unexamined.
		return refuse(ReasonResultFunctionUnknown, "no result shape for function %q", item.FnID)
	}
	return nil
}

// pseudonymLengthFor is the width the item's prf fixes.
func pseudonymLengthFor(item ReqItem) (int, bool) {
	prf, _ := item.Params["prf"].(string)
	switch prf {
	case PrfSHA256:
		return 32, true
	case PrfHashDHBLS12381G1:
		return 48, true
	default:
		return 0, false
	}
}

// decodeIssuerKeySet bounds and reads the issuer certificates.
func decodeIssuerKeySet(rawKeySet []cbor.RawMessage) ([][]byte, error) {
	if len(rawKeySet) == 0 {
		return nil, refuse(ReasonIssuerKeySetEmpty, "the issuer key set is empty")
	}
	if len(rawKeySet) > MaxIssuerKeySetSize {
		return nil, refuse(ReasonIssuerKeySetTooMany, "the issuer key set has %d elements; at most %d",
			len(rawKeySet), MaxIssuerKeySetSize)
	}
	keySet := make([][]byte, 0, len(rawKeySet))
	for i, raw := range rawKeySet {
		var der []byte
		if err := cborInto(raw, &der); err != nil {
			return nil, refuse(ReasonIssuerKeyNotBytes, "issuer key %d is not a byte string", i)
		}
		if len(der) == 0 {
			return nil, refuse(ReasonIssuerKeyEmpty, "issuer key %d is empty", i)
		}
		if len(der) > MaxIssuerKeyBytes {
			return nil, refuse(ReasonIssuerKeyTooLarge, "issuer key %d is %d bytes; at most %d", i, len(der), MaxIssuerKeyBytes)
		}
		keySet = append(keySet, der)
	}
	return keySet, nil
}

// cborInto decodes one raw CBOR item into a typed value, refusing
// CBOR null: null is a value of the WRONG TYPE here, never "absent".
func cborInto(raw cbor.RawMessage, into any) error {
	if isCBORNull(raw) {
		return errors.New("the value is null")
	}
	return zkpCBORMode.Unmarshal(raw, into)
}

// isCBORNull reports whether raw is the CBOR null (0xf6) or
// undefined (0xf7).
func isCBORNull(raw cbor.RawMessage) bool {
	return len(raw) == 1 && (raw[0] == 0xf6 || raw[0] == 0xf7)
}
