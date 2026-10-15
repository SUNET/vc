package openid4vp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// EC TS12 v1.0.1 / OpenID4VP 1.0 Appendix B.3.3.1: response side.

// TS12TypePrefix is the namespace of the built-in TS12 transaction data types
// (urn:eudi:sca:payment:1, login_risk_transaction:1, account_access:1,
// emandate:1). A request carrying one of them is an SCA request and its
// response is held to the TS12 KB-JWT rules (section 3.6), not just to the
// generic transaction_data_hashes rules.
const TS12TypePrefix = "urn:eudi:sca:"

// TS12 authentication-method categories (section 3.6).
const (
	AMRKnowledge  = "knowledge"
	AMRPossession = "possession"
	AMRInherence  = "inherence"
)

// ts12AMRVocabulary is the closed value set per category in TS12 v1.0.1
// section 3.6. A value outside it is refused rather than passed: the claim is
// the wallet's own assertion, and an unknown value is one we cannot interpret.
var ts12AMRVocabulary = map[string][]string{
	AMRKnowledge: {
		"pin_less_than_6_digits", "pin_6_or_more_digits",
		"passphrase_less_than_8_chars", "passphrase_8_to_11_chars", "passphrase_12_or_more_chars",
		"pattern", "other",
	},
	AMRPossession: {
		"key_in_remote_wscd", "key_in_local_external_wscd", "key_in_local_internal_wscd",
		"key_in_local_native_wscd", "other",
	},
	AMRInherence: {
		"fingerprint_device", "fingerprint_external", "face_device", "face_external", "other",
	},
}

// JTIStore records KB-JWT jti values so a presentation cannot be accepted
// twice. Claim reports whether jti was unseen, atomically recording it. An
// error means the store could not say, and the presentation is refused.
type JTIStore interface {
	Claim(jti string) (fresh bool, err error)
}

// decodedTransactionData is the part of a transaction_data entry the response
// check needs. It is read from the raw string for scoping and algorithm
// negotiation only; hashes are always computed over the raw string.
type decodedTransactionData struct {
	Raw           string
	Type          string
	CredentialIDs []string
	HashAlgs      []string
	HasAlgList    bool
}

func decodeTransactionDataEntry(raw string) (decodedTransactionData, error) {
	d := decodedTransactionData{Raw: raw}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return d, fmt.Errorf("not base64url: %w", err)
	}
	var m struct {
		Type          string          `json:"type"`
		CredentialIDs []string        `json:"credential_ids"`
		HashAlgs      json.RawMessage `json:"transaction_data_hashes_alg"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return d, fmt.Errorf("not a JSON object: %w", err)
	}
	if m.Type == "" {
		return d, fmt.Errorf("no type")
	}
	d.Type, d.CredentialIDs = m.Type, m.CredentialIDs
	if len(m.HashAlgs) > 0 && string(m.HashAlgs) != "null" {
		// The request member is an ARRAY (OpenID4VP 1.0 B.3.3.1). A bare
		// string is what some verifiers send and the WMP vectors tolerate on
		// input, but this verifier sent the entry, so anything else is a bug
		// here and is refused.
		if err := json.Unmarshal(m.HashAlgs, &d.HashAlgs); err != nil || len(d.HashAlgs) == 0 {
			return d, fmt.Errorf("transaction_data_hashes_alg is not a non-empty array")
		}
		d.HasAlgList = true
	}
	return d, nil
}

func decodeTransactionData(raw []string) ([]decodedTransactionData, error) {
	out := make([]decodedTransactionData, 0, len(raw))
	for i, r := range raw {
		d, err := decodeTransactionDataEntry(r)
		if err != nil {
			return nil, fmt.Errorf("transaction_data[%d]: %w", i, err)
		}
		out = append(out, d)
	}
	return out, nil
}

// TransactionDataForCredential returns the entries (as sent, in request order)
// whose credential_ids reference the DCQL credential query id.
//
// OpenID4VP 1.0 does not say whether a credential's KB-JWT carries the hashes
// of every transaction_data entry or only of the ones that reference it, and
// TS12 is silent too (SIROS plan B8). This verifier requires exactly the
// referencing entries, in request order: it is the reading under which a
// payment bound to one credential and an unrelated entry bound to another do
// not force each wallet presentation to commit to the other's transaction.
func TransactionDataForCredential(raw []string, queryID string) ([]string, error) {
	dec, err := decodeTransactionData(raw)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range dec {
		if slices.Contains(d.CredentialIDs, queryID) {
			out = append(out, d.Raw)
		}
	}
	return out, nil
}

// UncoveredTransactionData returns the entries that no answered credential
// query references. A response that never committed to one of them has not
// authorized it, so the caller must refuse.
func UncoveredTransactionData(raw []string, answeredQueryIDs []string) ([]string, error) {
	dec, err := decodeTransactionData(raw)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range dec {
		covered := false
		for _, id := range d.CredentialIDs {
			if slices.Contains(answeredQueryIDs, id) {
				covered = true
			}
		}
		if !covered {
			out = append(out, d.Raw)
		}
	}
	return out, nil
}

func txError(format string, args ...any) error {
	return &ErrorResponse{ErrorCode: ErrorInvalidTransactionData, ErrorDescription: fmt.Sprintf(format, args...)}
}

// allowedHashAlgs returns the set the wallet was allowed to use for the KB-JWT:
// entries' request lists and returns the set the wallet was allowed to use:
// the intersection of the entries' lists, with an entry that sent no list
// allowing only the sha-256 default.
func allowedHashAlgs(entries []decodedTransactionData) []string {
	var allowed []string
	for i, e := range entries {
		algs := e.HashAlgs
		if !e.HasAlgList {
			algs = []string{TransactionDataHashAlgDefault}
		}
		if i == 0 {
			allowed = slices.Clone(algs)
			continue
		}
		allowed = slices.DeleteFunc(allowed, func(a string) bool { return !slices.Contains(algs, a) })
	}
	return allowed
}

// validateTS12Claims applies EC TS12 v1.0.1 section 3.6 to the KB-JWT claims:
// jti, response_mode and amr. iat, nonce and aud are checked for every
// presentation elsewhere.
func (v *VPTokenValidator) validateTS12Claims(kb map[string]any) error {
	// amr: at least two DIFFERENT categories; single-key objects; closed vocabulary.
	amr, ok := kb["amr"].([]any)
	if !ok || len(amr) == 0 {
		return txError("amr missing from KB-JWT or not an array")
	}
	categories := map[string]bool{}
	for i, item := range amr {
		obj, ok := item.(map[string]any)
		if !ok || len(obj) != 1 {
			return txError("amr[%d] is not an object with exactly one member", i)
		}
		for category, val := range obj {
			vocab, known := ts12AMRVocabulary[category]
			if !known {
				return txError("amr[%d]: unknown category %q", i, category)
			}
			s, ok := val.(string)
			if !ok || !slices.Contains(vocab, s) {
				return txError("amr[%d]: value is not a TS12 %s method", i, category)
			}
			categories[category] = true
		}
	}
	if len(categories) < 2 {
		return txError("amr names %d authentication categories, TS12 requires at least 2 different ones", len(categories))
	}

	// response_mode: the value from the Authorization Request. The verifier
	// does not know which channel (QR/link or DC API) the wallet used, so the
	// caller supplies every mode it issued; with none, the claim cannot be
	// checked and the presentation is refused.
	rm, ok := kb["response_mode"].(string)
	if !ok || rm == "" {
		return txError("response_mode missing from KB-JWT")
	}
	if len(v.ResponseModes) == 0 {
		return txError("cannot verify response_mode: no issued response modes configured")
	}
	if !slices.Contains(v.ResponseModes, rm) {
		return txError("response_mode %q is not one this request was issued with", rm)
	}

	// jti: fresh, never seen. Entropy cannot be checked from here; uniqueness can.
	jti, ok := kb["jti"].(string)
	if !ok || strings.TrimSpace(jti) == "" {
		return txError("jti missing from KB-JWT")
	}
	if v.JTIStore == nil {
		return txError("cannot verify jti freshness: no replay store configured")
	}
	fresh, err := v.JTIStore.Claim(jti)
	if err != nil {
		return txError("cannot verify jti freshness: %v", err)
	}
	if !fresh {
		return txError("jti has been used before")
	}
	return nil
}
