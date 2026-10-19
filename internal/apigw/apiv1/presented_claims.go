package apiv1

import (
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/SUNET/vc/pkg/credential"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"

	"github.com/fxamacker/cbor/v2"
)

// extractAuthScopeIdentity extracts the identity attributes ResolveIdentifier
// matches on from a verified presented credential.
//
// Format-aware (lookupClaimPath), so a namespace-qualified mdoc claim
// resolves, and value-normalising, so an mdoc full-date - which arrives as a
// CBOR tag 1004, not a string - can be matched at all. Each claim is stored
// under entry.IdentityAttributes[claim] when present, else its own name.
func extractAuthScopeIdentity(sourceFormat string, presented map[string]any, entry model.AuthScopeEntry) (map[string]string, error) {
	out := make(map[string]string, len(entry.AuthClaims))
	var missing []string
	for _, claim := range entry.AuthClaims {
		raw, ok := lookupClaimPath(sourceFormat, presented, claim)
		if !ok {
			missing = append(missing, claim)
			continue
		}
		s, ok := claimString(raw)
		if !ok {
			missing = append(missing, claim)
			continue
		}
		key := claim
		if attr, ok := entry.IdentityAttributes[claim]; ok {
			key = attr
		}
		out[key] = s
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("required identity claims missing or not string: %v", missing)
	}
	return out, nil
}

// presentedDocumentClaims builds the claims entry.DocumentClaims copies from
// the verified presented credential into the issued document. A missing
// source claim, or a value that cannot be normalised to the target's type,
// fails closed: the caller must not issue from the datastore document alone
// when the configuration says the value comes from the presentation.
func presentedDocumentClaims(sourceFormat string, presented map[string]any, entry model.AuthScopeEntry, target *model.CredentialMetadata) (map[string]any, error) {
	out := make(map[string]any, len(entry.DocumentClaims))
	for _, src := range slices.Sorted(maps.Keys(entry.DocumentClaims)) {
		dst := entry.DocumentClaims[src]
		raw, ok := lookupClaimPath(sourceFormat, presented, src)
		if !ok {
			return nil, fmt.Errorf("document claim %q is not present on the presented credential", src)
		}
		switch targetValueType(target, dst) {
		case "full-date":
			d, err := normaliseFullDate(raw)
			if err != nil {
				return nil, fmt.Errorf("document claim %q -> %q: %w", src, dst, err)
			}
			out[dst] = d
		default:
			if s, ok := claimString(raw); ok {
				out[dst] = s
				continue
			}
			value, err := documentValue(raw)
			if err != nil {
				return nil, fmt.Errorf("document claim %q -> %q: %w", src, dst, err)
			}
			out[dst] = value
		}
	}
	return out, nil
}

// targetValueType returns the MDDL value_type the target credential declares
// for a top-level element, in whichever namespace declares it; "" when the
// target is not an mdoc or does not declare the element.
func targetValueType(target *model.CredentialMetadata, element string) string {
	schema := target.GetMDDL()
	if schema == nil {
		return ""
	}
	for _, ns := range slices.Sorted(maps.Keys(schema.Claims)) {
		if meta, ok := schema.Claims[ns][element]; ok {
			return meta.ValueType
		}
	}
	return ""
}

// claimString returns a presented claim value as a string: a plain string,
// mdoc's FullDate/TDate, or a CBOR tag 1004 (full-date) / tag 0 (tdate)
// wrapping one - the shape fxamacker/cbor decodes an mdoc date into when the
// target is `any`.
func claimString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case mdoc.FullDate:
		return string(t), true
	case mdoc.TDate:
		return string(t), true
	case cbor.Tag:
		if t.Number == mdoc.TagDate || t.Number == mdoc.TagDateTime {
			s, ok := t.Content.(string)
			return s, ok
		}
	case *cbor.Tag:
		if t != nil {
			return claimString(*t)
		}
	}
	return "", false
}

// normaliseFullDate turns a presented birth date into an RFC 3339 full-date
// ("YYYY-MM-DD"), which the mdoc issuer then encodes as CBOR tag 1004
// (convertElementValue). Accepted: a full-date string (SD-JWT PID
// "birthdate"), an mdoc tag 1004 or tag 0 (tdate) value, a date-time string,
// a time.Time, and a CBOR tag 1 epoch. Anything else - including a date that
// does not exist - is an error.
func normaliseFullDate(v any) (string, error) {
	switch t := v.(type) {
	case time.Time:
		return t.UTC().Format(time.DateOnly), nil
	case cbor.Tag:
		if t.Number == 1 {
			switch n := t.Content.(type) {
			case uint64:
				return time.Unix(int64(n), 0).UTC().Format(time.DateOnly), nil
			case int64:
				return time.Unix(n, 0).UTC().Format(time.DateOnly), nil
			case float64:
				return time.Unix(int64(n), 0).UTC().Format(time.DateOnly), nil
			}
			return "", fmt.Errorf("unsupported epoch content %T", t.Content)
		}
	case *cbor.Tag:
		if t != nil {
			return normaliseFullDate(*t)
		}
	}
	s, ok := claimString(v)
	if !ok {
		return "", fmt.Errorf("value of type %T is not a date", v)
	}
	if d, err := time.Parse(time.DateOnly, s); err == nil {
		return d.Format(time.DateOnly), nil
	}
	if d, err := time.Parse(time.RFC3339, s); err == nil {
		return d.UTC().Format(time.DateOnly), nil
	}
	return "", fmt.Errorf("%q is neither a full-date nor a date-time", s)
}

// maxExactJSONInt is the largest integer a float64 represents exactly,
// which is what the issued document's numbers become.
const maxExactJSONInt = 1<<53 - 1

// documentValue turns a presented claim value into one the issued document
// can carry: JSON-encodable, and sharing nothing with the presentation.
//
// A verified mdoc claim arrives CBOR-decoded, so a container is a
// map[any]any and not a map[string]any. json.Marshal refuses that outright
// ("unsupported type"), and the refusal surfaces at the END of issuance,
// where it reads as a broken credential rather than an unconvertible
// claim - a valid presentation of driving_privileges could not be issued
// from at all.
//
// Tags are unwrapped here too. A date tag nested inside a container never
// reached claimString, and json.Marshal renders a cbor.Tag as its struct -
// {"Number":1004,"Content":"..."} - which would be written into the
// credential as if it were the value.
//
// Anything else that cannot be represented is an error rather than a
// best effort: this function exists because a wrong value here is a wrong
// credential.
func documentValue(v any) (any, error) {
	switch typed := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			converted, err := documentValue(item)
			if err != nil {
				return nil, fmt.Errorf("member %q: %w", key, err)
			}
			out[key] = converted
		}
		return out, nil

	case map[any]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			name, ok := key.(string)
			if !ok {
				return nil, fmt.Errorf("map key of type %T cannot be a JSON member name", key)
			}
			converted, err := documentValue(item)
			if err != nil {
				return nil, fmt.Errorf("member %q: %w", name, err)
			}
			out[name] = converted
		}
		return out, nil

	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			converted, err := documentValue(item)
			if err != nil {
				return nil, fmt.Errorf("element %d: %w", i, err)
			}
			out[i] = converted
		}
		return out, nil

	case cbor.Tag, *cbor.Tag:
		if s, ok := claimString(typed); ok {
			return s, nil
		}
		return nil, fmt.Errorf("value of type %T is a CBOR tag this build cannot represent", v)

	case mdoc.FullDate:
		return string(typed), nil
	case mdoc.TDate:
		return string(typed), nil

	// An integer that cannot survive the issuer's float64 round trip is
	// refused rather than quietly changed.
	//
	// CBOR keeps an integer exact, but the issuer parses the document
	// JSON into map[string]any (pkg/mdoc/issuer.go), where every number
	// becomes a float64. A presented uint64(9007199254740993) is issued
	// as 9007199254740992: a verified value altered by one, in a
	// credential that says it came from the presentation.
	//
	// Refusing is the only honest answer here. The value cannot be
	// carried, and issuing a different number than the holder proved is
	// exactly what this copy exists to prevent.
	case int64:
		if typed > maxExactJSONInt || typed < -maxExactJSONInt {
			return nil, fmt.Errorf("%d cannot be carried exactly through the issued document, where numbers are float64", typed)
		}
		return typed, nil
	case uint64:
		if typed > maxExactJSONInt {
			return nil, fmt.Errorf("%d cannot be carried exactly through the issued document, where numbers are float64", typed)
		}
		return typed, nil

	default:
		return v, nil
	}
}

// applyPresentedDocumentClaims returns copies of docs with the copied
// claims replacing each document's own; the datastore's documents are not
// mutated.
func applyPresentedDocumentClaims(docs map[string]*model.CompleteDocument, claims map[string]any) map[string]*model.CompleteDocument {
	if len(claims) == 0 {
		return docs
	}
	out := make(map[string]*model.CompleteDocument, len(docs))
	for k, doc := range docs {
		if doc == nil {
			out[k] = doc
			continue
		}
		data := credential.CloneNestedClaims(doc.DocumentData)
		// REPLACED, not merged. Destinations are top-level element names
		// (validate.go refuses a dotted one), and the configuration says
		// the claim comes from the presentation - so merging an
		// object-valued source such as an SD-JWT "address" left
		// datastore-only members like street_address inside it, and the
		// issued credential carried a mixture of what was proved and what
		// was stored under one claim name.
		//
		// MergeNestedClaims stays as it is: derivations rely on its
		// recursive behaviour, and this was the wrong caller for it.
		for dst, value := range claims {
			data[dst] = value
		}
		out[k] = &model.CompleteDocument{
			Meta:               doc.Meta,
			IdentityMappingIDs: doc.IdentityMappingIDs,
			DocumentData:       data,
		}
	}
	return out
}

// provedClaims snapshots the document values the VERIFIED presentation
// supplied, before derivations run over the document.
//
// The names travel on the authorization context because the auth scope
// that chose them is known only to the verifier half, while derivations
// run in the issuance request.
func provedClaims(docData map[string]any, presented []string) map[string]any {
	if len(presented) == 0 {
		return nil
	}
	proved := make(map[string]any, len(presented))
	for _, claim := range presented {
		if v, ok := docData[claim]; ok {
			// CLONED, through the package's existing deep copy.
			// MergeNestedClaims writes INTO existing nested maps, so a
			// snapshot sharing them is changed by the very derivations it
			// exists to survive: a derivation adding
			// address.street_address would appear in the "proved" value
			// too, and restoring it would restore the derived object.
			proved[claim] = cloneClaimValue(v)
		}
	}
	return proved
}

// restoreProvedClaims puts the presented values back over whatever the
// derivations produced, and reports the claims a derivation had tried to
// write.
//
// A derivation computing birth_date from another stored field would
// otherwise replace a date the holder actually proved, and the credential
// would be issued asserting something that was never presented - with
// nothing in it to show the difference. The configuration says these
// claims come from the presentation, so they win; the returned names are
// a configuration mistake worth logging rather than resolving in silence.
func restoreProvedClaims(docData, derived, proved map[string]any) []string {
	var conflicts []string
	for _, claim := range slices.Sorted(maps.Keys(proved)) {
		if _, overwritten := derived[claim]; overwritten {
			conflicts = append(conflicts, claim)
		}
		docData[claim] = proved[claim]
	}
	return conflicts
}
