package apiv1

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"math/big"
	"slices"
	"time"

	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/credential"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"

	"github.com/fxamacker/cbor/v2"
)

// extractAuthScopeIdentity extracts the identity attributes ResolveIdentifier
// matches on from a verified presented credential.
//
// Read in the presented credential's shape, so a namespace-qualified mdoc
// claim resolves, and value-normalising, so an mdoc full-date - which
// arrives as a CBOR tag 1004, not a string - can be matched at all. Each
// claim is stored under its identity attribute (IdentityAttributes.For).
func extractAuthScopeIdentity(shape claimpath.Shape, presented map[string]any, entry model.AuthScopeEntry) (map[string]string, error) {
	out := make(map[string]string, len(entry.AuthClaims))
	var missing []string
	for _, claim := range entry.AuthClaims {
		s, ok, err := presentedString(shape, presented, claim)
		if err != nil {
			return nil, err
		}
		attribute, named := entry.IdentityAttributes.For(claim)
		if !named {
			return nil, fmt.Errorf("auth claim %s names no identity attribute", claim)
		}
		if !ok {
			missing = append(missing, claim.String())
			continue
		}
		out[attribute] = s
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("required identity claims missing or not string: %v", missing)
	}
	return out, nil
}

// authScopeIdentity extracts the identity attributes of a presentation of
// an auth scope, and returns the shape its claims are held in.
func (c *Client) authScopeIdentity(authScope string, presented map[string]any, entry model.AuthScopeEntry) (map[string]string, claimpath.Shape, error) {
	shape, err := c.cfg.PresentedShape(authScope)
	if err != nil {
		return nil, claimpath.Shape{}, serverFault(err)
	}
	identity, err := extractAuthScopeIdentity(shape, presented, entry)
	return identity, shape, err
}

// presentedString returns a presented claim as a string. A claim the
// presentation does not carry, holds in another structure, or holds as
// something other than a string is reported as not ok.
func presentedString(shape claimpath.Shape, presented map[string]any, claim claimpath.Pointer) (string, bool, error) {
	raw, present, err := shape.Get(presented, claim)
	if errors.Is(err, claimpath.ErrMismatch) {
		return "", false, nil
	}
	if err != nil || !present {
		return "", false, err
	}
	s, ok := claimString(raw)
	return s, ok, nil
}

// presentedDocumentClaims builds the claims entry.DocumentClaims copies from
// the verified presented credential into the issued document, keyed by the
// document key each target names. A missing source claim, or a value that
// cannot be normalised to the target's type, fails closed: the caller must
// not issue from the datastore document alone when the configuration says
// the value comes from the presentation.
func presentedDocumentClaims(shape claimpath.Shape, presented map[string]any, entry model.AuthScopeEntry, target *model.CredentialMetadata) (map[string]any, error) {
	document, err := target.DocumentShape()
	if err != nil {
		return nil, err
	}
	out := make(map[string]any, len(entry.DocumentClaims))
	for _, claim := range entry.DocumentClaims {
		key, value, err := presentedDocumentClaim(shape, document, presented, claim, target)
		if err != nil {
			return nil, err
		}
		out[key] = value
	}
	return out, nil
}

// presentedDocumentClaim returns the document key a copy targets and the
// value it copies there.
func presentedDocumentClaim(shape, document claimpath.Shape, presented map[string]any, claim model.DocumentClaim, target *model.CredentialMetadata) (string, any, error) {
	location, err := document.Locate(claim.To)
	if err != nil {
		return "", nil, err
	}
	key, ok := location.Name()
	if !ok || location.Len() != 1 {
		return "", nil, fmt.Errorf("document claim %s is no top-level claim of the issued document", claim.To)
	}
	raw, present, err := shape.Get(presented, claim.From)
	if err != nil {
		return "", nil, fmt.Errorf("document claim %s: %w", claim.From, err)
	}
	if !present {
		return "", nil, fmt.Errorf("document claim %s is not present on the presented credential", claim.From)
	}
	if targetValueType(target, claim.To) == "full-date" {
		d, err := normaliseFullDate(raw)
		if err != nil {
			return "", nil, fmt.Errorf("document claim %s -> %s: %w", claim.From, claim.To, err)
		}
		return key, d, nil
	}
	if s, ok := claimString(raw); ok {
		return key, s, nil
	}
	value, err := documentValue(raw)
	if err != nil {
		return "", nil, fmt.Errorf("document claim %s -> %s: %w", claim.From, claim.To, err)
	}
	return key, value, nil
}

// targetValueType returns the MDDL value_type the target credential declares
// for an element; "" when the target is not an mdoc or the claim is no
// element its MDDL declares.
func targetValueType(target *model.CredentialMetadata, claim claimpath.Pointer) string {
	schema := target.GetMDDL()
	namespace, element, err := claim.MDoc()
	if schema == nil || err != nil {
		return ""
	}
	return schema.Claims[namespace][element].ValueType
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
		// In UTC, like epochFullDate does it explicitly. The zone on a
		// decoded CBOR timestamp is the HOST's, not anything the holder
		// presented, so without this the issued date depends on where
		// the service runs: on a UTC-08 host, epoch 632361600 renders
		// as 1990-01-14 instead of 1990-01-15. A birth date silently
		// off by a day is exactly the kind of wrong this copy exists to
		// prevent.
		return fullDate(t.UTC())
	case cbor.Tag:
		if t.Number == 1 {
			return epochFullDate(t.Content)
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
		// Already UTC - a full-date carries no time and no offset, and
		// this is the ordinary case: an mdoc birth date is tag 1004 and
		// an SD-JWT PID birthdate is "YYYY-MM-DD".
		return fullDate(d)
	}
	if d, err := time.Parse(time.RFC3339, s); err == nil {
		// In UTC, like every other route here.
		//
		// The offset in a date-time string is arguably the holder's
		// data rather than a decoding artifact, so taking the date as
		// written has an argument for it. Consistency has a better one:
		// a tag 0 date-time and a tag 1 epoch for the SAME INSTANT
		// would otherwise issue dates a day apart, so which credential
		// a subject gets would depend on which CBOR encoding their
		// wallet happened to choose. One instant, one issued date.
		return fullDate(d.UTC())
	}
	return "", fmt.Errorf("%q is neither a full-date nor a date-time", s)
}

// epochFullDate converts a CBOR tag 1 epoch, refusing the values that
// would convert into a different date instead of failing.
//
// uint64 is NOT int64: 18446744073709551615 wraps to -1 and dates to
// 1969-12-31, a verified birth date silently replaced by a plausible
// one. And a negative fraction truncates TOWARD ZERO, so -0.5 became
// 1970-01-01 when the second it falls in is 1969-12-31; seconds since
// the epoch floor, they do not round to it.
func epochFullDate(content any) (string, error) {
	switch n := content.(type) {
	case uint64:
		if n > math.MaxInt64 {
			return "", fmt.Errorf("epoch %d is beyond the representable range", n)
		}
		return fullDate(time.Unix(int64(n), 0).UTC())
	case int64:
		return fullDate(time.Unix(n, 0).UTC())
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return "", fmt.Errorf("epoch %v is not a number", n)
		}
		seconds := math.Floor(n)
		if seconds > math.MaxInt64 || seconds < math.MinInt64 {
			return "", fmt.Errorf("epoch %v is beyond the representable range", n)
		}
		return fullDate(time.Unix(int64(seconds), 0).UTC())
	}
	return "", fmt.Errorf("unsupported epoch content %T", content)
}

// fullDate renders a time as an RFC 3339 full-date, refusing one the
// format cannot express.
//
// Applied to EVERY shape, not just the epoch: a time.Time or a date-time
// string can carry a year outside 0001-9999 just as an epoch can, and
// 253402300800 formatted happily as "10000-01-01" - four digits of year
// is what the grammar allows, so that string is not a full-date at all
// and no verifier reading it gets the date the holder presented.
func fullDate(t time.Time) (string, error) {
	if year := t.Year(); year < 1 || year > 9999 {
		return "", fmt.Errorf("year %d is outside the range an RFC 3339 full-date can express", year)
	}
	return t.Format(time.DateOnly), nil
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
		return documentObject(typed)
	case map[any]any:
		return documentObject(typed)
	case []any:
		return documentArray(typed)

	case cbor.Tag, *cbor.Tag:
		if s, ok := claimString(typed); ok {
			return s, nil
		}
		return nil, fmt.Errorf("value of type %T is a CBOR tag this build cannot represent", v)

	case mdoc.FullDate:
		return string(typed), nil
	case mdoc.TDate:
		return string(typed), nil

	// A decoded CBOR timestamp is normalised to the string the document
	// will carry anyway, rather than left as a time.Time.
	//
	// Left alone it diverges by cache backend, which is the failure this
	// PR has already had three times: MemoryStore hands back the stored
	// value, so a derivation reading this claim sees a time.Time, while
	// the Mongo-backed store round-trips through JSON and hands back a
	// string. A `trim` derivation then works on one backend and fails
	// with "must be a string or []string" on the other - and only under
	// HA, which is where it is hardest to see.
	//
	// Through the encoder rather than a chosen layout, so the value is
	// byte-identical to what the JSON round trip would have produced,
	// and so a year the format cannot express is still refused here.
	case time.Time:
		return jsonTimestamp(typed)

	// A decoded mdoc byte string is normalised for the same reason as a
	// timestamp, and it is the only other type that changes shape across
	// the cache: the memory store hands back []byte, while the
	// Mongo-backed store round-trips through JSON and hands back the
	// base64 string. A derivation reading the claim then behaves
	// differently by backend.
	case []byte:
		if typed == nil {
			// What json.Marshal does with it, kept so a null claim
			// stays a null claim rather than becoming "".
			return nil, nil
		}
		return base64.StdEncoding.EncodeToString(typed), nil

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
	// A CBOR bignum (tags 2 and 3) decodes to a big.Int, which reaches
	// neither integer guard below - and serialising cleanly is not the
	// same as being carried faithfully, which is what the guard before
	// the default branch can check and this cannot be left to.
	//
	// Both shapes are wrong in their own way, and both were verified
	// rather than reasoned about. A *big.Int marshals as a number and
	// the issuer's map[string]any parse rounds it:
	// 18446744073709551617 is issued as ...552000. A big.Int VALUE is
	// worse - MarshalJSON is on the pointer receiver, so a
	// non-addressable value in an `any` does not reach it and the claim
	// is emitted as `{}`, an empty object where a number was proved.
	case big.Int:
		return bignumValue(&typed)
	case *big.Int:
		return bignumValue(typed)

	// And the same hazard for a decoder set to UseNumber: the literal
	// survives this hop and is rounded at the next one.
	case json.Number:
		return numberValue(typed)

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

	// An SD-JWT claim never reaches the cases above. Token.Parse and
	// disclosure decoding unmarshal JSON into `any`, so every number is
	// ALREADY a float64 by the time it is copied - 9007199254740993
	// arrives as ...992 and walks past both integer guards unchanged.
	//
	// The damage is done before this point and cannot be undone here, so
	// the only honest move is to refuse a magnitude that cannot have
	// survived: beyond 2^53 a float64 is not a trustworthy integer, and
	// issuing it would assert a number the holder may never have proved.
	case float64:
		if err := refuseNonFinite(typed); err != nil {
			return nil, err
		}
		if typed > maxExactJSONInt || typed < -maxExactJSONInt {
			return nil, fmt.Errorf("%v exceeds the range a JSON number carries exactly, so it cannot be copied from the presentation without risking a changed value", typed)
		}
		return typed, nil

	default:
		// The fallback returns the value unchanged, so it is the one
		// place a shape nobody enumerated reaches the document. What the
		// caller is owed here is not a Go type, it is a value the issued
		// document can CARRY - so that is what is checked, once, rather
		// than a type case added each time a reviewer finds another one.
		//
		// time.Time proved the point. A CBOR tag 1 epoch decodes to one,
		// and for a target other than full-date it arrived here
		// untouched; year 10000 converts happily and then fails inside
		// encoding/json - where, with the Mongo-backed cache, the
		// failure is SILENT: upsertAt logs the marshal error and drops
		// the write while the handler still returns a successful
		// redirect. A narrower or named float reached it the same way.
		if err := refuseUnserialisable(v); err != nil {
			return nil, err
		}
		return v, nil
	}
}

// documentObject converts a decoded object, whichever map type it
// arrived as: a CBOR map decodes to map[any]any and a JSON one to
// map[string]any, and both have to become a JSON object.
//
// Generic over the key so the two cases share one body. A non-string key
// is refused rather than stringified - JSON has no member name for it,
// and inventing one would put a claim in the credential under a name
// nobody presented.
func documentObject[K comparable](in map[K]any) (map[string]any, error) {
	out := make(map[string]any, len(in))
	for key, item := range in {
		name, ok := any(key).(string)
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
}

// documentArray converts a decoded array, element by element.
func documentArray(in []any) ([]any, error) {
	out := make([]any, len(in))
	for i, item := range in {
		converted, err := documentValue(item)
		if err != nil {
			return nil, fmt.Errorf("element %d: %w", i, err)
		}
		out[i] = converted
	}
	return out, nil
}

// bignumValue carries a CBOR bignum only when it survives the issuer's
// float64 round trip, and refuses it otherwise - the same rule the int64
// and uint64 cases apply, reached by a type neither of them sees.
func bignumValue(n *big.Int) (any, error) {
	if n == nil {
		// Not reachable from a decoded presentation: a CBOR null
		// decodes to an untyped nil, not to a typed nil pointer. So
		// something built this by hand, and guessing what it meant is
		// not this function's job.
		return nil, errors.New("a claim value of nil *big.Int is not a number this document can carry")
	}
	if !n.IsInt64() {
		return nil, fmt.Errorf("%s cannot be carried exactly through the issued document, where numbers are float64", n)
	}
	v := n.Int64()
	if v > maxExactJSONInt || v < -maxExactJSONInt {
		return nil, fmt.Errorf("%d cannot be carried exactly through the issued document, where numbers are float64", v)
	}
	return v, nil
}

// numberValue carries a json.Number under the same rule, as an integer
// where it is one and as a float otherwise.
func numberValue(n json.Number) (any, error) {
	if i, err := n.Int64(); err == nil {
		if i > maxExactJSONInt || i < -maxExactJSONInt {
			return nil, fmt.Errorf("%d cannot be carried exactly through the issued document, where numbers are float64", i)
		}
		return i, nil
	}
	f, err := n.Float64()
	if err != nil {
		return nil, fmt.Errorf("a claim value of %q is not a number this document can carry", n.String())
	}
	if err := refuseNonFinite(f); err != nil {
		return nil, err
	}
	if f > maxExactJSONInt || f < -maxExactJSONInt {
		return nil, fmt.Errorf("%v exceeds the range a JSON number carries exactly, so it cannot be copied from the presentation without risking a changed value", f)
	}
	return f, nil
}

// jsonTimestamp renders a timestamp exactly as encoding/json would, so
// that what a derivation reads does not depend on which cache backend
// the deployment runs.
func jsonTimestamp(t time.Time) (string, error) {
	// UTC for the same reason normaliseFullDate uses it: the zone on a
	// decoded CBOR timestamp is the host's, and a claim's issued value
	// must not depend on where the service runs.
	encoded, err := json.Marshal(t.UTC())
	if err != nil {
		return "", fmt.Errorf("a timestamp claim cannot be carried in the issued document: %w", err)
	}
	var rendered string
	if err := json.Unmarshal(encoded, &rendered); err != nil {
		return "", fmt.Errorf("a timestamp claim cannot be carried in the issued document: %w", err)
	}
	return rendered, nil
}

// refuseUnserialisable refuses a leaf the issued document cannot carry.
//
// It asks the encoder rather than enumerating types, because the
// enumeration is what kept being incomplete: every value that reaches the
// fallback is eventually handed to json.Marshal, so handing it one here -
// where the claim can still be named and the issuance refused - is the
// same question asked at a point where the answer is actionable.
func refuseUnserialisable(v any) error {
	if _, err := json.Marshal(v); err != nil {
		return fmt.Errorf("a claim value of type %T cannot be carried in the issued document: %w", v, err)
	}
	return nil
}

// refuseNonFinite refuses NaN and the infinities.
//
// NaN is the one numeric value that walks past a range guard: every
// comparison with it is false, so `n > max || n < -max` lets it through.
// It then reaches the issued document, where encoding/json cannot
// represent it - and where that failure lands decides whether anyone
// hears about it. With the Mongo-backed cache, MongoCache.upsertAt logs
// the marshal error and DROPS the write while VerificationDirectPost
// still returns a successful redirect: a presentation reported as
// published that was never stored.
//
// The infinities are caught by the range guard, but its message - "exceeds
// the range a JSON number carries exactly" - describes a precision loss
// rather than a value JSON has no syntax for at all, so they are named
// here instead.
func refuseNonFinite(f float64) error {
	if math.IsNaN(f) {
		return fmt.Errorf("a claim value of NaN is not a number JSON can carry, so it cannot be copied from the presentation")
	}
	if math.IsInf(f, 0) {
		return fmt.Errorf("a claim value of %v is not a number JSON can carry, so it cannot be copied from the presentation", f)
	}
	return nil
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
			PresentedClaims:    slices.Sorted(maps.Keys(claims)),
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
