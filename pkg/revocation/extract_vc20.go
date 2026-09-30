package revocation

import (
	"encoding/json"
	"math"
	"strconv"

	"github.com/SUNET/vc/pkg/vc20/contextstore"
)

// ExtractCredentialStatusReference extracts a Token Status List reference
// from a W3C VC 2.0 credential's credentialStatus property.
//
// draft-ietf-oauth-status-list binds its status claim to JOSE (Section 6.2)
// and COSE (Section 6.3) only; there is no VCDM binding, so the shape read
// here is vc's own - see contextstore.TokenStatusListContextURL. What it
// resolves to is the same Reference every other format produces, so one
// revocation check still covers all four.
//
// Returns nil when there is no credentialStatus, or when the entry names a
// mechanism this function does not implement. A nil return is NOT "the
// credential is fine": Registry.Validate refuses a credential that declares
// a status it could not read, rather than letting it through as
// non-revocable.
func ExtractCredentialStatusReference(claims map[string]any) *Reference {
	raw, ok := claims["credentialStatus"]
	if !ok {
		return nil
	}

	// VCDM allows credentialStatus to be a single object or a set of them.
	// A credential may carry several mechanisms; take the first Token
	// Status List entry and ignore the rest.
	var entries []any
	switch v := raw.(type) {
	case []any:
		entries = v
	case map[string]any:
		entries = []any{v}
	default:
		return nil
	}

	for _, entry := range entries {
		m, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		if !hasType(m, contextstore.TokenStatusListEntryType) {
			continue
		}

		uri, _ := m["statusListUri"].(string)
		if uri == "" {
			continue
		}

		index, ok := statusListIndex(m["statusListIndex"])
		if !ok {
			continue
		}

		return &Reference{Scheme: SchemeStatusList, URI: uri, Index: index}
	}
	return nil
}

// hasType reports whether a credentialStatus entry declares the given type.
// VCDM's "type" is a single value or a set of them.
func hasType(entry map[string]any, want string) bool {
	switch t := entry["type"].(type) {
	case string:
		return t == want
	case []any:
		for _, item := range t {
			if s, ok := item.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

// statusListIndex reads the entry's index. It is written as a string (the
// same choice W3C's BitstringStatusListEntry makes) so that its canonical
// RDF form cannot depend on how a JSON number round-trips, but a number is
// maxExactJSONInteger is the largest integer a float64 represents exactly,
// 2^53-1. A JSON number decodes to float64, so beyond this an index cannot
// be read back as written.
const maxExactJSONInteger = 1<<53 - 1

// accepted too rather than silently treated as absent.
func statusListIndex(raw any) (int64, bool) {
	switch v := raw.(type) {
	case string:
		i, err := strconv.ParseInt(v, 10, 64)
		if err != nil || i < 0 {
			return 0, false
		}
		return i, true
	case float64:
		// A JSON number decodes to float64, which stops being able to name
		// an integer exactly above 2^53. Converting a larger one yields a
		// ROUNDED index - so the credential would be checked against a
		// different entry than the one it names, silently, and a revoked
		// credential could land on a neighbour's VALID bit.
		//
		// Refused rather than rounded. A status list with more than 2^53
		// entries is not a thing; a value that large is a malformed or
		// hostile credential, and "cannot read the index" has to mean
		// refuse, not guess.
		if v != math.Trunc(v) || v < 0 || v > maxExactJSONInteger {
			return 0, false
		}
		return int64(v), true
	case int64:
		if v < 0 {
			return 0, false
		}
		return v, true
	case int:
		if v < 0 {
			return 0, false
		}
		return int64(v), true
	case json.Number:
		i, err := v.Int64()
		if err != nil || i < 0 {
			return 0, false
		}
		return i, true
	default:
		return 0, false
	}
}

// declaresStatus reports whether a credential claims to carry revocation
// information at all, whatever mechanism it names.
//
// This is what separates "this credential is not revocable" from "this
// credential says it is revocable and we could not read how". The first is
// a normal credential; the second is a credential whose revocation state is
// unknown, and treating the two alike lets a revoked credential through on
// nothing more than an unrecognised type name or a malformed entry.
func declaresStatus(claims map[string]any) bool {
	// credentialStatus is a VCDM term and means one thing, so its PRESENCE
	// is the declaration - `"credentialStatus": null` names a mechanism and
	// fails to describe it, which is a malformed declaration rather than
	// the absence of one, and requiring a non-nil value was a
	// one-character way past this guard.
	if _, ok := claims["credentialStatus"]; ok {
		return true
	}

	// `status` is not exclusive to revocation. The draft's claim is an
	// OBJECT (it holds status_list), while an application claim or an mdoc
	// data element of the same name is typically a string - `"status":
	// "active"` is an ordinary credential claim and must not make every
	// such credential unverifiable. So: an object declares, a null
	// declares (nothing puts a null where an application status belongs),
	// and a scalar is somebody else's claim.
	v, ok := claims["status"]
	if !ok {
		return false
	}
	if v == nil {
		return true
	}
	_, isObject := v.(map[string]any)
	return isObject
}
