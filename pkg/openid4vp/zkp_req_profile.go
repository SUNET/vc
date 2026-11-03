package openid4vp

import (
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"
	"time"
)

// ProfileNymAuth validates a zkp_req request against the EUDI nym_auth
// rulebook.
//
// It is one profile among possible others, which is why it is named
// rather than being a "strict" flag. A zkp_req request that is not a
// nym_auth request is not invalid - the format is general, the rulebook
// is one use of it - and a boolean would say otherwise.
const ProfileNymAuth = "nym_auth"

// ValidateProfile checks query against the named profile.
//
// Nothing calls this on the request path. It is for CONFIGURATION: an
// operator who wants to be told that a preset violates the rulebook asks
// for it by name, at startup, where the answer is useful. Traffic stays
// unvalidated on purpose - this verifier is how wallets are tested, and
// the specifications under it are still moving.
func ValidateProfile(profile string, query CredentialQuery) error {
	switch profile {
	case "":
		return nil
	case ProfileNymAuth:
		return validateNymAuth(query)
	default:
		return fmt.Errorf("unknown validation profile %q", profile)
	}
}

// nymAuthDoctype is the credential the rulebook defines.
//
// Pinned rather than "any non-empty doctype": a profile named after the
// rulebook that accepts an unrelated document is not checking the thing
// it is named for. A later revision of the rulebook will mint a new
// identifier and this will need updating with it - which is the right
// cost, since the alternative is a check that passes on anything.
const nymAuthDoctype = "eu.europa.ec.eudi.nym_auth.1"

// nym_auth pseudonym configurations, and whether each takes a
// verifier_context.
//
// Whether a configuration derives verifier_input is no longer a property
// of the REQUEST. The rulebook took verifier_id_type out of it
// (nym_auth_rulebook#5): the wallet decides how to identify the verifier,
// from its own ordered list of identity kinds and the trust framework's
// answer, so there is nothing for a request to say and nothing here to
// check. known-offender-matching-ssc and account-recovery-ssc still
// derive one; the circuit knows that, and the wallet does.
//
// The rulebook's -psc configurations are deliberately ABSENT. They are
// well-defined there, but a psc is a commitment the HOLDER already knows,
// and nothing yet specifies how a Verifier conveys one to a wallet -
// which means a preset naming one cannot be sent, whatever this profile
// says about it. Accepting it here would report a request as valid that
// no wallet can be asked for. See nymAuthPendingConfigs.
var nymAuthConfigs = map[string]struct{ usesContext bool }{
	"known-offender-matching-ssc":      {},
	"account-recovery-ssc":             {usesContext: true},
	"user-managed-pseudonym-xsite-ssc": {},
}

// nymAuthPendingConfigs are rulebook configurations this build cannot
// request yet, named separately so an operator gets told WHY rather than
// "not a configuration the rulebook defines", which would be false.
var nymAuthPendingConfigs = map[string]string{
	"known-offender-matching-psc": "a psc is a commitment the holder already knows, and there is no specified mechanism yet for conveying one to a wallet",
}

func validateNymAuth(query CredentialQuery) error {
	if query.Raw != nil {
		return fmt.Errorf("a raw query cannot be checked against the %s profile; the profile reads members a raw query does not model", ProfileNymAuth)
	}
	if !IsZkpReqFormat(query.Format) {
		return fmt.Errorf("format is %q, and the %s profile describes zkp_req requests", query.Format, ProfileNymAuth)
	}
	if err := validateNymAuthMeta(query.Meta); err != nil {
		return err
	}
	// The shared matcher vectors list an explicit false among the
	// well-formed-but-rulebook-unsatisfiable requests
	// (ok_satisfiability_not_judged.json): the planner passes it and the
	// rulebook does not. Absent is fine - OpenID4VP 1.0 6.1 defaults it to
	// true - so only an explicit false is refused.
	if query.RequireCryptographicHolderBinding != nil && !*query.RequireCryptographicHolderBinding {
		return fmt.Errorf("require_cryptographic_holder_binding is explicitly false, which the %s rulebook does not allow", ProfileNymAuth)
	}
	if len(query.Claims) > 0 || len(query.ClaimSet) > 0 {
		return fmt.Errorf("a zkp_req query discloses nothing, so it carries no claims: every value comes from req")
	}
	if len(query.Req) == 0 {
		return fmt.Errorf("req is required and must not be empty")
	}

	handles := map[string]bool{}
	counts := map[string]int{}
	for i, item := range query.Req {
		where := fmt.Sprintf("req[%d]", i)
		if item.FnID == "" {
			return fmt.Errorf("%s: id is required", where)
		}
		if item.Return == "" {
			return fmt.Errorf("%s: return is required", where)
		}
		if handles[item.Return] {
			return fmt.Errorf("%s: return %q is used more than once; a handle identifies one result", where, item.Return)
		}
		handles[item.Return] = true
		counts[item.FnID]++

		switch item.FnID {
		case FunctionPseudonym:
			if err := validateNymAuthPseudonym(where, query.Meta.SourceFormat, item); err != nil {
				return err
			}
		case FunctionAgeCheck:
			if err := validateNymAuthAgeCheck(where, item); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s: %q is not a function the %s rulebook registers", where, item.FnID, ProfileNymAuth)
		}
	}

	// "A req MUST NOT contain more than one pseudonym item", and
	// the same for age_check.
	for _, function := range slices.Sorted(maps.Keys(counts)) {
		if counts[function] > 1 {
			return fmt.Errorf("req carries %d %s items; the rulebook allows one", counts[function], function)
		}
	}
	return nil
}

// nymAuthBBSSchemaID is the type value of the blind-BBS nym_auth
// attestation, the way nymAuthDoctype is for the mdoc one.
const nymAuthBBSSchemaID = "eu.europa.ec.eudi.nym_auth.bbs.1"

// validateNymAuthMeta checks the pair that has to agree: which stored
// attestation the proof is made over, and the type value naming it.
//
// They are one check and not two because each source format has exactly
// one type value member - doctype_value for mso_mdoc, schema_id_value
// for bbs_cd - and carrying the other one, or carrying vct_values, which
// belongs to dc+sd-jwt, is what the matcher refuses as
// meta_type_value_invalid.
func validateNymAuthMeta(meta MetaQuery) error {
	// The planner refuses a zkp_req meta with no string source_format
	// (invalid_meta) before it reads anything else, so a request that
	// goes out without one is answered by nobody.
	switch meta.SourceFormat {
	case SourceFormatMsoMdoc:
		if meta.DoctypeValue != nymAuthDoctype {
			if meta.DoctypeValue == "" {
				return fmt.Errorf("meta.doctype_value is required for source_format %s, and the %s rulebook defines it as %q",
					SourceFormatMsoMdoc, ProfileNymAuth, nymAuthDoctype)
			}
			return fmt.Errorf("meta.doctype_value is %q; the %s rulebook defines this credential as %q",
				meta.DoctypeValue, ProfileNymAuth, nymAuthDoctype)
		}
		if meta.SchemaIDValue != "" {
			return fmt.Errorf("meta.schema_id_value belongs to source_format %s; an %s request names its type with doctype_value",
				SourceFormatBbsCd, SourceFormatMsoMdoc)
		}
	case SourceFormatBbsCd:
		if meta.SchemaIDValue != nymAuthBBSSchemaID {
			if meta.SchemaIDValue == "" {
				return fmt.Errorf("meta.schema_id_value is required for source_format %s, and the %s rulebook defines it as %q",
					SourceFormatBbsCd, ProfileNymAuth, nymAuthBBSSchemaID)
			}
			return fmt.Errorf("meta.schema_id_value is %q; the %s rulebook defines this credential as %q",
				meta.SchemaIDValue, ProfileNymAuth, nymAuthBBSSchemaID)
		}
		if meta.DoctypeValue != "" {
			return fmt.Errorf("meta.doctype_value belongs to source_format %s; a %s request names its type with schema_id_value",
				SourceFormatMsoMdoc, SourceFormatBbsCd)
		}
	case "":
		return fmt.Errorf("meta.source_format is required for a %s request, and names the stored attestation the proof is made over (%s or %s)",
			FormatZkpReq, SourceFormatMsoMdoc, SourceFormatBbsCd)
	default:
		return fmt.Errorf("meta.source_format is %q; the %s rulebook defines %s and %s (dc+sd-jwt is reserved)",
			meta.SourceFormat, ProfileNymAuth, SourceFormatMsoMdoc, SourceFormatBbsCd)
	}
	if len(meta.VCTValues) > 0 {
		return fmt.Errorf("meta.vct_values belongs to dc+sd-jwt; a %s request names its type with doctype_value or schema_id_value", FormatZkpReq)
	}
	return nil
}

func validateNymAuthPseudonym(where, sourceFormat string, item ReqItem) error {
	config, _ := item.Params["config"].(string)
	if config == "" {
		return fmt.Errorf("%s: params.config is required", where)
	}
	spec, known := nymAuthConfigs[config]
	if !known {
		if why, pending := nymAuthPendingConfigs[config]; pending {
			return fmt.Errorf("%s: %q is defined by the rulebook but cannot be requested yet: %s", where, config, why)
		}
		return fmt.Errorf("%s: %q is not a configuration the rulebook defines (%s)", where, config,
			strings.Join(slices.Sorted(maps.Keys(nymAuthConfigs)), ", "))
	}

	// Two named members the rulebook does not allow on a request, kept
	// separate from the unknown-member case: everything this profile
	// supports is an -ssc configuration, so a psc - the commitment a
	// HOLDER already knows - has no place in one; and the request names
	// the KIND of verifier identity, which the wallet then derives,
	// rather than the identity itself.
	//
	// Named members only. An unknown parameter stays permissive, because
	// a newer rulebook adding one is the case this whole format is built
	// around.
	for name, why := range map[string]string{
		"psc":         "every configuration this profile supports is -ssc, and a psc is the holder's own commitment",
		"verifier_id": "the wallet derives the verifier's identity itself; a request never carries it",
	} {
		if _, present := item.Params[name]; present {
			return fmt.Errorf("%s: params.%s is not a member the %s rulebook allows on a request: %s", where, name, ProfileNymAuth, why)
		}
	}

	// verifier_id_type is deliberately NOT checked, in either direction.
	//
	// It is no longer part of the request (nym_auth_rulebook#5). A
	// missing one is not a violation, so this does not require it; and a
	// request still carrying one has to remain sendable, so this does not
	// refuse it either. A verifier testing a wallet against the legacy
	// shape is a thing this format exists to allow, and wallets accept
	// and ignore the member.
	//
	// It is named here rather than simply left out, because "the profile
	// says nothing about it" is a decision and not an oversight.

	// ver and prf became REQUIRED parameters of pseudonym in v0.4, and
	// the matcher refuses a request missing either as unsatisfiable
	// (pseudonym_ver_missing, pseudonym_prf_missing). An operator who
	// copies an older example gets a preset that starts cleanly and is
	// then declined by every wallet.
	ver, hasVer := item.Params["ver"]
	if !hasVer {
		return fmt.Errorf("%s: params.ver is required, and the %s rulebook defines %d", where, ProfileNymAuth, PseudonymVer1)
	}
	n, whole := wholeNumber(ver)
	if !whole {
		return fmt.Errorf("%s: params.ver must be an integer", where)
	}
	if n != PseudonymVer1 {
		return fmt.Errorf("%s: params.ver is %d; the %s rulebook defines %d", where, n, ProfileNymAuth, PseudonymVer1)
	}

	prf, hasPRF := item.Params["prf"]
	if !hasPRF {
		return fmt.Errorf("%s: params.prf is required", where)
	}
	name, isString := prf.(string)
	if !isString {
		return fmt.Errorf("%s: params.prf must be a string", where)
	}
	// Which prf is defined depends on BOTH the source format and the
	// configuration: hashdh-bls12381g1 exists for blind-BBS, and only
	// for the one configuration that uses it.
	switch {
	case sourceFormat == SourceFormatMsoMdoc && name == PrfSHA256:
	case sourceFormat == SourceFormatBbsCd && name == PrfHashDHBLS12381G1 && config == "known-offender-matching-ssc":
	default:
		return fmt.Errorf("%s: params.prf %q is not defined for source_format %q with config %q", where, name, sourceFormat, config)
	}

	context, hasContext := item.Params["verifier_context"]
	switch {
	case spec.usesContext && !hasContext:
		return fmt.Errorf("%s: %q requires params.verifier_context", where, config)
	case !spec.usesContext && hasContext:
		return fmt.Errorf("%s: %q does not allow params.verifier_context", where, config)
	}
	if hasContext {
		value, ok := context.(string)
		if !ok {
			return fmt.Errorf("%s: params.verifier_context must be a string", where)
		}
		if n := len(value); n < 1 || n > 64 {
			return fmt.Errorf("%s: params.verifier_context is %d bytes; the rulebook allows 1 to 64", where, n)
		}
	}
	return nil
}

// wholeNumber reads a configured or received integer, whatever numeric
// type it arrived as: YAML gives an int, JSON a float64, and a decoder
// set to UseNumber a json.Number. A value with a fractional part is not
// an integer and is reported as such rather than truncated.
func wholeNumber(value any) (int64, bool) {
	switch n := value.(type) {
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case uint64:
		return int64(n), n <= math.MaxInt64
	case float64:
		return int64(n), n == math.Trunc(n)
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}

// minAgeSpanDays is the rulebook's floor on an age_check range: a
// sufficiently narrow range is an exact birth date, which the predicate
// is not meant to reveal.
const minAgeSpanDays = 365

func validateNymAuthAgeCheck(where string, item ReqItem) error {
	ge, hasGE, err := nymAuthDate(where, item.Params, "ge")
	if err != nil {
		return err
	}
	le, hasLE, err := nymAuthDate(where, item.Params, "le")
	if err != nil {
		return err
	}
	if !hasGE && !hasLE {
		return fmt.Errorf("%s: at least one of params.ge and params.le is required", where)
	}
	if !hasGE || !hasLE {
		return nil
	}
	if le.Before(ge) {
		return fmt.Errorf("%s: params.le is before params.ge", where)
	}
	// Inclusive, as the rulebook counts it: le - ge + 1 days.
	if days := int(le.Sub(ge).Hours()/24) + 1; days < minAgeSpanDays {
		return fmt.Errorf("%s: the range spans %d days; the rulebook requires at least %d, since a narrow range is an exact date",
			where, days, minAgeSpanDays)
	}
	return nil
}

func nymAuthDate(where string, params map[string]any, name string) (time.Time, bool, error) {
	raw, present := params[name]
	if !present {
		return time.Time{}, false, nil
	}
	s, ok := raw.(string)
	if !ok {
		return time.Time{}, false, fmt.Errorf("%s: params.%s must be a string", where, name)
	}
	parsed, err := time.Parse(time.DateOnly, s)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("%s: params.%s is %q, which is not an RFC 3339 full-date", where, name, s)
	}
	return parsed, true, nil
}
