package openid4vp

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
)

// ProfileNymAuth validates a circuit_zk request against the EUDI nym_auth
// rulebook.
//
// It is one profile among possible others, which is why it is named
// rather than being a "strict" flag. A circuit_zk request that is not a
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

// nym_auth pseudonym configurations, and whether each uses verifier_input
// (and so requires a verifier_id_type) or verifier_context.
//
// The rulebook's -psc configurations are deliberately ABSENT. They are
// well-defined there, but a psc is a commitment the HOLDER already knows,
// and nothing yet specifies how a Verifier conveys one to a wallet -
// which means a preset naming one cannot be sent, whatever this profile
// says about it. Accepting it here would report a request as valid that
// no wallet can be asked for. See nymAuthPendingConfigs.
var nymAuthConfigs = map[string]struct{ usesVerifierID, usesContext bool }{
	"known-offender-matching-ssc":      {usesVerifierID: true},
	"account-recovery-ssc":             {usesVerifierID: true, usesContext: true},
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
	if !IsCircuitZkFormat(query.Format) {
		return fmt.Errorf("format is %q, and the %s profile describes circuit_zk requests", query.Format, ProfileNymAuth)
	}
	if query.Meta.DoctypeValue != nymAuthDoctype {
		if query.Meta.DoctypeValue == "" {
			return fmt.Errorf("meta.doctype_value is required, and the %s rulebook defines it as %q", ProfileNymAuth, nymAuthDoctype)
		}
		return fmt.Errorf("meta.doctype_value is %q; the %s rulebook defines this credential as %q",
			query.Meta.DoctypeValue, ProfileNymAuth, nymAuthDoctype)
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
		return fmt.Errorf("a circuit_zk query discloses nothing, so it carries no claims: every value comes from req")
	}
	if len(query.Req) == 0 {
		return fmt.Errorf("req is required and must not be empty")
	}

	handles := map[string]bool{}
	counts := map[string]int{}
	for i, item := range query.Req {
		where := fmt.Sprintf("req[%d]", i)
		if item.ID == "" {
			return fmt.Errorf("%s: id is required", where)
		}
		if item.Return == "" {
			return fmt.Errorf("%s: return is required", where)
		}
		if handles[item.Return] {
			return fmt.Errorf("%s: return %q is used more than once; a handle identifies one result", where, item.Return)
		}
		handles[item.Return] = true
		counts[item.ID]++

		switch item.ID {
		case FunctionPseudonym:
			if err := validateNymAuthPseudonym(where, item); err != nil {
				return err
			}
		case FunctionAgeCheck:
			if err := validateNymAuthAgeCheck(where, item); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s: %q is not a function the %s rulebook registers", where, item.ID, ProfileNymAuth)
		}
	}

	// "A req MUST NOT contain more than one pseudonym-v1-sha256 item", and
	// the same for age_check.
	for _, function := range slices.Sorted(maps.Keys(counts)) {
		if counts[function] > 1 {
			return fmt.Errorf("req carries %d %s items; the rulebook allows one", counts[function], function)
		}
	}
	return nil
}

func validateNymAuthPseudonym(where string, item ReqItem) error {
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
		"verifier_id": "the request names verifier_id_type, and the wallet derives the identity itself",
	} {
		if _, present := item.Params[name]; present {
			return fmt.Errorf("%s: params.%s is not a member the %s rulebook allows on a request: %s", where, name, ProfileNymAuth, why)
		}
	}

	idType, hasIDType := item.Params["verifier_id_type"]
	switch {
	case spec.usesVerifierID && !hasIDType:
		return fmt.Errorf("%s: %q derives verifier_input, so params.verifier_id_type is required", where, config)
	case !spec.usesVerifierID && hasIDType:
		return fmt.Errorf("%s: %q does not use verifier_input, so params.verifier_id_type must not be present", where, config)
	}
	if hasIDType {
		value, ok := idType.(string)
		if !ok {
			return fmt.Errorf("%s: params.verifier_id_type must be a string", where)
		}
		if !slices.Contains(nymAuthVerifierIDTypes, value) {
			return fmt.Errorf("%s: params.verifier_id_type is %q; the %s rulebook defines %s",
				where, value, ProfileNymAuth, strings.Join(nymAuthVerifierIDTypes, " and "))
		}
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

// nymAuthVerifierIDTypes are the identity kinds the rulebook defines for
// a pseudonym request.
//
// An open string let the profile approve an empty one, which nothing can
// derive a verifier_input from, and an unknown one that a wallet must
// treat as unsatisfiable. Both are requests this verifier would build and
// no wallet could answer.
//
// Provenance, because it is not all equal: the shared matcher vectors use
// x509_san_dns, and carry an empty one only in the vector that exists to
// show the planner treats these as opaque. "semantic" is from the review
// that raised this and is not in any artefact I can check here - worth a
// glance from someone holding the rulebook. The cost of it being wrong is
// bounded either way: this profile is opt-in, and an operator who needs a
// value it does not know simply leaves validate unset.
var nymAuthVerifierIDTypes = []string{"semantic", "x509_san_dns"}

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
