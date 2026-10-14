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

// nym_auth pseudonym configurations, and whether each uses verifier_input
// (and so requires a verifier_id_type) or verifier_context.
var nymAuthConfigs = map[string]struct{ usesVerifierID, usesContext bool }{
	"known-offender-matching-ssc":      {usesVerifierID: true},
	"known-offender-matching-psc":      {usesVerifierID: true},
	"account-recovery-ssc":             {usesVerifierID: true, usesContext: true},
	"user-managed-pseudonym-xsite-ssc": {},
}

func validateNymAuth(query CredentialQuery) error {
	if query.Raw != nil {
		return fmt.Errorf("a raw query cannot be checked against the %s profile; the profile reads members a raw query does not model", ProfileNymAuth)
	}
	if !IsCircuitZkFormat(query.Format) {
		return fmt.Errorf("format is %q, and the %s profile describes circuit_zk requests", query.Format, ProfileNymAuth)
	}
	if query.Meta.DoctypeValue == "" {
		return fmt.Errorf("meta.doctype_value is required")
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
		return fmt.Errorf("%s: %q is not a configuration the rulebook defines (%s)", where, config,
			strings.Join(slices.Sorted(maps.Keys(nymAuthConfigs)), ", "))
	}

	idType, hasIDType := item.Params["verifier_id_type"]
	switch {
	case spec.usesVerifierID && !hasIDType:
		return fmt.Errorf("%s: %q derives verifier_input, so params.verifier_id_type is required", where, config)
	case !spec.usesVerifierID && hasIDType:
		return fmt.Errorf("%s: %q does not use verifier_input, so params.verifier_id_type must not be present", where, config)
	}
	if hasIDType {
		if _, ok := idType.(string); !ok {
			return fmt.Errorf("%s: params.verifier_id_type must be a string", where)
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
