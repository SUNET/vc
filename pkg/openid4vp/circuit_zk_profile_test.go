package openid4vp

import (
	"encoding/json"
	"maps"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func nymQuery(items ...ReqItem) CredentialQuery {
	return CredentialQuery{
		ID: "nym_attestation", Format: FormatCircuitZk,
		Meta: MetaQuery{DoctypeValue: "eu.europa.ec.eudi.nym_auth.1"},
		Req:  items,
	}
}

func pseudonymItem(params map[string]any) ReqItem {
	return ReqItem{ID: FunctionPseudonym, Return: "nym-1", Params: params}
}

// The conformant request from the rulebook passes.
func TestNymAuthProfileAcceptsTheRulebookExample(t *testing.T) {
	query := nymQuery(
		pseudonymItem(map[string]any{"config": "known-offender-matching-ssc"}),
		ReqItem{ID: FunctionAgeCheck, Return: "age-1", Params: map[string]any{"ge": "2008-10-10", "le": "2013-10-09"}},
	)
	assert.NoError(t, ValidateProfile(ProfileNymAuth, query))
}

// Each rulebook MUST, violated in turn.
func TestNymAuthProfileRejectsEachViolation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query CredentialQuery
		want  string
	}{
		{
			name:  "two pseudonym items",
			query: nymQuery(pseudonymItem(map[string]any{"config": "user-managed-pseudonym-xsite-ssc"}), ReqItem{ID: FunctionPseudonym, Return: "nym-2", Params: map[string]any{"config": "user-managed-pseudonym-xsite-ssc"}}),
			want:  "allows one",
		},
		{
			name: "two age_check items",
			query: nymQuery(
				ReqItem{ID: FunctionAgeCheck, Return: "a1", Params: map[string]any{"ge": "2000-01-01"}},
				ReqItem{ID: FunctionAgeCheck, Return: "a2", Params: map[string]any{"ge": "2000-01-01"}}),
			want: "allows one",
		},
		{
			name:  "a duplicate handle",
			query: nymQuery(ReqItem{ID: FunctionAgeCheck, Return: "same", Params: map[string]any{"ge": "2000-01-01"}}, ReqItem{ID: FunctionPseudonym, Return: "same", Params: map[string]any{"config": "user-managed-pseudonym-xsite-ssc"}}),
			want:  "more than once",
		},
		{
			name:  "an unknown function",
			query: nymQuery(ReqItem{ID: "no-such-function", Return: "h"}),
			want:  "not a function the nym_auth rulebook registers",
		},
		{
			name:  "an unknown pseudonym configuration",
			query: nymQuery(pseudonymItem(map[string]any{"config": "made-up"})),
			want:  "not a configuration the rulebook defines",
		},
		{
			name:  "no verifier_context for account recovery",
			query: nymQuery(pseudonymItem(map[string]any{"config": "account-recovery-ssc"})),
			want:  "requires params.verifier_context",
		},
		{
			name:  "a verifier_context where it is not allowed",
			query: nymQuery(pseudonymItem(map[string]any{"config": "known-offender-matching-ssc", "verifier_context": "x"})),
			want:  "does not allow params.verifier_context",
		},
		{
			name:  "a verifier_context past 64 bytes",
			query: nymQuery(pseudonymItem(map[string]any{"config": "account-recovery-ssc", "verifier_context": string(make([]byte, 65))})),
			want:  "1 to 64",
		},
		{
			name:  "an age_check with neither bound",
			query: nymQuery(ReqItem{ID: FunctionAgeCheck, Return: "a"}),
			want:  "at least one of params.ge and params.le",
		},
		{
			name:  "le before ge",
			query: nymQuery(ReqItem{ID: FunctionAgeCheck, Return: "a", Params: map[string]any{"ge": "2013-10-09", "le": "2008-10-10"}}),
			want:  "before params.ge",
		},
		{
			name:  "a range under 365 days",
			query: nymQuery(ReqItem{ID: FunctionAgeCheck, Return: "a", Params: map[string]any{"ge": "2010-01-01", "le": "2010-06-01"}}),
			want:  "at least 365",
		},
		{
			name:  "a date that is not a full-date",
			query: nymQuery(ReqItem{ID: FunctionAgeCheck, Return: "a", Params: map[string]any{"ge": "2010-01-01T00:00:00Z"}}),
			want:  "not an RFC 3339 full-date",
		},
		{
			name:  "no req at all",
			query: nymQuery(),
			want:  "req is required",
		},
		{
			name:  "no doctype",
			query: CredentialQuery{Format: FormatCircuitZk, Req: []ReqItem{{ID: FunctionAgeCheck, Return: "a", Params: map[string]any{"ge": "2000-01-01"}}}},
			want:  "meta.doctype_value is required",
		},
		{
			name: "claims alongside req",
			query: func() CredentialQuery {
				q := nymQuery(ReqItem{ID: FunctionAgeCheck, Return: "a", Params: map[string]any{"ge": "2000-01-01"}})
				q.Claims = []ClaimQuery{{Path: StringPath("ssc")}}
				return q
			}(),
			want: "discloses nothing",
		},
		{
			name:  "the wrong format",
			query: CredentialQuery{Format: FormatMsoMdoc, Meta: MetaQuery{DoctypeValue: "d"}, Req: []ReqItem{{ID: FunctionAgeCheck, Return: "a"}}},
			want:  "describes circuit_zk requests",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateProfile(ProfileNymAuth, tc.query)
			require.Error(t, err, "this violates a rulebook MUST and the profile must say so")
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// Exactly 365 days is allowed; 364 is not. The rulebook counts the range
// inclusively, so an off-by-one here silently moves where the line is.
func TestNymAuthProfileAgeSpanBoundary(t *testing.T) {
	// 2010-01-01 to 2010-12-31 is 365 days inclusive (2010 is not a leap year).
	ok := nymQuery(ReqItem{ID: FunctionAgeCheck, Return: "a", Params: map[string]any{"ge": "2010-01-01", "le": "2010-12-31"}})
	assert.NoError(t, ValidateProfile(ProfileNymAuth, ok))

	short := nymQuery(ReqItem{ID: FunctionAgeCheck, Return: "a", Params: map[string]any{"ge": "2010-01-01", "le": "2010-12-30"}})
	require.Error(t, ValidateProfile(ProfileNymAuth, short))
}

// No profile means no validation. That is the default, and it is what
// lets this verifier send a request no rulebook would accept.
func TestNoProfileValidatesNothing(t *testing.T) {
	nonsense := CredentialQuery{
		Format: FormatCircuitZk,
		Req: []ReqItem{
			{ID: "whatever", Return: "same"},
			{ID: "whatever", Return: "same"},
		},
	}
	assert.NoError(t, ValidateProfile("", nonsense))

	err := ValidateProfile("no-such-profile", nonsense)
	require.Error(t, err, "an unknown profile name is a configuration mistake, not a silent no-op")
	assert.Contains(t, err.Error(), "unknown validation profile")
}

// A raw query is bytes this package does not model, so the profile says
// it cannot check it rather than passing it as if it had.
func TestProfileRefusesToJudgeARawQuery(t *testing.T) {
	err := ValidateProfile(ProfileNymAuth, CredentialQuery{Raw: json.RawMessage(`{"format":"circuit_zk"}`)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "raw query cannot be checked")
}

// A profile named after the rulebook has to check the credential the
// rulebook is about. "Some doctype is present" would pass a request for
// an unrelated document.
func TestNymAuthProfilePinsTheDoctype(t *testing.T) {
	conforming := pseudonymItem(map[string]any{"config": "known-offender-matching-ssc"})

	for _, tc := range []struct{ name, doctype, want string }{
		{"the rulebook's own", nymAuthDoctype, ""},
		{"absent", "", "required"},
		{"an unrelated document", "org.iso.18013.5.1.mDL", "defines this credential as"},
		{"a version the rulebook has not minted", "eu.europa.ec.eudi.nym_auth.2", "defines this credential as"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := nymQuery(conforming)
			query.Meta.DoctypeValue = tc.doctype

			err := ValidateProfile(ProfileNymAuth, query)
			if tc.want == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// The shared matcher vectors put an explicit false among the requests
// that are well-formed and rulebook-UNSATISFIABLE
// (ok_satisfiability_not_judged.json). The planner passes it by design;
// the profile is the thing that is supposed to say so.
//
// Absent must stay fine: OpenID4VP 1.0 6.1 defaults it to true, and a nil
// pointer is how that default is preserved.
func TestNymAuthProfileRejectsExplicitlyDisabledHolderBinding(t *testing.T) {
	conforming := pseudonymItem(map[string]any{"config": "known-offender-matching-ssc"})
	no, yes := false, true

	for _, tc := range []struct {
		name string
		set  *bool
		want string
	}{
		{"absent, which means true", nil, ""},
		{"explicitly true", &yes, ""},
		{"explicitly false", &no, "require_cryptographic_holder_binding"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := nymQuery(conforming)
			query.RequireCryptographicHolderBinding = tc.set

			err := ValidateProfile(ProfileNymAuth, query)
			if tc.want == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// A -psc configuration is well-defined by the rulebook and cannot be
// requested: a psc is a commitment the holder already knows, and nothing
// specifies yet how a Verifier conveys one to a wallet. Accepting it
// would report a preset as valid that no wallet can be asked for.
//
// The error has to say which of the two it is. "Not a configuration the
// rulebook defines" would be false, and would send an operator looking
// for a typo.
func TestNymAuthProfileRefusesPSCConfigurationsAsPending(t *testing.T) {
	err := ValidateProfile(ProfileNymAuth, nymQuery(pseudonymItem(map[string]any{
		"config": "known-offender-matching-psc",
	})))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "defined by the rulebook but cannot be requested yet")
	assert.Contains(t, err.Error(), "conveying one to a wallet")
	assert.NotContains(t, err.Error(), "is not a configuration the rulebook defines")
}

// Two named members the rulebook does not allow on a request. Separate
// from the unknown-member case, which stays permissive: a newer rulebook
// adding a parameter is what this whole format is built around.
func TestNymAuthProfileRefusesMembersTheRulebookDoesNotAllow(t *testing.T) {
	base := map[string]any{"config": "known-offender-matching-ssc"}
	with := func(name string, value any) map[string]any {
		params := map[string]any{}
		maps.Copy(params, base)
		params[name] = value
		return params
	}

	for _, tc := range []struct{ name, param, want string }{
		{"a psc, which only a holder has", "psc", "every configuration this profile supports is -ssc"},
		{"a verifier_id, where the request names the kind", "verifier_id", "the wallet derives the verifier"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateProfile(ProfileNymAuth, nymQuery(pseudonymItem(with(tc.param, "x"))))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.Contains(t, err.Error(), "params."+tc.param)
		})
	}

	t.Run("an unknown parameter is still allowed", func(t *testing.T) {
		assert.NoError(t, ValidateProfile(ProfileNymAuth,
			nymQuery(pseudonymItem(with("some_future_param", "x")))))
	})
}

// verifier_id_type is no longer part of the request
// (nym_auth_rulebook#5): the wallet decides how to identify the verifier,
// from its own ordered list of identity kinds, so there is nothing for a
// request to say about it.
//
// This profile therefore says nothing about it either, in BOTH
// directions, and that is what this pins. A missing one is not a
// violation - every other case in this file now omits it - and a request
// still carrying one stays sendable whatever its value, because testing a
// wallet against the legacy shape is a thing this format exists to allow.
// An earlier revision of this profile REQUIRED it on some configurations
// and REFUSED it on others; neither rule survives, so both are exercised
// here against the configurations that used to carry them.
func TestNymAuthProfileIgnoresVerifierIDType(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"the kind the legacy requests carried", "x509_san_dns"},
		{"another the old rulebook named", "semantic"},
		{"empty", ""},
		{"an unknown kind", "dns"},
		{"a different case, which used to be refused", "X509_SAN_DNS"},
		{"and a value that is not even a string", 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, config := range []string{
				"known-offender-matching-ssc",      // used to REQUIRE it
				"user-managed-pseudonym-xsite-ssc", // used to REFUSE it
			} {
				assert.NoError(t, ValidateProfile(ProfileNymAuth, nymQuery(pseudonymItem(
					map[string]any{"config": config, "verifier_id_type": tc.value}))),
					"config %q must neither require nor refuse verifier_id_type", config)
			}
		})
	}

	// And the request shape the rulebook now defines - no
	// verifier_id_type at all - validates on every configuration.
	for _, params := range []map[string]any{
		{"config": "known-offender-matching-ssc"},
		{"config": "user-managed-pseudonym-xsite-ssc"},
		{"config": "account-recovery-ssc", "verifier_context": "ctx"},
	} {
		assert.NoError(t, ValidateProfile(ProfileNymAuth, nymQuery(pseudonymItem(params))),
			"the normative request form must validate: %v", params)
	}
}
