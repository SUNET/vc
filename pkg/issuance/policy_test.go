package issuance

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/sirosfoundation/go-spocp/pkg/sexp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPolicyEngine_NilPolicy(t *testing.T) {
	engine, err := NewPolicyEngine(nil)
	require.NoError(t, err)
	assert.Nil(t, engine)
}

// TestNewPolicyEngine_ConfiguredButNoRules covers every way a configured
// policy can end up with nothing to match against.
//
// They used to fail in opposite directions, both silently. No rules and no
// rules_file made BuildEngine return (nil, nil), which reads as "no policy
// configured" - the gate disabled itself. A rules_file that parses to nothing
// returns an engine with zero rules instead, which no query can satisfy -
// every issuance for the scope denied at runtime. Neither is a deployment
// anyone means to have, so both are refused where the scope can still be
// named.
func TestNewPolicyEngine_ConfiguredButNoRules(t *testing.T) {
	t.Run("no rules and no rules_file", func(t *testing.T) {
		engine, err := NewPolicyEngine(&model.IssuancePolicy{})
		require.Error(t, err)
		assert.Nil(t, engine)
		assert.Contains(t, err.Error(), "neither rules nor rules_file")
	})

	for _, tc := range []struct {
		name     string
		contents string
	}{
		{"empty rules_file", ""},
		{"comments-only rules_file", "# nothing here\n# still nothing\n"},
		{"blank-lines-only rules_file", "\n\n   \n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rules.spocp")
			require.NoError(t, os.WriteFile(path, []byte(tc.contents), 0o600))

			engine, err := NewPolicyEngine(&model.IssuancePolicy{
				RulesFile:     path,
				QueryTemplate: []model.QueryDimension{{Dimension: "acr", Claim: "acr"}},
			})
			require.Error(t, err, "a rules_file that loads no rules must not yield a usable engine")
			assert.Nil(t, engine)
			assert.Contains(t, err.Error(), "no rules were loaded")
		})
	}
}

// TestNewPolicyEngine_RulesWithoutQueryTemplate pins the refusal of the
// claim-driven fallback.
//
// SPOCP matches rule dimensions to query dimensions by position. The fallback
// built the query from whatever claims the token carried, in name order, so a
// rule naming two claims matched only when those two sorted ahead of every
// other claim present - and a real ID token always carries aud, iss, nonce
// and sub. Such a policy denied every request while reading as configured.
func TestNewPolicyEngine_RulesWithoutQueryTemplate(t *testing.T) {
	engine, err := NewPolicyEngine(&model.IssuancePolicy{
		Rules: []string{"(credential (scope pid)(acr loa3)(org_id))"},
	})
	require.Error(t, err)
	assert.Nil(t, engine)
	assert.Contains(t, err.Error(), "no query_template")
}

func TestNewPolicyEngine_InvalidRule(t *testing.T) {
	policy := &model.IssuancePolicy{
		Rules:         []string{"(invalid (unclosed"},
		QueryTemplate: []model.QueryDimension{{Dimension: "email_verified", Claim: "email_verified"}},
	}
	engine, err := NewPolicyEngine(policy)
	assert.Error(t, err)
	assert.Nil(t, engine)
	assert.Contains(t, err.Error(), "invalid inline issuance policy rule #1")
}

func TestNewPolicyEngine_ValidRules(t *testing.T) {
	policy := &model.IssuancePolicy{
		Rules: []string{
			"(credential (scope pid)(email_verified true))",
		},
		QueryTemplate: []model.QueryDimension{{Dimension: "email_verified", Claim: "email_verified"}},
	}
	engine, err := NewPolicyEngine(policy)
	require.NoError(t, err)
	require.NotNil(t, engine)
	assert.Equal(t, 1, engine.RuleCount())
}

func TestEvaluate_SimpleMatch(t *testing.T) {
	policy := &model.IssuancePolicy{
		Rules: []string{
			"(credential (scope pid)(email_verified true))",
		},
		QueryTemplate: []model.QueryDimension{
			{Dimension: "email_verified", Claim: "email_verified"},
		},
	}
	engine, err := NewPolicyEngine(policy)
	require.NoError(t, err)

	// Should pass: claims match the rule
	err = engine.Evaluate("pid", map[string]any{
		"email_verified": "true",
	}, policy.QueryTemplate)
	assert.NoError(t, err)
}

func TestEvaluate_SimpleDeny(t *testing.T) {
	policy := &model.IssuancePolicy{
		Rules: []string{
			"(credential (scope pid)(email_verified true))",
		},
		QueryTemplate: []model.QueryDimension{
			{Dimension: "email_verified", Claim: "email_verified"},
		},
	}
	engine, err := NewPolicyEngine(policy)
	require.NoError(t, err)

	// Should deny: email_verified is false
	err = engine.Evaluate("pid", map[string]any{
		"email_verified": "false",
	}, policy.QueryTemplate)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "issuance policy denied")
}

func TestEvaluate_WrongScope(t *testing.T) {
	policy := &model.IssuancePolicy{
		Rules: []string{
			"(credential (scope pid)(email_verified true))",
		},
		QueryTemplate: []model.QueryDimension{
			{Dimension: "email_verified", Claim: "email_verified"},
		},
	}
	engine, err := NewPolicyEngine(policy)
	require.NoError(t, err)

	// Should deny: scope doesn't match
	err = engine.Evaluate("ehic", map[string]any{
		"email_verified": "true",
	}, policy.QueryTemplate)
	assert.Error(t, err)
}

func TestEvaluate_WildcardRule(t *testing.T) {
	policy := &model.IssuancePolicy{
		Rules: []string{
			// Allow any scope with any email_verified value
			"(credential (scope pid)(email_verified))",
		},
		QueryTemplate: []model.QueryDimension{
			{Dimension: "email_verified", Claim: "email_verified"},
		},
	}
	engine, err := NewPolicyEngine(policy)
	require.NoError(t, err)

	// Should pass: wildcard matches any value
	err = engine.Evaluate("pid", map[string]any{
		"email_verified": "false",
	}, policy.QueryTemplate)
	assert.NoError(t, err)
}

func TestEvaluate_StarForms(t *testing.T) {
	tests := []struct {
		name      string
		rule      string
		scope     string
		passCases []map[string]any
		failCases []map[string]any
	}{
		{
			name:  "prefix match",
			rule:  "(credential (scope org_cred)(acr (* prefix urn:example:loa)))",
			scope: "org_cred",
			passCases: []map[string]any{
				{"acr": "urn:example:loa3"},
			},
			failCases: []map[string]any{
				{"acr": "urn:other:loa3"},
			},
		},
		{
			name:  "set match",
			rule:  "(credential (scope pid)(acr (* set loa3 loa4)))",
			scope: "pid",
			passCases: []map[string]any{
				{"acr": "loa3"},
				{"acr": "loa4"},
			},
			failCases: []map[string]any{
				{"acr": "loa1"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &model.IssuancePolicy{
				Rules:         []string{tt.rule},
				QueryTemplate: []model.QueryDimension{{Dimension: "acr", Claim: "acr"}},
			}
			engine, err := NewPolicyEngine(policy)
			require.NoError(t, err)

			for _, claims := range tt.passCases {
				assert.NoError(t, engine.Evaluate(tt.scope, claims, policy.QueryTemplate), "expected pass for %v", claims)
			}
			for _, claims := range tt.failCases {
				assert.Error(t, engine.Evaluate(tt.scope, claims, policy.QueryTemplate), "expected deny for %v", claims)
			}
		})
	}
}

func TestEvaluate_MultipleRules(t *testing.T) {
	policy := &model.IssuancePolicy{
		Rules: []string{
			"(credential (scope pid)(acr loa3)(org_id 123))",
			"(credential (scope pid)(acr loa4)(org_id))",
		},
		QueryTemplate: []model.QueryDimension{
			{Dimension: "acr", Claim: "acr"},
			{Dimension: "org_id", Claim: "org_id"},
		},
	}
	engine, err := NewPolicyEngine(policy)
	require.NoError(t, err)

	// Should pass: matches first rule
	err = engine.Evaluate("pid", map[string]any{
		"acr":    "loa3",
		"org_id": "123",
	}, policy.QueryTemplate)
	assert.NoError(t, err)

	// Should pass: matches second rule (loa4 with any org_id)
	err = engine.Evaluate("pid", map[string]any{
		"acr":    "loa4",
		"org_id": "999",
	}, policy.QueryTemplate)
	assert.NoError(t, err)

	// Should deny: loa3 requires org_id 123
	err = engine.Evaluate("pid", map[string]any{
		"acr":    "loa3",
		"org_id": "999",
	}, policy.QueryTemplate)
	assert.Error(t, err)
}

// TestEvaluate_NoQueryTemplate pins the second half of the fallback removal.
//
// NewPolicyEngine refuses to build an engine without a template, but Evaluate
// receives the template as its own argument, from a caller that reads it back
// out of the config. A check that cannot decide has to refuse: with no
// dimensions the query carries only the scope, so whether it matched would say
// nothing about the claims.
func TestEvaluate_NoQueryTemplate(t *testing.T) {
	policy := &model.IssuancePolicy{
		Rules: []string{
			"(credential (scope pid)(email_verified true)(sub))",
		},
		QueryTemplate: []model.QueryDimension{
			{Dimension: "email_verified", Claim: "email_verified"},
			{Dimension: "sub", Claim: "sub"},
		},
	}
	engine, err := NewPolicyEngine(policy)
	require.NoError(t, err)

	err = engine.Evaluate("pid", map[string]any{
		"email_verified": "true",
		"sub":            "alice",
	}, nil)
	require.Error(t, err, "evaluating with no dimensions must refuse, not answer")
	assert.Contains(t, err.Error(), "no query_template")
}

// TestEvaluate_FallbackWouldHaveDenied is the evidence that the removed
// fallback was not merely unvalidated but wrong.
//
// The claim set is what a real ID token looks like. Both claims the rule names
// are present and correct, and under the old claim-driven query this denied,
// because aud/auth_time/iss/nonce/sub sorted in between acr and org_id and
// pushed them out of the positions the rule occupied. With the template the
// same claims pass.
func TestEvaluate_FallbackWouldHaveDenied(t *testing.T) {
	policy := &model.IssuancePolicy{
		Rules: []string{"(credential (scope pid)(acr loa3)(org_id SE123))"},
		QueryTemplate: []model.QueryDimension{
			{Dimension: "acr", Claim: "acr"},
			{Dimension: "org_id", Claim: "org_id"},
		},
	}
	engine, err := NewPolicyEngine(policy)
	require.NoError(t, err)

	realIDToken := map[string]any{
		"aud": "client", "auth_time": 1.0, "iss": "https://op",
		"nonce": "n", "sub": "u1",
		"acr": "loa3", "org_id": "SE123",
	}
	assert.NoError(t, engine.Evaluate("pid", realIDToken, policy.QueryTemplate))
}

func TestEvaluate_MissingClaim(t *testing.T) {
	policy := &model.IssuancePolicy{
		Rules: []string{
			// Rule requires org_id to have a value
			"(credential (scope pid)(org_id 123))",
		},
		QueryTemplate: []model.QueryDimension{
			{Dimension: "org_id", Claim: "org_id"},
		},
	}
	engine, err := NewPolicyEngine(policy)
	require.NoError(t, err)

	// Should deny: org_id not in claims (empty dimension doesn't match specific value)
	err = engine.Evaluate("pid", map[string]any{
		"sub": "alice",
	}, policy.QueryTemplate)
	assert.Error(t, err)
}

func TestEvaluate_BooleanClaims(t *testing.T) {
	policy := &model.IssuancePolicy{
		Rules: []string{
			"(credential (scope pid)(email_verified true))",
		},
		QueryTemplate: []model.QueryDimension{
			{Dimension: "email_verified", Claim: "email_verified"},
		},
	}
	engine, err := NewPolicyEngine(policy)
	require.NoError(t, err)

	// Boolean true should convert to string "true"
	err = engine.Evaluate("pid", map[string]any{
		"email_verified": true,
	}, policy.QueryTemplate)
	assert.NoError(t, err)

	// Boolean false should convert to "false" and not match "true"
	err = engine.Evaluate("pid", map[string]any{
		"email_verified": false,
	}, policy.QueryTemplate)
	assert.Error(t, err)
}

func TestBuildQuery_WithTemplate(t *testing.T) {
	query := BuildQuery("pid", map[string]any{
		"acr":    "loa3",
		"org_id": "123",
		"sub":    "alice",
	}, []model.QueryDimension{
		{Dimension: "acr", Claim: "acr"},
		{Dimension: "org_id", Claim: "org_id"},
	})

	// Query should be a list with tag "credential"
	list, ok := query.(*sexp.List)
	require.True(t, ok)
	assert.Equal(t, "credential", list.Tag)

	// Should have scope + 2 template dimensions = 3 elements
	assert.Len(t, list.Elements, 3)
}

// TestBuildQuery_WithoutTemplate pins that no template means no claim
// dimensions - the query carries the scope and nothing else, rather than
// silently reaching for whatever claims happened to be present.
func TestBuildQuery_WithoutTemplate(t *testing.T) {
	query := BuildQuery("pid", map[string]any{
		"acr": "loa3",
		"sub": "alice",
	}, nil)

	list, ok := query.(*sexp.List)
	require.True(t, ok)
	assert.Equal(t, "credential", list.Tag)
	assert.Len(t, list.Elements, 1, "only the scope dimension")
}

// TestToStringValueComposite pins determinism for object and array claims.
//
// A claim can legitimately be an object (an address) or an array. fmt's %v
// walks a map in Go's randomised order, so the same claim value rendered to a
// different atom between two requests and a rule written against one spelling
// matched sometimes and denied sometimes, with nothing in the logs telling the
// two runs apart.
func TestToStringValueComposite(t *testing.T) {
	nested := map[string]any{
		"street": "Main", "city": "Stockholm", "zip": "11122",
		"country": "SE", "region": "Sodermanland", "extra": "x",
	}
	first := toStringValue(nested)
	for range 50 {
		assert.Equal(t, first, toStringValue(nested), "composite claim must render identically every time")
	}
	assert.Equal(t, `{"city":"Stockholm","country":"SE","extra":"x","region":"Sodermanland","street":"Main","zip":"11122"}`, first)

	assert.Equal(t, `["a","b"]`, toStringValue([]any{"a", "b"}))
}

func TestToStringValue(t *testing.T) {
	assert.Equal(t, "hello", toStringValue("hello"))
	assert.Equal(t, "true", toStringValue(true))
	assert.Equal(t, "false", toStringValue(false))
	assert.Equal(t, "42", toStringValue(42))
	assert.Equal(t, "3.14", toStringValue(3.14))
}

// TestBuildQueryResolvesNestedClaimPaths covers the dot-notation the
// configuration documents and the doc_example advertises
// ("identity.given_name").
//
// BuildQuery used a flat map lookup, so such a path never resolved. The
// dimension was then emitted empty, which matches a wildcard rule and fails
// a rule requiring a value - a policy would widen or hard-deny with nothing
// saying why. ProcessCallback fills the claims via idToken.Claims, so a
// nested claim really does arrive as a map under its parent.
func TestBuildQueryResolvesNestedClaimPaths(t *testing.T) {
	claims := map[string]any{
		"acr": "loa3",
		"identity": map[string]any{
			"given_name": "Ada",
			"address":    map[string]any{"country": "SE"},
		},
		// A claim whose name itself contains a dot must keep winning over
		// the traversal, so nested support cannot change existing configs.
		"identity.given_name": "flat-wins",
	}

	for _, tc := range []struct {
		name  string
		claim string
		want  string
	}{
		{name: "a nested path resolves", claim: "identity.address.country", want: "(10:credential(5:scope3:pid)(3:dim2:SE))"},
		{name: "a flat key still resolves", claim: "acr", want: "(10:credential(5:scope3:pid)(3:dim4:loa3))"},
		{name: "a literal dotted key beats the traversal", claim: "identity.given_name", want: "(10:credential(5:scope3:pid)(3:dim9:flat-wins))"},
		{name: "an absent path leaves the dimension empty", claim: "identity.missing", want: "(10:credential(5:scope3:pid)(3:dim))"},
		{name: "a path through a non-map leaves it empty", claim: "acr.nope", want: "(10:credential(5:scope3:pid)(3:dim))"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// String() renders the canonical length-prefixed SPOCP form,
			// not the human-readable one the rules are written in.
			q := BuildQuery("pid", claims, []model.QueryDimension{{Dimension: "dim", Claim: tc.claim}})
			assert.Equal(t, tc.want, q.String())
		})
	}
}

// TestEvaluateAbsentClaimIsNotAWildcard pins the difference between "any
// value" and "no value", which the query S-expression cannot express.
//
// An unresolved dimension is emitted empty, as `(org_id)` — and that is also
// how a wildcard rule is written under this rule set's convention, so SPOCP
// matched them against each other. `(credential (scope pid)(org_id))`, the
// weakest rule an operator can write for that dimension, therefore authorized
// a token carrying no org_id at all: asserting nothing satisfied it.
//
// An operator who genuinely does not care about a dimension leaves it out of
// query_template, where it appears in neither the query nor the rule shape.
// Listing it is a statement that the provider must assert it.
func TestEvaluateAbsentClaimIsNotAWildcard(t *testing.T) {
	policy := &model.IssuancePolicy{
		Rules:         []string{"(credential (scope pid)(org_id))"},
		QueryTemplate: []model.QueryDimension{{Dimension: "org_id", Claim: "org_id"}},
	}
	engine, err := NewPolicyEngine(policy)
	require.NoError(t, err)

	t.Run("present satisfies the wildcard", func(t *testing.T) {
		require.NoError(t, engine.Evaluate("pid", map[string]any{"org_id": "SE123"}, policy.QueryTemplate))
	})

	t.Run("absent is denied", func(t *testing.T) {
		err := engine.Evaluate("pid", map[string]any{"sub": "alice"}, policy.QueryTemplate)
		require.Error(t, err, "a claim the OP did not assert must not satisfy a wildcard dimension")
		assert.Contains(t, err.Error(), "did not assert")
		assert.Contains(t, err.Error(), "org_id", "the denial must name the claim that was missing")
	})

	t.Run("absent is denied even against a value rule", func(t *testing.T) {
		valuePolicy := &model.IssuancePolicy{
			Rules: []string{"(credential (scope pid)(acr loa3)(org_id SE123))"},
			QueryTemplate: []model.QueryDimension{
				{Dimension: "acr", Claim: "acr"},
				{Dimension: "org_id", Claim: "org_id"},
			},
		}
		valueEngine, err := NewPolicyEngine(valuePolicy)
		require.NoError(t, err)

		err = valueEngine.Evaluate("pid", map[string]any{"acr": "loa3"}, valuePolicy.QueryTemplate)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "org_id")
	})

	t.Run("a nested claim path still resolves", func(t *testing.T) {
		nestedPolicy := &model.IssuancePolicy{
			Rules:         []string{"(credential (scope pid)(given_name Alice))"},
			QueryTemplate: []model.QueryDimension{{Dimension: "given_name", Claim: "identity.given_name"}},
		}
		nestedEngine, err := NewPolicyEngine(nestedPolicy)
		require.NoError(t, err)

		require.NoError(t, nestedEngine.Evaluate("pid", map[string]any{
			"identity": map[string]any{"given_name": "Alice"},
		}, nestedPolicy.QueryTemplate), "dot-notation resolution must count as present")
	})
}
