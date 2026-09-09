package issuance

import (
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

func TestNewPolicyEngine_EmptyPolicy(t *testing.T) {
	engine, err := NewPolicyEngine(&model.IssuancePolicy{})
	require.NoError(t, err)
	assert.Nil(t, engine)
}

func TestNewPolicyEngine_InvalidRule(t *testing.T) {
	policy := &model.IssuancePolicy{
		Rules: []string{"(invalid (unclosed"},
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
	}
	engine, err := NewPolicyEngine(policy)
	require.NoError(t, err)
	require.NotNil(t, engine)
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

func TestEvaluate_NoQueryTemplate(t *testing.T) {
	policy := &model.IssuancePolicy{
		Rules: []string{
			"(credential (scope pid)(email_verified true)(sub))",
		},
	}
	engine, err := NewPolicyEngine(policy)
	require.NoError(t, err)

	// Should pass: all claims included as dimensions, query template nil
	err = engine.Evaluate("pid", map[string]any{
		"email_verified": "true",
		"sub":            "alice",
	}, nil)
	assert.NoError(t, err)
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

func TestBuildQuery_WithoutTemplate(t *testing.T) {
	query := BuildQuery("pid", map[string]any{
		"acr": "loa3",
		"sub": "alice",
	}, nil)

	list, ok := query.(*sexp.List)
	require.True(t, ok)
	assert.Equal(t, "credential", list.Tag)

	// Should have scope + 2 claim dimensions = 3 elements
	assert.Len(t, list.Elements, 3)
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
