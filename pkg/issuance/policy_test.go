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
		QueryTemplate: map[string]string{
			"email_verified": "email_verified",
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
		QueryTemplate: map[string]string{
			"email_verified": "email_verified",
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
		QueryTemplate: map[string]string{
			"email_verified": "email_verified",
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
		QueryTemplate: map[string]string{
			"email_verified": "email_verified",
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

func TestEvaluate_PrefixStarForm(t *testing.T) {
	policy := &model.IssuancePolicy{
		Rules: []string{
			"(credential (scope org_cred)(acr (* prefix urn:example:loa)))",
		},
		QueryTemplate: map[string]string{
			"acr": "acr",
		},
	}
	engine, err := NewPolicyEngine(policy)
	require.NoError(t, err)

	// Should pass: acr starts with the prefix
	err = engine.Evaluate("org_cred", map[string]any{
		"acr": "urn:example:loa3",
	}, policy.QueryTemplate)
	assert.NoError(t, err)

	// Should deny: acr doesn't match prefix
	err = engine.Evaluate("org_cred", map[string]any{
		"acr": "urn:other:loa3",
	}, policy.QueryTemplate)
	assert.Error(t, err)
}

func TestEvaluate_SetStarForm(t *testing.T) {
	policy := &model.IssuancePolicy{
		Rules: []string{
			"(credential (scope pid)(acr (* set loa3 loa4)))",
		},
		QueryTemplate: map[string]string{
			"acr": "acr",
		},
	}
	engine, err := NewPolicyEngine(policy)
	require.NoError(t, err)

	// Should pass: acr is in the set
	err = engine.Evaluate("pid", map[string]any{
		"acr": "loa3",
	}, policy.QueryTemplate)
	assert.NoError(t, err)

	err = engine.Evaluate("pid", map[string]any{
		"acr": "loa4",
	}, policy.QueryTemplate)
	assert.NoError(t, err)

	// Should deny: acr not in set
	err = engine.Evaluate("pid", map[string]any{
		"acr": "loa1",
	}, policy.QueryTemplate)
	assert.Error(t, err)
}

func TestEvaluate_MultipleRules(t *testing.T) {
	policy := &model.IssuancePolicy{
		Rules: []string{
			"(credential (scope pid)(acr loa3)(org_id 123))",
			"(credential (scope pid)(acr loa4)(org_id))",
		},
		QueryTemplate: map[string]string{
			"acr":    "acr",
			"org_id": "org_id",
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
		QueryTemplate: map[string]string{
			"org_id": "org_id",
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
		QueryTemplate: map[string]string{
			"email_verified": "email_verified",
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
	}, map[string]string{
		"acr":    "acr",
		"org_id": "org_id",
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
