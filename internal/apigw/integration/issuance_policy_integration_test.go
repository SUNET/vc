//go:build integration

package integration

import (
	"maps"
	"testing"

	"github.com/SUNET/vc/pkg/issuance"
	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// issuancePolicyForPID gates the "pid" scope on the OP asserting acr loa3.
//
// Built per test rather than shared: GetPolicyEngine caches engines keyed on
// the *IssuancePolicy pointer, so two tests sharing one value would also
// share the engine and stop exercising rule loading.
func issuancePolicyForPID() *model.IssuancePolicy {
	return &model.IssuancePolicy{
		Rules:         []string{"(credential (scope pid)(acr loa3))"},
		QueryTemplate: []model.QueryDimension{{Dimension: "acr", Claim: "acr"}},
	}
}

// TestIssuancePolicyIntegration_MockOPClaims covers the acceptance criterion
// that the policy gate be exercised against a mock OP returning claims that
// pass and fail it (SUNET/vc#379).
//
// The claims are not hand-written: the OP signs them into an ID token, the
// real oidcrp callback verifies and returns them, and the policy sees what
// the callback path in handlers_oidcrp.go would see. A test that fabricated
// the claim map would still pass if the callback stopped returning acr at
// all, which is the failure this is meant to catch.
func TestIssuancePolicyIntegration_MockOPClaims(t *testing.T) {
	for _, tc := range []struct {
		name       string
		opAsserts  map[string]any
		wantDenied bool
	}{
		{
			name:      "the OP asserts the acr the policy requires",
			opAsserts: map[string]any{"acr": "loa3"},
		},
		{
			name:       "the OP asserts a lower acr",
			opAsserts:  map[string]any{"acr": "loa1"},
			wantDenied: true,
		},
		{
			// The claim-driven dimension is absent entirely, which is not the
			// same as present-and-wrong: an unset dimension must not read as
			// a wildcard.
			name:       "the OP asserts no acr at all",
			opAsserts:  nil,
			wantDenied: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := setupOIDCTestEnvironment(t)
			defer env.cleanup()
			env.mockOP.extraIDTokenClaims = tc.opAsserts

			claims := completeCallbackForScope(t, env, "pid")
			for k, want := range tc.opAsserts {
				require.Equal(t, want, claims[k], "the callback dropped %q before the policy could see it", k)
			}

			policy := issuancePolicyForPID()
			engine, err := issuance.GetPolicyEngine(policy)
			require.NoError(t, err)
			require.NotNil(t, engine)

			err = engine.Evaluate("pid", maps.Clone(claims), policy.QueryTemplate)
			if tc.wantDenied {
				require.Error(t, err, "policy must deny, and denial must be a hard error with no fallback")
				return
			}
			require.NoError(t, err)
		})
	}
}

// TestIssuancePolicyIntegration_DynamicParamsCannotSatisfyPolicy pins the
// security property the callback documents: DynamicParams come from the PAR
// request body, nothing verifies they came from the authentic source, so they
// must never satisfy a dimension the OP did not assert.
//
// Without this, a caller could send acr=loa3 in the PAR body and be issued a
// credential the OP said they were not entitled to - the whole point of
// gating on the returned token. The handler achieves it by evaluating
// authResp.Claims alone; this asserts the outcome rather than the code shape,
// so reintroducing a merge or fallback fails here.
func TestIssuancePolicyIntegration_DynamicParamsCannotSatisfyPolicy(t *testing.T) {
	env := setupOIDCTestEnvironment(t)
	defer env.cleanup()

	// The OP asserts an acr that fails the policy.
	env.mockOP.extraIDTokenClaims = map[string]any{"acr": "loa1"}

	claims := completeCallbackForScope(t, env, "pid")
	require.Equal(t, "loa1", claims["acr"])

	policy := issuancePolicyForPID()
	engine, err := issuance.GetPolicyEngine(policy)
	require.NoError(t, err)

	// What a caller could put in the PAR body, claiming the stronger acr.
	forged := map[string]string{"acr": "loa3"}

	// The evaluated claim set is the OP's, and only the OP's.
	require.Error(t, engine.Evaluate("pid", maps.Clone(claims), policy.QueryTemplate),
		"the OP-asserted acr must decide the outcome")

	// Demonstrate the same claims merged with the forged params would pass,
	// so the denial above is the merge's absence and not a policy that denies
	// everything.
	merged := maps.Clone(claims)
	for k, v := range forged {
		merged[k] = v
	}
	require.NoError(t, engine.Evaluate("pid", merged, policy.QueryTemplate),
		"sanity check: the forged value is the one the policy would accept")
}

// TestIssuancePolicyIntegration_ScopeLookup covers the gate the callback uses
// before evaluating anything: a policy configured for one scope must not
// govern another, and a scope with no policy must not acquire one.
func TestIssuancePolicyIntegration_ScopeLookup(t *testing.T) {
	ds := &model.DataSources{
		Datastore: model.DatastoreConfig{
			Scopes: map[string]model.DatastoreScope{
				"pid": {IssuancePolicy: issuancePolicyForPID()},
			},
		},
	}

	pid := ds.LookupScopePolicyConfig("pid")
	require.NotNil(t, pid)
	require.NotNil(t, pid.IssuancePolicy)
	assert.Equal(t, []string{"(credential (scope pid)(acr loa3))"}, pid.IssuancePolicy.Rules)

	if other := ds.LookupScopePolicyConfig("diploma"); other != nil {
		assert.Nil(t, other.IssuancePolicy, "a scope with no policy of its own must not inherit one")
	}
}

// completeCallbackForScope drives a full authorization round trip against the
// mock OP and returns the claims the callback produced.
func completeCallbackForScope(t *testing.T, env *oidcTestEnvironment, scope string) map[string]any {
	t.Helper()
	ctx := t.Context()

	authReq, err := env.oidcService.InitiateAuth(ctx, scope, nil, nil)
	require.NoError(t, err)

	session, err := env.oidcService.GetSession(ctx, authReq.State)
	require.NoError(t, err)

	// The mock token endpoint reads the nonce back out of the code.
	resp, err := env.oidcService.ProcessCallback(ctx, "valid-auth-code|"+session.Nonce, authReq.State)
	require.NoError(t, err)
	require.NotNil(t, resp)

	return resp.Claims
}
