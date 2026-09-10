package oidcrp

import (
	"net/url"
	"testing"

	"github.com/SUNET/vc/pkg/model"

	"golang.org/x/oauth2"
)

// TestResolveOIDCRequestParams_CustomParamsCannotOverrideReserved verifies that
// a configured custom_params key matching a core authorization request
// parameter (e.g. "nonce", "state", "code_challenge") is rejected, since
// oauth2.AuthCodeOption values are applied by key with last-write-wins
// semantics and would otherwise silently override state/nonce/PKCE
// guarantees InitiateAuth sets before calling AuthCodeURL.
func TestResolveOIDCRequestParams_CustomParamsCannotOverrideReserved(t *testing.T) {
	for reserved := range reservedOIDCParams {
		t.Run(reserved, func(t *testing.T) {
			params := &model.OIDCRequestParams{
				CustomParams: map[string]string{reserved: "attacker-controlled"},
			}
			_, err := resolveOIDCRequestParams(params, nil)
			if err == nil {
				t.Fatalf("expected error for reserved custom_params key %q, got nil", reserved)
			}
		})
	}
}

// TestResolveOIDCRequestParams_AllowsNonReservedCustomParams verifies that
// custom_params keys which don't collide with core parameters are still
// resolved and passed through to the authorization URL normally.
func TestResolveOIDCRequestParams_AllowsNonReservedCustomParams(t *testing.T) {
	params := &model.OIDCRequestParams{
		CustomParams: map[string]string{"login_hint": "user@example.com"},
	}
	opts, err := resolveOIDCRequestParams(params, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfg := &oauth2.Config{
		ClientID: "test-client",
		Endpoint: oauth2.Endpoint{AuthURL: "https://op.example.com/authorize"},
	}
	authURL := cfg.AuthCodeURL("test-state", opts...)

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("failed to parse generated auth URL: %v", err)
	}
	if got := parsed.Query().Get("login_hint"); got != "user@example.com" {
		t.Errorf("expected login_hint=user@example.com in %q, got %q", authURL, got)
	}
}

// TestResolveOIDCRequestParams_CustomParamsCannotShadowDedicatedFields covers
// why acr_values and claims are reserved, which differs from the rest of the
// set: they are not core protocol parameters but ones with dedicated
// OIDCRequestParams fields.
//
// CustomParams is applied after those fields, so with last-write-wins a
// custom param of the same name silently replaced the configured value - the
// operator would read acr_values in the config and a different acr_values
// would go on the wire. Rejecting makes the precedence unambiguous instead.
func TestResolveOIDCRequestParams_CustomParamsCannotShadowDedicatedFields(t *testing.T) {
	for _, tc := range []struct {
		name   string
		params *model.OIDCRequestParams
	}{
		{
			name: "acr_values alongside the dedicated field",
			params: &model.OIDCRequestParams{
				ACRValues:    "loa3",
				CustomParams: map[string]string{"acr_values": "loa1"},
			},
		},
		{
			name: "claims alongside the dedicated field",
			params: &model.OIDCRequestParams{
				Claims:       `{"id_token":{"acr":null}}`,
				CustomParams: map[string]string{"claims": "{}"},
			},
		},
		{
			// Rejected even with no dedicated value set, so the rule is a
			// property of the key rather than of the combination.
			name: "acr_values with no dedicated value configured",
			params: &model.OIDCRequestParams{
				CustomParams: map[string]string{"acr_values": "loa1"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := resolveOIDCRequestParams(tc.params, nil); err == nil {
				t.Fatal("expected the shadowing custom_params key to be rejected, got nil")
			}
		})
	}
}
