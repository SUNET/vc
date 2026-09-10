package oidcrp

import (
	"encoding/json"
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

// TestResolveOIDCRequestParams_ClaimsCannotBeStructurallyInjected covers the
// claims parameter against its own dynamic values.
//
// They arrive in the PAR request body, so they are caller-supplied, and
// text/template escapes nothing. The documented way to write this parameter
// puts the variable inside a JSON string, so a value carrying a quote used
// to close that string and let the caller append JSON of their own.
func TestResolveOIDCRequestParams_ClaimsCannotBeStructurallyInjected(t *testing.T) {
	const tmpl = `{"id_token":{"org_id":{"value":"{{.org_id}}"}}}`

	t.Run("a quote stays inside the value", func(t *testing.T) {
		// Reads as: close the string, add an essential claim of the
		// caller's choosing, and balance the braces.
		injection := `x","email":{"essential":true}},"ignored":{"y":"z`
		opts, err := resolveOIDCRequestParams(
			&model.OIDCRequestParams{Claims: tmpl},
			map[string]string{"org_id": injection},
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		claims := authURLParam(t, opts, "claims")

		// The structure must be exactly what the operator wrote, with the
		// whole injection sitting in the value as text.
		var got struct {
			IDToken map[string]struct {
				Value string `json:"value"`
			} `json:"id_token"`
			Email any `json:"email"`
		}
		if err := json.Unmarshal([]byte(claims), &got); err != nil {
			t.Fatalf("resolved claims is not valid JSON: %v\n%s", err, claims)
		}
		if got.Email != nil {
			t.Fatalf("the injected email claim reached the request: %s", claims)
		}
		if got.IDToken["org_id"].Value != injection {
			t.Fatalf("value was altered\n got: %q\nwant: %q", got.IDToken["org_id"].Value, injection)
		}
	})

	t.Run("a backslash cannot escape the escaping", func(t *testing.T) {
		opts, err := resolveOIDCRequestParams(
			&model.OIDCRequestParams{Claims: tmpl},
			map[string]string{"org_id": `back\slash"and quote`},
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if claims := authURLParam(t, opts, "claims"); !json.Valid([]byte(claims)) {
			t.Fatalf("resolved claims is not valid JSON: %s", claims)
		}
	})

	t.Run("an operator template that is not JSON is refused", func(t *testing.T) {
		_, err := resolveOIDCRequestParams(
			&model.OIDCRequestParams{Claims: `{"id_token": oops}`},
			nil,
		)
		if err == nil {
			t.Fatal("expected a malformed claims parameter to be rejected")
		}
	})

	t.Run("a plain value is unchanged", func(t *testing.T) {
		opts, err := resolveOIDCRequestParams(
			&model.OIDCRequestParams{Claims: tmpl},
			map[string]string{"org_id": "SUNET"},
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got, want := authURLParam(t, opts, "claims"), `{"id_token":{"org_id":{"value":"SUNET"}}}`; got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})
}

// authURLParam reads one parameter back out of the AuthCodeOption list by
// rendering an authorization URL, since the options are opaque otherwise.
func authURLParam(t *testing.T, opts []oauth2.AuthCodeOption, key string) string {
	t.Helper()
	cfg := &oauth2.Config{ClientID: "test-client", Endpoint: oauth2.Endpoint{AuthURL: "https://op.example.com/authorize"}}
	u, err := url.Parse(cfg.AuthCodeURL("state", opts...))
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get(key)
}
