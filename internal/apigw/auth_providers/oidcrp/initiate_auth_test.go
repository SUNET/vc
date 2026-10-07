package oidcrp

import (
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"golang.org/x/oauth2"

	"github.com/stretchr/testify/require"
)

func readyService(t *testing.T) *Service {
	t.Helper()
	s := &Service{
		cfg:          &model.OIDCRP{IssuerURL: "https://op.example.com", SessionDuration: 300},
		sessionCache: cache.NewMemoryCache[*Session](5 * time.Minute),
		log:          logger.NewSimple("test"),
		ready:        true,
		creds:        newCredentialSet(5 * time.Minute),
	}
	s.creds.store(&credentials{
		clientID: "vc",
		config: &oauth2.Config{
			ClientID:    "vc",
			RedirectURL: "https://apigw.example.com/callback",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://op.example.com/authorize"},
			Scopes:      []string{"openid"},
		},
	})
	return s
}

// TestInitiateAuthLeavesNoSessionWhenParamsAreRejected: a request whose OIDC
// parameters cannot be resolved was never sent to the OP, so no state for it
// should exist. Creating the session first left one behind until the TTL
// expired, and a caller retrying a misconfigured scope accumulated one dead
// entry per attempt.
func TestInitiateAuthLeavesNoSessionWhenParamsAreRejected(t *testing.T) {
	for name, params := range map[string]*model.OIDCRequestParams{
		"reserved custom parameter": {
			CustomParams: map[string]string{"nonce": "attacker-controlled"},
		},
		"unresolved template placeholder": {
			ACRValues: "{{.org_id}}",
		},
	} {
		t.Run(name, func(t *testing.T) {
			svc := readyService(t)

			_, err := svc.InitiateAuth(t.Context(), "pid", params, nil)
			require.Error(t, err)
			require.Zero(t, svc.sessionCache.Len(),
				"a request that was never sent must not leave state behind")
		})
	}
}

// TestInitiateAuthStoresTheSessionOnSuccess is the other half, so the
// reordering is not simply failing to create sessions.
func TestInitiateAuthStoresTheSessionOnSuccess(t *testing.T) {
	svc := readyService(t)

	got, err := svc.InitiateAuth(t.Context(), "pid", &model.OIDCRequestParams{
		CustomParams: map[string]string{"login_hint": "user@example.com"},
		ExtraScopes:  []string{"profile"},
	}, nil)
	require.NoError(t, err)
	require.NotEmpty(t, got.State)
	require.Equal(t, 1, svc.sessionCache.Len())

	// The resolved parameters still reach the URL - moving them above the
	// session must not have dropped them.
	require.Contains(t, got.AuthorizationURL, "login_hint=user%40example.com")
	require.Contains(t, got.AuthorizationURL, "code_challenge_method=S256")
	require.Contains(t, got.AuthorizationURL, "scope=openid+profile")

	session, err := svc.getSession(t.Context(), got.State)
	require.NoError(t, err)
	require.Equal(t, "pid", session.CredentialType)
}
