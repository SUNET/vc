package apiv1

import (
	"testing"

	"github.com/SUNET/vc/internal/verifier/cache"
	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/require"
)

// TestMissingQueryRefusesOnlyWhatThisPathMustCheck: a session whose DCQL query
// cannot be recovered is a normal cross-replica condition - the persisted
// request is gone, or this process never held the request object. Refusing
// every response for it turned that cache miss into an outage for flows this
// path has nothing to do with: an SD-JWT-only OIDC response carries no W3C
// document and asks no W3C scope, so there is nothing here to check and
// nothing downstream relying on this having checked it.
//
// It still fails closed where it matters, and either reason alone is enough: a
// W3C document actually arrived, or the session's scopes are CONFIGURED as a
// W3C format and so could have asked for one.
func TestMissingQueryRefusesOnlyWhatThisPathMustCheck(t *testing.T) {
	withScopes := func(formats map[string]string) *Client {
		client, _ := CreateTestClientWithMock(t, nil)
		client.cfg.Common = &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{}}
		for scope, format := range formats {
			client.cfg.Common.CredentialMetadata[scope] = &model.CredentialMetadata{Format: format}
		}
		return client
	}

	// No DCQLQuery on the session and no request object in this process, so
	// sessionDCQL answers nil - the condition under test.
	session := func(scopes ...string) *cache.AuthorizationContext {
		return &cache.AuthorizationContext{Scopes: scopes}
	}

	t.Run("an SD-JWT only session is not this path's business", func(t *testing.T) {
		client := withScopes(map[string]string{"pid": "dc+sd-jwt"})
		err := client.refuseAResponseThisPathCannotCheck(
			session("openid", "pid"),
			map[string][]string{},
			map[string][]string{"pid": {"sd-jwt-token"}},
		)
		require.NoError(t, err,
			"nothing W3C was asked for or returned, so a missing query costs this path nothing")
	})

	t.Run("a W3C document present refuses", func(t *testing.T) {
		client := withScopes(map[string]string{"pid": "dc+sd-jwt"})
		err := client.refuseAResponseThisPathCannotCheck(
			session("openid", "pid"),
			map[string][]string{"pid": {"{\"@context\":[]}"}},
			map[string][]string{},
		)
		require.ErrorContains(t, err, "no longer available",
			"a W3C document arrived and nothing can say what was asked for")
	})

	t.Run("a W3C scope configured refuses even with no W3C document", func(t *testing.T) {
		client := withScopes(map[string]string{"diploma": "ldp_vc"})
		err := client.refuseAResponseThisPathCannotCheck(
			session("openid", "diploma"),
			map[string][]string{},
			map[string][]string{"diploma": {"sd-jwt-token"}},
		)
		require.ErrorContains(t, err, "no longer available",
			"the session could have asked for a W3C credential, so this must not be waved through")
	})

	t.Run("no credential metadata at all cannot tell, so refuses", func(t *testing.T) {
		client, _ := CreateTestClientWithMock(t, nil)
		client.cfg.Common = nil
		err := client.refuseAResponseThisPathCannotCheck(
			session("openid", "pid"),
			map[string][]string{},
			map[string][]string{"pid": {"sd-jwt-token"}},
		)
		require.ErrorContains(t, err, "no longer available")
	})
}
