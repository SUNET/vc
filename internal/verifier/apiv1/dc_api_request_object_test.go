package apiv1

import (
	"context"
	"net/url"
	"testing"

	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dcAPIRequestObjectFrom resolves the request object a dc_api authorization
// request points at, the way a wallet would: read request_uri out of the
// URI, take its id, and fetch what was persisted under it.
func dcAPIRequestObjectFrom(t *testing.T, ctx context.Context, client *Client, authorizationRequest string) *openid4vp.RequestObject {
	t.Helper()

	parsed, err := url.Parse(authorizationRequest)
	require.NoError(t, err)
	requestURI := parsed.Query().Get("request_uri")
	require.NotEmpty(t, requestURI, "a dc_api authorization request must carry a request_uri")

	parsedRequestURI, err := url.Parse(requestURI)
	require.NoError(t, err)
	id := parsedRequestURI.Query().Get("id")
	require.NotEmpty(t, id)

	requestObject, found := client.cacheService.RequestObject.Get(ctx, id)
	require.True(t, found, "the dc_api request object must have been persisted under the id its request_uri names")
	return requestObject
}

// A SIGNED dc_api request MUST name the origin it may be invoked from
// (OpenID4VP 1.0 Appendix A.3), and MUST NOT carry a response_uri, because
// a dc_api response comes back inside the browser call (Appendix A.2).
//
// Asserted on what the three UI entry points actually persist rather than
// on the request-object builder, because the builder taking an origin is
// not the thing that can regress: a caller passing "" is, and that reads as
// perfectly ordinary code.
func TestUIEntryPointsBuildDCAPIRequestsWithTheirOrigin(t *testing.T) {
	const publicURL = "https://verifier.example.com/some/path"

	newClient := func(t *testing.T) *Client {
		t.Helper()
		client := newSigningTestClient(t)
		client.cfg.Verifier.DigitalCredentials.Enable = true
		client.cfg.Verifier.PublicURL = publicURL
		return client
	}

	assertDCAPIShape := func(t *testing.T, requestObject *openid4vp.RequestObject) {
		t.Helper()
		assert.Equal(t, []string{"https://verifier.example.com"}, requestObject.ExpectedOrigins,
			"a signed dc_api request must name the origin it may be invoked from")
		assert.Empty(t, requestObject.ResponseURI,
			"a dc_api response returns inside the browser call, so the request carries no response_uri")
		assert.Equal(t, openid4vp.ResponseModeDCAPIJWT, requestObject.ResponseMode)
	}

	t.Run("first interaction", func(t *testing.T) {
		ctx := t.Context()
		client := newClient(t)

		reply, err := client.UIInteraction(ctx, &UIInteractionRequest{DCQLQuery: createTestDCQLForVP(t)})
		require.NoError(t, err)
		require.NotEmpty(t, reply.DCAPIAuthorizationRequest)

		assertDCAPIShape(t, dcAPIRequestObjectFrom(t, ctx, client, reply.DCAPIAuthorizationRequest))
	})

	t.Run("reload reusing an in-flight session", func(t *testing.T) {
		ctx := t.Context()
		client := newClient(t)

		first, err := client.UIInteraction(ctx, &UIInteractionRequest{DCQLQuery: createTestDCQLForVP(t)})
		require.NoError(t, err)

		second, err := client.UIInteraction(ctx, &UIInteractionRequest{
			DCQLQuery: createTestDCQLForVP(t),
			SessionID: first.SessionID,
		})
		require.NoError(t, err)
		require.Equal(t, first.SessionID, second.SessionID, "this subtest only means anything if the session was reused")
		require.NotEmpty(t, second.DCAPIAuthorizationRequest)

		assertDCAPIShape(t, dcAPIRequestObjectFrom(t, ctx, client, second.DCAPIAuthorizationRequest))
	})

	t.Run("resume", func(t *testing.T) {
		ctx := t.Context()
		client := newClient(t)

		first, err := client.UIInteraction(ctx, &UIInteractionRequest{DCQLQuery: createTestDCQLForVP(t)})
		require.NoError(t, err)

		resumed, err := client.UIResume(ctx, first.SessionID)
		require.NoError(t, err)
		require.NotEmpty(t, resumed.DCAPIAuthorizationRequest)

		assertDCAPIShape(t, dcAPIRequestObjectFrom(t, ctx, client, resumed.DCAPIAuthorizationRequest))
	})
}
