package apiv1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-gonic/gin"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolveDirectPostEncrypted covers the reported direct_post.jwt failure.
//
// With response_mode=direct_post.jwt a wallet posts only `response`, a JWE
// holding state and vp_token (OpenID4VP 1.0 8.3.1). The OIDC endpoint required
// `state` as a form field and looked the session up by it before decrypting, so
// a conformant wallet was rejected at binding with
//
//	Key: 'DirectPostRequest.state' Error:Field validation for 'state' failed on the 'required' tag
//
// and behind that the encrypted branch was a TODO stub.
func TestResolveDirectPostEncrypted(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)

	const (
		// In this flow state IS the session id, and the ephemeral key is
		// cached under the same value - so the kid the wallet echoes back
		// equals the state inside the JWE.
		kid   = "test-session-123"
		state = kid
		token = "eyJhbGciOiJFUzI1NiJ9.e30.sig~"
	)

	_, ephemeralPubJWK, err := client.ephemeralEncryptionKey(t.Context(), kid)
	require.NoError(t, err)

	encrypt := func(t *testing.T, payload any) string {
		t.Helper()
		raw, err := json.Marshal(payload)
		require.NoError(t, err)
		out, err := jwe.Encrypt(raw,
			jwe.WithKey(jwa.ECDH_ES(), ephemeralPubJWK),
			jwe.WithContentEncryption(jwa.A256GCM()),
		)
		require.NoError(t, err)
		return string(out)
	}

	t.Run("state and vp_token come out of the JWE", func(t *testing.T) {
		// No form-level state at all, which is what a conformant wallet sends.
		req := &DirectPostRequest{Response: encrypt(t, openid4vp.VPResponse{
			State:   state,
			VPToken: map[string][]string{"pid": {token}},
		})}

		gotState, gotToken, err := client.resolveDirectPost(t.Context(), req)
		require.NoError(t, err)
		assert.Equal(t, state, gotState, "the session is looked up by the decrypted state")
		assert.Equal(t, token, gotToken)
	})

	t.Run("plain direct_post still uses the form fields", func(t *testing.T) {
		gotState, gotToken, err := client.resolveDirectPost(t.Context(), &DirectPostRequest{
			State: state, VPToken: token,
		})
		require.NoError(t, err)
		assert.Equal(t, state, gotState)
		assert.Empty(t, gotToken, "the unencrypted path carries its token separately")
	})

	t.Run("neither state nor response is refused", func(t *testing.T) {
		_, _, err := client.resolveDirectPost(t.Context(), &DirectPostRequest{})
		require.Error(t, err)
	})

	t.Run("a response encrypted to an unknown key is refused", func(t *testing.T) {
		_, _, err := client.resolveDirectPost(t.Context(), &DirectPostRequest{
			Response: "eyJhbGciOiJFQ0RILUVTIiwia2lkIjoibm8tc3VjaC1raWQifQ..aaaa.bbbb.cccc",
		})
		require.Error(t, err)
	})

	t.Run("a response encrypted to one session cannot claim another", func(t *testing.T) {
		// The ephemeral public key is published in the request object, so
		// anyone can encrypt to it. Decryption alone must not be taken as
		// proof of which session the payload belongs to.
		_, _, err := client.resolveDirectPost(t.Context(), &DirectPostRequest{Response: encrypt(t, openid4vp.VPResponse{
			State:   "some-other-session",
			VPToken: map[string][]string{"pid": {token}},
		})})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "different session")
	})

	t.Run("several credentials are refused rather than guessed at", func(t *testing.T) {
		// This flow maps one credential onto the OIDC claims it issues.
		_, _, err := client.resolveDirectPost(t.Context(), &DirectPostRequest{Response: encrypt(t, openid4vp.VPResponse{
			State:   state,
			VPToken: map[string][]string{"pid": {token}, "ehic": {token}},
		})})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exactly one")
	})
}

// TestDirectPostRequestBindsWithoutState covers the half of the reported bug
// that resolveDirectPost cannot: the failure Lam saw happened at BINDING, before
// any handler code ran, because State carried binding:"required".
//
// Constructing a DirectPostRequest in Go skips that entirely, so this drives the
// real form-encoded bind and would fail if the tag came back.
func TestDirectPostRequestBindsWithoutState(t *testing.T) {
	ctx := t.Context()
	log := logger.NewSimple("directpost-binding")
	tracer, err := trace.NewForTesting(ctx, "directpost-binding", log)
	require.NoError(t, err)
	helpers, err := httphelpers.New(ctx, tracer, &model.Cfg{}, log)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)

	bind := func(t *testing.T, form url.Values) (*DirectPostRequest, error) {
		t.Helper()
		body := form.Encode()
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		httpReq := httptest.NewRequest(http.MethodPost, "/verification/oidc-direct_post", strings.NewReader(body))
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		c.Request = httpReq

		req := &DirectPostRequest{}
		return req, helpers.Binding.Request(ctx, c, req)
	}

	t.Run("response alone binds", func(t *testing.T) {
		// Exactly what a direct_post.jwt wallet posts: no state field at all.
		req, err := bind(t, url.Values{"response": {"eyJhbGciOiJFQ0RILUVTIn0..a.b.c"}})
		require.NoError(t, err, "state lives inside the JWE; requiring it here rejected a conformant wallet")
		assert.Empty(t, req.State)
		assert.NotEmpty(t, req.Response)
	})

	t.Run("plain direct_post still binds", func(t *testing.T) {
		req, err := bind(t, url.Values{"state": {"s-1"}, "vp_token": {"tok~"}})
		require.NoError(t, err)
		assert.Equal(t, "s-1", req.State)
		assert.Equal(t, "tok~", req.VPToken)
	})
}
