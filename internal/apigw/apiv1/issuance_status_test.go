package apiv1

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/SUNET/vc/internal/apigw/cache"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newStatusTestClient(t *testing.T) *Client {
	t.Helper()
	log, err := logger.New("test", "", false)
	require.NoError(t, err)
	return &Client{
		log: log,
		cacheService: &cache.Service{
			IssuanceStatus:      cache.NewTestMemoryCache[*cache.IssuanceStatusRecord](time.Hour),
			NotificationBinding: cache.NewTestMemoryCache[string](time.Hour),
		},
	}
}

func statusReq(id string) *IssuanceStatusRequest {
	return &IssuanceStatusRequest{IssuanceID: id, AuthenticSource: "SUNET", Scope: "pid"}
}

func TestIssuanceStatus_MovesForwardOnly(t *testing.T) {
	c := newStatusTestClient(t)
	ctx := t.Context()
	deadline := time.Now().Add(time.Hour).Unix()
	c.createIssuanceStatus(ctx, "id-1", "pid", "SUNET", deadline)

	for _, step := range []string{
		IssuanceStatusAuthorizationStarted,
		IssuanceStatusTokenIssued,
		IssuanceStatusCredentialIssued,
		IssuanceStatusAccepted,
	} {
		c.recordIssuanceStatus(ctx, "id-1", step, "", 0)
		reply, err := c.IssuanceStatus(ctx, statusReq("id-1"))
		require.NoError(t, err)
		assert.Equal(t, step, reply.Status)
	}

	// Neither a late earlier event nor a conflicting outcome changes a final state.
	c.recordIssuanceStatus(ctx, "id-1", IssuanceStatusTokenIssued, "", 0)
	c.recordIssuanceStatus(ctx, "id-1", IssuanceStatusRejected, "", 0)
	reply, err := c.IssuanceStatus(ctx, statusReq("id-1"))
	require.NoError(t, err)
	assert.Equal(t, IssuanceStatusAccepted, reply.Status)
}

func TestIssuanceStatus_FailedThenIssuedOnRetry(t *testing.T) {
	c := newStatusTestClient(t)
	ctx := t.Context()
	c.createIssuanceStatus(ctx, "id-1", "pid", "SUNET", 0)

	c.recordIssuanceStatus(ctx, "id-1", IssuanceStatusFailed, "boom", 0)
	reply, err := c.IssuanceStatus(ctx, statusReq("id-1"))
	require.NoError(t, err)
	assert.Equal(t, IssuanceStatusFailed, reply.Status)
	assert.Equal(t, "boom", reply.EventDescription)

	c.recordIssuanceStatus(ctx, "id-1", IssuanceStatusCredentialIssued, "", 0)
	reply, err = c.IssuanceStatus(ctx, statusReq("id-1"))
	require.NoError(t, err)
	assert.Equal(t, IssuanceStatusCredentialIssued, reply.Status)
}

func TestIssuanceStatus_ExpiredIsDerivedForInProgressOnly(t *testing.T) {
	c := newStatusTestClient(t)
	ctx := t.Context()
	past := time.Now().Add(-time.Minute).Unix()

	c.createIssuanceStatus(ctx, "open", "pid", "SUNET", past)
	reply, err := c.IssuanceStatus(ctx, statusReq("open"))
	require.NoError(t, err)
	assert.Equal(t, IssuanceStatusExpired, reply.Status)

	c.createIssuanceStatus(ctx, "done", "pid", "SUNET", past)
	c.recordIssuanceStatus(ctx, "done", IssuanceStatusCredentialIssued, "", 0)
	reply, err = c.IssuanceStatus(ctx, statusReq("done"))
	require.NoError(t, err)
	assert.Equal(t, IssuanceStatusCredentialIssued, reply.Status)
}

func TestIssuanceStatus_NotFoundIsTheSameForUnknownAndForeign(t *testing.T) {
	c := newStatusTestClient(t)
	ctx := t.Context()
	c.createIssuanceStatus(ctx, "id-1", "pid", "SUNET", 0)

	cases := map[string]*IssuanceStatusRequest{
		"unknown id":       statusReq("nope"),
		"other source":     {IssuanceID: "id-1", AuthenticSource: "OTHER", Scope: "pid"},
		"other scope":      {IssuanceID: "id-1", AuthenticSource: "SUNET", Scope: "ehic"},
		"empty store miss": statusReq(strings.Repeat("a", 64)),
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			reply, err := c.IssuanceStatus(ctx, req)
			assert.Nil(t, reply)
			var herr *helpers.Error
			require.True(t, errors.As(err, &herr))
			assert.Equal(t, "issuance_not_found", herr.Title)
			assert.Equal(t, http.StatusNotFound, herr.HTTPStatus)
		})
	}
}

func TestIssuanceStatus_UntrackedIssuanceIsIgnored(t *testing.T) {
	c := newStatusTestClient(t)
	ctx := t.Context()

	c.recordIssuanceStatus(ctx, "", IssuanceStatusTokenIssued, "", 0)
	c.recordIssuanceStatus(ctx, "never-created", IssuanceStatusTokenIssued, "", 0)
	assert.Zero(t, c.cacheService.IssuanceStatus.Len())

	id, err := c.newNotificationID(ctx, "")
	require.NoError(t, err)
	assert.Empty(t, id)
}

func TestIssuanceStatus_EventDescriptionIsBounded(t *testing.T) {
	c := newStatusTestClient(t)
	ctx := t.Context()
	c.createIssuanceStatus(ctx, "id-1", "pid", "SUNET", 0)

	c.recordIssuanceStatus(ctx, "id-1", IssuanceStatusRejected, strings.Repeat("x", 1000), 0)
	reply, err := c.IssuanceStatus(ctx, statusReq("id-1"))
	require.NoError(t, err)
	assert.Len(t, reply.EventDescription, maxEventDescriptionLen)
}

func TestVCINotification_UpdatesIssuanceStatus(t *testing.T) {
	events := map[string]string{
		"credential_accepted": IssuanceStatusAccepted,
		"credential_failure":  IssuanceStatusRejected,
		"credential_deleted":  IssuanceStatusRejected,
	}
	for event, want := range events {
		t.Run(event, func(t *testing.T) {
			c := newStatusTestClient(t)
			ctx := t.Context()
			c.createIssuanceStatus(ctx, "id-1", "pid", "SUNET", 0)
			c.recordIssuanceStatus(ctx, "id-1", IssuanceStatusCredentialIssued, "", 0)
			notificationID, err := c.newNotificationID(ctx, "id-1")
			require.NoError(t, err)
			require.NotEmpty(t, notificationID)

			err = c.VCINotification(ctx, &openid4vci.NotificationRequest{
				NotificationID:   notificationID,
				Event:            event,
				EventDescription: "from wallet",
			})
			require.NoError(t, err)

			reply, err := c.IssuanceStatus(ctx, statusReq("id-1"))
			require.NoError(t, err)
			assert.Equal(t, want, reply.Status)
			assert.Equal(t, "from wallet", reply.EventDescription)
		})
	}
}

func TestVCINotification_UnknownIDIsRefused(t *testing.T) {
	c := newStatusTestClient(t)

	err := c.VCINotification(t.Context(), &openid4vci.NotificationRequest{
		NotificationID: "unknown",
		Event:          "credential_accepted",
	})

	var verr *openid4vci.Error
	require.True(t, errors.As(err, &verr))
	assert.Equal(t, openid4vci.InvalidNotificationID, verr.Err)
}
