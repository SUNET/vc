package apiv1

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/SUNET/vc/internal/apigw/cache"
	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/crypto"
	"github.com/SUNET/vc/pkg/helpers"
)

// Issuance states a customer service can observe. They only move forward;
// see issuanceStatusRank.
const (
	IssuanceStatusOfferCreated         = "offer_created"
	IssuanceStatusAuthorizationStarted = "authorization_started"
	IssuanceStatusTokenIssued          = "token_issued"
	IssuanceStatusFailed               = "failed"
	IssuanceStatusCredentialIssued     = "credential_issued"
	IssuanceStatusAccepted             = "accepted"
	IssuanceStatusRejected             = "rejected"

	// IssuanceStatusExpired is derived on read and never stored.
	IssuanceStatusExpired = "expired"
)

// maxEventDescriptionLen bounds the wallet-supplied event_description kept on a record.
const maxEventDescriptionLen = 256

// issuanceStatusRank orders the states. A write is accepted only when it
// ranks above the stored state, so a late or repeated event cannot move an
// issuance backwards. failed ranks below credential_issued because a wallet
// may retry the credential request after a failure.
var issuanceStatusRank = map[string]int{
	IssuanceStatusOfferCreated:         1,
	IssuanceStatusAuthorizationStarted: 2,
	IssuanceStatusTokenIssued:          3,
	IssuanceStatusFailed:               4,
	IssuanceStatusCredentialIssued:     5,
	IssuanceStatusAccepted:             6,
	IssuanceStatusRejected:             6,
}

// issuanceInProgress holds the states that can still expire. After the
// credential is issued the outcome is whatever the wallet reports, or
// nothing, so those states never turn into expired.
var issuanceInProgress = map[string]bool{
	IssuanceStatusOfferCreated:         true,
	IssuanceStatusAuthorizationStarted: true,
	IssuanceStatusTokenIssued:          true,
}

// effectiveStatus is the stored status, or expired when an in-progress
// issuance has passed its deadline.
func effectiveStatus(r *cache.IssuanceStatusRecord, now time.Time) string {
	if issuanceInProgress[r.Status] && r.Deadline > 0 && now.Unix() > r.Deadline {
		return IssuanceStatusExpired
	}
	return r.Status
}

// newIssuanceID returns an opaque handle for a customer service to poll with.
func newIssuanceID() (string, error) {
	return crypto.GenerateSecureToken(32, 0)
}

// createIssuanceStatus stores the first record for an issuance.
func (c *Client) createIssuanceStatus(ctx context.Context, issuanceID, scope, authenticSource string, deadline int64) {
	if issuanceID == "" || c.cacheService == nil || c.cacheService.IssuanceStatus == nil {
		return
	}
	now := time.Now().Unix()
	c.cacheService.IssuanceStatus.Set(ctx, issuanceID, &cache.IssuanceStatusRecord{
		IssuanceID:      issuanceID,
		Scope:           scope,
		AuthenticSource: authenticSource,
		Status:          IssuanceStatusOfferCreated,
		CreatedAt:       now,
		UpdatedAt:       now,
		Deadline:        deadline,
	})
}

// recordIssuanceStatus moves an issuance forward. It does nothing for an
// empty id, an unknown id, or a state that does not outrank the stored one.
// A non-zero deadline replaces the stored one.
func (c *Client) recordIssuanceStatus(ctx context.Context, issuanceID, status, description string, deadline int64) {
	if issuanceID == "" || c.cacheService == nil || c.cacheService.IssuanceStatus == nil {
		return
	}
	record, ok := c.cacheService.IssuanceStatus.Get(ctx, issuanceID)
	if !ok || record == nil {
		return
	}
	if issuanceStatusRank[status] <= issuanceStatusRank[record.Status] {
		return
	}

	// A copy: the memory cache hands out the stored pointer.
	updated := *record
	updated.Status = status
	updated.UpdatedAt = time.Now().Unix()
	updated.EventDescription = truncateEventDescription(description)
	if deadline > 0 {
		updated.Deadline = deadline
	}
	c.cacheService.IssuanceStatus.Set(ctx, issuanceID, &updated)
}

func truncateEventDescription(s string) string {
	runes := []rune(s)
	if len(runes) > maxEventDescriptionLen {
		runes = runes[:maxEventDescriptionLen]
	}
	return string(runes)
}

// newNotificationID creates the notification_id for an issued credential and
// binds it to the issuance. It returns "" when the issuance is not tracked,
// so no notification_id is advertised for it.
func (c *Client) newNotificationID(ctx context.Context, issuanceID string) (string, error) {
	if issuanceID == "" || c.cacheService == nil || c.cacheService.NotificationBinding == nil {
		return "", nil
	}
	id, err := crypto.GenerateSecureToken(32, 0)
	if err != nil {
		return "", err
	}
	c.cacheService.NotificationBinding.Set(ctx, id, issuanceID)
	return id, nil
}

// IssuanceStatusRequest identifies one issuance. authentic_source and scope
// are required so that the authorization middleware, which reads exactly
// those two from the query string, scopes a caller to its own issuances.
//
// header:"-" keeps the values from being bound from headers the middleware
// never looks at.
type IssuanceStatusRequest struct {
	IssuanceID      string `json:"issuance_id" form:"issuance_id" header:"-" validate:"required,max=128,printascii"`
	AuthenticSource string `json:"authentic_source" form:"authentic_source" header:"-" validate:"required,max=128,printascii"`
	Scope           string `json:"scope" form:"scope" header:"-" validate:"required,max=128,printascii"`
}

// IssuanceStatusReply is the state of one issuance.
type IssuanceStatusReply struct {
	IssuanceID string `json:"issuance_id"`

	// Status is one of offer_created, authorization_started, token_issued,
	// credential_issued, accepted, rejected, failed or expired.
	Status          string `json:"status"`
	Scope           string `json:"scope"`
	AuthenticSource string `json:"authentic_source"`

	// CreatedAt and UpdatedAt are Unix timestamps.
	CreatedAt        int64  `json:"created_at"`
	UpdatedAt        int64  `json:"updated_at"`
	EventDescription string `json:"event_description,omitempty"`
}

// IssuanceStatus returns the state of an issuance created by
// /api/v1/issuance/prepare or /api/v1/datastore/preauth_offer.
//
//	@Summary		IssuanceStatus
//	@ID				issuance-status
//	@Description	Get the state of a credential issuance by issuance_id
//	@Tags			vc-platform
//	@Produce		json
//	@Success		200					{object}	IssuanceStatusReply		"Success"
//	@Failure		404					{object}	helpers.ErrorResponse	"Unknown, expired or not owned by the given authentic_source and scope"
//	@Param			issuance_id			query		string					true	"issuance_id from the offer reply"
//	@Param			authentic_source	query		string					true	"authentic_source the offer was created for"
//	@Param			scope				query		string					true	"scope the offer was created for"
//	@Router			/api/v1/issuance/status [get]
func (c *Client) IssuanceStatus(ctx context.Context, req *IssuanceStatusRequest) (*IssuanceStatusReply, error) {
	if c.cacheService == nil || c.cacheService.IssuanceStatus == nil {
		return nil, helpers.NewErrorDetailsWithStatus("issuance_status_unavailable",
			"issuance status is not available", http.StatusServiceUnavailable)
	}

	notFound := helpers.NewErrorDetailsWithStatus("issuance_not_found",
		"no such issuance", http.StatusNotFound)

	record, err := c.cacheService.IssuanceStatus.GetErr(ctx, req.IssuanceID)
	switch {
	case errors.Is(err, pkgcache.ErrNoDocuments):
		return nil, notFound
	case err != nil:
		c.log.Error(err, "failed to read issuance status")
		return nil, err
	case record == nil:
		return nil, notFound
	}

	// Same answer as an unknown id, so ids of other tenants cannot be probed.
	if record.AuthenticSource != req.AuthenticSource || record.Scope != req.Scope {
		return nil, notFound
	}

	return &IssuanceStatusReply{
		IssuanceID:       record.IssuanceID,
		Status:           effectiveStatus(record, time.Now()),
		Scope:            record.Scope,
		AuthenticSource:  record.AuthenticSource,
		CreatedAt:        record.CreatedAt,
		UpdatedAt:        record.UpdatedAt,
		EventDescription: record.EventDescription,
	}, nil
}
