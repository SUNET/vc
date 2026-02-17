package apiv1

import (
	"context"
	"errors"
	"time"
	"vc/internal/gen/status/apiv1_status"
	"vc/pkg/model"
	"vc/pkg/vcclient"
)

func (c *Client) Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	probes := model.Probes{}
	status := probes.Check("ui")
	return status, nil
}

type LoginRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type LoggedinReply struct {
	Username string `json:"username" validate:"required"`
	// LoggedInTime RFC3339
	LoggedInTime time.Time `json:"logged_in_time" validate:"required"`
}

func (c *Client) Login(ctx context.Context, req *LoginRequest) (*LoggedinReply, error) {
	if req.Username != c.cfg.UI.Username || req.Password != c.cfg.UI.Password {
		return nil, errors.New("invalid username and/or password")
	}

	reply := &LoggedinReply{
		Username:     c.cfg.UI.Username,
		LoggedInTime: time.Now(),
	}

	return reply, nil
}

func (c *Client) Logout(ctx context.Context) error {
	return nil
}

func (c *Client) User(ctx context.Context) (*LoggedinReply, error) {
	return nil, nil
}

func (c *Client) DocumentList(ctx context.Context, req *vcclient.DocumentListQuery) ([]model.DocumentList, error) {
	documents, _, err := c.vcClient.APIGW.Document.List(ctx, req)
	if err != nil {
		return nil, err
	}
	return documents, nil
}

func (c *Client) Upload(ctx context.Context, req *vcclient.UploadRequest) error {
	_, err := c.vcClient.APIGW.Root.Upload(ctx, req)
	if err != nil {
		return err
	}
	return nil
}

// CredentialRequest is the request for the Credential endpoint
type CredentialRequest struct {
	AuthenticSource string          `json:"authentic_source" validate:"required"`
	Identity        *model.Identity `json:"identity" validate:"required"`
	VCT             string          `json:"vct" validate:"required"`
	CredentialType  string          `json:"credential_type" validate:"required"`
	CollectID       string          `json:"collect_id" validate:"required"`
	JWK             map[string]any  `json:"jwk"`
}

func (c *Client) GetDocument(ctx context.Context, req *vcclient.DocumentGetQuery) (*model.Document, error) {
	document, _, err := c.vcClient.APIGW.Document.Get(ctx, req)
	if err != nil {
		return nil, err
	}
	return document, nil
}

func (c *Client) Notification(ctx context.Context, req *vcclient.NotificationRequest) (*vcclient.NotificationReply, error) {
	reply, _, err := c.vcClient.APIGW.Root.Notification(ctx, req)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (c *Client) MockNext(ctx context.Context, req *vcclient.MockNextRequest) (*vcclient.MockNextReply, error) {
	if c.cfg.Common.Kafka.Enable {
		if err := c.eventPublisher.MockNext(req); err != nil {
			return nil, err
		}
		return nil, nil
	}

	reply, _, err := c.vcClient.MockAS.Mock.Next(ctx, req)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (c *Client) HealthAPIGW(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	reply, _, err := c.vcClient.APIGW.Root.Health(ctx)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (c *Client) HealthVerifier(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	reply, _, err := c.vcClient.Verifier.Health(ctx)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (c *Client) HealthMockAS(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	reply, _, err := c.vcClient.MockAS.Root.Health(ctx)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

type VPFlowDebugInfoRequest struct {
	SessionID string `json:"session_id" binding:"required,uuid"`
}

func (c *Client) SearchDocuments(ctx context.Context, req *model.SearchDocumentsRequest) (*model.SearchDocumentsReply, error) {
	reply, _, err := c.vcClient.APIGW.Document.Search(ctx, req)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (c *Client) DeleteDocument(ctx context.Context, req *vcclient.DocumentDeleteQuery) error {
	_, err := c.vcClient.APIGW.Document.Delete(ctx, req)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) AddPIDUser(ctx context.Context, req *vcclient.AddPIDRequest) error {
	_, err := c.vcClient.APIGW.User.AddPID(ctx, req)
	if err != nil {
		return err
	}

	return nil
}
