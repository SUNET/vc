package apiv1

import (
	"context"
	"errors"
	"time"
	apiv1_apigw "vc/internal/apigw/apiv1"
	"vc/internal/gen/status/apiv1_status"
	"vc/pkg/model"
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

type DocumentListRequest struct {
	AuthenticSource string          `json:"authentic_source"`
	Identity        *model.Identity `json:"identity" validate:"required"`
	DocumentType    string          `json:"document_type"`
	ValidFrom       int64           `json:"valid_from"`
	ValidTo         int64           `json:"valid_to"`
}

func (c *Client) DocumentList(ctx context.Context, req *DocumentListRequest) (any, error) {
	reply, err := c.apigwClient.DocumentList(req)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (c *Client) Upload(ctx context.Context, req *apiv1_apigw.UploadRequest) (any, error) {
	reply, err := c.apigwClient.Upload(req)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

// CredentialRequest is the request for the Credential endpoint
type CredentialRequest struct {
	AuthenticSource string          `json:"authentic_source" validate:"required"`
	Identity        *model.Identity `json:"identity" validate:"required"`
	DocumentType    string          `json:"document_type" validate:"required"`
	CredentialType  string          `json:"credential_type" validate:"required"`
	CollectID       string          `json:"collect_id" validate:"required"`
	JWK             map[string]any  `json:"jwk"`
}

// Credential sends POST to apigw /api/v1/credential
func (c *Client) Credential(ctx context.Context, req *CredentialRequest) (any, error) {
	req.JWK = map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"kid": "ejV4WXZMQnE4Sy1meGJRUGFvZ2NiZHltUGQ5SmdNNy1KS1hjYTNOZGdTMA",
		"x":   "cyViIENmqo4D2CVOc2uGZbe5a8NheCyvN9CsF7ui3tk",
		"y":   "XA0lVXgjgZzFTDwkndZEo-zVr9ieO2rY9HGiiaaASog",
	}
	reply, err := c.apigwClient.Credential(req)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

// GetDocumentRequest is the request for the GetDocument endpoint
type GetDocumentRequest struct {
	AuthenticSource string `json:"authentic_source" validate:"required"`
	DocumentType    string `json:"document_type" validate:"required"`
	DocumentID      string `json:"document_id" validate:"required"`
}

func (c *Client) GetDocument(ctx context.Context, req *GetDocumentRequest) (any, error) {
	reply, err := c.apigwClient.GetDocument(req)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

type NotificationRequest struct {
	AuthenticSource string `json:"authentic_source" validate:"required"`
	DocumentType    string `json:"document_type" validate:"required"`
	DocumentID      string `json:"document_id" validate:"required"`
}

func (c *Client) Notification(ctx context.Context, request *NotificationRequest) (any, error) {
	reply, err := c.apigwClient.Notification(request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

type MockNextRequest struct {
	DocumentType            string `json:"document_type" validate:"required"`
	AuthenticSource         string `json:"authentic_source" validate:"required"`
	AuthenticSourcePersonId string `json:"authentic_source_person_id" validate:"required"`
	IdentitySchemaName      string `json:"identity_schema_name" validate:"required"`
}

func (c *Client) MockNext(ctx context.Context, req *MockNextRequest) (any, error) {
	if c.cfg.Common.Kafka.Enabled {
		if err := c.eventPublisher.MockNext(req); err != nil {
			return nil, err
		}
		return nil, nil
	}

	reply, err := c.mockasClient.MockNext(req)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (c *Client) StatusAPIGW(ctx context.Context, req *apiv1_status.StatusRequest) (any, error) {
	reply, err := c.apigwClient.Status()
	if err != nil {
		return nil, err
	}
	return reply, nil
}
