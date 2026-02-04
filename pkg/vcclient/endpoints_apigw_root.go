package vcclient

import (
	"context"
	"net/http"
	"net/url"
	"vc/pkg/logger"
	"vc/pkg/model"
)

type rootHandler struct {
	client             *Client
	serviceBaseURL     string
	baseURL            string
	log                *logger.Log
	defaultContentType string
}

type UploadRequest struct {
	Meta                *model.MetaData        `json:"meta" validate:"required"`
	Identities          []model.Identity       `json:"identities,omitempty" validate:"dive"`
	DocumentDisplay     *model.DocumentDisplay `json:"document_display,omitempty"`
	DocumentData        map[string]any         `json:"document_data" validate:"required"`
	DocumentDataVersion string                 `json:"document_data_version,omitempty" validate:"required,semver"`
}

func (s *rootHandler) Upload(ctx context.Context, body *UploadRequest) (*http.Response, error) {
	s.log.Info("Upload")

	if body.Meta.VCT == model.CredentialTypeUrnEudiPid1 {
		s.log.Info("Uploading PID document", "body", body)
	}

	fullURL, err := url.JoinPath(s.serviceBaseURL, "upload")
	if err != nil {
		s.log.Error(err, "failed to construct URL")
		return nil, err
	}

	resp, err := s.client.call(ctx, http.MethodPost, fullURL, s.defaultContentType, body, nil, false, s.baseURL)
	if err != nil {
		s.log.Error(err, "Upload call failed")
		return resp, err
	}
	return resp, nil
}

// NotificationRequest is the request for Notification
type NotificationRequest struct {
	AuthenticSource string `json:"authentic_source" validate:"required"`
	VCT             string `json:"vct" validate:"required"`
	DocumentID      string `json:"document_id" validate:"required"`
}

// NotificationReply is the reply for Notification
type NotificationReply struct {
	Data any `json:"data"`
}

// Notification gets QR code and DeepLink for a document
func (s *rootHandler) Notification(ctx context.Context, body *NotificationRequest) (*NotificationReply, *http.Response, error) {
	s.log.Info("Notification")

	fullURL, err := url.JoinPath(s.serviceBaseURL, "notification")
	if err != nil {
		s.log.Error(err, "failed to construct URL")
		return nil, nil, err
	}

	reply := &NotificationReply{}
	resp, err := s.client.call(ctx, http.MethodPost, fullURL, s.defaultContentType, body, reply, false, s.baseURL)
	if err != nil {
		s.log.Error(err, "Notification call failed")
		return nil, resp, err
	}
	return reply, resp, nil
}

// Health checks the health of the APIGW service
func (s *rootHandler) Health(ctx context.Context) (map[string]any, *http.Response, error) {
	s.log.Debug("Health")

	fullURL, err := url.Parse("/health")
	if err != nil {
		s.log.Error(err, "failed to construct URL")
		return nil, nil, err
	}

	reply := make(map[string]any)
	resp, err := s.client.call(ctx, http.MethodGet, fullURL.String(), s.defaultContentType, nil, &reply, false, s.baseURL)
	if err != nil {
		s.log.Error(err, "Health call failed")
		return nil, resp, err
	}
	return reply, resp, nil
}
