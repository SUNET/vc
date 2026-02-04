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

	resp, err := s.client.call(ctx, http.MethodPost, fullURL, s.defaultContentType, body, nil, false)
	if err != nil {
		s.log.Error(err, "Upload call failed")
		return resp, err
	}
	return resp, nil
}
