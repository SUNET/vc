package vcclient

import (
	"context"
	"net/http"
	"net/url"
	"vc/internal/gen/status/apiv1_status"
	"vc/pkg/logger"
)

type mockasRootHandler struct {
	client  *Client
	baseURL string
	log     *logger.Log
}

type mockHandler struct {
	client             *Client
	serviceBaseURL     string
	baseURL            string
	log                *logger.Log
	defaultContentType string
}

// Health checks the health of the MockAS service
func (s *mockasRootHandler) Health(ctx context.Context) (*apiv1_status.StatusReply, *http.Response, error) {
	s.log.Debug("Health (MockAS)")

	fullURL, err := url.JoinPath("/health")
	if err != nil {
		s.log.Error(err, "failed to construct URL")
		return nil, nil, err
	}

	jsonResp := &apiv1_status.StatusReply{}
	resp, err := s.client.call(ctx, "GET", fullURL, "", nil, jsonResp, false, s.baseURL)
	if err != nil {
		return nil, resp, err
	}

	return jsonResp, resp, nil
}

// MockNextRequest is the request for MockNext
type MockNextRequest struct {
	VCT                     string `json:"vct"`
	DocumentID              string `json:"document_id"`
	AuthenticSource         string `json:"authentic_source"`
	AuthenticSourcePersonID string `json:"authentic_source_person_id"`
	GivenName               string `json:"given_name"`
	FamilyName              string `json:"family_name"`
	BirthDate               string `json:"birth_date"`
	CollectID               string `json:"collect_id"`
	IdentitySchemaName      string `json:"identity_schema_name"`
}

// MockNextReply is the reply for MockNext
type MockNextReply struct {
	Upload map[string]any `json:"upload"`
}

// Next sends a mock action request
func (s *mockHandler) Next(ctx context.Context, req *MockNextRequest) (*MockNextReply, *http.Response, error) {
	s.log.Debug("Next (MockAS)")

	fullURL, err := url.JoinPath(s.serviceBaseURL, "next")
	if err != nil {
		s.log.Error(err, "failed to construct URL")
		return nil, nil, err
	}

	jsonResp := &MockNextReply{}
	resp, err := s.client.call(ctx, "POST", fullURL, s.defaultContentType, req, jsonResp, false, s.baseURL)
	if err != nil {
		return nil, resp, err
	}

	return jsonResp, resp, nil
}

// MockBulkRequest is the request for MockBulk
type MockBulkRequest struct {
	MockNextRequest
	N int `form:"n" json:"n"`
}

// MockBulkReply is the reply for MockBulk
type MockBulkReply struct {
	DocumentIDS []string `json:"document_ids"`
}

// Bulk sends N mock uploads to the datastore
func (s *mockHandler) Bulk(ctx context.Context, req *MockBulkRequest) (*MockBulkReply, *http.Response, error) {
	s.log.Debug("Bulk (MockAS)")

	fullURL, err := url.JoinPath(s.serviceBaseURL, "bulk")
	if err != nil {
		s.log.Error(err, "failed to construct URL")
		return nil, nil, err
	}

	jsonResp := &MockBulkReply{}
	resp, err := s.client.call(ctx, "POST", fullURL, s.defaultContentType, req, jsonResp, false, s.baseURL)
	if err != nil {
		return nil, resp, err
	}

	return jsonResp, resp, nil
}
