package vcclient

import (
	"context"
	"net/http"
	"net/url"

	"github.com/SUNET/vc/pkg/logger"
)

type identityHandler struct {
	client             *Client
	serviceBaseURL     string
	baseURL            string
	log                *logger.Log
	defaultContentType string
}

// IdentityMappingCreateRequest is the request for creating an identity mapping
type IdentityMappingCreateRequest struct {
	AuthenticSource         string            `json:"authentic_source"`
	AuthenticSourcePersonID string            `json:"authentic_source_person_id,omitempty"`
	Attributes              map[string]string `json:"attributes,omitempty"`
}

// IdentityMappingCreateReply is the reply containing the identifier
type IdentityMappingCreateReply struct {
	AuthenticSourcePersonID string `json:"authentic_source_person_id"`
}

// Create creates a new identity mapping and returns the assigned identifier.
func (s *identityHandler) Create(ctx context.Context, req *IdentityMappingCreateRequest) (*IdentityMappingCreateReply, *http.Response, error) {
	s.log.Info("Create")

	fullURL, err := url.JoinPath(s.serviceBaseURL, "mapping")
	if err != nil {
		return nil, nil, err
	}
	reply := &IdentityMappingCreateReply{}
	resp, err := s.client.call(ctx, http.MethodPost, fullURL, s.defaultContentType, req, reply, true, s.baseURL)
	if err != nil {
		return nil, resp, err
	}
	return reply, resp, nil
}

// IdentityMappingResolveRequest is the request for resolving attributes to an identifier
type IdentityMappingResolveRequest struct {
	AuthenticSource string            `json:"authentic_source"`
	Attributes      map[string]string `json:"attributes"`
}

// IdentityMappingResolveReply is the reply with the resolved identifier
type IdentityMappingResolveReply struct {
	AuthenticSourcePersonID string `json:"authentic_source_person_id"`
}

// Resolve resolves attributes to an authentic_source_person_id.
func (s *identityHandler) Resolve(ctx context.Context, req *IdentityMappingResolveRequest) (*IdentityMappingResolveReply, *http.Response, error) {
	s.log.Info("Resolve")

	fullURL, err := url.JoinPath(s.serviceBaseURL, "mapping", "resolve")
	if err != nil {
		return nil, nil, err
	}
	reply := &IdentityMappingResolveReply{}
	resp, err := s.client.call(ctx, http.MethodPost, fullURL, s.defaultContentType, req, reply, true, s.baseURL)
	if err != nil {
		return nil, resp, err
	}
	return reply, resp, nil
}

// IdentityMappingUpdateRequest is the request for updating an identity mapping
type IdentityMappingUpdateRequest struct {
	AuthenticSource         string            `json:"authentic_source"`
	AuthenticSourcePersonID string            `json:"authentic_source_person_id"`
	Attributes              map[string]string `json:"attributes,omitempty"`
}

// Update updates an existing identity mapping's attributes.
func (s *identityHandler) Update(ctx context.Context, req *IdentityMappingUpdateRequest) (*http.Response, error) {
	s.log.Info("Update")

	fullURL, err := url.JoinPath(s.serviceBaseURL, "mapping")
	if err != nil {
		return nil, err
	}
	resp, err := s.client.call(ctx, http.MethodPut, fullURL, s.defaultContentType, req, nil, true, s.baseURL)
	if err != nil {
		return resp, err
	}
	return resp, nil
}

// IdentityMappingDeleteRequest is the request for deleting an identity mapping
type IdentityMappingDeleteRequest struct {
	AuthenticSource         string `json:"authentic_source"`
	AuthenticSourcePersonID string `json:"authentic_source_person_id"`
}

// Delete deletes an identity mapping.
func (s *identityHandler) Delete(ctx context.Context, req *IdentityMappingDeleteRequest) (*http.Response, error) {
	s.log.Info("Delete")

	fullURL, err := url.JoinPath(s.serviceBaseURL, "mapping")
	if err != nil {
		return nil, err
	}
	resp, err := s.client.call(ctx, http.MethodDelete, fullURL, s.defaultContentType, req, nil, true, s.baseURL)
	if err != nil {
		return resp, err
	}
	return resp, nil
}
