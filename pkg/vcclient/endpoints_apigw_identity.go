package vcclient

import (
	"context"
	"net/http"
	"net/url"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
)

type identityHandler struct {
	client             *Client
	serviceBaseURL     string
	baseURL            string
	log                *logger.Log
	defaultContentType string
}

// IdentityMappingQuery is the query for IdentityMapping
type IdentityMappingQuery struct {
	AuthenticSource string          `json:"authentic_source"`
	Identity        *model.Identity `json:"identity"`
}

// Mapping maps an identity, return authentic_source_person_id
func (s *identityHandler) Mapping(ctx context.Context, query *IdentityMappingQuery) (string, *http.Response, error) {
	s.log.Info("Mapping")

	fullURL, err := url.JoinPath(s.serviceBaseURL, "mapping")
	if err != nil {
		s.log.Error(err, "failed to construct URL")
		return "", nil, err
	}
	reply := ""
	resp, err := s.client.call(ctx, http.MethodPost, fullURL, s.defaultContentType, nil, reply, true, s.baseURL)
	if err != nil {
		return "", resp, err
	}
	return reply, resp, nil
}
