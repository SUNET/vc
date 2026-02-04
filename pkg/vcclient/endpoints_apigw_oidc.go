package vcclient

import (
	"context"
	"fmt"
	"net/http"
	"vc/pkg/logger"
	"vc/pkg/openid4vci"
)

type oidcHandler struct {
	client             *Client
	baseURL            string
	log                *logger.Log
	defaultContentType string
}

func (s *oidcHandler) Authorize(ctx context.Context, body *openid4vci.PARRequest) (*openid4vci.AuthorizationResponse, *http.Response, error) {
	s.log.Info("Authorize")

	reply := &openid4vci.AuthorizationResponse{}
	resp, err := s.client.call(ctx, http.MethodGet, "/authorize", s.defaultContentType, body, reply, false, s.baseURL)
	if err != nil {
		return nil, resp, err
	}
	fmt.Println("authorize response", "reply", reply)
	return reply, resp, nil
}

func (s *oidcHandler) Par(ctx context.Context, body *openid4vci.PARRequest) (*openid4vci.AuthorizationResponse, *http.Response, error) {
	s.log.Info("par")

	reply := &openid4vci.AuthorizationResponse{}
	httpResp, err := s.client.call(ctx, http.MethodPost, "/op/par", "application/x-www-form-urlencoded", body, reply, false, s.baseURL)
	if err != nil {
		return nil, httpResp, err
	}
	fmt.Println("par response", "reply", reply)
	return reply, httpResp, nil
}

func (s *oidcHandler) IssuerMetadata(ctx context.Context) (*openid4vci.CredentialIssuerMetadataParameters, *http.Response, error) {
	s.log.Info("IssuerMetadata")

	reply := &openid4vci.CredentialIssuerMetadataParameters{}
	resp, err := s.client.call(ctx, http.MethodGet, "/.well-known/openid-credential-issuer", s.defaultContentType, nil, reply, false, s.baseURL)
	if err != nil {
		return nil, resp, err
	}
	fmt.Println("issuer metadata response", "reply", reply)
	return reply, resp, nil
}
