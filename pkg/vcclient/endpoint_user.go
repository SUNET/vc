package vcclient

import (
	"context"
	"net/http"
	"net/url"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/sdjwtvc"
)

type userHandler struct {
	client             *Client
	serviceBaseURL     string
	log                *logger.Log
	defaultContentType string
}

type AddPIDRequest struct {
	Username string          `json:"username" validate:"required"`
	Password string          `json:"password" validate:"required"`
	Identity *model.Identity `json:"identity,omitempty" validate:"required"`
	Meta     *model.MetaData `json:"meta,omitempty" validate:"required"`
}

func (s *userHandler) AddPID(ctx context.Context, body *AddPIDRequest) (*http.Response, error) {
	fullURL, err := url.JoinPath(s.serviceBaseURL, "/pid")
	if err != nil {
		s.log.Error(err, "failed to construct URL")
		return nil, err
	}
	resp, err := s.client.call(ctx, http.MethodPost, fullURL, s.defaultContentType, body, nil, false)
	if err != nil {
		s.log.Error(err, "AddPID call failed")
		return resp, err
	}

	return resp, nil
}

type LoginPIDUserRequest struct {
	Username string `json:"username" form:"username" validate:"required"`
	Password string `json:"password" form:"password" validate:"required"`

	// RequestURI comes from session cookie
	RequestURI string `json:"-"`
}

func (s *userHandler) LoginPIDUser(ctx context.Context, body *LoginPIDUserRequest) (*http.Response, error) {
	fullURL, err := url.JoinPath(s.serviceBaseURL, "/pid/login")
	if err != nil {
		s.log.Error(err, "failed to construct URL")
		return nil, err
	}
	resp, err := s.client.call(ctx, http.MethodPost, fullURL, s.defaultContentType, body, nil, false)
	if err != nil {
		s.log.Error(err, "LoginPIDUser call failed")
		return resp, err
	}

	return resp, nil
}

type GetPIDRequest struct {
	Username string `json:"username" form:"username" validate:"required"`
}

type GetPIDReply struct {
	Identity *model.Identity `json:"identity,omitempty"`
}

type UserLookupRequest struct {
	Username     string        `json:"-"`
	AuthMethod   string        `json:"-"`
	ResponseCode string        `json:"-"`
	RequestURI   string        `json:"-"`
	VCTM         *sdjwtvc.VCTM `json:"-"`
}

type SVGClaim struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type UserLookupReply struct {
	SVGTemplateClaims map[string]SVGClaim `json:"svg_template_claims,omitempty"`
	RedirectURL       string              `json:"redirect_url,omitempty"`
}

type UserAuthenticSourceLookupRequest struct {
	AuthenticSource string `json:"authentic_source,omitempty"`
	SessionID       string `json:"-"`
}

type UserAuthenticSourceLookupReply struct {
	AuthenticSources []string `json:"authentic_sources,omitempty"`
}
