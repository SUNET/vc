package vcclient

import (
	"context"
	"net/http"
	"net/url"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/sdjwtvc"
)

type userHandler struct {
	client             *Client
	serviceBaseURL     string
	baseURL            string
	log                *logger.Log
	defaultContentType string
}

type AddPIDRequest struct {
	Username string          `json:"username" validate:"required,max=128,printascii"`
	Password string          `json:"password" validate:"required,max=128,printascii"`
	Identity *model.Identity `json:"identity,omitempty" validate:"required"`
	Meta     *model.MetaData `json:"meta,omitempty" validate:"required"`
}

func (s *userHandler) AddPID(ctx context.Context, body *AddPIDRequest) (*http.Response, error) {
	fullURL, err := url.JoinPath(s.serviceBaseURL, "/pid")
	if err != nil {
		s.log.Error(err, "failed to construct URL")
		return nil, err
	}
	resp, err := s.client.call(ctx, http.MethodPost, fullURL, s.defaultContentType, body, nil, false, s.baseURL)
	if err != nil {
		s.log.Error(err, "AddPID call failed")
		return resp, err
	}

	return resp, nil
}

type LoginPIDUserRequest struct {
	Username string `json:"username" form:"username" validate:"required,max=128,printascii"`
	Password string `json:"password" form:"password" validate:"required,max=128,printascii"`

	// RequestURI comes from session cookie
	RequestURI string `json:"-" validate:"omitempty,max=128,printascii"`
}

func (s *userHandler) LoginPIDUser(ctx context.Context, body *LoginPIDUserRequest) (*http.Response, error) {
	fullURL, err := url.JoinPath(s.serviceBaseURL, "/pid/login")
	if err != nil {
		s.log.Error(err, "failed to construct URL")
		return nil, err
	}
	resp, err := s.client.call(ctx, http.MethodPost, fullURL, s.defaultContentType, body, nil, false, s.baseURL)
	if err != nil {
		s.log.Error(err, "LoginPIDUser call failed")
		return resp, err
	}

	return resp, nil
}

type GetPIDRequest struct {
	Username string `json:"username" form:"username" validate:"required,max=128,printascii"`
}

type GetPIDReply struct {
	Identity *model.Identity `json:"identity,omitempty"`
}

type UserLookupRequest struct {
	Username     string        `json:"-"`
	AuthMethod   string        `json:"-"`
	ResponseCode string        `json:"-"`
	RequestURI   string        `json:"-" validate:"omitempty,max=128,printascii"`
	VCTM         *sdjwtvc.VCTM `json:"-"`
}

type SVGClaim struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// SVGTemplateReply holds SVG template data.
type SVGTemplateReply struct {
	Template string `json:"template"`
}

type UserLookupReply struct {
	SVGTemplateClaims map[string]SVGClaim `json:"svg_template_claims,omitempty"`
	RedirectURL       string              `json:"redirect_url,omitempty"`
}

type UserAuthenticSourceLookupRequest struct {
	AuthenticSource string `json:"authentic_source,omitempty" validate:"omitempty,max=128,printascii"`
	SessionID       string `json:"-"`
}

type UserAuthenticSourceLookupReply struct {
	AuthenticSources []string `json:"authentic_sources,omitempty" validate:"omitempty,dive,max=128,printascii"`
}
