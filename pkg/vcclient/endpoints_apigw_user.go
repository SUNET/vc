package vcclient

import (
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/sdjwtvc"
)

type userHandler struct {
	client             *Client
	serviceBaseURL     string
	baseURL            string
	log                *logger.Log
	defaultContentType string
}

type UserLookupRequest struct {
	AuthProvider string        `json:"-"`
	ResponseCode string        `json:"-"`
	RequestURI   string        `json:"-" validate:"omitempty,max=128,printascii"`
	VCTM         *sdjwtvc.VCTM `json:"-"`
}

type SVGClaim struct {
	Label string `json:"label"`
	// Value is the displayable claim value. Typically a string, but may be a
	// nested map/array when the claim itself is structured (e.g. an address).
	// The consent UI renders structured values as a tree.
	Value any `json:"value"`
}

// SVGTemplateReply holds SVG template data.
type SVGTemplateReply struct {
	Template string `json:"template"`
}

type UserLookupReply struct {
	SVGTemplateClaims map[string]SVGClaim `json:"svg_template_claims"`
	RedirectURL       string              `json:"redirect_url,omitempty"`
}

type UserAuthenticSourceLookupRequest struct {
	AuthenticSource string `json:"authentic_source,omitempty" validate:"omitempty,max=128,printascii"`
	SessionID       string `json:"-"`
}

type UserAuthenticSourceLookupReply struct {
	AuthenticSources []string `json:"authentic_sources,omitempty" validate:"omitempty,dive,max=128,printascii"`
}
