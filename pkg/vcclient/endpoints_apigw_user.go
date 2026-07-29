package vcclient

import (
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/mdoc"
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
	// MDDL is set instead of VCTM for mso_mdoc scopes, which have no VCTM.
	MDDL *mdoc.MDDLSchema `json:"-"`
}

// SVGTemplateReply holds SVG template data.
type SVGTemplateReply struct {
	Template string `json:"template"`
}

type UserLookupReply struct {
	// SVGTemplateClaims is keyed by svg_id — flat values for SVG template placeholder substitution.
	SVGTemplateClaims map[string]sdjwtvc.SVGValue `json:"svg_template_claims"`
	// PresentationClaims is keyed by claim name — nested parent/children structure for the consent page.
	PresentationClaims map[string]any `json:"presentation_claims"`
	RedirectURL        string         `json:"redirect_url,omitempty"`
}

type UserAuthenticSourceLookupRequest struct {
	AuthenticSource string `json:"authentic_source,omitempty" validate:"omitempty,max=128,printascii"`
	SessionID       string `json:"-"`
}

type UserAuthenticSourceLookupReply struct {
	AuthenticSources []string `json:"authentic_sources,omitempty" validate:"omitempty,dive,max=128,printascii"`
}
