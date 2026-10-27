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
	// CredentialDisplay names the credential about to be issued, so the
	// consent page can lead with what the holder is getting and from whom
	// instead of opening on a claim dump. Resolved from the scope's VCTM
	// or MDDL schema, which the lookup already has in hand and used to
	// throw away.
	//
	// Omitted when the scope resolves to neither, and the page then falls
	// back to a generic heading: a missing name is a worse page, never a
	// broken one.
	CredentialDisplay *CredentialDisplay `json:"credential_display,omitempty"`
}

// CredentialDisplay is the subset of type metadata the consent page shows.
// Deliberately small - four strings, no rendering instructions - because
// the card image already comes through SVGTemplateClaims and everything
// else on that page is claims.
type CredentialDisplay struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	// VCT is the SD-JWT VC type identifier, or the doctype for an mdoc.
	VCT string `json:"vct,omitempty"`
	// Issuer is the Credential Issuer identifier the holder is dealing
	// with, which is the one thing on this page they cannot infer from
	// the claims.
	Issuer string `json:"issuer,omitempty"`
}

type UserAuthenticSourceLookupRequest struct {
	AuthenticSource string `json:"authentic_source,omitempty" validate:"omitempty,max=128,printascii"`
	SessionID       string `json:"-"`
}

type UserAuthenticSourceLookupReply struct {
	AuthenticSources []string `json:"authentic_sources,omitempty" validate:"omitempty,dive,max=128,printascii"`
}
