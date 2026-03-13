package openid4vci

import (
	"github.com/go-playground/validator/v10"
)

// VCTM represents SD-JWT VC Type Metadata as defined in
// draft-ietf-oauth-sd-jwt-vc-15, Section 5.2.
type VCTM struct {
	VCT                string        `json:"vct" bson:"vct" validate:"required"`
	Name               string        `json:"name,omitempty" bson:"name,omitempty"`
	Description        string        `json:"description,omitempty" bson:"description,omitempty"`
	Extends            string        `json:"extends,omitempty" bson:"extends,omitempty" validate:"omitempty,url"`
	ExtendsIntegrity   string        `json:"extends#integrity,omitempty" bson:"extends_integrity,omitempty"`
	Comment            string        `json:"$comment,omitempty" bson:"comment,omitempty"`
	Display            []VCTMDisplay `json:"display,omitempty" bson:"display,omitempty" validate:"omitempty,dive"`
	Claims             []VCTMClaim   `json:"claims,omitempty" bson:"claims,omitempty" validate:"omitempty,dive"`
	SchemaURI          string        `json:"schema_uri,omitempty" bson:"schema_uri,omitempty" validate:"omitempty,url"`
	SchemaURIIntegrity string        `json:"schema_uri#integrity,omitempty" bson:"schema_uri_integrity,omitempty" validate:"omitempty"`
}

// VCTMDisplay contains locale-specific display information for a credential type.
// See draft-ietf-oauth-sd-jwt-vc-15, Section 7.
type VCTMDisplay struct {
	Locale      string                `json:"locale" bson:"locale" validate:"required,bcp47_language_tag"`
	Name        string                `json:"name" bson:"name" validate:"required"`
	Description string                `json:"description,omitempty" bson:"description,omitempty"`
	Rendering   *VCTMDisplayRendering `json:"rendering,omitempty" bson:"rendering,omitempty" validate:"omitempty"`
}

// VCTMDisplayRendering contains rendering methods for the credential type.
// See draft-ietf-oauth-sd-jwt-vc-15, Section 7.1.
type VCTMDisplayRendering struct {
	Simple       *VCTMDisplayRenderingSimple       `json:"simple,omitempty" bson:"simple,omitempty" validate:"omitempty"`
	SVGTemplates []VCTMDisplayRenderingSVGTemplate `json:"svg_templates,omitempty" bson:"svg_templates,omitempty" validate:"omitempty,dive"`
}

// VCTMDisplayRenderingSimple is the "simple" rendering method intended for
// applications that do not support SVG rendering.
// See draft-ietf-oauth-sd-jwt-vc-15, Section 7.1.1.
type VCTMDisplayRenderingSimple struct {
	Logo            *VCTMDisplayRenderingSimpleLogo            `json:"logo,omitempty" bson:"logo,omitempty" validate:"omitempty"`
	BackgroundImage *VCTMDisplayRenderingSimpleBackgroundImage `json:"background_image,omitempty" bson:"background_image,omitempty" validate:"omitempty"`
	BackgroundColor string                                     `json:"background_color,omitempty" bson:"background_color,omitempty"`
	TextColor       string                                     `json:"text_color,omitempty" bson:"text_color,omitempty"`
}

// VCTMDisplayRenderingSimpleLogo contains logo information for the simple rendering method.
// See draft-ietf-oauth-sd-jwt-vc-15, Section 7.1.1.1.
type VCTMDisplayRenderingSimpleLogo struct {
	URI          string `json:"uri" bson:"uri" validate:"required,url"`
	URIIntegrity string `json:"uri#integrity,omitempty" bson:"uri_integrity,omitempty"`
	AltText      string `json:"alt_text,omitempty" bson:"alt_text,omitempty"`
}

// VCTMDisplayRenderingSimpleBackgroundImage contains background image information
// for the simple rendering method.
// See draft-ietf-oauth-sd-jwt-vc-15, Section 7.1.1.2.
type VCTMDisplayRenderingSimpleBackgroundImage struct {
	URI          string `json:"uri" bson:"uri" validate:"required,url"`
	URIIntegrity string `json:"uri#integrity,omitempty" bson:"uri_integrity,omitempty"`
}

// VCTMDisplayRenderingSVGTemplate represents an SVG template entry in the
// "svg_templates" rendering method.
// See draft-ietf-oauth-sd-jwt-vc-15, Section 7.1.2.
type VCTMDisplayRenderingSVGTemplate struct {
	URI          string                            `json:"uri" bson:"uri" validate:"required,url"`
	URIIntegrity string                            `json:"uri#integrity,omitempty" bson:"uri_integrity,omitempty" validate:"omitempty"`
	Properties   *VCTMDisplayRenderingSVGProperties `json:"properties,omitempty" bson:"properties,omitempty" validate:"omitempty"`
}

// VCTMDisplayRenderingSVGProperties contains selection properties for an SVG template.
// See draft-ietf-oauth-sd-jwt-vc-15, Section 7.1.2.1.
type VCTMDisplayRenderingSVGProperties struct {
	Orientation string `json:"orientation,omitempty" bson:"orientation,omitempty" validate:"omitempty,oneof=landscape portrait"`
	ColorScheme string `json:"color_scheme,omitempty" bson:"color_scheme,omitempty" validate:"omitempty,oneof=light dark"`
	Contrast    string `json:"contrast,omitempty" bson:"contrast,omitempty" validate:"omitempty,oneof=normal high"`
}

// VCTMClaim contains metadata about a particular claim in the credential.
// See draft-ietf-oauth-sd-jwt-vc-15, Section 8.
type VCTMClaim struct {
	Path      []string           `json:"path" bson:"path" validate:"required,min=1,dive,required"`
	Display   []VCTMClaimDisplay `json:"display,omitempty" bson:"display,omitempty" validate:"omitempty,dive"`
	SD        string             `json:"sd,omitempty" bson:"sd,omitempty" validate:"omitempty,oneof=always allowed never"`
	Mandatory bool               `json:"mandatory,omitempty" bson:"mandatory,omitempty"`
	SVGID     string             `json:"svg_id,omitempty" bson:"svg_id,omitempty" validate:"omitempty"`
}

// VCTMClaimDisplay contains locale-specific display information for a claim.
// See draft-ietf-oauth-sd-jwt-vc-15, Section 8.2.
type VCTMClaimDisplay struct {
	Locale      string `json:"locale" bson:"locale" validate:"required,bcp47_language_tag"`
	Label       string `json:"label" bson:"label" validate:"required"`
	Description string `json:"description,omitempty" bson:"description,omitempty"`
}

func (v *VCTM) Validate() error {
	validator := validator.New()
	return validator.Struct(v)
}
