package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
)

const (
	templateURI = "https://issuer.example.com/card.svg"
	logoURI     = "data:image/svg+xml;base64,PHN2Zy8+"
)

// A credential whose metadata offers a logo and no SVG template used to
// render no card at all, which is not what the metadata said. The same
// fallback runs in reverse when the issuer metadata is generated
// (mapSvgTemplates fills an absent logo from the first template).
func TestVCTMCardURI(t *testing.T) {
	for name, tc := range map[string]struct {
		vctm     *sdjwtvc.VCTM
		want     string
		wantLogo bool
	}{
		"template wins": {
			vctm: &sdjwtvc.VCTM{Display: []sdjwtvc.VCTMDisplay{{Rendering: &sdjwtvc.Rendering{
				SVGTemplates: []sdjwtvc.SVGTemplates{{URI: templateURI}},
				Simple:       &sdjwtvc.SimpleRendering{Logo: &sdjwtvc.Logo{URI: logoURI}},
			}}}},
			want: templateURI,
		},
		"logo when there is no template": {
			vctm: &sdjwtvc.VCTM{Display: []sdjwtvc.VCTMDisplay{{Rendering: &sdjwtvc.Rendering{
				Simple: &sdjwtvc.SimpleRendering{Logo: &sdjwtvc.Logo{URI: logoURI}},
			}}}},
			want:     logoURI,
			wantLogo: true,
		},
		"nothing when rendering offers neither": {
			vctm: &sdjwtvc.VCTM{Display: []sdjwtvc.VCTMDisplay{{Rendering: &sdjwtvc.Rendering{
				Simple: &sdjwtvc.SimpleRendering{BackgroundColor: "#fff"},
			}}}},
			want: "",
		},
		"nothing when there is no rendering": {
			vctm: &sdjwtvc.VCTM{Display: []sdjwtvc.VCTMDisplay{{}}},
			want: "",
		},
		"nothing when there is no display": {
			vctm: &sdjwtvc.VCTM{},
			want: "",
		},
	} {
		t.Run(name, func(t *testing.T) {
			uri, fromLogo := vctmCardURI(tc.vctm)
			assert.Equal(t, tc.want, uri)
			assert.Equal(t, tc.wantLogo, fromLogo, "the caller needs to know a logo is not a declared template")
		})
	}
}

// The mdoc dialect keeps its logo on the display entry rather than under a
// "simple" sub-object, which is why this is a separate function and not a
// generic one. Both shipped mdoc schemas (mDL, PID) carry display and no
// rendering, which is the configuration in the report.
func TestMDDLCardURI(t *testing.T) {
	for name, tc := range map[string]struct {
		mddl     *mdoc.MDDLSchema
		want     string
		wantLogo bool
	}{
		"template wins": {
			mddl: &mdoc.MDDLSchema{Display: []mdoc.DisplayProperties{{
				Rendering: &mdoc.Rendering{SVGTemplates: []mdoc.SVGTemplate{{URI: templateURI}}},
				Logo:      &mdoc.Logo{URI: logoURI},
			}}},
			want: templateURI,
		},
		"logo when there is no template": {
			mddl: &mdoc.MDDLSchema{Display: []mdoc.DisplayProperties{{
				Logo: &mdoc.Logo{URI: logoURI},
			}}},
			want:     logoURI,
			wantLogo: true,
		},
		"logo when rendering is present but empty": {
			mddl: &mdoc.MDDLSchema{Display: []mdoc.DisplayProperties{{
				Rendering: &mdoc.Rendering{},
				Logo:      &mdoc.Logo{URI: logoURI},
			}}},
			want:     logoURI,
			wantLogo: true,
		},
		"nothing when the display carries neither": {
			mddl: &mdoc.MDDLSchema{Display: []mdoc.DisplayProperties{{Name: "mDL"}}},
			want: "",
		},
		"nothing when there is no display": {
			mddl: &mdoc.MDDLSchema{},
			want: "",
		},
	} {
		t.Run(name, func(t *testing.T) {
			uri, fromLogo := mddlCardURI(tc.mddl)
			assert.Equal(t, tc.want, uri)
			assert.Equal(t, tc.wantLogo, fromLogo)
		})
	}
}

// "This credential has no card" has to be a value the caller can test for,
// not one error among many: the endpoint answers it with 200 and an empty
// template, while every other failure is a 400.
func TestSVGTemplateReplyReportsAnAbsentTemplate(t *testing.T) {
	c := &Client{}

	for name, req := range map[string]*SVGTemplateRequest{
		"vctm with no display":  {VCTM: &sdjwtvc.VCTM{}},
		"vctm with no renderin": {VCTM: &sdjwtvc.VCTM{Display: []sdjwtvc.VCTMDisplay{{}}}},
		"mddl with no display":  {MDDL: &mdoc.MDDLSchema{}},
		"mddl with only a name": {MDDL: &mdoc.MDDLSchema{Display: []mdoc.DisplayProperties{{Name: "mDL"}}}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.SVGTemplateReply(t.Context(), req)
			assert.ErrorIs(t, err, ErrNoSVGTemplate)
		})
	}
}

// The other refusals stay distinct, so a caller cannot mistake a malformed
// request for a credential that simply has no card.
func TestSVGTemplateReplyStillRefusesABadRequest(t *testing.T) {
	c := &Client{}

	for name, req := range map[string]*SVGTemplateRequest{
		"neither":      {},
		"both at once": {VCTM: &sdjwtvc.VCTM{}, MDDL: &mdoc.MDDLSchema{}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.SVGTemplateReply(t.Context(), req)
			assert.Error(t, err)
			assert.NotErrorIs(t, err, ErrNoSVGTemplate)
		})
	}

	_, err := c.SVGTemplateReply(t.Context(), nil)
	assert.Error(t, err)
	assert.NotErrorIs(t, err, ErrNoSVGTemplate)
}

// A logo is any image, while this pipeline carries SVG only: the reply has
// no media type and consent.js decodes it as UTF-8 text to substitute claim
// values. Handing it raster bytes would produce a BROKEN image where there
// used to be none, so a non-SVG logo means "this credential has no card".
func TestSVGTemplateReplyIgnoresARasterLogo(t *testing.T) {
	c := &Client{}

	const pngDataURI = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=="

	t.Run("vctm", func(t *testing.T) {
		_, err := c.SVGTemplateReply(t.Context(), &SVGTemplateRequest{
			VCTM: &sdjwtvc.VCTM{Display: []sdjwtvc.VCTMDisplay{{Rendering: &sdjwtvc.Rendering{
				Simple: &sdjwtvc.SimpleRendering{Logo: &sdjwtvc.Logo{URI: pngDataURI}},
			}}}},
		})
		assert.ErrorIs(t, err, ErrNoSVGTemplate)
	})

	t.Run("mddl", func(t *testing.T) {
		_, err := c.SVGTemplateReply(t.Context(), &SVGTemplateRequest{
			MDDL: &mdoc.MDDLSchema{Display: []mdoc.DisplayProperties{{
				Logo: &mdoc.Logo{URI: pngDataURI},
			}}},
		})
		assert.ErrorIs(t, err, ErrNoSVGTemplate)
	})
}

// The gate only applies to a logo. A declared svg_template carrying the
// wrong media type is a configuration error that still travels the old
// path - this does not change that, and claiming otherwise would be a test
// asserting behaviour nobody wrote.
func TestIsSVGDataURI(t *testing.T) {
	for uri, want := range map[string]bool{
		"data:image/svg+xml;base64,PHN2Zy8+":      true,
		"data:image/svg+xml,<svg/>":               true,
		"data:image/svg+xml;charset=utf-8,<svg/>": true,
		"data:image/png;base64,iVBORw0KGgo=":      false,
		"data:image/jpeg;base64,/9j/4AA=":         false,
		"data:text/plain,hello":                   false,
		"data:,hello":                             false,
		"data:image/svg+xml;base64":               false,
		"https://issuer.example.com/card.svg":     false,
	} {
		t.Run(uri, func(t *testing.T) {
			assert.Equal(t, want, isSVGDataURI(uri))
		})
	}
}
