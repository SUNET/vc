package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSignedMetadataJWT = "eyJ0eXAiOiJvcGVuaWR2Y2ktaXNzdWVyLW1ldGFkYXRhK2p3dCJ9.eyJzdWIiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSJ9.c2ln"

// metadataAPI hands back a metadata document that carries a signed form, the
// way VCIMetadata does once the background signer has run.
type metadataAPI struct {
	unimplementedApiv1
	signed string
}

func (m *metadataAPI) VCIMetadata(context.Context) (*openid4vci.CredentialIssuerMetadataParameters, error) {
	return &openid4vci.CredentialIssuerMetadataParameters{
		CredentialIssuer: "https://issuer.example.com",
		SignedMetadata:   m.signed,
	}, nil
}

func metadataTestEngine(t *testing.T, signed string, includeInJSON bool) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	ctx := context.Background()
	tracer, err := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, err)

	cfg := &model.Cfg{
		Common: &model.Common{},
		APIGW: &model.APIGW{
			IssuerMetadata: model.IssuerMetadata{IncludeSignedMetadataInJSON: &includeInJSON},
		},
	}

	helpers, err := httphelpers.New(ctx, tracer, cfg, log)
	require.NoError(t, err)

	s := &Service{
		cfg:         cfg,
		log:         log.New("httpserver"),
		apiv1:       &metadataAPI{signed: signed},
		tracer:      tracer,
		httpHelpers: helpers,
	}

	engine := gin.New()
	rg := engine.Group("")
	helpers.Server.RegEndpoint(ctx, rg, http.MethodGet, ".well-known/openid-credential-issuer", http.StatusOK, s.endpointVCIMetadata)

	return engine
}

func getMetadata(t *testing.T, engine *gin.Engine, accept string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-credential-issuer", nil)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

// The unsigned JSON document is what a wallet gets unless it asks for
// something else, and it does not carry the signed form as a member:
// OpenID4VCI 1.0 §12.2.4 defines no signed_metadata parameter.
func TestVCIMetadata_UnsignedByDefault(t *testing.T) {
	for _, accept := range []string{"", "application/json", "*/*", "text/html,application/json;q=0.9,*/*;q=0.8"} {
		t.Run("accept="+accept, func(t *testing.T) {
			w := getMetadata(t, metadataTestEngine(t, testSignedMetadataJWT, false), accept)

			require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
			assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

			var got map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
			assert.Equal(t, "https://issuer.example.com", got["credential_issuer"])
			assert.NotContains(t, got, "signed_metadata")
		})
	}
}

// A wallet that asks for the signed form gets the JWT as the whole response,
// typed application/jwt (SUNET/vc#708).
//
// The spellings vary because media type tokens are case-insensitive
// (RFC 9110 §8.3.1), and gin's own negotiation compares them byte by byte.
func TestVCIMetadata_SignedWhenRequested(t *testing.T) {
	for _, accept := range []string{
		"application/jwt",
		"Application/JWT",
		"APPLICATION/JWT, application/json;q=0.5",
		"application/jwt; q=1.0",
	} {
		t.Run(accept, func(t *testing.T) {
			w := getMetadata(t, metadataTestEngine(t, testSignedMetadataJWT, false), accept)

			require.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, MediaTypeJWT, w.Header().Get("Content-Type"))
			assert.Equal(t, testSignedMetadataJWT, w.Body.String())
		})
	}
}

// Signed metadata is a MAY and can be unavailable at runtime. The unsigned
// form is a MUST, so it is served rather than an error.
func TestVCIMetadata_FallsBackToUnsignedWhenNothingIsSigned(t *testing.T) {
	w := getMetadata(t, metadataTestEngine(t, "", false), MediaTypeJWT)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	var got map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.NotContains(t, got, "signed_metadata")
}

// An Accept header that rules out both forms is answered honestly, whether
// it does so by naming something else or by giving one of ours q=0
// (RFC 9110 §12.4.2).
func TestVCIMetadata_NotAcceptable(t *testing.T) {
	for _, accept := range []string{
		"application/xml",
		"*/*;q=0",
		"application/jwt;q=0, application/json;q=0",
		"application/jwt;q=0",
	} {
		t.Run(accept, func(t *testing.T) {
			w := getMetadata(t, metadataTestEngine(t, testSignedMetadataJWT, false), accept)

			assert.Equal(t, http.StatusNotAcceptable, w.Code, "body: %s", w.Body.String())
		})
	}
}

// The draft-era shape is still reachable, for a wallet that reads
// signed_metadata out of the JSON - but only when the deployment asks.
func TestVCIMetadata_SignedMemberWhenConfigured(t *testing.T) {
	w := getMetadata(t, metadataTestEngine(t, testSignedMetadataJWT, true), "application/json")

	require.Equal(t, http.StatusOK, w.Code)

	var got map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, testSignedMetadataJWT, got["signed_metadata"])
}

// ... and turning that on does not change what the signed form looks like.
func TestVCIMetadata_SignedMemberDoesNotChangeTheJWTResponse(t *testing.T) {
	w := getMetadata(t, metadataTestEngine(t, testSignedMetadataJWT, true), MediaTypeJWT)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, MediaTypeJWT, w.Header().Get("Content-Type"))
	assert.Equal(t, testSignedMetadataJWT, w.Body.String())
}
