package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// offersAPI records the request the route bound and replies with a fully
// populated offer.
type offersAPI struct {
	unimplementedApiv1
	gotScope string
	err      error
}

func (o *offersAPI) UICreateCredentialOffer(_ context.Context, req *apiv1.UICredentialOfferRequest) (*apiv1.CredentialOfferReply, error) {
	o.gotScope = req.Scope
	if o.err != nil {
		return nil, o.err
	}
	return &apiv1.CredentialOfferReply{
		Name:  "SIROS ID",
		ID:    "urn:siros:id",
		Offer: "credential_offer=%7B%7D",
		URI:   "openid-credential-offer://?credential_offer=%7B%7D",
		QR: openid4vp.QRReply{
			Base64Image: "aW1n",
			URI:         "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example.com%2Fcredential-offer%2Fabc",
		},
		Wallets: map[string]apiv1.CredentialOfferWalletReply{
			"local": {Name: "Local Wallet", URI: "https://wallet.example.com/cb?credential_offer=%7B%7D"},
		},
	}, nil
}

// offersTestEngine registers the offer route exactly as service.go does.
func offersTestEngine(t *testing.T, mockAPI Apiv1) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	ctx := context.Background()
	tracer, err := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, err)

	cfg := &model.Cfg{Common: &model.Common{}}

	helpers, err := httphelpers.New(ctx, tracer, cfg, log)
	require.NoError(t, err)

	s := &Service{
		cfg:         cfg,
		log:         log.New("httpserver"),
		apiv1:       mockAPI,
		tracer:      tracer,
		httpHelpers: helpers,
	}

	engine := gin.New()
	rg := engine.Group("")
	helpers.Server.RegEndpoint(ctx, rg, http.MethodGet, "offers/:scope", http.StatusOK, s.endpointUICreateCredentialOffer)

	return engine
}

// The route is now single-segment: the offer is wallet-independent, so no
// wallet is chosen before it is produced.
func TestEndpointUICreateCredentialOffer_Route(t *testing.T) {
	api := &offersAPI{}
	engine := offersTestEngine(t, api)

	req := httptest.NewRequest(http.MethodGet, "/offers/siros_id", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	require.Equal(t, "siros_id", api.gotScope)

	var got map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))

	require.Equal(t, "SIROS ID", got["name"])
	require.Equal(t, "urn:siros:id", got["id"])
	require.Equal(t, "credential_offer=%7B%7D", got["offer"])
	require.Equal(t, "openid-credential-offer://?credential_offer=%7B%7D", got["uri"])

	qr, ok := got["qr"].(map[string]any)
	require.True(t, ok, "qr must be an object, got %#v", got["qr"])
	require.Equal(t, "aW1n", qr["base64_image"])

	wallets, ok := got["wallets"].(map[string]any)
	require.True(t, ok, "wallets must be an object, got %#v", got["wallets"])
	local, ok := wallets["local"].(map[string]any)
	require.True(t, ok, "wallets.local must be an object, got %#v", wallets["local"])
	require.Equal(t, "Local Wallet", local["name"])
	require.Equal(t, "https://wallet.example.com/cb?credential_offer=%7B%7D", local["uri"])
}

// The old two-segment form is gone; nothing is registered to serve it.
func TestEndpointUICreateCredentialOffer_TwoSegmentRouteGone(t *testing.T) {
	engine := offersTestEngine(t, &offersAPI{})

	req := httptest.NewRequest(http.MethodGet, "/offers/siros_id/local", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)
}

// The page renders the offer three ways from one response, so the wallet
// pre-selection the old page required is gone from the template.
func TestOffersTemplate_ThreeRenderings(t *testing.T) {
	tmpl := parseConsentTemplate(t)

	var buf bytes.Buffer
	err := tmpl.ExecuteTemplate(&buf, "offers.html", map[string]*apiv1.CredentialOfferLookupMetadata{
		"offers": {
			CredentialTypes: map[string]apiv1.CredentialOfferTypeData{
				"siros_id": {Name: "SIROS ID", Description: "A SIROS identity"},
			},
			Wallets: map[string]string{"local": "Local Wallet"},
		},
	})
	require.NoError(t, err)

	out := buf.String()
	require.Contains(t, out, `"credential_types"`)
	require.Contains(t, out, "SIROS ID")

	// No wallet radio group, no opaque checkbox.
	require.NotContains(t, out, `type="radio"`)
	require.NotContains(t, out, `name="wallet"`)
	require.NotContains(t, out, `name="opaque"`)

	// 1. QR, always. 2. DC API, gated. 3. One button per configured wallet.
	require.Contains(t, out, "credentialOffer.qr.base64_image")
	require.Contains(t, out, `x-if="issuanceAvailable"`)
	require.Contains(t, out, "handleIssueOnThisDevice")
	require.Contains(t, out, "handleOpenInWallet(wallet.uri)")
}
