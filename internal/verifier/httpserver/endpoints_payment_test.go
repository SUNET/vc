package httpserver

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func paymentPageService(t *testing.T, enable bool, vcts []string) *Service {
	t.Helper()
	log, err := logger.New("test", "", false)
	require.NoError(t, err)
	tracer, err := trace.NewForTesting(context.Background(), "test", log)
	require.NoError(t, err)
	return &Service{
		cfg: &model.Cfg{
			Common:   &model.Common{},
			Verifier: &model.Verifier{TS12: model.TS12Config{Enable: enable, SCAVCTValues: vcts}},
		},
		tracer: tracer,
	}
}

func paymentPageEngine(t *testing.T, enable bool, vcts []string) *gin.Engine {
	t.Helper()
	engine, _ := setupUIEndpointEngine(t, &uiInteractionApiv1{})
	// setupUIEndpointEngine returns the engine only; build the page route on
	// a Service of the same shape.
	svc := paymentPageService(t, enable, vcts)
	engine.SetHTMLTemplate(htmlTemplates())
	engine.GET("/payment", func(c *gin.Context) { _, _ = svc.endpointPaymentPage(c.Request.Context(), c) })
	return engine
}

func TestPaymentPage(t *testing.T) {
	t.Run("not found unless ts12 is enabled", func(t *testing.T) {
		w := httptest.NewRecorder()
		paymentPageEngine(t, false, nil).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/payment", nil))
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
	t.Run("served when enabled, with the configured vct", func(t *testing.T) {
		w := httptest.NewRecorder()
		paymentPageEngine(t, true, []string{"https://psp.example/sca"}).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/payment", nil))
		require.Equal(t, http.StatusOK, w.Code)
		body := w.Body.String()
		assert.Contains(t, body, "urn:eudi:sca:payment:1")
		assert.Contains(t, body, "https://psp.example/sca")
		assert.Contains(t, body, "[hidden] { display: none !important; }", "Bulma's .box would otherwise keep hidden panels visible")
		assert.NotContains(t, body, "{{", "template actions must all have been expanded")
	})

	// The wallet link must hand off through the shared helper, so the
	// session is marked same-device.
	//
	// /verification/direct_post only returns redirect_uri for a session
	// marked same-device, so without the preference POST the wallet has
	// nowhere to send the user back to and the operator has to find this
	// page again by hand. It cannot be an awaited fetch before the
	// navigation either: Chrome on Android only lets a page launch a
	// custom scheme while it still holds the click's transient
	// activation, and one await loses it silently. wallet-handoff.js is
	// where that ordering is worked out, so the page imports it rather
	// than growing a second copy.
	//
	// Only the LINK is armed: scanning the QR code is a cross-device
	// flow and must not be marked same-device.
	t.Run("the wallet link hands off through the shared helper", func(t *testing.T) {
		w := httptest.NewRecorder()
		paymentPageEngine(t, true, []string{"https://psp.example/sca"}).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/payment", nil))
		require.Equal(t, http.StatusOK, w.Code)
		body := w.Body.String()

		assert.Contains(t, body, `import { armWalletLink } from "/static/payment-handoff.js"`,
			"the page must use the shared handoff, not a second implementation of it")
		assert.Contains(t, body, `<script type="module">`,
			"a static import needs a module script, or the import is a syntax error and the whole page is dead")
		// Armed on the link element, and on nothing else: scanning the
		// QR code is a cross-device flow. What the handoff then does -
		// which clicks count, what the preference says, and that
		// nothing is awaited before a custom-scheme launch - is tested
		// in tests/payment-handoff.test.js, where it can be driven.
		arm := strings.Index(body, "armWalletLink(")
		require.Positive(t, arm, "the link must still be armed")
		assert.Contains(t, body[arm:arm+120], `armWalletLink($("link"), reply.session_id`,
			"the link is armed with THIS session; a cookie fallback would claim another tab's")
		assert.NotContains(t, body, `armWalletLink($("qr")`,
			"the QR code is a cross-device flow and must not be marked same-device")
	})

	// A successful /ui/interaction response that cannot be read must fail
	// loudly, not quietly become {}.
	//
	// The page used one decode with an empty fallback for BOTH outcomes.
	// On a truncated or unreadable success body that left reply = {}, so
	// the page set the QR image to "data:image/png;base64,undefined",
	// linked to "undefined" and polled session_id=undefined 150 times -
	// the operator sees a payment waiting for a wallet that was never
	// asked for anything. There is no JS test runner here, so this pins
	// the structure: the empty fallback lives on the error branch only,
	// and the success branch checks that the reply carries what the page
	// goes on to use.
	t.Run("a successful reply is decoded without a silent fallback", func(t *testing.T) {
		w := httptest.NewRecorder()
		paymentPageEngine(t, true, []string{"https://psp.example/sca"}).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/payment", nil))
		require.Equal(t, http.StatusOK, w.Code)
		body := w.Body.String()

		start := strings.Index(body, "await fetch(\"/ui/interaction\"")
		require.Positive(t, start, "the submit handler must still post to /ui/interaction")
		end := strings.Index(body[start:], "await poll(")
		require.Positive(t, end, "the submit handler must still start polling")
		handler := body[start : start+end]

		ok := strings.Index(handler, "if (!res.ok)")
		require.Positive(t, ok, "the handler must branch on res.ok")
		success := handler[strings.Index(handler, "var reply = await res.json()"):]
		require.NotEmpty(t, success, "the success path must decode the reply")
		assert.NotContains(t, success, "catch(",
			"a decode failure on a SUCCESSFUL response must propagate, not become an empty object")
		assert.Contains(t, success, "is missing",
			"and a reply without session_id, qr_code or authorization_request must be refused too")
	})
}

// The payment object the page posts must survive the HTTP binding into the
// handler: amount as a JSON string and as a JSON number.
func TestUIInteractionBindsPayment(t *testing.T) {
	for _, amount := range []string{`"49.99"`, `49.99`} {
		mock := &uiInteractionApiv1{replySessionID: "s"}
		engine, _ := setupUIEndpointEngine(t, mock)
		body := `{"dcql_query":{"credentials":[{"id":"sca","format":"dc+sd-jwt","meta":{"vct_values":["x"]}}]},` +
			`"payment":{"amount":` + amount + `,"currency":"EUR","payee_name":"Shop AB","payee_id":"SE1","credential_id":"sca"}}`
		req := httptest.NewRequest(http.MethodPost, "/ui/interaction", bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.NotNil(t, mock.receivedPayment, "amount %s", amount)
		assert.Equal(t, "49.99", string(mock.receivedPayment.Amount))
		assert.Equal(t, "sca", mock.receivedPayment.CredentialID)
		assert.True(t, strings.HasPrefix(mock.receivedPayment.PayeeName, "Shop"))
	}
}
