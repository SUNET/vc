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
		assert.Equal(t, "49.99", mock.receivedPayment.Amount.String())
		assert.Equal(t, "sca", mock.receivedPayment.CredentialID)
		assert.True(t, strings.HasPrefix(mock.receivedPayment.PayeeName, "Shop"))
	}
}
