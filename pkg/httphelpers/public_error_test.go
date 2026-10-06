package httphelpers

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// logLine is one line of the production logger's JSON output.
type logLine struct {
	Level   string `json:"level"`
	Message string `json:"msg"`
	ReqID   string `json:"req_id"`
	Error   string `json:"error"`
	Path    string `json:"path"`
	Status  int    `json:"status"`
}

// errorEngine registers one route that fails with err, behind the same
// RequestID middleware the real server uses, and logs to a file so a test
// can read back what an operator would see.
//
// The production logger is deliberate: it emits JSON and drops Debug, which
// is the threshold this behaviour is about.
func errorEngine(t *testing.T, err error) (*gin.Engine, func() []logLine) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	dir := t.TempDir()
	log, logErr := logger.New("errtest", dir, true)
	require.NoError(t, logErr)

	ctx := context.Background()
	tracer, tErr := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, tErr)

	client, cErr := New(ctx, tracer, &model.Cfg{Common: &model.Common{}}, log)
	require.NoError(t, cErr)

	engine := gin.New()
	rg := engine.Group("")
	rg.Use(client.Middleware.RequestID(ctx))
	client.Server.RegEndpoint(ctx, rg, http.MethodGet, "boom", http.StatusOK,
		func(context.Context, *gin.Context) (any, error) { return nil, err })

	read := func() []logLine {
		t.Helper()
		f, oErr := os.Open(filepath.Join(dir, "errtest.log"))
		if os.IsNotExist(oErr) {
			return nil
		}
		require.NoError(t, oErr)
		defer f.Close()

		var lines []logLine
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			var l logLine
			require.NoError(t, json.Unmarshal(scanner.Bytes(), &l), "line: %s", scanner.Text())
			lines = append(lines, l)
		}
		require.NoError(t, scanner.Err())
		return lines
	}

	return engine, read
}

func callBoom(t *testing.T, engine *gin.Engine) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/boom", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	var body struct {
		Error map[string]any `json:"error"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body), "body: %s", w.Body.String())
	return w, body.Error
}

// The leak: an error nothing recognised went out as its raw wrapped text.
//
// The status is not asserted here. StatusCode infers one by matching
// substrings of the error text, so it varies with the message - and that
// inference is unchanged by this: a coarse classification still reaches the
// caller through the status code. Redacting the body does not pretend
// otherwise, and reworking that heuristic is a separate question.
func TestUnclassifiedErrorDetailsDoNotReachTheClient(t *testing.T) {
	secret := "opening /etc/vc/secrets/issuer.pem at 10.0.3.17:5432"
	engine, _ := errorEngine(t, fmt.Errorf("loading the signing key: %w", errors.New(secret)))

	w, body := callBoom(t, engine)

	assert.Equal(t, "internal_server_error", body["title"])
	assert.NotContains(t, w.Body.String(), secret, "the wrapped error must not reach the caller")
	assert.NotContains(t, w.Body.String(), "/etc/vc/secrets", "nor any part of it")
	assert.NotContains(t, w.Body.String(), "loading the signing key")
}

// ... and the operator gets what the caller no longer does.
func TestUnclassifiedErrorIsLoggedWithTheRequestID(t *testing.T) {
	engine, readLog := errorEngine(t, errors.New("the underlying cause"))

	w, body := callBoom(t, engine)

	assert.Equal(t, http.StatusInternalServerError, w.Code,
		"an error nothing recognised is a server error")

	details, ok := body["details"].(map[string]any)
	require.True(t, ok, "details is %T", body["details"])
	requestID, ok := details["req_id"].(string)
	require.True(t, ok, "the body must carry the request id")
	assert.NotEmpty(t, requestID)
	assert.Equal(t, w.Header().Get("req_id"), requestID,
		"the id in the body and the header must be the same one")

	var found *logLine
	for i, line := range readLog() {
		if line.ReqID == requestID {
			found = &readLog()[i]
			break
		}
	}
	require.NotNil(t, found, "nothing was logged against the id the caller was given")
	assert.Equal(t, "error", found.Level, "it must survive the production level threshold")
	assert.Contains(t, found.Error, "the underlying cause", "the chain belongs in the log")
	assert.Equal(t, "/boom", found.Path)
	assert.Equal(t, http.StatusInternalServerError, found.Status)
}

// Errors that were recognised are shapes somebody chose to publish: useful
// to an API client, and not secrets. They are returned unchanged.
func TestClassifiedErrorsKeepTheirDetails(t *testing.T) {
	for name, tc := range map[string]struct {
		err          error
		wantTitle    string
		wantInBody   string
		wantStatusIn []int
	}{
		"validation error": {
			err:        validationError(t),
			wantTitle:  "validation_error",
			wantInBody: "required_field",
		},
		"json syntax error": {
			err:        jsonSyntaxError(t),
			wantTitle:  "json_syntax_error",
			wantInBody: "position",
		},
		"sentinel": {
			err:        helpers.ErrNoDocumentFound,
			wantTitle:  "NO_DOCUMENT_FOUND",
			wantInBody: "",
		},
		"chosen error": {
			err:        helpers.NewErrorDetails("teapot", "a deliberate, publishable message"),
			wantTitle:  "teapot",
			wantInBody: "a deliberate, publishable message",
		},
	} {
		t.Run(name, func(t *testing.T) {
			engine, _ := errorEngine(t, tc.err)
			w, body := callBoom(t, engine)

			assert.Equal(t, tc.wantTitle, body["title"], "body: %s", w.Body.String())
			if tc.wantInBody != "" {
				assert.Contains(t, w.Body.String(), tc.wantInBody,
					"a classified error's details are useful and must survive")
			}
			assert.NotContains(t, w.Body.String(), "req_id",
				"only the redacted response carries the request id")
		})
	}
}

func validationError(t *testing.T) error {
	t.Helper()
	validate, err := helpers.NewValidator()
	require.NoError(t, err)

	type payload struct {
		RequiredField string `json:"required_field" validate:"required"`
	}
	err = validate.Struct(&payload{})
	require.Error(t, err)
	return err
}

func jsonSyntaxError(t *testing.T) error {
	t.Helper()
	var v map[string]any
	err := json.Unmarshal([]byte(`{"broken":`), &v)
	require.Error(t, err)
	return err
}
