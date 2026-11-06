package httphelpers

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vci"
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
	engine, read, _ := errorEngineAtLevel(t, err, true)
	return engine, read
}

// errorEngineAtLevel is errorEngine with the logger's production flag
// exposed, for the one test that is about a Debug line - which production
// drops by design.
func errorEngineAtLevel(t *testing.T, err error, production bool) (*gin.Engine, func() []logLine, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	dir := t.TempDir()
	log, logErr := logger.New("errtest", dir, production)
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

	return engine, read, dir
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

		// Wrapped with %w, which is ordinary Go and what handlers in this
		// tree actually do. The classification used to be direct type
		// assertions, so every one of these fell past every branch and out
		// the catch-all. Survivable while the catch-all returned the error
		// text; now that it redacts, it turns a client error into an
		// opaque internal_server_error and takes the parse offset or the
		// field report with it.
		"wrapped validation error": {
			err:        fmt.Errorf("binding the request: %w", validationError(t)),
			wantTitle:  "validation_error",
			wantInBody: "required_field",
		},
		"wrapped json syntax error": {
			err:        fmt.Errorf("parsing the credential request: %w", jsonSyntaxError(t)),
			wantTitle:  "json_syntax_error",
			wantInBody: "position",
		},
		"wrapped sentinel": {
			err:        fmt.Errorf("resolving the identity: %w", helpers.ErrNoDocumentFound),
			wantTitle:  "database_error",
			wantInBody: "NO_DOCUMENT_FOUND",
		},
		"wrapped chosen error": {
			err:        fmt.Errorf("looking up the mapping: %w", helpers.NewErrorDetails("teapot", "a deliberate, publishable message")),
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
			// The wrapping context is the operator's, not the caller's:
			// it goes to the log, never to the body.
			for _, context := range []string{"binding the request", "parsing the credential request", "resolving the identity", "looking up the mapping"} {
				assert.NotContains(t, w.Body.String(), context,
					"a wrapper's own context must not reach the client")
			}
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

type rejectingDecoder struct{}

func (*rejectingDecoder) UnmarshalJSON([]byte) error {
	return errors.New("the token is missing")
}

type clientBody struct {
	Name        string            `json:"name"`
	AccessToken string            `json:"access_token"`
	MissingItem string            `json:"missing_item"`
	When        time.Time         `json:"when"`
	Rejecting   *rejectingDecoder `json:"rejecting"`
}

type requiredTokenBody struct {
	AccessToken string `json:"access_token" binding:"required" validate:"required"`
}

// HTTP's contract: a request body the client got wrong is a 4xx error
// (RFC 9110 §15.5), whichever words the decoder's error text holds, and a
// body over the limit is a 413 (§15.5.14).
func TestClientJSONBodyErrorStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)
	log, err := logger.New("bodytest", t.TempDir(), true)
	require.NoError(t, err)
	ctx := context.Background()
	tracer, err := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, err)
	client, err := New(ctx, tracer, &model.Cfg{Common: &model.Common{}}, log)
	require.NoError(t, err)

	request := func(c *gin.Context, v any) error { return client.Binding.Request(ctx, c, v) }
	binders := []struct {
		name string
		bind func(c *gin.Context, v any) error
		// typeOnly binders run only the rows whose error a JSON type
		// identifies: FastAndSimple skips validation and ShouldBindJSON
		// sets no RequestBodyError.
		typeOnly bool
	}{
		{name: "Request", bind: request},
		{name: "JSONBody", bind: func(c *gin.Context, v any) error { return client.Binding.JSONBody(ctx, c, v) }},
		{name: "wrapped", bind: func(c *gin.Context, v any) error {
			if err := request(c, v); err != nil {
				return fmt.Errorf("binding the request: %w", err)
			}
			return nil
		}},
		{name: "FastAndSimple", typeOnly: true, bind: func(c *gin.Context, v any) error { return client.Binding.FastAndSimple(ctx, c, v) }},
		{name: "ShouldBindJSON", typeOnly: true, bind: func(c *gin.Context, v any) error { return c.ShouldBindJSON(v) }},
	}

	newClientBody := func() any { return &clientBody{} }
	for _, tc := range []struct {
		name       string
		body       string
		target     func() any
		maxBytes   int64
		typeOnly   bool
		wantStatus int
		wantTitle  string
	}{
		{name: "wrong type", body: `{"name":[1]}`, target: newClientBody, typeOnly: true, wantStatus: http.StatusBadRequest, wantTitle: "json_type_error"},
		{name: "wrong type in a token field", body: `{"access_token":[1]}`, target: newClientBody, typeOnly: true, wantStatus: http.StatusBadRequest, wantTitle: "json_type_error"},
		{name: "wrong type in a missing field", body: `{"missing_item":[1]}`, target: newClientBody, typeOnly: true, wantStatus: http.StatusBadRequest, wantTitle: "json_type_error"},
		{name: "syntax", body: `{"name":}`, target: newClientBody, typeOnly: true, wantStatus: http.StatusBadRequest, wantTitle: "json_syntax_error"},
		{name: "truncated", body: `{"name":"x"`, target: newClientBody, wantStatus: http.StatusBadRequest, wantTitle: "json_syntax_error"},
		{name: "whitespace", body: "   ", target: newClientBody, wantStatus: http.StatusBadRequest, wantTitle: "json_syntax_error"},
		{name: "required token field absent", body: `{}`, target: func() any { return &requiredTokenBody{} }, wantStatus: http.StatusBadRequest, wantTitle: "validation_error"},
		{name: "malformed time", body: `{"when":"yesterday"}`, target: newClientBody, wantStatus: http.StatusBadRequest, wantTitle: "json_value_error"},
		{name: "custom decoder refusal", body: `{"rejecting":1}`, target: newClientBody, wantStatus: http.StatusBadRequest, wantTitle: "json_value_error"},
		{name: "over the size limit", body: `{"name":"x"}`, target: newClientBody, maxBytes: 4, wantStatus: http.StatusRequestEntityTooLarge, wantTitle: "internal_server_error"},
	} {
		for _, binder := range binders {
			if binder.typeOnly && !tc.typeOnly {
				continue
			}
			for _, endpoint := range []string{"RegEndpoint", "RegStreamEndpoint"} {
				t.Run(tc.name+"/"+binder.name+"/"+endpoint, func(t *testing.T) {
					engine := gin.New()
					rg := engine.Group("")
					handler := func(c *gin.Context) (any, error) {
						if tc.maxBytes > 0 {
							c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, tc.maxBytes)
						}
						return map[string]string{}, binder.bind(c, tc.target())
					}
					if endpoint == "RegEndpoint" {
						client.Server.RegEndpoint(ctx, rg, http.MethodPost, "bind", http.StatusOK,
							func(_ context.Context, c *gin.Context) (any, error) { return handler(c) })
					} else {
						client.Server.RegStreamEndpoint(ctx, rg, http.MethodPost, "bind", http.StatusOK, nil,
							func(_ context.Context, c *gin.Context, _ chan string) (any, error) { return handler(c) })
					}

					req := httptest.NewRequest(http.MethodPost, "/bind", strings.NewReader(tc.body))
					req.Header.Set("Content-Type", "application/json")
					w := httptest.NewRecorder()
					engine.ServeHTTP(w, req)

					var body struct {
						Error map[string]any `json:"error"`
					}
					require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body), "body: %s", w.Body.String())
					assert.Equal(t, tc.wantStatus, w.Code, "body: %s", w.Body.String())
					assert.Equal(t, tc.wantTitle, body.Error["title"], "body: %s", w.Body.String())
				})
			}
		}
	}
}

// A chunked request has ContentLength -1. The authorization middleware and the
// binding must read the same body: a body only the binding reads carries an
// authentic_source that nothing authorized. A real server produces the length.
func TestUnknownLengthBodyReachesMiddlewareAndBinding(t *testing.T) {
	gin.SetMode(gin.TestMode)
	log, err := logger.New("chunkedtest", t.TempDir(), true)
	require.NoError(t, err)
	ctx := context.Background()
	tracer, err := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, err)
	client, err := New(ctx, tracer, &model.Cfg{Common: &model.Common{}}, log)
	require.NoError(t, err)

	type target struct {
		AuthenticSource string `json:"authentic_source" form:"authentic_source"`
	}
	engine := gin.New()
	engine.Use(client.Middleware.MaxBodySize(64))
	client.Server.RegEndpoint(ctx, engine.Group(""), http.MethodPost, "bind", http.StatusOK,
		func(_ context.Context, c *gin.Context) (any, error) {
			pairs := extractResourcePairs(c)
			v := &target{}
			if err := client.Binding.Request(ctx, c, v); err != nil {
				return nil, err
			}
			authorized := ""
			if len(pairs) > 0 {
				authorized = pairs[0].authenticSource
			}
			return map[string]string{"bound": v.AuthenticSource, "authorized": authorized}, nil
		})
	server := httptest.NewServer(engine)
	defer server.Close()

	const jsonType = "application/json"
	for _, tc := range []struct {
		name           string
		query          string
		contentType    string
		body           io.Reader
		wantStatus     int
		wantTitle      string
		wantBound      string
		wantAuthorized string
	}{
		{name: "valid JSON", contentType: jsonType, body: strings.NewReader(`{"authentic_source":"a"}`), wantStatus: http.StatusOK, wantBound: "a", wantAuthorized: "a"},
		{name: "wrong type", contentType: jsonType, body: strings.NewReader(`{"authentic_source":[1]}`), wantStatus: http.StatusBadRequest, wantTitle: "json_type_error"},
		{name: "no body bytes", query: "?authentic_source=q", contentType: jsonType, body: strings.NewReader(""), wantStatus: http.StatusOK, wantBound: "q", wantAuthorized: "q"},
		{name: "whitespace", contentType: jsonType, body: strings.NewReader("   "), wantStatus: http.StatusBadRequest, wantTitle: "json_syntax_error"},
		{name: "form", contentType: "application/x-www-form-urlencoded", body: strings.NewReader("authentic_source=f"), wantStatus: http.StatusOK, wantBound: "f"},
		{name: "over the size limit", contentType: jsonType, body: strings.NewReader(`{"authentic_source":"` + strings.Repeat("x", 64) + `"}`), wantStatus: http.StatusRequestEntityTooLarge, wantTitle: "internal_server_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// io.MultiReader hides the length, so the client sends chunked.
			req, err := http.NewRequest(http.MethodPost, server.URL+"/bind"+tc.query, io.MultiReader(tc.body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", tc.contentType)

			resp, err := server.Client().Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			var reply struct {
				Bound      string         `json:"bound"`
				Authorized string         `json:"authorized"`
				Error      map[string]any `json:"error"`
			}
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&reply))
			assert.Equal(t, tc.wantStatus, resp.StatusCode)
			if tc.wantTitle != "" {
				assert.Equal(t, tc.wantTitle, reply.Error["title"])
			}
			assert.Equal(t, tc.wantBound, reply.Bound)
			if tc.wantAuthorized != "" {
				assert.Equal(t, tc.wantAuthorized, reply.Authorized)
			}
		})
	}
}

// The OAuth and OpenID4VCI branches return before publicError, so moving
// the Debug line into it took their only log away - and those are exactly
// the paths that withhold the cause from the RESPONSE on purpose, which is
// what makes the log the only place it exists.
//
// A development logger, because the line under test is a Debug one and the
// production threshold drops it. That is the point of the line being at
// Debug: an OAuth refusal is an ordinary event, not an operator's problem.
func TestStructuredErrorsAreStillLoggedWithTheirCause(t *testing.T) {
	for name, err := range map[string]error{
		"oauth2": &oauth2.OAuthError{
			ErrorCode:        "invalid_client",
			ErrorDescription: "client authentication failed",
			HTTPStatus:       http.StatusUnauthorized,
			Cause:            errors.New("client secret mismatch for acme-corp"),
		},
		"openid4vci": &openid4vci.Error{
			Err:              "invalid_proof",
			ErrorDescription: "proof of possession is invalid",
		},
	} {
		t.Run(name, func(t *testing.T) {
			wrapped := fmt.Errorf("resolving the client: %w", err)
			engine, _, logDir := errorEngineAtLevel(t, wrapped, false)

			req := httptest.NewRequest(http.MethodGet, "/boom", nil)
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)

			// Still the structured response, unchanged.
			assert.NotEqual(t, http.StatusOK, w.Code)
			assert.NotContains(t, w.Body.String(), "resolving the client",
				"the structured response must not grow a Go error chain")

			// The development encoder is console, not JSON, so the parsed
			// logLine reader does not apply - read the file directly.
			data, readErr := os.ReadFile(filepath.Join(logDir, "errtest.log"))
			require.NoError(t, readErr)
			assert.Contains(t, string(data), "resolving the client",
				"a structured refusal still has to put its cause in the log")
		})
	}
}
