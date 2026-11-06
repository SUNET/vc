package httphelpers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"

	"github.com/creasty/defaults"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
)

// bindingHandler is the bindingHandler object for httphelpers
type bindingHandler struct {
	client *Client
	log    *logger.Log
}

// FastAndSimple binds the request body to the given struct without use of struct tags (except for json)
func (b *bindingHandler) FastAndSimple(ctx context.Context, c *gin.Context, v any) error {
	_, span := b.client.tracer.Start(ctx, "httpserver:bindFastAndSimple")
	defer span.End()

	return decodeBody(c, func(body []byte) error {
		return json.NewDecoder(bytes.NewReader(body)).Decode(&v)
	})
}

// JSONBody decodes and validates the JSON request body into v. A body the
// client got wrong returns a *helpers.RequestBodyError. A failure to read the
// body returns as it is: *http.MaxBytesError answers 413.
func (b *bindingHandler) JSONBody(ctx context.Context, c *gin.Context, v any) error {
	_, span := b.client.tracer.Start(ctx, "httpserver:bindJSONBody")
	defer span.End()

	return decodeBody(c, func(body []byte) error {
		return binding.JSON.BindBody(body, v)
	})
}

// decodeBody reads the whole body before decode runs, so every error decode
// returns describes the client's bytes. io.ErrUnexpectedEOF from the read is a
// body shorter than its Content-Length: decode judges the bytes that arrived.
func decodeBody(c *gin.Context, decode func(body []byte) error) error {
	reader := c.Request.Body
	if reader == nil {
		reader = http.NoBody
	}

	body, err := io.ReadAll(reader)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	}

	if err := decode(body); err != nil {
		return &helpers.RequestBodyError{Err: truncationAsSyntaxError(body, err)}
	}
	return nil
}

// truncationAsSyntaxError turns the EOF a json.Decoder returns for a body with
// no complete value into the *json.SyntaxError json.Unmarshal returns for the
// same bytes, which holds the position. Any other error returns as it is.
func truncationAsSyntaxError(body []byte, err error) error {
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	}
	if syntaxErr := json.Unmarshal(body, new(json.RawMessage)); syntaxErr != nil {
		return syntaxErr
	}
	return err
}

func (b *bindingHandler) Request(ctx context.Context, c *gin.Context, v any) error {
	_, span := b.client.tracer.Start(ctx, "httpserver:bindRequest")
	defer span.End()

	// Apply struct default tags (github.com/creasty/defaults) before binding,
	// so that request values override defaults.
	if err := defaults.Set(v); err != nil {
		return err
	}

	// Bind URI parameters (e.g., /path/:id) - without validation
	if err := c.ShouldBindUri(v); err != nil {
		// Ignore validation errors from URI binding, only fail on actual binding errors
		if _, ok := err.(validator.ValidationErrors); !ok {
			return err
		}
	}

	// Always bind headers first (they're always available)
	if err := c.ShouldBindHeader(v); err != nil {
		// Ignore validation errors from header binding, validate at the end
		if _, ok := err.(validator.ValidationErrors); !ok {
			return err
		}
	}

	// Bind JSON body if present
	if c.Request.ContentLength > 0 && c.ContentType() == "application/json" {
		return b.JSONBody(ctx, c, v)
	}

	// Bind form data if present (application/x-www-form-urlencoded or multipart/form-data)
	if c.Request.ContentLength > 0 && (c.ContentType() == "application/x-www-form-urlencoded" || c.ContentType() == "multipart/form-data") {
		if err := c.ShouldBind(v); err != nil {
			return err
		}
		return nil
	}

	// For non-JSON/form requests, bind query parameters
	if err := c.ShouldBindQuery(v); err != nil {
		return err
	}

	return nil
}

// BindingValidator returns a new DefaultValidator instance with validator. Used for gin binding
func (b *bindingHandler) Validator() (*DefaultValidator, error) {
	validate, err := helpers.NewValidator()
	if err != nil {
		return nil, err
	}

	return &DefaultValidator{Validate: validate}, nil
}
