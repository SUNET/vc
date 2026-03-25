package httphelpers

import (
	"context"
	"encoding/json"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"

	"github.com/creasty/defaults"
	"github.com/gin-gonic/gin"
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

	return json.NewDecoder(c.Request.Body).Decode(&v)
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
		if err := c.ShouldBindJSON(v); err != nil {
			return err
		}
		return nil
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
