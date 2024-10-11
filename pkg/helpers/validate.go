package helpers

import (
	"context"
	"reflect"
	"strings"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"github.com/go-playground/validator/v10"
)

// NewValidator creates a new validator
func NewValidator() (*validator.Validate, error) {
	validate := validator.New()

	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]

		if name == "-" {
			return ""
		}

		return name
	})

	return validate, nil
}

// Check checks for validation error
func Check(ctx context.Context, cfg *model.Cfg, s any, log *logger.Log) error {
	tp, err := trace.New(ctx, cfg, "vc", log)
	if err != nil {
		return err
	}

	ctx, span := tp.Start(ctx, "helpers:check")
	defer span.End()

	validate, err := NewValidator()
	if err != nil {
		return err
	}

	if err := validate.Struct(s); err != nil {
		return NewErrorFromError(err)
	}

	return nil
}

// CheckSimple checks for validation error with a simpler signature
func CheckSimple(s any) error {
	validate, err := NewValidator()
	if err != nil {
		return err
	}

	if err := validate.Struct(s); err != nil {
		return NewErrorFromError(err)
	}

	return nil
}
