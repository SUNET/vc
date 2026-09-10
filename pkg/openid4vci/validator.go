package openid4vci

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
)

// NewValidator creates a new validator
func NewValidator() (*validator.Validate, error) {
	validate := validator.New(validator.WithRequiredStructEnabled())

	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]

		if name == "-" {
			return ""
		}

		return name
	})

	// PARRequest.DynamicParams is tagged safe_key, and an unregistered tag
	// panics when the struct is first parsed - not merely when the field is
	// set - so this is required for any validation of that struct at all.
	if err := RegisterSafeKey(validate); err != nil {
		return nil, err
	}

	return validate, nil
}

// CheckSimple checks for validation error with a simpler signature
func CheckSimple(s any) error {
	validate, err := NewValidator()
	if err != nil {
		return err
	}

	if err := validate.Struct(s); err != nil {
		fmt.Println("error validating struct", err)
		return err
	}

	return nil
}
