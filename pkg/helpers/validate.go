package helpers

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"time"
	"vc/pkg/logger"
	"vc/pkg/model"

	"vc/pkg/trace"

	"github.com/go-playground/validator/v10"
	"github.com/kaptinlin/jsonschema"
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

	// Register custom validation for httpurl - validates URLs with http or https scheme
	err := validate.RegisterValidation("httpurl", func(fl validator.FieldLevel) bool {
		urlStr := fl.Field().String()
		if urlStr == "" {
			return false
		}

		parsedURL, err := url.Parse(urlStr)
		if err != nil {
			return false
		}

		// Ensure scheme is either http or https
		scheme := strings.ToLower(parsedURL.Scheme)
		if scheme != "http" && scheme != "https" {
			return false
		}

		// Ensure host is present (url.Parse accepts "http://" without host)
		if parsedURL.Host == "" {
			return false
		}

		return true
	})
	if err != nil {
		return nil, err
	}

	// Register custom validation for httpsurl - validates URLs with https scheme and host.
	// Used by OIDC dynamic client registration (RFC 7591 Section 2) for metadata URIs
	// such as logo_uri, client_uri, policy_uri, and tos_uri.
	err = validate.RegisterValidation("httpsurl", func(fl validator.FieldLevel) bool {
		urlStr := fl.Field().String()
		if urlStr == "" {
			return false
		}

		parsedURL, err := url.Parse(urlStr)
		if err != nil {
			return false
		}

		if parsedURL.Scheme != "https" {
			return false
		}

		if parsedURL.Host == "" {
			return false
		}

		if parsedURL.Fragment != "" {
			return false
		}

		return true
	})
	if err != nil {
		return nil, err
	}

	// Register custom validation for redirect_uri - validates OAuth 2.0 redirect URI format.
	// Used by OIDC dynamic client registration (RFC 7591) for redirect_uris.
	// Per RFC 6749: must have a scheme and must not contain a fragment.
	err = validate.RegisterValidation("redirect_uri", func(fl validator.FieldLevel) bool {
		urlStr := fl.Field().String()
		if urlStr == "" {
			return false
		}

		parsedURL, err := url.Parse(urlStr)
		if err != nil {
			return false
		}

		if parsedURL.Scheme == "" {
			return false
		}

		if parsedURL.Fragment != "" {
			return false
		}

		return true
	})
	if err != nil {
		return nil, err
	}

	// Register custom validation for safe_uri - validates URI with SSRF prevention.
	// Blocks private IP ranges, loopback, link-local addresses, and localhost.
	// No fragment allowed. When combined with httpsurl, also enforces HTTPS scheme.
	err = validate.RegisterValidation("safe_uri", func(fl validator.FieldLevel) bool {
		urlStr := fl.Field().String()
		if urlStr == "" {
			return false
		}

		parsedURL, err := url.Parse(urlStr)
		if err != nil {
			return false
		}

		if parsedURL.Scheme == "" {
			return false
		}

		if parsedURL.Fragment != "" {
			return false
		}

		hostname := parsedURL.Hostname()
		if hostname == "" {
			return false
		}

		// Block localhost
		if strings.ToLower(hostname) == "localhost" {
			return false
		}

		// Resolve hostname and check IPs
		ips, err := net.LookupIP(hostname)
		if err != nil {
			return false
		}

		for _, ip := range ips {
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
				return false
			}
		}

		return true
	})
	if err != nil {
		return nil, err
	}

	// Register custom validation for image_png - validates that the file exists and is a PNG image.
	// Uses net/http.DetectContentType on the first 512 bytes to check the MIME type.
	err = validate.RegisterValidation("image_png", func(fl validator.FieldLevel) bool {
		path := fl.Field().String()
		if path == "" {
			return false
		}
		f, err := os.Open(path)
		if err != nil {
			return false
		}
		defer f.Close()
		header := make([]byte, 512)
		n, _ := f.Read(header)
		return http.DetectContentType(header[:n]) == "image/png"
	})
	if err != nil {
		return nil, err
	}

	// Register struct-level validation for SAMLConfig
	validate.RegisterStructValidation(func(sl validator.StructLevel) {
		cfg := sl.Current().Interface().(model.SAMLConfig)
		if !cfg.Enable {
			return
		}

		hasMDQ := cfg.MDQServer != ""
		hasStatic := cfg.StaticIDPMetadata != nil

		if !hasMDQ && !hasStatic {
			sl.ReportError(cfg.MDQServer, "MDQServer", "MDQServer", "saml_metadata_source_required", "")
		}
		if hasMDQ && hasStatic {
			sl.ReportError(cfg.MDQServer, "MDQServer", "MDQServer", "saml_metadata_source_exclusive", "")
		}
	}, model.SAMLConfig{})

	// Register struct-level validation for OIDCRPConfig
	validate.RegisterStructValidation(func(sl validator.StructLevel) {
		cfg := sl.Current().Interface().(model.OIDCRPConfig)
		if !cfg.Enable {
			return
		}

		// 'openid' scope is mandatory for OIDC
		if !slices.Contains(cfg.Scopes, "openid") {
			sl.ReportError(cfg.Scopes, "Scopes", "Scopes", "oidc_openid_scope_required", "")
		}
	}, model.OIDCRPConfig{})

	// Register struct-level validation for Common: credential constructor constraints
	validate.RegisterStructValidation(func(sl validator.StructLevel) {
		common := sl.Current().Interface().(model.Common)
		for scope, cc := range common.CredentialConstructor {
			if cc == nil {
				continue
			}
			// auth_scopes must not reference self
			if slices.Contains(cc.AuthScopes, scope) {
				sl.ReportError(cc.AuthScopes, "AuthScopes", "AuthScopes", "auth_scopes_self_reference", scope)
			}
			// openid4vp requires non-empty auth_scopes and auth_claims
			if cc.AuthMethod == "openid4vp" {
				if len(cc.AuthScopes) == 0 {
					sl.ReportError(cc.AuthScopes, "AuthScopes", "AuthScopes", "auth_scopes_required_for_openid4vp", scope)
				}
				if len(cc.AuthClaims) == 0 {
					sl.ReportError(cc.AuthClaims, "AuthClaims", "AuthClaims", "auth_claims_required_for_openid4vp", scope)
				}
			}
		}
	}, model.Common{})

	return validate, nil
}

// Check checks for validation error
func Check(ctx context.Context, cfg *model.Cfg, s any, log *logger.Log) error {
	tp, err := trace.New(ctx, cfg, "vc", log)
	if err != nil {
		return err
	}

	_, span := tp.Start(ctx, "helpers:check")
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

// ValidateDocumentData validates DocumentData against the schemaRef in MetaData.DocumentDataValidationRef
func ValidateDocumentData(ctx context.Context, completeDocument *model.CompleteDocument, log *logger.Log) error {
	_, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	if completeDocument.Meta.DocumentDataValidationRef == "" {
		return nil
	}

	if completeDocument.DocumentData == nil {
		return fmt.Errorf("no document data")
	}

	compiler := jsonschema.NewCompiler()

	jsonSchema, err := getValidationSchema(completeDocument.Meta.DocumentDataValidationRef, compiler)
	if err != nil {
		return err
	}

	result := jsonSchema.Validate(completeDocument.DocumentData)

	if !result.IsValid() {
		return NewErrorFromError(result)
	}

	return nil
}
