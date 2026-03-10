package helpers

import (
	"context"
	"fmt"
	"net"
	"net/url"
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

	// Register custom validation for auth_method_exists
	err := validate.RegisterValidation("auth_method_exists", func(fl validator.FieldLevel) bool {
		authMethod := fl.Field().String()

		// Built-in auth methods that don't require configuration in common.auth_methods:
		// - "basic": Simple username-based authentication
		// - "saml": SAML SP authentication (requires saml config to be enabled)
		// - "oidc": OIDC RP authentication (requires oidcrp config to be enabled)
		switch authMethod {
		case "basic", "saml", "oidc":
			return true
		}

		// Navigate up the struct hierarchy to get the Cfg
		// CredentialConstructor -> map value -> map[string]*CredentialConstructor -> Common -> Cfg
		top := fl.Top()
		if top.Kind() == reflect.Ptr {
			top = top.Elem()
		}

		if top.Type().Name() != "Cfg" {
			// If not in Cfg context, fail validation
			return false
		}

		// Get Common field from Cfg, then AuthMethods from Common
		commonField := top.FieldByName("Common")
		if !commonField.IsValid() || commonField.IsNil() {
			return false
		}
		common := commonField.Elem()

		authMethodsField := common.FieldByName("AuthMethods")
		if !authMethodsField.IsValid() || authMethodsField.IsNil() {
			return false
		}

		// Check if the auth method exists in the map
		authMethodsMap := authMethodsField.Interface().(map[string]*model.AuthMethod)
		_, exists := authMethodsMap[authMethod]

		return exists
	})
	if err != nil {
		return nil, err
	}

	// Register custom validation for httpurl - validates URLs with http or https scheme
	err = validate.RegisterValidation("httpurl", func(fl validator.FieldLevel) bool {
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

	// Register custom validation for vcts_exist - validates that VCTs in AuthMethods exist in CredentialConstructors
	err = validate.RegisterValidation("vcts_exist", func(fl validator.FieldLevel) bool {
		// Get the AuthMethods map
		authMethodsField := fl.Field()
		if authMethodsField.Kind() != reflect.Map || authMethodsField.IsNil() {
			return true // Skip validation if not a map or nil
		}

		// Get the Cfg from top level
		top := fl.Top()
		if top.Kind() == reflect.Ptr {
			top = top.Elem()
		}

		if top.Type().Name() != "Cfg" {
			return false
		}

		// Get Common field from Cfg, then CredentialConstructor from Common
		commonField := top.FieldByName("Common")
		if !commonField.IsValid() || commonField.IsNil() {
			return true // No Common to validate against
		}
		common := commonField.Elem()

		credentialConstructorField := common.FieldByName("CredentialConstructor")
		if !credentialConstructorField.IsValid() || credentialConstructorField.IsNil() {
			return true // No constructors to validate against
		}

		credentialConstructors := credentialConstructorField.Interface().(map[string]*model.CredentialConstructor)

		// Build a map of VCT -> format for quick lookup
		vctToFormat := make(map[string]string)
		for _, constructor := range credentialConstructors {
			if constructor != nil && constructor.VCTM != nil && constructor.VCTM.VCT != "" {
				vctToFormat[constructor.VCTM.VCT] = constructor.Format
			}
		}

		// If no VCTMs are loaded (e.g. services like ui, mockas, registry that
		// share the config but don't load VCTM files), skip cross-reference validation.
		if len(vctToFormat) == 0 {
			return true
		}

		// Validate each AuthMethod
		authMethodsMap := authMethodsField.Interface().(map[string]*model.AuthMethod)
		for authMethodName, authMethod := range authMethodsMap {
			if authMethod == nil {
				continue
			}

			// Check each VCT in the auth method
			for _, vct := range authMethod.VCTs {
				if _, exists := vctToFormat[vct]; !exists {
					// VCT not found in any credential constructor
					return false
				}
			}

			// Validate that all VCTs in the same auth method have the same format
			if len(authMethod.VCTs) > 1 {
				firstFormat := vctToFormat[authMethod.VCTs[0]]
				for i := 1; i < len(authMethod.VCTs); i++ {
					format := vctToFormat[authMethod.VCTs[i]]
					if format != firstFormat {
						// Mixed formats in same auth method
						_ = authMethodName // Suppress unused warning
						return false
					}
				}
			}
		}

		return true
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
