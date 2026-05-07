package helpers

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/SUNET/vc/pkg/trace"

	"github.com/go-playground/validator/v10"
	"github.com/kaptinlin/jsonschema"
)

// NewValidator creates a new validator
func NewValidator() (*validator.Validate, error) {
	validate := validator.New(validator.WithRequiredStructEnabled())

	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		// Prefer yaml tag (used by config structs), fall back to json tag
		name := strings.SplitN(fld.Tag.Get("yaml"), ",", 2)[0]
		if name == "" || name == "-" {
			name = strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		}

		if name == "" || name == "-" {
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
	// Also blocks private/loopback IPs to prevent SSRF since these URIs may be fetched server-side.
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

		hostname := parsedURL.Hostname()

		// Block localhost
		if strings.ToLower(hostname) == "localhost" {
			return false
		}

		// Resolve hostname and block private/loopback IPs
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

	// Register custom validation for redirect_uri - validates OAuth 2.0 redirect URI format.
	// Used by OIDC dynamic client registration (RFC 7591) for redirect_uris.
	// Per RFC 6749: must have a scheme and must not contain a fragment.
	// Also blocks private/loopback IPs to prevent SSRF if the URI is ever fetched server-side.
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

		hostname := parsedURL.Hostname()
		if hostname == "" {
			return false
		}

		// Block localhost
		if strings.ToLower(hostname) == "localhost" {
			return false
		}

		// Resolve hostname and block private/loopback IPs
		ips, err := net.LookupIP(hostname)
		if err != nil {
			// If we can't resolve, allow — it may be a custom scheme (e.g. eudi-wallet://)
			// Custom schemes won't have a resolvable hostname
			return parsedURL.Scheme != "http" && parsedURL.Scheme != "https"
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
		f, err := os.Open(filepath.Clean(path))
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

	// Register custom validation for safe_key - validates map keys used in MongoDB field paths.
	// Only allows simple alphanumeric/underscore keys starting with a letter (max 64 chars).
	// Prevents field-path injection via dots or MongoDB operator prefixes ($).
	safeKeyRe := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,63}$`)
	err = validate.RegisterValidation("safe_key", func(fl validator.FieldLevel) bool {
		return safeKeyRe.MatchString(fl.Field().String())
	})
	if err != nil {
		return nil, err
	}

	// Register struct-level validation for SAMLConfig
	validate.RegisterStructValidation(func(sl validator.StructLevel) {
		cfg := sl.Current().Interface().(model.SAMLSP)
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
	}, model.SAMLSP{})

	// Register struct-level validation for OIDCRPConfig
	validate.RegisterStructValidation(func(sl validator.StructLevel) {
		cfg := sl.Current().Interface().(model.OIDCRP)
		if !cfg.Enable {
			return
		}

		// 'openid' scope is mandatory for OIDC
		if !slices.Contains(cfg.Scopes, "openid") {
			sl.ReportError(cfg.Scopes, "Scopes", "Scopes", "oidc_openid_scope_required", "")
		}
	}, model.OIDCRP{})

	// Register struct-level validation for APIAuth: JWKS and OIDC are mutually exclusive
	validate.RegisterStructValidation(func(sl validator.StructLevel) {
		cfg := sl.Current().Interface().(model.APIAuth)
		if cfg.JWKS.Enable && cfg.OIDC.Enable {
			sl.ReportError(cfg.JWKS.Enable, "JWKS", "JWKS", "api_auth_jwks_oidc_exclusive", "")
		}
	}, model.APIAuth{})

	// Register struct-level validation for DataSources: openid4vp auth_scopes must not self-reference
	validate.RegisterStructValidation(func(sl validator.StructLevel) {
		ds := sl.Current().Interface().(model.DataSources)
		for scope, cred := range ds.Datastore.Scopes {
			switch cred.AuthProvider {
			case model.AuthProviderOpenID4VP:
				if slices.Contains(cred.AuthScopes, scope) {
					sl.ReportError(cred.AuthScopes, "AuthScopes", "AuthScopes", "auth_scopes_self_reference", scope)
				}
				if len(cred.AuthScopes) == 0 {
					sl.ReportError(cred.AuthScopes, "AuthScopes", "AuthScopes", "auth_scopes_required_for_openid4vp", scope)
				}
				if len(cred.AuthClaims) == 0 {
					sl.ReportError(cred.AuthClaims, "AuthClaims", "AuthClaims", "auth_claims_required_for_identity_lookup", scope)
				}
			case model.AuthProviderSAML, model.AuthProviderOIDC:
				if len(cred.AuthClaims) == 0 {
					sl.ReportError(cred.AuthClaims, "AuthClaims", "AuthClaims", "auth_claims_required_for_identity_lookup", scope)
				}
				if len(cred.AuthScopes) > 0 {
					sl.ReportError(cred.AuthScopes, "AuthScopes", "AuthScopes", "auth_scopes_only_for_openid4vp", scope)
				}
			}
		}
	}, model.DataSources{})

	// Register struct-level validation for OpenID4VPConfig: supported_credentials scopes must cover all client scopes
	validate.RegisterStructValidation(func(sl validator.StructLevel) {
		cfg := sl.Current().Interface().(model.OpenID4VPConfig)

		// Collect the union of all scopes from supported_credentials
		supportedScopes := make(map[string]bool)
		for _, cred := range cfg.SupportedCredentials {
			for _, scope := range cred.Scopes {
				supportedScopes[scope] = true
			}
		}

		// Collect the union of all client scopes
		clientScopes := make(map[string]bool)
		for _, client := range cfg.Clients {
			for _, scope := range client.Scopes {
				clientScopes[scope] = true
			}
		}

		// Every client scope must exist in supported_credentials
		for scope := range clientScopes {
			if !supportedScopes[scope] {
				sl.ReportError(cfg.Clients, "Clients", "Clients", "client_scope_not_in_supported_credentials", scope)
			}
		}

		// Every supported_credentials scope must be used by at least one client
		for scope := range supportedScopes {
			if !clientScopes[scope] {
				sl.ReportError(cfg.SupportedCredentials, "SupportedCredentials", "SupportedCredentials", "supported_credential_scope_unused", scope)
			}
		}
	}, model.OpenID4VPConfig{})

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
