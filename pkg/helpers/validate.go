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
	"github.com/SUNET/vc/pkg/sqlstore"
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
	// Per RFC 8252 §7.3: loopback redirect URIs MUST be allowed for native clients.
	// No DNS resolution or SSRF check: redirect URIs are never fetched
	// server-side — the browser follows them. Blocking unresolvable
	// hostnames would reject valid registrations (e.g. any TLD not in the
	// verifier's DNS).
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

		// For http/https, require a hostname. For custom schemes (native apps
		// per RFC 8252 §7.1), only require that the URI has content beyond the scheme.
		if parsedURL.Scheme == "http" || parsedURL.Scheme == "https" {
			if parsedURL.Hostname() == "" {
				return false
			}
		} else {
			// Custom scheme: must have an opaque part or path (e.g. com.example.app:/callback)
			if parsedURL.Host == "" && parsedURL.Path == "" && parsedURL.Opaque == "" {
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

	// NOTE: a "single_proof_type" custom validator used to be registered here
	// to enforce that CredentialRequest.Proofs declares exactly one proof
	// type. It was removed: confirmed live (via a canary panic that never
	// fired) that go-playground/validator was not actually invoking it for
	// requests going through pkg/httphelpers' gin binding path, for reasons
	// not tracked down within the time spent investigating -- every request
	// with a non-nil Proofs field failed with "single_proof_type" regardless
	// of the field's actual contents or this function's logic, which broke
	// the pid self-issuance credential_configuration_id path (it has no
	// credential_identifier to route around it) and any other caller not
	// using the deprecated singular Proof field. The same check now lives in
	// CredentialRequest.Validate() (pkg/openid4vci/credential.go), which
	// reliably runs for this request instead.

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

	// doc:constraint name="mongo_uri_required" struct="Common" applies="Mongo,SQL,HA" description="Mongo.URI is required when SQL.Backend is 'mongo' (the default primary-store backend) or when HA.Enable is true (HA caching has no relational backend yet, so it always uses Mongo); not required for a pure relational deployment (a non-mongo SQL.Backend with HA disabled)."
	validate.RegisterStructValidation(func(sl validator.StructLevel) {
		cfg := sl.Current().Interface().(model.Common)
		backend := cfg.SQL.Backend
		if backend == "" {
			backend = "mongo"
		}
		if (backend == "mongo" || cfg.HA.Enable) && cfg.Mongo.URI == "" {
			sl.ReportError(cfg.Mongo.URI, "Mongo.URI", "URI", "mongo_uri_required", "")
		}
	}, model.Common{})

	// doc:constraint name="sql_backend_config_required" struct="SQL" applies="Postgres,MariaDB" description="When Backend is 'postgres', Postgres.Host and Postgres.User are required; when Backend is 'mariadb', MariaDB.Host and MariaDB.User are required. Enforced at the SQL struct level (rather than required_if tags on PostgresConfig/MariaDBConfig themselves) because 'Backend' lives on the parent SQL struct, not on those nested structs."
	validate.RegisterStructValidation(func(sl validator.StructLevel) {
		cfg := sl.Current().Interface().(sqlstore.SQL)
		switch cfg.Backend {
		case "postgres":
			if cfg.Postgres == nil {
				return // reported separately by SQL.Postgres's own required_if tag
			}
			if cfg.Postgres.Host == "" {
				sl.ReportError(cfg.Postgres.Host, "Postgres.Host", "Host", "postgres_host_required", "")
			}
			if cfg.Postgres.User == "" {
				sl.ReportError(cfg.Postgres.User, "Postgres.User", "User", "postgres_user_required", "")
			}
		case "mariadb":
			if cfg.MariaDB == nil {
				return // reported separately by SQL.MariaDB's own required_if tag
			}
			if cfg.MariaDB.Host == "" {
				sl.ReportError(cfg.MariaDB.Host, "MariaDB.Host", "Host", "mariadb_host_required", "")
			}
			if cfg.MariaDB.User == "" {
				sl.ReportError(cfg.MariaDB.User, "MariaDB.User", "User", "mariadb_user_required", "")
			}
		}
	}, sqlstore.SQL{})

	// doc:constraint name="saml_metadata_source" struct="SAMLSP" applies="MDQServer,StaticIDPMetadata" description="Exactly one of mdq_server or static_idp_metadata must be set when enable is true. Mutual exclusivity is enforced by field tags."
	validate.RegisterStructValidation(func(sl validator.StructLevel) {
		cfg := sl.Current().Interface().(model.SAMLSP)
		if !cfg.Enable {
			return
		}
		if cfg.MDQServer == "" && cfg.StaticIDPMetadata == nil {
			sl.ReportError(cfg.MDQServer, "MDQServer", "MDQServer", "saml_metadata_source_required", "")
		}
	}, model.SAMLSP{})

	// doc:constraint name="oidc_openid_scope" struct="OIDCRP" applies="Scopes" description="The 'openid' scope is mandatory when OIDC RP is enabled."
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

	// doc:constraint name="api_auth_exclusive" struct="APIAuth" applies="JWKS,OIDC" description="JWKS and OIDC are mutually exclusive — enable at most one."
	// doc:constraint name="api_auth_rules_require_auth" struct="APIAuth" applies="Rules,RulesFile" description="Authorization rules require JWKS or OIDC to be enabled."
	// Register struct-level validation for APIAuth
	validate.RegisterStructValidation(func(sl validator.StructLevel) {
		cfg := sl.Current().Interface().(model.APIAuth)
		// JWKS and OIDC are mutually exclusive
		if cfg.JWKS.Enable && cfg.OIDC.Enable {
			sl.ReportError(cfg.JWKS.Enable, "JWKS", "JWKS", "api_auth_jwks_oidc_exclusive", "")
		}
		// Rules require an auth mode
		hasAuth := cfg.JWKS.Enable || cfg.OIDC.Enable
		if !hasAuth {
			if len(cfg.Rules) > 0 {
				sl.ReportError(cfg.Rules, "Rules", "Rules", "api_auth_rules_require_auth", "")
			}
			if cfg.RulesFile != "" {
				sl.ReportError(cfg.RulesFile, "RulesFile", "RulesFile", "api_auth_rules_require_auth", "")
			}
		}
	}, model.APIAuth{})

	// doc:constraint name="jwks_source_required" struct="APIAuthJWKS" applies="JWKSURL,JWKSFilePath" description="Exactly one of jwks_url or jwks_file_path must be set when enable is true."
	validate.RegisterStructValidation(func(sl validator.StructLevel) {
		cfg := sl.Current().Interface().(model.APIAuthJWKS)
		if !cfg.Enable {
			return
		}
		if cfg.JWKSURL == "" && cfg.JWKSFilePath == "" {
			sl.ReportError(cfg.JWKSURL, "JWKSURL", "JWKSURL", "jwks_source_required", "")
		}
	}, model.APIAuthJWKS{})

	// Register struct-level validation for DataSources: openid4vp auth_scopes must not self-reference
	validate.RegisterStructValidation(func(sl validator.StructLevel) {
		ds := sl.Current().Interface().(model.DataSources)
		for scope, cred := range ds.Datastore.Scopes {
			switch cred.AuthProvider {
			case model.AuthProviderOpenID4VP:
				if _, selfRef := cred.AuthScopes[scope]; selfRef {
					sl.ReportError(cred.AuthScopes, "AuthScopes", "AuthScopes", "auth_scopes_self_reference", scope)
				}
				if len(cred.AuthScopes) == 0 {
					sl.ReportError(cred.AuthScopes, "AuthScopes", "AuthScopes", "auth_scopes_required_for_openid4vp", scope)
				}
				for name, entry := range cred.AuthScopes {
					if len(entry.AuthClaims) == 0 {
						sl.ReportError(entry.AuthClaims, "AuthClaims", "AuthClaims", "auth_claims_required_for_auth_scope", name)
					}
				}
				if len(cred.AuthClaims) > 0 {
					sl.ReportError(cred.AuthClaims, "AuthClaims", "AuthClaims", "auth_claims_not_allowed_for_openid4vp", scope)
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
