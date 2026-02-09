package model

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"time"
	"vc/pkg/oauth2"
	"vc/pkg/openid4vci"
	"vc/pkg/openid4vp"
	"vc/pkg/pki"
	"vc/pkg/sdjwtvc"
)

// APIServer holds the api server configuration
type APIServer struct {
	Addr      string    `yaml:"addr" validate:"required" default:":8080"`
	TLS       TLS       `yaml:"tls" validate:"omitempty"`
	BasicAuth BasicAuth `yaml:"basic_auth"`
	CORS      *CORS     `yaml:"cors,omitempty" validate:"omitempty"`
}

// CORS holds the CORS configuration
type CORS struct {
	AllowedOrigins []string `yaml:"allowed_origins" validate:"omitempty" default:"[]"`
}

// TLS holds the tls configuration
type TLS struct {
	Enabled      bool   `yaml:"enabled" default:"false"`
	CertFilePath string `yaml:"cert_file_path" validate:"required"`
	KeyFilePath  string `yaml:"key_file_path" validate:"required"`
}

// Mongo holds the database configuration
type Mongo struct {
	URI string `yaml:"uri" validate:"required"`
}

// Kafka holds the kafka configuration that is common for the entire system
type Kafka struct {
	Enabled bool     `yaml:"enabled" default:"false"`
	Brokers []string `yaml:"brokers" validate:"required" default:"[\"kafka0:9092\", \"kafka1:9092\"]"`
}

// Log holds the log configuration
type Log struct {
	FolderPath string `yaml:"folder_path"`
}

// Common holds the common configuration
type Common struct {
	Production        bool                    `yaml:"production" default:"true"`
	Log               Log                     `yaml:"log"`
	Mongo             Mongo                   `yaml:"mongo" validate:"omitempty"`
	Tracing           OTEL                    `yaml:"tracing" validate:"required"`
	Kafka             Kafka                   `yaml:"kafka" validate:"omitempty"`
	CredentialOfferQR CredentialOfferQRConfig `yaml:"credential_offer_qr" validate:"omitempty"`
}

type CredentialOfferQRConfig struct {
	Type string `yaml:"type" validate:"required,oneof=credential_offer_uri credential_offer" default:"credential_offer"`
	QR   QRCfg  `yaml:"qr" validate:"omitempty"`
}

// QRCfg holds the qr configuration
type QRCfg struct {
	RecoveryLevel int `yaml:"recovery_level" validate:"required,min=0,max=3" default:"2"`
	Size          int `yaml:"size" validate:"required" default:"256"`
}

// GRPCServer holds the rpc configuration
type GRPCServer struct {
	Addr string  `yaml:"addr" validate:"required" default:":8090"`
	TLS  GRPCTLS `yaml:"tls,omitempty"`
}

// GRPCTLS holds the mTLS configuration for gRPC server
type GRPCTLS struct {
	Enabled                   bool              `yaml:"enabled" default:"false"`
	CertFilePath              string            `yaml:"cert_file_path" validate:"required_if=Enabled true" default:"/pki/grpc_server.crt"` // Server certificate
	KeyFilePath               string            `yaml:"key_file_path" validate:"required_if=Enabled true" default:"/pki/grpc_server.key"`  // Server private key
	ClientCAPath              string            `yaml:"client_ca_path" validate:"required_if=Enabled true" default:"/pki/client_ca.crt"`   // CA to verify client certificates (for mTLS)
	AllowedClientFingerprints map[string]string `yaml:"allowed_client_fingerprints"`                                                         // SHA256 fingerprint -> friendly name (e.g., "a1b2c3..." -> "issuer-prod")
}

// JWTAttribute holds the jwt attribute configuration.
// In a later state this should be placed under authentic source in order to issue credentials based on that configuration.
type JWTAttribute struct {
	// Issuer of the token example: https://issuer.sunet.se
	Issuer string `yaml:"issuer" validate:"required"`

	// StaticHost is the static host of the issuer, expose static files, like pictures.
	StaticHost string `yaml:"static_host" validate:"omitempty"`

	// EnableNotBefore states the time not before which the token is valid
	EnableNotBefore bool `yaml:"enable_not_before" default:"false"`

	// Valid duration of the token in seconds
	ValidDuration int64 `yaml:"valid_duration" validate:"required_with=EnableNotBefore" default:"3600"`

	// VerifiableCredentialType URL example: https://credential.sunet.se/identity_credential
	VerifiableCredentialType string `yaml:"verifiable_credential_type" validate:"required"`

	// Status status of the Verifiable Credential
	Status string `yaml:"status"`

	// Kid key id of the signing key
	Kid string `yaml:"kid"`
}

// SAMLConfig holds SAML Service Provider configuration for the issuer
type SAMLConfig struct {
	// Enabled turns on SAML support (default: false)
	Enabled bool `yaml:"enabled" default:"false"`

	// EntityID is the SAML SP entity identifier (typically the metadata URL)
	EntityID string `yaml:"entity_id" validate:"required_if=Enabled true"`

	// MetadataURL is the public URL where SP metadata is served (optional, auto-generated if empty)
	MetadataURL string `yaml:"metadata_url,omitempty"`

	// MDQServer is the base URL for MDQ (Metadata Query Protocol) server
	// Example: "https://md.example.org/entities/" (must end with /)
	// Mutually exclusive with StaticIDPMetadata
	MDQServer string `yaml:"mdq_server,omitempty"`

	// StaticIDPMetadata configures a single static IdP as alternative to MDQ
	// Mutually exclusive with MDQServer
	StaticIDPMetadata *StaticIDPConfig `yaml:"static_idp_metadata,omitempty"`

	// CertificatePath is the path to X.509 certificate for SAML signing/encryption
	CertificatePath string `yaml:"certificate_path" validate:"required_if=Enabled true"`

	// PrivateKeyPath is the path to private key for SAML signing/encryption
	PrivateKeyPath string `yaml:"private_key_path" validate:"required_if=Enabled true"`

	// ACSEndpoint is the Assertion Consumer Service URL where IdP sends SAML responses
	// Example: "https://issuer.example.com/saml/acs"
	ACSEndpoint string `yaml:"acs_endpoint" validate:"required_if=Enabled true"`

	// SessionDuration in seconds (default: 3600)
	SessionDuration int `yaml:"session_duration"`

	// CredentialMappings defines how to map external attributes to credential claims
	// Key: credential type identifier (e.g., "pid", "diploma")
	// Maps to credential_constructor keys and OpenID4VCI credential_configuration_ids
	CredentialMappings map[string]CredentialMapping `yaml:"credential_mappings" validate:"required_if=Enabled true"`

	// MetadataCacheTTL in seconds (default: 3600) - how long to cache IdP metadata from MDQ
	MetadataCacheTTL int `yaml:"metadata_cache_ttl"`
}

// StaticIDPConfig holds configuration for a single static IdP connection
type StaticIDPConfig struct {
	// EntityID is the IdP entity identifier
	EntityID string `yaml:"entity_id" validate:"required"`

	// MetadataPath is the file path to IdP metadata XML (mutually exclusive with MetadataURL)
	MetadataPath string `yaml:"metadata_path,omitempty"`

	// MetadataURL is the HTTP(S) URL to fetch IdP metadata from (mutually exclusive with MetadataPath)
	MetadataURL string `yaml:"metadata_url,omitempty"`
}

// Validate validates SAMLConfig for consistency
func (c *SAMLConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	// Check mutual exclusivity of MDQ and static IdP
	hasMDQ := c.MDQServer != ""
	hasStatic := c.StaticIDPMetadata != nil

	if !hasMDQ && !hasStatic {
		return errors.New("SAML enabled but neither mdq_server nor static_idp_metadata configured")
	}

	if hasMDQ && hasStatic {
		return errors.New("SAML configuration cannot have both mdq_server and static_idp_metadata")
	}

	// Validate static IdP config if present
	if hasStatic {
		if c.StaticIDPMetadata.EntityID == "" {
			return errors.New("static_idp_metadata.entity_id is required")
		}

		hasPath := c.StaticIDPMetadata.MetadataPath != ""
		hasURL := c.StaticIDPMetadata.MetadataURL != ""

		if !hasPath && !hasURL {
			return errors.New("static_idp_metadata requires either metadata_path or metadata_url")
		}

		if hasPath && hasURL {
			return errors.New("static_idp_metadata cannot have both metadata_path and metadata_url")
		}
	}

	return nil
}

// OIDCRPConfig holds OIDC Relying Party configuration for credential issuance
type OIDCRPConfig struct {
	// Enabled turns on OIDC RP support (default: false)
	Enabled bool `yaml:"enabled" default:"false"`

	// Dynamic Registration (RFC 7591) support
	// If enabled, the OIDC RP will attempt to register itself with the OIDC Provider
	// instead of using pre-configured client credentials
	DynamicRegistration DynamicRegistrationConfig `yaml:"dynamic_registration"`

	// ClientID is the OIDC client identifier (required if not using dynamic registration)
	ClientID string `yaml:"client_id"`

	// ClientSecret is the OIDC client secret (required if not using dynamic registration)
	ClientSecret string `yaml:"client_secret"`

	// RedirectURI is the callback URL where the OIDC Provider sends the authorization response
	// Example: "https://issuer.example.com/oidcrp/callback"
	RedirectURI string `yaml:"redirect_uri" validate:"required_if=Enabled true"`

	// IssuerURL is the OIDC Provider's issuer URL for discovery
	// Example: "https://accounts.google.com"
	// Used for .well-known/openid-configuration discovery
	IssuerURL string `yaml:"issuer_url" validate:"required_if=Enabled true"`

	// Scopes are the OAuth2/OIDC scopes to request
	// Default: ["openid", "profile", "email"]
	Scopes []string `yaml:"scopes" validate:"required,min=1,dive,required" default:"[\"openid\", \"profile\", \"email\"]"`

	// SessionDuration in seconds (default: 3600)
	SessionDuration int `yaml:"session_duration" default:"3600"`

	// Client metadata for dynamic registration or display purposes
	ClientName string   `yaml:"client_name,omitempty"`
	ClientURI  string   `yaml:"client_uri,omitempty"`
	LogoURI    string   `yaml:"logo_uri,omitempty"`
	Contacts   []string `yaml:"contacts,omitempty"`
	TosURI     string   `yaml:"tos_uri,omitempty"`
	PolicyURI  string   `yaml:"policy_uri,omitempty"`

	// CredentialMappings defines how to map OIDC claims to credential claims
	// Key: credential type identifier (e.g., "pid", "diploma")
	// Maps to credential_constructor keys and OpenID4VCI credential_configuration_ids
	CredentialMappings map[string]CredentialMapping `yaml:"credential_mappings" validate:"required_if=Enabled true"`
}

// DynamicRegistrationConfig configures RFC 7591 dynamic client registration
type DynamicRegistrationConfig struct {
	// Enabled turns on dynamic client registration
	// If true, ClientID and ClientSecret from OIDCRPConfig are ignored
	Enabled bool `yaml:"enabled" default:"false"`

	// InitialAccessToken is an optional bearer token for registration
	// Required by some OIDC Providers (e.g., Keycloak)
	InitialAccessToken string `yaml:"initial_access_token,omitempty"`

	// StoragePath is where registered client credentials are cached
	// Example: "/var/lib/vc/oidcrp-registration.json"
	// If empty, credentials are not persisted (re-register on restart)
	StoragePath string `yaml:"storage_path,omitempty"`
}

// Validate validates OIDCRPConfig for consistency
func (c *OIDCRPConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	// Ensure 'openid' scope is present (mandatory for OIDC)
	if !slices.Contains(c.Scopes, "openid") {
		return errors.New("OIDC scopes must include 'openid'")
	}

	// Validate that either static credentials or dynamic registration is configured
	if !c.DynamicRegistration.Enabled {
		if c.ClientID == "" || c.ClientSecret == "" {
			return errors.New("OIDC RP requires either client_id/client_secret or dynamic_registration.enabled=true")
		}
	}

	return nil
}

// CredentialMapping defines how to issue a specific credential type via SAML
// The credential type identifier (map key) is used in API requests and session state
type CredentialMapping struct {
	// CredentialConfigID is the OpenID4VCI credential configuration identifier
	// Example: "urn:eudi:pid:1"
	CredentialConfigID string `yaml:"credential_config_id" validate:"required"`

	// Attributes maps SAML attribute OIDs to claim paths with transformation rules
	// Example: "urn:oid:2.5.4.42" -> {claim: "identity.given_name", required: true}
	Attributes map[string]AttributeConfig `yaml:"attributes" validate:"required"`

	// DefaultIdP is the optional default IdP entityID for this credential type
	DefaultIdP string `yaml:"default_idp,omitempty"`
}

// AttributeConfig defines how a single external attribute maps to a credential claim
// Generic across protocols (SAML, OIDC, etc.) - uses protocol-specific identifiers as keys
type AttributeConfig struct {
	// Claim is the target claim name (supports dot-notation for nesting)
	// Example: "given_name" or "identity.given_name"
	Claim string `yaml:"claim" validate:"required"`

	// Required indicates if this attribute must be present in the assertion/response
	Required bool `yaml:"required" default:"false"`

	// Transform is an optional transformation to apply
	// Supported: "lowercase", "uppercase", "trim"
	Transform string `yaml:"transform,omitempty" validate:"omitempty,oneof=lowercase uppercase trim"`

	// Default is an optional default value if attribute is missing
	Default string `yaml:"default,omitempty"`
}

// Issuer holds the issuer configuration
type Issuer struct {
	APIServer      APIServer      `yaml:"api_server" validate:"required"`
	GRPCServer     GRPCServer     `yaml:"grpc_server" validate:"required"`
	KeyConfig      *pki.KeyConfig `yaml:"key_config" validate:"required"`
	JWTAttribute   JWTAttribute   `yaml:"jwt_attribute" validate:"required"`
	IssuerURL      string         `yaml:"issuer_url" validate:"required"`
	RegistryClient GRPCClientTLS  `yaml:"registry_client" validate:"omitempty"`
	MDoc           *MDocConfig    `yaml:"mdoc" validate:"omitempty"`      // mDL/mdoc configuration
	AuditLog       *AuditLog      `yaml:"audit_log" validate:"omitempty"` // Audit log webhook configuration
}

// AuditLog holds audit log configuration for multiple destinations
type AuditLog struct {
	Enabled      bool          `yaml:"enabled" default:"false"`
	Destinations []string      `yaml:"destinations" validate:"required_if=Enabled true,min=1"`
	FileSyncInterval time.Duration `yaml:"file_sync_interval" default:"5s"` // File destinations: 0 = fsync every write, >0 = periodic batched fsync at interval
	// Destinations can be:
	//   - "console" or "stdout": write to standard output
	//   - File path (e.g., "/var/log/audit.log"): write to file
	//   - URL (http:// or https://): send webhook POST request
}

// MDocConfig holds mDL (ISO 18013-5) issuer configuration
type MDocConfig struct {
	CertificateChainPath string        `yaml:"certificate_chain_path" validate:"required"` // Path to PEM certificate chain
	DefaultValidity      time.Duration `yaml:"default_validity" default:"8760h"`           // Default credential validity (365 days)
	DigestAlgorithm      string        `yaml:"digest_algorithm" default:"SHA-256"`         // "SHA-256", "SHA-384", or "SHA-512"
}

// GRPCClientTLS holds mTLS configuration for gRPC client connections
type GRPCClientTLS struct {
	Addr         string `yaml:"addr" validate:"required"` // Registry gRPC server address
	TLS          bool   `yaml:"tls" default:"false"`      // Enable TLS
	CertFilePath string `yaml:"cert_file_path"`           // Client certificate for mTLS
	KeyFilePath  string `yaml:"key_file_path"`            // Client private key for mTLS
	CAFilePath   string `yaml:"ca_file_path"`             // CA certificate to verify server
	ServerName   string `yaml:"server_name"`              // Server name for TLS verification (optional)
}

// PKCS11 holds PKCS#11 HSM configuration
type PKCS11 struct {
	ModulePath string `yaml:"module_path" default:"/usr/lib/softhsm/libsofthsm2.so"`
	SlotID     uint   `yaml:"slot_id" default:"0"`
	PIN        string `yaml:"pin" validate:"required"`
	KeyLabel   string `yaml:"key_label" validate:"required"`
	KeyID      string `yaml:"key_id" validate:"required"`
}

// Registry holds the registry configuration
type Registry struct {
	APIServer        APIServer        `yaml:"api_server" validate:"required"`
	PublicURL        string           `yaml:"public_url" validate:"required,httpurl"`
	GRPCServer       GRPCServer       `yaml:"grpc_server" validate:"required"`
	TokenStatusLists TokenStatusLists `yaml:"token_status_lists,omitempty" validate:"omitempty"`
	AdminGUI         AdminGUI         `yaml:"admin_gui,omitempty" validate:"omitempty"`
}

// AdminGUI holds the admin GUI configuration
type AdminGUI struct {
	Enabled       bool   `yaml:"enabled" default:"true"`
	Username      string `yaml:"username" validate:"required_if=Enabled true" default:"admin"`
	Password      string `yaml:"password" validate:"required_if=Enabled true"`
	SessionSecret string `yaml:"session_secret" validate:"required_if=Enabled true"` // Secret for session cookies
}

// MockAS holds the mock as configuration
type MockAS struct {
	APIServer      APIServer `yaml:"api_server" validate:"required"`
	DatastoreURL   string    `yaml:"datastore_url" validate:"required"`
	BootstrapUsers []string  `yaml:"bootstrap_users" default:"[\"100\", \"102\"]"`
}

// Verifier holds the verifier configuration
type Verifier struct {
	APIServer            APIServer                     `yaml:"api_server" validate:"required"`
	GRPCServer           GRPCServer                    `yaml:"grpc_server" validate:"required"`
	PublicURL            string                        `yaml:"public_url" validate:"required,httpurl"`
	KeyConfig            *pki.KeyConfig                `yaml:"key_config" validate:"required"`
	OAuthServer          OAuthServer                   `yaml:"oauth_server" validate:"required"`
	PreferredVPFormats   *openid4vp.VPFormatsSupported `yaml:"preferred_vp_formats,omitempty"` // Informational: tells wallets what formats/algorithms are supported
	SupportedWallets     map[string]string             `yaml:"supported_wallets" validate:"omitempty"`
	OIDC                 OIDCConfig                    `yaml:"oidc" validate:"omitempty"`
	OpenID4VP            OpenID4VPConfig               `yaml:"openid4vp" validate:"omitempty"`
	DigitalCredentials   DigitalCredentialsConfig      `yaml:"digital_credentials,omitempty"`
	AuthorizationPageCSS AuthorizationPageCSSConfig    `yaml:"authorization_page_css,omitempty"`
	CredentialDisplay    CredentialDisplayConfig       `yaml:"credential_display,omitempty"`
	Trust                TrustConfig                   `yaml:"trust,omitempty"`
}

// TrustConfig holds configuration for key resolution and trust evaluation via go-trust.
// This is used for validating W3C VC Data Integrity proofs and other trust-related operations.
type TrustConfig struct {
	// GoTrustURL is the URL of the go-trust PDP (Policy Decision Point) service.
	// Example: "https://trust.example.com/pdp"
	// If empty, trust evaluation is disabled and only local DID methods will work.
	GoTrustURL string `yaml:"go_trust_url,omitempty"`

	// LocalDIDMethods specifies which DID methods can be resolved locally without go-trust.
	// Self-contained methods like "did:key" and "did:jwk" are always resolved locally.
	LocalDIDMethods []string `yaml:"local_did_methods,omitempty" default:"[\"did:key\", \"did:jwk\"]"`

	// TrustPolicies configures per-role trust evaluation policies.
	// The key is the role (e.g., "issuer", "verifier") and the value contains policy settings.
	TrustPolicies map[string]TrustPolicyConfig `yaml:"trust_policies,omitempty"`

	// Enabled controls whether trust evaluation is enabled.
	// When false, keys are resolved but not validated against trust frameworks.
	// Default: true
	Enabled bool `yaml:"enabled,omitempty" default:"true"`
}

// TrustPolicyConfig defines trust policy settings for a specific role.
type TrustPolicyConfig struct {
	// TrustFrameworks lists the accepted trust frameworks for this role.
	// Examples: "did:web", "did:ebsi", "etsi-tl", "openid-federation", "x509"
	TrustFrameworks []string `yaml:"trust_frameworks,omitempty"`

	// TrustAnchors specifies trusted root entities for this role.
	// Format depends on the trust framework (e.g., DID for did:web, federation entity for OpenID Fed).
	TrustAnchors []string `yaml:"trust_anchors,omitempty"`

	// RequireRevocationCheck enforces revocation status checking for this role.
	// Default: false
	RequireRevocationCheck bool `yaml:"require_revocation_check,omitempty" default:"false"`
}

// OIDCConfig holds OIDC-specific configuration for the verifier-proxy's role as an OpenID Provider.
// This configures how the verifier-proxy issues ID tokens and access tokens to relying parties.
// Note: This is NOT related to verifiable credential issuance (see IssuerConfig for VC issuance).
// The signing key is shared from the parent Verifier.KeyConfig.
type OIDCConfig struct {
	// Issuer is the OIDC Provider identifier that appears in ID tokens and discovery metadata.
	// This identifies the verifier-proxy itself as an OpenID Provider.
	// Must match the 'iss' claim in all issued ID tokens.
	Issuer               string `yaml:"issuer" validate:"required"`
	SessionDuration      int    `yaml:"session_duration" validate:"required" default:"3600"`        // in seconds
	CodeDuration         int    `yaml:"code_duration" validate:"required" default:"300"`            // in seconds
	AccessTokenDuration  int    `yaml:"access_token_duration" validate:"required" default:"3600"`   // in seconds
	IDTokenDuration      int    `yaml:"id_token_duration" validate:"required" default:"3600"`       // in seconds
	RefreshTokenDuration int    `yaml:"refresh_token_duration" validate:"required" default:"86400"` // in seconds
	SubjectType          string `yaml:"subject_type" validate:"required,oneof=public pairwise"`
	SubjectSalt          string `yaml:"subject_salt" validate:"required"`
}

// OpenID4VPConfig holds OpenID4VP-specific configuration
type OpenID4VPConfig struct {
	PresentationTimeout     int                         `yaml:"presentation_timeout" validate:"required" default:"300"`
	SupportedCredentials    []SupportedCredentialConfig `yaml:"supported_credentials" validate:"required"`
	PresentationRequestsDir string                      `yaml:"presentation_requests_dir,omitempty"` // Optional: directory with presentation request templates
}

// DigitalCredentialsConfig holds W3C Digital Credentials API configuration
type DigitalCredentialsConfig struct {
	// Enabled toggles W3C Digital Credentials API support in browser
	Enabled bool `yaml:"enabled" default:"false"`

	// UseJAR enables JWT Authorization Request (JAR) for wallet communication
	// When true, request objects are signed JWTs instead of plain JSON
	UseJAR bool `yaml:"use_jar" default:"false"`

	// PreferredFormats specifies the order of preference for credential formats
	// Supported values: "vc+sd-jwt", "dc+sd-jwt", "mso_mdoc"
	// Default: ["vc+sd-jwt", "dc+sd-jwt", "mso_mdoc"]
	PreferredFormats []string `yaml:"preferred_formats,omitempty" default:"[\"vc+sd-jwt\", \"dc+sd-jwt\", \"mso_mdoc\"]"`

	// ResponseMode specifies the OpenID4VP response mode for DC API flows
	// Supported values: "dc_api.jwt" (encrypted), "direct_post.jwt" (signed), "direct_post"
	// Default: "dc_api.jwt"
	ResponseMode string `yaml:"response_mode,omitempty" validate:"omitempty,oneof=dc_api.jwt direct_post.jwt direct_post" default:"dc_api.jwt"`

	// AllowQRFallback enables automatic fallback to QR code if DC API is unavailable
	// Default: true
	AllowQRFallback bool `yaml:"allow_qr_fallback" default:"true"`

	// DeepLinkScheme for mobile wallet integration (e.g., "eudi-wallet://")
	DeepLinkScheme string `yaml:"deep_link_scheme,omitempty"`
}

// AuthorizationPageCSSConfig allows deployers to customize the authorization page styling
type AuthorizationPageCSSConfig struct {
	// CustomCSS is inline CSS that will be injected into the authorization page
	// Allows deployers to override default styling without modifying templates
	CustomCSS string `yaml:"custom_css,omitempty"`

	// CSSFile is a path to an external CSS file to include
	// If both CustomCSS and CSSFile are provided, both are included
	CSSFile string `yaml:"css_file,omitempty"`

	// Theme sets predefined color scheme: "light" (default), "dark", "blue", "purple"
	Theme string `yaml:"theme,omitempty" validate:"omitempty,oneof=light dark blue purple" default:"light"`

	// PrimaryColor overrides the primary brand color (hex format: #667eea)
	PrimaryColor string `yaml:"primary_color,omitempty"`

	// SecondaryColor overrides the secondary brand color (hex format: #764ba2)
	SecondaryColor string `yaml:"secondary_color,omitempty"`

	// LogoURL provides a URL to a custom logo image
	LogoURL string `yaml:"logo_url,omitempty"`

	// Title overrides the page title (default: "Wallet Authorization")
	Title string `yaml:"title,omitempty"`

	// Subtitle overrides the page subtitle
	Subtitle string `yaml:"subtitle,omitempty"`
}

// CredentialDisplayConfig controls whether and how credentials are displayed before being sent to RP
type CredentialDisplayConfig struct {
	// Enabled allows users to optionally view credential details before completing authorization
	// When enabled, a checkbox appears on the authorization page
	Enabled bool `yaml:"enabled" default:"false"`

	// RequireConfirmation forces users to review credentials before proceeding
	// When true, the credential display step is mandatory (checkbox is pre-checked and disabled)
	RequireConfirmation bool `yaml:"require_confirmation" default:"false"`

	// ShowRawCredential displays the raw VP token/credential in the display page
	// Useful for debugging and technical users
	ShowRawCredential bool `yaml:"show_raw_credential" default:"false"`

	// ShowClaims displays the parsed claims that will be sent to the RP
	// Recommended for transparency and user consent
	ShowClaims bool `yaml:"show_claims" default:"true"`

	// AllowEdit allows users to redact certain claims before sending to RP (future feature)
	// Currently not implemented
	AllowEdit bool `yaml:"allow_edit,omitempty" default:"false"`
}

// SupportedCredentialConfig maps credential types to OIDC scopes
type SupportedCredentialConfig struct {
	VCT    string   `yaml:"vct" validate:"required"`
	Scopes []string `yaml:"scopes" validate:"required"`
}

// BasicAuth holds the basic auth configuration
type BasicAuth struct {
	Users   map[string]string `yaml:"users"`
	Enabled bool              `yaml:"enabled" default:"false"`
}

type IssuerMetadata struct {
	AuthorizationServers                 []string                                         `yaml:"authorization_servers" validate:"omitempty"`
	DeferredCredentialEndpoint           string                                           `yaml:"deferred_credential_endpoint" validate:"omitempty"`
	NotificationEndpoint                 string                                           `yaml:"notification_endpoint" validate:"omitempty"`
	CryptographicBindingMethodsSupported []string                                         `yaml:"cryptographic_binding_methods_supported" validate:"omitempty"`
	CredentialSigningAlgValuesSupported  []string                                         `yaml:"credential_signing_alg_values_supported" validate:"omitempty"`
	ProofSigningAlgValuesSupported       []string                                         `yaml:"proof_signing_alg_values_supported" validate:"omitempty"`
	CredentialResponseEncryption         *openid4vci.MetadataCredentialResponseEncryption `yaml:"credential_response_encryption" validate:"omitempty"`
	BatchCredentialIssuance              *openid4vci.BatchCredentialIssuance              `yaml:"batch_credential_issuance" validate:"omitempty"`
	Display                              []openid4vci.MetadataDisplay                     `yaml:"display" validate:"omitempty"`
}

type CredentialOfferWallets struct {
	Label       string `yaml:"label" validate:"required"`
	RedirectURI string `yaml:"redirect_uri" validate:"required"`
}

type CredentialOffers struct {
	IssuerURL string                            `yaml:"issuer_url" validate:"required"`
	Wallets   map[string]CredentialOfferWallets `yaml:"wallets" validate:"required"`
}

// APIGW holds the datastore configuration
type APIGW struct {
	APIServer         APIServer        `yaml:"api_server" validate:"required"`
	KeyConfig         *pki.KeyConfig   `yaml:"key_config" validate:"required"`
	CredentialOffers  CredentialOffers `yaml:"credential_offers" validate:"omitempty"`
	OauthServer       OAuthServer      `yaml:"oauth_server" validate:"omitempty"`
	IssuerMetadata    IssuerMetadata   `yaml:"issuer_metadata" validate:"omitempty"`
	PublicURL         string           `yaml:"public_url" validate:"required,httpurl"`
	RegistryPublicURL string           `yaml:"registry_public_url" validate:"required,httpurl"` // Public URL of the registry service for constructing status list URIs
	SAML              SAMLConfig       `yaml:"saml,omitempty" validate:"omitempty"`
	OIDCRP            OIDCRPConfig     `yaml:"oidcrp,omitempty" validate:"omitempty"`
	IssuerClient      GRPCClientTLS    `yaml:"issuer_client" validate:"required"`   // gRPC client config for issuer
	RegistryClient    GRPCClientTLS    `yaml:"registry_client" validate:"required"` // gRPC client config for registry
}

// TokenStatusLists holds the configuration for Token Status List per draft-ietf-oauth-status-list
type TokenStatusLists struct {
	// KeyConfig holds the key configuration for signing Token Status List tokens.
	KeyConfig *pki.KeyConfig `yaml:"key_config" validate:"required"`
	// TokenRefreshInterval is how often (in seconds) new Token Status List tokens are generated. Default: 43200 (12 hours)
	TokenRefreshInterval int64 `yaml:"token_refresh_interval" default:"43200"`
	// SectionSize is the number of entries (decoys) per section. Default: 1000000 (1 million)
	SectionSize int64 `yaml:"section_size" default:"1000000"`
	// RateLimitRequestsPerMinute is the maximum requests per minute per IP for token status list endpoints. Default: 60
	RateLimitRequestsPerMinute int `yaml:"rate_limit_requests_per_minute" default:"60"`
}

// OTEL holds the opentelemetry configuration
type OTEL struct {
	Addr    string `yaml:"addr" validate:"required"`
	Timeout int64  `yaml:"timeout" default:"10"`
}

// OAuthServer holds the oauth server configuration
type OAuthServer struct {
	TokenEndpoint string         `yaml:"token_endpoint" validate:"required"`
	Clients       oauth2.Clients `yaml:"clients" validate:"required"`
}

// UI holds the user-interface configuration
type UI struct {
	APIServer                         APIServer `yaml:"api_server" validate:"required"`
	Username                          string    `yaml:"username" validate:"required"`
	Password                          string    `yaml:"password" validate:"required"`
	SessionCookieAuthenticationKey    string    `yaml:"session_cookie_authentication_key" validate:"required"`
	SessionStoreEncryptionKey         string    `yaml:"session_store_encryption_key" validate:"required"`
	SessionInactivityTimeoutInSeconds int       `yaml:"session_inactivity_timeout_in_seconds" validate:"required"`
	Services                          struct {
		APIGW struct {
			BaseURL string `yaml:"base_url"`
		} `yaml:"apigw"`
		MockAS struct {
			BaseURL string `yaml:"base_url"`
		} `yaml:"mockas"`
		Verifier struct {
			BaseURL string `yaml:"base_url"`
		} `yaml:"verifier"`
	} `yaml:"services"`
}

// Cfg is the main configuration structure for this application
type Cfg struct {
	Common      *Common                `yaml:"common"`
	AuthMethods map[string]*AuthMethod `yaml:"auth_methods" json:"auth_methods" validate:"omitempty,vcts_exist,dive"`
	APIGW       *APIGW                 `yaml:"apigw" validate:"omitempty"`
	Issuer      *Issuer                `yaml:"issuer" validate:"omitempty"`
	Verifier    *Verifier              `yaml:"verifier" validate:"omitempty"`
	Registry    *Registry              `yaml:"registry" validate:"omitempty"`
	MockAS      *MockAS                `yaml:"mock_as" validate:"omitempty"`
	UI          *UI                    `yaml:"ui" validate:"omitempty"`
	// CredentialConstructor maps OAuth2 scope values to their constructor configuration
	// Key: OAuth2 scope (e.g., "pid", "ehic", "diploma") - matches AuthorizationContext.Scope
	// The constructor contains the VCT URN and other configuration for issuing that credential type
	CredentialConstructor map[string]*CredentialConstructor `yaml:"credential_constructor" validate:"omitempty,dive"`
}

// GetCredentialConstructorAuthMethod returns the auth method for the given credential type or "basic" if not found
func (c *Cfg) GetCredentialConstructorAuthMethod(credentialType string) string {
	if constructor, ok := c.CredentialConstructor[credentialType]; ok {
		return constructor.AuthMethod
	}
	return "basic"
}

// GetCredentialConstructor returns the credential constructor for a given scope
func (c *Cfg) GetCredentialConstructor(scope string) *CredentialConstructor {
	// Direct lookup by scope (map key)
	if constructor, ok := c.CredentialConstructor[scope]; ok {
		return constructor
	}

	return nil
}

// GetFormatForVCT returns the format for a given VCT by looking it up in credential constructors
// Returns empty string if not found
func (c *Cfg) GetFormatForVCT(vct string) string {
	for _, constructor := range c.CredentialConstructor {
		if constructor != nil && constructor.GetVCT() == vct {
			return constructor.Format
		}
	}
	return ""
}

type CredentialConstructor struct {
	VCTMFilePath string                         `yaml:"vctm_file_path" json:"vctm_file_path" validate:"required"`
	VCTM         *sdjwtvc.VCTM                  `yaml:"-" json:"-"`
	VCT          string                         `yaml:"vct" json:"vct" validate:"required"`
	Format       string                         `yaml:"format" json:"format" validate:"required"`
	AuthMethod   string                         `yaml:"auth_method" json:"auth_method" validate:"required,auth_method_exists"`
	Attributes   map[string]map[string][]string `yaml:"attributes" json:"attributes_v2" validate:"omitempty,dive,required"`
}

// AuthMethod defines the authentication method configuration for credential issuance
// This specifies what credentials the wallet must present for authentication
// The format of the credentials is determined by looking up the VCTs in the credential_constructor
type AuthMethod struct {
	// VCTs is the list of acceptable Verifiable Credential Type URNs for authentication
	VCTs []string `yaml:"vcts" json:"vcts" validate:"required,min=1"`
	// Claims are the identity claims to extract from the authentication credential
	Claims []string `yaml:"claims" json:"claims" validate:"required,min=1"`
}

// The scope parameter is used only for error messages.
func (c *CredentialConstructor) LoadVCTMetadata(ctx context.Context, scope string) error {
	if c.VCTMFilePath == "" {
		return fmt.Errorf("vctm_file_path is empty for scope: %s", scope)
	}

	fileByte, err := os.ReadFile(c.VCTMFilePath)
	if err != nil {
		return fmt.Errorf("failed to read VCTM file %s for scope %s: %w", c.VCTMFilePath, scope, err)
	}

	if err := json.Unmarshal(fileByte, &c.VCTM); err != nil {
		return fmt.Errorf("failed to unmarshal VCTM file %s for scope %s: %w", c.VCTMFilePath, scope, err)
	}

	// Validate that VCTM has a VCT
	if c.VCTM.VCT == "" {
		return fmt.Errorf("VCTM file %s for scope %s is missing required 'vct' field", c.VCTMFilePath, scope)
	}

	return nil
}

// GetVCT returns the VCT from the loaded VCTM metadata.
// Falls back to the VCT field from the YAML configuration if VCTM is not yet loaded.
func (c *CredentialConstructor) GetVCT() string {
	if c.VCTM != nil && c.VCTM.VCT != "" {
		return c.VCTM.VCT
	}
	return c.VCT
}

// Generate generates issuer metadata from configuration.
// Returns unsigned metadata that should be signed on-demand in the endpoint handler for freshness.
func (cfg *IssuerMetadata) Generate(ctx context.Context, publicURL string, credentialConstructors map[string]*CredentialConstructor) (*openid4vci.CredentialIssuerMetadataParameters, error) {
	// Convert CredentialConstructor to CredentialConfigurationsSupported
	credentialConfigs := make(map[string]openid4vci.CredentialConfigurationsSupported)
	for scope, constructor := range credentialConstructors {
		if constructor == nil {
			continue
		}

		credConfig := openid4vci.CredentialConfigurationsSupported{
			Format: constructor.Format,
			Scope:  scope,
			VCT:    constructor.GetVCT(),
			CredentialDefinition: openid4vci.CredentialDefinition{
				Type: []string{"VerifiableCredential"},
			},
		}

		// Use VCTM display information
		if constructor.VCTM != nil && len(constructor.VCTM.Display) > 0 {
			credConfig.Display = make([]openid4vci.CredentialMetadataDisplay, len(constructor.VCTM.Display))
			for i, vctmDisplay := range constructor.VCTM.Display {
				display := openid4vci.CredentialMetadataDisplay{
					Name:        vctmDisplay.Name,
					Locale:      vctmDisplay.Locale,
					Description: vctmDisplay.Description,
				}

				// Map rendering information from VCTM to OpenID4VCI format
				if vctmDisplay.Rendering != nil {
					if vctmDisplay.Rendering.Simple.BackgroundColor != "" {
						display.BackgroundColor = vctmDisplay.Rendering.Simple.BackgroundColor
					}
					if vctmDisplay.Rendering.Simple.TextColor != "" {
						display.TextColor = vctmDisplay.Rendering.Simple.TextColor
					}
					if vctmDisplay.Rendering.Simple.Logo.URI != "" {
						display.Logo = openid4vci.MetadataLogo{
							URI:     vctmDisplay.Rendering.Simple.Logo.URI,
							AltText: vctmDisplay.Rendering.Simple.Logo.AltText,
						}
					}
					if vctmDisplay.Rendering.Simple.BackgroundImage != nil && vctmDisplay.Rendering.Simple.BackgroundImage.URI != "" {
						display.BackgroundImage = openid4vci.MetadataBackgroundImage{
							URI: vctmDisplay.Rendering.Simple.BackgroundImage.URI,
						}
					}
				}

				credConfig.Display[i] = display
			}
		}

		// Set cryptographic binding methods
		if len(cfg.CryptographicBindingMethodsSupported) > 0 {
			credConfig.CryptographicBindingMethodsSupported = cfg.CryptographicBindingMethodsSupported
		} else {
			credConfig.CryptographicBindingMethodsSupported = []string{"jwk"}
		}

		// Set credential signing algorithms from configuration
		// These must be explicitly configured to match the Issuer service's capabilities
		if len(cfg.CredentialSigningAlgValuesSupported) > 0 {
			credConfig.CredentialSigningAlgValuesSupported = make([]any, len(cfg.CredentialSigningAlgValuesSupported))
			for i, alg := range cfg.CredentialSigningAlgValuesSupported {
				credConfig.CredentialSigningAlgValuesSupported[i] = alg
			}
		} else {
			// Default to common algorithms if not configured
			credConfig.CredentialSigningAlgValuesSupported = []any{"ES256", "ES384", "RS256"}
		}

		// Set proof types supported from configuration
		// These must be explicitly configured to match what the Issuer service accepts
		proofAlgs := cfg.ProofSigningAlgValuesSupported
		if len(proofAlgs) == 0 {
			// Default to common algorithms if not configured
			proofAlgs = []string{"ES256", "ES384", "ES512", "RS256", "RS384", "RS512"}
		}
		credConfig.ProofTypesSupported = map[string]openid4vci.ProofsTypesSupported{
			"jwt": {
				ProofSigningAlgValuesSupported: proofAlgs,
			},
		}

		credentialConfigs[scope] = credConfig
	}

	credentialEndpoint, err := url.JoinPath(publicURL, "/credential")
	if err != nil {
		return nil, fmt.Errorf("failed to construct credential endpoint URL: %w", err)
	}
	metadataConfig := &openid4vci.MetadataConfig{
		CredentialIssuer:                     publicURL,
		CredentialEndpoint:                   credentialEndpoint,
		AuthorizationServers:                 cfg.AuthorizationServers,
		DeferredCredentialEndpoint:           cfg.DeferredCredentialEndpoint,
		NotificationEndpoint:                 cfg.NotificationEndpoint,
		CryptographicBindingMethodsSupported: cfg.CryptographicBindingMethodsSupported,
		CredentialSigningAlgValuesSupported:  cfg.CredentialSigningAlgValuesSupported,
		ProofSigningAlgValuesSupported:       cfg.ProofSigningAlgValuesSupported,
		CredentialResponseEncryption:         cfg.CredentialResponseEncryption,
		BatchCredentialIssuance:              cfg.BatchCredentialIssuance,
		Display:                              cfg.Display,
		CredentialConfigurationsSupported:    credentialConfigs,
	}

	metadata := metadataConfig.GenerateIssuerMetadata(ctx)

	return metadata, nil
}

// GenerateMetadata generates OAuth2 metadata from configuration.
// Returns unsigned metadata that should be signed on-demand in the endpoint handler for freshness.
func (cfg *OAuthServer) GenerateMetadata(ctx context.Context, issuerURL string) *oauth2.AuthorizationServerMetadata {
	metadata := oauth2.GenerateMetadata(&oauth2.MetadataConfig{
		IssuerURL:     issuerURL,
		TokenEndpoint: cfg.TokenEndpoint,
	})

	return metadata
}
