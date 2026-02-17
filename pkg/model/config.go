package model

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"time"
	"vc/pkg/oauth2"
	"vc/pkg/openid4vci"
	"vc/pkg/openid4vp"
	"vc/pkg/pki"
	"vc/pkg/sdjwtvc"
)

// APIServer holds the HTTP API server configuration
type APIServer struct {
	// Addr is the listen address for the HTTP server
	Addr      string    `yaml:"addr" validate:"required" default:":8080"`
	TLS       TLS       `yaml:"tls" validate:"omitempty"`
	BasicAuth BasicAuth `yaml:"basic_auth"`
	CORS      *CORS     `yaml:"cors,omitempty" validate:"omitempty"`
}

// CORS holds the CORS configuration
type CORS struct {
	// AllowedOrigins is the list of allowed CORS origins
	// Example: ["https://wallet.sunet.se", "https://app.sunet.se"]
	AllowedOrigins []string `yaml:"allowed_origins" validate:"omitempty" default:"[]"`
}

// TLS holds the TLS configuration
type TLS struct {
	// Enable enables TLS
	Enable bool `yaml:"enable" default:"false"`
	// CertFilePath is the path to the TLS certificate
	CertFilePath string `yaml:"cert_file_path" validate:"required"`
	// KeyFilePath is the path to the TLS private key
	KeyFilePath string `yaml:"key_file_path" validate:"required"`
}

// Mongo holds the MongoDB configuration
type Mongo struct {
	// URI is the MongoDB connection URI
	// Example: "mongodb://user:password@mongo:27017/vc"
	URI string `yaml:"uri" validate:"required"`
}

// Kafka holds the Kafka message broker configuration
type Kafka struct {
	// Enable enables Kafka integration
	Enable bool `yaml:"enable" default:"false"`
	// Brokers is the list of Kafka broker addresses
	Brokers []string `yaml:"brokers" validate:"required" default:"[\"kafka0:9092\", \"kafka1:9092\"]"`
}

// Log holds the logging configuration
type Log struct {
	// FolderPath is the path to the log folder
	// Example: "/var/log/vc"
	FolderPath string `yaml:"folder_path"`
}

// Common holds the shared configuration used across all services
type Common struct {
	// Production enables production mode
	Production bool `yaml:"production" default:"true"`
	// Log is the logging configuration
	Log Log `yaml:"log"`
	// Mongo is the MongoDB configuration
	Mongo Mongo `yaml:"mongo" validate:"omitempty"`
	// Tracing is the OpenTelemetry tracing configuration
	Tracing OTEL `yaml:"tracing" validate:"omitempty"`
	// Kafka is the Kafka message broker configuration
	Kafka Kafka `yaml:"kafka" validate:"omitempty"`
	// CredentialOfferQR holds credential offer QR code settings
	CredentialOfferQR CredentialOfferQRConfig `yaml:"credential_offer_qr" validate:"omitempty"`
	// SecretFilePath is the path to a separate YAML file containing secrets; when set, secret values in config.yaml are cleared and only non-empty fields from the secrets file are applied. Example: "/etc/vc/secrets.yaml"
	SecretFilePath string `yaml:"secret_file_path,omitempty"`
	// HA enables high-availability mode. When true, caches use MongoDB (Common.Mongo.URI)
	// instead of in-memory storage so state is shared across instances.
	HA bool `yaml:"ha" default:"false"`
}

// CredentialOfferQRConfig holds credential offer QR code settings
type CredentialOfferQRConfig struct {
	// Type is the credential offer type: "credential_offer" or "credential_offer_uri"
	Type string `yaml:"type" validate:"required,oneof=credential_offer_uri credential_offer" default:"credential_offer"`
	// QR holds QR code generation settings
	QR QRCfg `yaml:"qr" validate:"omitempty"`
}

// QRCfg holds the QR code generation settings
type QRCfg struct {
	// RecoveryLevel is the error correction level (0-3)
	RecoveryLevel int `yaml:"recovery_level" validate:"required,min=0,max=3" default:"2"`
	// Size is the QR code size in pixels
	Size int `yaml:"size" validate:"required" default:"256"`
}

// GRPCServer holds the gRPC server configuration
type GRPCServer struct {
	// Addr is the gRPC server listen address
	Addr string `yaml:"addr" validate:"required" default:":8090"`
	// TLS holds the mTLS configuration
	TLS GRPCTLS `yaml:"tls,omitempty"`
}

// GRPCTLS holds the mTLS configuration for gRPC server
type GRPCTLS struct {
	Enable                    bool              `yaml:"enable" default:"false"`
	CertFilePath              string            `yaml:"cert_file_path" validate:"required_if=Enable true" default:"/pki/grpc_server.crt"` // Server certificate
	KeyFilePath               string            `yaml:"key_file_path" validate:"required_if=Enable true" default:"/pki/grpc_server.key"`  // Server private key
	ClientCAPath              string            `yaml:"client_ca_path" validate:"required_if=Enable true" default:"/pki/client_ca.crt"`   // CA to verify client certificates (for mTLS)
	AllowedClientFingerprints map[string]string `yaml:"allowed_client_fingerprints"`                                                       // SHA256 fingerprint -> friendly name (e.g., "a1b2c3..." -> "issuer-prod")
	AllowedClientDNs          map[string]string `yaml:"allowed_client_dns"`                                                                // Certificate Subject DN -> friendly name (e.g., "CN=apigw,O=SUNET" -> "apigw-prod")
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
	// Enable turns on SAML support (default: false)
	Enable bool `yaml:"enable" default:"false"`

	// EntityID is the SAML SP entity identifier (typically the metadata URL)
	// Example: "https://issuer.sunet.se/saml/metadata"
	EntityID string `yaml:"entity_id" validate:"required_if=Enable true"`

	// MetadataURL is the public URL where SP metadata is served (optional, auto-generated if empty)
	MetadataURL string `yaml:"metadata_url,omitempty"`

	// MDQServer is the base URL for MDQ (Metadata Query Protocol) server
	// Example: "https://md.sunet.se/entities/" (must end with /)
	// Mutually exclusive with StaticIDPMetadata
	MDQServer string `yaml:"mdq_server,omitempty"`

	// StaticIDPMetadata configures a single static IdP as alternative to MDQ
	// Mutually exclusive with MDQServer
	StaticIDPMetadata *StaticIDPConfig `yaml:"static_idp_metadata,omitempty"`

	// CertificatePath is the path to X.509 certificate for SAML signing/encryption
	CertificatePath string `yaml:"certificate_path" validate:"required_if=Enable true"`

	// PrivateKeyPath is the path to private key for SAML signing/encryption
	PrivateKeyPath string `yaml:"private_key_path" validate:"required_if=Enable true"`

	// ACSEndpoint is the Assertion Consumer Service URL where IdP sends SAML responses
	// Example: "https://issuer.sunet.se/saml/acs"
	ACSEndpoint string `yaml:"acs_endpoint" validate:"required_if=Enable true"`

	// SessionDuration is the maximum time in seconds an in-flight SAML authentication flow
	// (AuthnRequest → Response) may remain active before it expires
	SessionDuration int `yaml:"session_duration" validate:"required" default:"300"`

	// CredentialMappings defines how to map external attributes to credential claims
	// Key: credential type identifier (e.g., "pid", "diploma")
	// Maps to credential_constructor keys and OpenID4VCI credential_configuration_ids
	CredentialMappings map[string]CredentialMapping `yaml:"credential_mappings" validate:"required_if=Enable true"`

	// MetadataCacheTTL in seconds (default: 3600) - how long to cache IdP metadata from MDQ
	MetadataCacheTTL int `yaml:"metadata_cache_ttl"`
}

// StaticIDPConfig holds configuration for a single static IdP connection
type StaticIDPConfig struct {
	// EntityID is the IdP entity identifier
	EntityID string `yaml:"entity_id" validate:"required"`

	// MetadataPath is the file path to IdP metadata XML (mutually exclusive with MetadataURL)
	MetadataPath string `yaml:"metadata_path,omitempty" validate:"required_without=MetadataURL,excluded_with=MetadataURL"`

	// MetadataURL is the HTTP(S) URL to fetch IdP metadata from (mutually exclusive with MetadataPath)
	MetadataURL string `yaml:"metadata_url,omitempty"`
}

// OIDCRPConfig holds OIDC Relying Party configuration for credential issuance.
type OIDCRPConfig struct {
	// Enable turns on OIDC RP support (default: false)
	Enable bool `yaml:"enable" default:"false"`

	// Registration configures how the client obtains credentials from the OIDC Provider.
	// Exactly one of preconfigured or dynamic must be set:
	//   - preconfigured: pre-registered client_id and client_secret
	//   - dynamic: RFC 7591 dynamic client registration (credentials obtained at startup)
	Registration *OIDCRPRegistrationConfig `yaml:"registration" validate:"required_if=Enable true"`

	// RedirectURI is the callback URL where the OIDC Provider sends the authorization response
	// Example: "https://issuer.sunet.se/oidcrp/callback"
	RedirectURI string `yaml:"redirect_uri" validate:"required_if=Enable true"`

	// IssuerURL is the OIDC Provider's issuer URL for discovery
	// Example: "https://accounts.google.com"
	// Used for .well-known/openid-configuration discovery
	IssuerURL string `yaml:"issuer_url" validate:"required_if=Enable true"`

	// Scopes are the OAuth2/OIDC scopes to request (at least one scope is required, e.g. "openid")
	Scopes []string `yaml:"scopes" validate:"required,min=1,dive,required" default:"[\"openid\", \"profile\", \"email\"]"`

	// SessionDuration is the maximum time in seconds an in-flight OIDC authorization flow
	// (state, nonce, PKCE verifier) may remain active before it expires
	SessionDuration int `yaml:"session_duration" validate:"required" default:"300"`

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
	CredentialMappings map[string]CredentialMapping `yaml:"credential_mappings" validate:"required_if=Enable true"`
}

// OIDCRPRegistrationConfig configures how the client obtains its credentials.
// Exactly one of Preconfigured or Dynamic must be set.
type OIDCRPRegistrationConfig struct {
	// Preconfigured uses pre-registered client credentials.
	// Set this when the client is already registered with the OIDC Provider.
	Preconfigured *OIDCRPPreconfiguredConfig `yaml:"preconfigured,omitempty" validate:"required_without=Dynamic,excluded_with=Dynamic"`

	// Dynamic uses RFC 7591 dynamic client registration.
	// Set this when the client should register itself at startup.
	Dynamic *OIDCRPDynamicRegistrationConfig `yaml:"dynamic,omitempty" validate:"required_without=Preconfigured,excluded_with=Preconfigured"`
}

// OIDCRPPreconfiguredConfig holds pre-registered client credentials.
type OIDCRPPreconfiguredConfig struct {
	// Enable activates preconfigured client credentials
	Enable bool `yaml:"enable"`

	// ClientID is the OIDC client identifier
	ClientID string `yaml:"client_id" validate:"required_if=Enable true"`

	// ClientSecret is the OIDC client secret
	ClientSecret string `yaml:"client_secret" validate:"required_if=Enable true"`
}

// OIDCRPDynamicRegistrationConfig configures RFC 7591 dynamic client registration.
// When set, client credentials are obtained automatically at startup and
// persisted in the database.
type OIDCRPDynamicRegistrationConfig struct {
	// Enable activates dynamic client registration
	Enable bool `yaml:"enable"`

	// InitialAccessToken is a bearer token for registration
	// Required by some OIDC Providers (e.g., Keycloak)
	InitialAccessToken string `yaml:"initial_access_token,omitempty" validate:"required_if=Enable true"`
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

// Issuer holds the configuration for the Issuer service that signs and issues verifiable credentials
type Issuer struct {
	// APIServer is the HTTP API server configuration
	APIServer APIServer `yaml:"api_server" validate:"required"`
	// GRPCServer is the gRPC server configuration
	GRPCServer GRPCServer `yaml:"grpc_server" validate:"required"`
	// KeyConfig is the signing key configuration
	KeyConfig *pki.KeyConfig `yaml:"key_config" validate:"required"`
	// JWTAttribute holds the JWT credential attribute configuration
	JWTAttribute JWTAttribute `yaml:"jwt_attribute" validate:"required"`
	// IssuerURL is the issuer identifier URL
	// Example: "https://issuer.sunet.se"
	IssuerURL string `yaml:"issuer_url" validate:"required"`
	// RegistryClient is the registry gRPC client config
	RegistryClient GRPCClientTLS `yaml:"registry_client" validate:"omitempty"`
	// MDoc holds mDL/mdoc configuration
	MDoc *MDocConfig `yaml:"mdoc" validate:"omitempty"`
	// AuditLog holds audit log configuration
	AuditLog *AuditLog `yaml:"audit_log" validate:"omitempty"`
}

// AuditLog holds audit log configuration for multiple destinations
type AuditLog struct {
	// Enable enables audit logging
	Enable bool `yaml:"enable" default:"false"`
	// Destinations is the list of log destinations (console/stdout, file path, or HTTP URL)
	// Example: ["stdout", "/var/log/audit.log", "https://audit.sunet.se/webhook"]
	Destinations []string `yaml:"destinations" validate:"required_if=Enable true,min=1"`
	// FileSyncInterval controls fsync behavior for file destinations.
	// 0 = fsync after every write (strict durability, lower throughput).
	// >0 = periodic batched fsync at the given interval (better throughput, bounded data-loss window).
	// Has no effect on console or webhook destinations.
	FileSyncInterval time.Duration `yaml:"file_sync_interval" default:"5s"`
}

// MDocConfig holds mDL (ISO 18013-5) issuer configuration
type MDocConfig struct {
	// CertificateChainPath is the path to the PEM certificate chain
	CertificateChainPath string `yaml:"certificate_chain_path" validate:"required"`
	// DefaultValidity is the default credential validity (default: 365 days)
	DefaultValidity time.Duration `yaml:"default_validity" default:"8760h"`
	// DigestAlgorithm is the digest algorithm: "SHA-256", "SHA-384", or "SHA-512"
	DigestAlgorithm string `yaml:"digest_algorithm" default:"SHA-256"`
}

// GRPCClientTLS holds mTLS configuration for gRPC client connections
type GRPCClientTLS struct {
	// Addr is the gRPC server address
	// Example: "issuer:8090"
	Addr string `yaml:"addr" validate:"required"`
	// TLS enables TLS
	TLS bool `yaml:"tls" default:"false"`
	// CertFilePath is the client certificate for mTLS
	CertFilePath string `yaml:"cert_file_path"`
	// KeyFilePath is the client private key for mTLS
	KeyFilePath string `yaml:"key_file_path"`
	// CAFilePath is the CA certificate to verify the server
	CAFilePath string `yaml:"ca_file_path"`
	// ServerName is the server name for TLS verification (optional)
	ServerName string `yaml:"server_name"`
}

// PKCS11 holds PKCS#11 HSM configuration for hardware security module integration
type PKCS11 struct {
	// ModulePath is the path to the PKCS#11 module
	ModulePath string `yaml:"module_path" default:"/usr/lib/softhsm/libsofthsm2.so"`
	// SlotID is the HSM slot ID
	SlotID uint `yaml:"slot_id" default:"0"`
	// PIN is the PIN for HSM access
	PIN string `yaml:"pin" validate:"required"`
	// KeyLabel is the key label in HSM
	KeyLabel string `yaml:"key_label" validate:"required"`
	// KeyID is the key ID in HSM
	KeyID string `yaml:"key_id" validate:"required"`
}

// Registry holds the configuration for the Registry service that manages credential status
type Registry struct {
	// APIServer is the HTTP API server configuration
	APIServer APIServer `yaml:"api_server" validate:"required"`
	// PublicURL is the public URL of this service (must be valid HTTP/HTTPS URL)
	// Example: "https://registry.sunet.se"
	PublicURL string `yaml:"public_url" validate:"required,httpurl"`
	// GRPCServer is the gRPC server configuration
	GRPCServer GRPCServer `yaml:"grpc_server" validate:"required"`
	// TokenStatusLists holds the Token Status List configuration
	TokenStatusLists TokenStatusLists `yaml:"token_status_lists,omitempty" validate:"omitempty"`
	// AdminGUI holds the admin GUI configuration
	AdminGUI AdminGUI `yaml:"admin_gui,omitempty" validate:"omitempty"`
}

// AdminGUI holds the admin GUI configuration
type AdminGUI struct {
	// Enable enables the admin GUI
	Enable bool `yaml:"enable" default:"true"`
	// Username is the admin username
	Username string `yaml:"username" validate:"required_if=Enable true" default:"admin"`
	// Password is the admin password
	Password string `yaml:"password" validate:"required_if=Enable true"`
}

// MockAS holds the configuration for the Mock Authentic Source service used for testing
type MockAS struct {
	// APIServer is the HTTP API server configuration
	APIServer APIServer `yaml:"api_server" validate:"required"`
	// DatastoreURL is the datastore service URL
	// Example: "http://datastore:8080"
	DatastoreURL string `yaml:"datastore_url" validate:"required"`
	// BootstrapUsers is the list of user IDs to bootstrap on startup
	BootstrapUsers []string `yaml:"bootstrap_users" default:"[\"100\", \"102\"]"`
}

// Verifier holds the configuration for the Verifier service that verifies credentials and acts as an OIDC Provider
type Verifier struct {
	// APIServer is the HTTP API server configuration
	APIServer APIServer `yaml:"api_server" validate:"required"`
	// PublicURL is the public URL of this service (must be valid HTTP/HTTPS URL)
	// Example: "https://verifier.sunet.se"
	PublicURL string `yaml:"public_url" validate:"required,httpurl"`
	// KeyConfig is the signing key configuration
	KeyConfig *pki.KeyConfig `yaml:"key_config" validate:"required"`
	// OAuthServer is the OAuth2 server configuration
	OAuthServer OAuthServer `yaml:"oauth_server" validate:"required"`
	// PreferredVPFormats specifies informational VP formats and algorithms supported by wallets
	PreferredVPFormats *openid4vp.VPFormatsSupported `yaml:"preferred_vp_formats,omitempty"`
	// SupportedWallets holds supported wallet configurations
	SupportedWallets map[string]string `yaml:"supported_wallets" validate:"omitempty"`
	// OIDC holds the OIDC Provider configuration
	OIDC OIDCConfig `yaml:"oidc" validate:"omitempty"`
	// OpenID4VP holds the OpenID4VP configuration
	OpenID4VP OpenID4VPConfig `yaml:"openid4vp" validate:"omitempty"`
	// DigitalCredentials holds the W3C Digital Credentials API configuration
	DigitalCredentials DigitalCredentialsConfig `yaml:"digital_credentials,omitempty"`
	// AuthorizationPageCSS holds the authorization page styling configuration
	AuthorizationPageCSS AuthorizationPageCSSConfig `yaml:"authorization_page_css,omitempty"`
	// CredentialDisplay holds the credential display settings
	CredentialDisplay CredentialDisplayConfig `yaml:"credential_display,omitempty"`
	// Trust holds the trust evaluation configuration
	Trust TrustConfig `yaml:"trust,omitempty"`
}

// TrustConfig holds configuration for key resolution and trust evaluation via go-trust.
// This is used for validating W3C VC Data Integrity proofs and other trust-related operations.
type TrustConfig struct {
	// GoTrustURL is the URL of the go-trust PDP (Policy Decision Point) service.
	// Example: "https://trust.sunet.se/pdp"
	// If empty, trust evaluation is disabled and only local DID methods will work.
	GoTrustURL string `yaml:"go_trust_url,omitempty"`

	// LocalDIDMethods specifies which DID methods can be resolved locally without go-trust.
	// Self-contained methods like "did:key" and "did:jwk" are always resolved locally.
	LocalDIDMethods []string `yaml:"local_did_methods,omitempty" default:"[\"did:key\", \"did:jwk\"]"`

	// TrustPolicies configures per-role trust evaluation policies.
	// The key is the role (e.g., "issuer", "verifier") and the value contains policy settings.
	TrustPolicies map[string]TrustPolicyConfig `yaml:"trust_policies,omitempty"`

	// Enable controls whether trust evaluation is enabled.
	// When false, keys are resolved but not validated against trust frameworks.
	// Default: true
	Enable bool `yaml:"enable,omitempty" default:"true"`
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

// OIDCConfig holds OIDC-specific configuration for the verifier's role as an OpenID Provider.
// This configures how the verifier issues ID tokens and access tokens to relying parties.
// Note: This is NOT related to verifiable credential issuance (see IssuerConfig for VC issuance).
// The signing key is shared from the parent Verifier.KeyConfig.
type OIDCConfig struct {
	// Issuer is the OIDC Provider identifier that appears in ID tokens and discovery metadata.
	// This identifies the verifier as an OpenID Provider.
	// Must match the 'iss' claim in all issued ID tokens.
	// Example: "https://verifier.sunet.se"
	Issuer string `yaml:"issuer" validate:"required"`
	// SessionDuration is the session duration in seconds
	SessionDuration int `yaml:"session_duration" validate:"required" default:"3600"`
	// CodeDuration is the authorization code duration in seconds
	CodeDuration int `yaml:"code_duration" validate:"required" default:"300"`
	// AccessTokenDuration is the access token duration in seconds
	AccessTokenDuration int `yaml:"access_token_duration" validate:"required" default:"3600"`
	// IDTokenDuration is the ID token duration in seconds
	IDTokenDuration int `yaml:"id_token_duration" validate:"required" default:"3600"`
	// RefreshTokenDuration is the refresh token duration in seconds
	RefreshTokenDuration int `yaml:"refresh_token_duration" validate:"required" default:"86400"`
	// SubjectType is the subject type: "public" or "pairwise"
	SubjectType string `yaml:"subject_type" validate:"required,oneof=public pairwise"`
	// SubjectSalt is the salt for pairwise subject generation
	SubjectSalt string `yaml:"subject_salt" validate:"required"`
}

// OpenID4VPConfig holds OpenID4VP-specific configuration
type OpenID4VPConfig struct {
	// PresentationTimeout is the presentation timeout in seconds
	PresentationTimeout int `yaml:"presentation_timeout" validate:"required" default:"300"`
	// SupportedCredentials holds the supported credential configurations
	SupportedCredentials []SupportedCredentialConfig `yaml:"supported_credentials" validate:"required"`
	// PresentationRequestsDir is an optional directory with presentation request templates
	PresentationRequestsDir string `yaml:"presentation_requests_dir,omitempty"`
}

// DigitalCredentialsConfig holds W3C Digital Credentials API configuration
type DigitalCredentialsConfig struct {
	// Enable toggles W3C Digital Credentials API support in browser
	Enable bool `yaml:"enable" default:"false"`

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

	// DeepLinkScheme for mobile wallet integration
	// Example: "eudi-wallet://"
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

	// PrimaryColor overrides the primary brand color
	// Example: "#667eea"
	PrimaryColor string `yaml:"primary_color,omitempty"`

	// SecondaryColor overrides the secondary brand color
	// Example: "#764ba2"
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
	// Enable allows users to optionally view credential details before completing authorization
	// When enabled, a checkbox appears on the authorization page
	Enable bool `yaml:"enable" default:"false"`

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
	// VCT is the verifiable credential type
	// Example: "urn:eudi:pid:1"
	VCT string `yaml:"vct" validate:"required"`
	// Scopes are the OIDC scopes that grant access to this credential
	Scopes []string `yaml:"scopes" validate:"required"`
}

// BasicAuth holds the HTTP Basic authentication configuration
type BasicAuth struct {
	// Users is a username to password mapping
	Users map[string]string `yaml:"users"`
	// Enable enables HTTP Basic authentication
	Enable bool `yaml:"enable" default:"false"`
}

// IssuerMetadata holds the OpenID4VCI issuer metadata configuration
type IssuerMetadata struct {
	// AuthorizationServers lists the authorization server URLs
	AuthorizationServers []string `yaml:"authorization_servers" validate:"omitempty"`
	// DeferredCredentialEndpoint is the deferred credential endpoint
	DeferredCredentialEndpoint string `yaml:"deferred_credential_endpoint" validate:"omitempty"`
	// NotificationEndpoint is the notification endpoint
	NotificationEndpoint string `yaml:"notification_endpoint" validate:"omitempty"`
	// CryptographicBindingMethodsSupported lists the supported binding methods
	CryptographicBindingMethodsSupported []string `yaml:"cryptographic_binding_methods_supported" validate:"omitempty"`
	// CredentialSigningAlgValuesSupported lists the supported signing algorithms
	CredentialSigningAlgValuesSupported []string `yaml:"credential_signing_alg_values_supported" validate:"omitempty"`
	// ProofSigningAlgValuesSupported lists the supported proof algorithms
	ProofSigningAlgValuesSupported []string `yaml:"proof_signing_alg_values_supported" validate:"omitempty"`
	// CredentialResponseEncryption holds the response encryption configuration
	CredentialResponseEncryption *openid4vci.MetadataCredentialResponseEncryption `yaml:"credential_response_encryption" validate:"omitempty"`
	// BatchCredentialIssuance holds the batch issuance configuration
	BatchCredentialIssuance *openid4vci.BatchCredentialIssuance `yaml:"batch_credential_issuance" validate:"omitempty"`
	// Display holds the display metadata
	Display []openid4vci.MetadataDisplay `yaml:"display" validate:"omitempty"`
}

// CredentialOfferWallets holds wallet redirect configuration
type CredentialOfferWallets struct {
	// Label is the display label for the wallet
	Label string `yaml:"label" validate:"required"`
	// RedirectURI is the wallet redirect URI
	// Example: "eudi-wallet://credential-offer"
	RedirectURI string `yaml:"redirect_uri" validate:"required"`
}

// CredentialOffers holds credential offer configurations
type CredentialOffers struct {
	// IssuerURL is the issuer URL for credential offers
	IssuerURL string `yaml:"issuer_url" validate:"required"`
	// Wallets holds wallet redirect configurations
	Wallets map[string]CredentialOfferWallets `yaml:"wallets" validate:"required"`
}

// APIGW holds the configuration for the API Gateway service that handles credential issuance requests
type APIGW struct {
	// APIServer is the HTTP API server configuration
	APIServer APIServer `yaml:"api_server" validate:"required"`
	// KeyConfig is the signing key configuration
	KeyConfig *pki.KeyConfig `yaml:"key_config" validate:"required"`
	// CredentialOffers holds credential offer wallet configurations
	CredentialOffers CredentialOffers `yaml:"credential_offers" validate:"omitempty"`
	// OauthServer is the OAuth2 server configuration
	OauthServer OAuthServer `yaml:"oauth_server" validate:"omitempty"`
	// IssuerMetadata holds the OpenID4VCI issuer metadata
	IssuerMetadata IssuerMetadata `yaml:"issuer_metadata" validate:"omitempty"`
	// PublicURL is the public URL of this service (must be valid HTTP/HTTPS URL)
	// Example: "https://issuer.sunet.se"
	PublicURL string `yaml:"public_url" validate:"required,httpurl"`
	// RegistryPublicURL is the public URL of the registry service for constructing status list URIs
	// Example: "https://registry.sunet.se"
	RegistryPublicURL string `yaml:"registry_public_url" validate:"required,httpurl"`
	// SAML holds the SAML Service Provider configuration
	SAML SAMLConfig `yaml:"saml,omitempty" validate:"omitempty"`
	// OIDCRP holds the OIDC Relying Party configuration
	OIDCRP OIDCRPConfig `yaml:"oidcrp,omitempty" validate:"omitempty"`
	// IssuerClient is the gRPC client config for issuer
	IssuerClient GRPCClientTLS `yaml:"issuer_client" validate:"required"`
	// RegistryClient is the gRPC client config for registry
	RegistryClient GRPCClientTLS `yaml:"registry_client" validate:"required"`
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

// OTEL holds the OpenTelemetry tracing configuration
type OTEL struct {
	// Enable activates OpenTelemetry tracing
	Enable bool `yaml:"enable" default:"false"`
	// Addr is the OTEL collector address
	// Example: "jaeger:4318"
	Addr string `yaml:"addr" validate:"required_if=Enable true"`
	// Timeout is the timeout in seconds
	Timeout int64 `yaml:"timeout" default:"10"`
}

// OAuthServer holds the OAuth2 server configuration
type OAuthServer struct {
	// TokenEndpoint is the OAuth2 token endpoint URL
	// Example: "https://verifier.sunet.se/token"
	TokenEndpoint string `yaml:"token_endpoint" validate:"required"`
	// Clients holds the OAuth2 client configurations
	Clients oauth2.Clients `yaml:"clients" validate:"required"`
}

// UI holds the configuration for the User Interface service
type UI struct {
	// APIServer is the HTTP API server configuration
	APIServer APIServer `yaml:"api_server" validate:"required"`
	// Username is the UI login username
	Username string `yaml:"username" validate:"required"`
	// Password is the UI login password
	Password string `yaml:"password" validate:"required"`
	// SessionInactivityTimeoutInSeconds is the session inactivity timeout in seconds
	SessionInactivityTimeoutInSeconds int `yaml:"session_inactivity_timeout_in_seconds" validate:"required"`
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
		if constructor != nil && constructor.VCTM.VCT == vct {
			return constructor.Format
		}
	}
	return ""
}

type CredentialConstructor struct {
	VCTMFilePath string                         `yaml:"vctm_file_path" json:"vctm_file_path" validate:"required"`
	VCTM         *sdjwtvc.VCTM                  `yaml:"-" json:"-"`
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

// Generate generates issuer metadata from configuration.
// Returns unsigned metadata that should be signed on-demand in the endpoint handler for freshness.
func (cfg *IssuerMetadata) Generate(ctx context.Context, publicURL string, credentialConstructors map[string]*CredentialConstructor) (*openid4vci.CredentialIssuerMetadataParameters, error) {
	// Convert CredentialConstructor to CredentialConfigurationsSupported
	credentialConfigs := make(map[string]openid4vci.CredentialConfigurationsSupported)
	for scope, constructor := range credentialConstructors {
		if constructor == nil {
			continue
		}
		if constructor.VCTM == nil {
			return nil, fmt.Errorf("credential constructor for scope %q has no VCTM metadata loaded (check vctm_file_path)", scope)
		}

		credConfig := openid4vci.CredentialConfigurationsSupported{
			Format: constructor.Format,
			Scope:  scope,
		}

		// Set format-specific parameters per OID4VCI 1.0 Appendix A
		switch constructor.Format {
		case "dc+sd-jwt":
			// Appendix A.3: only vct is format-specific for dc+sd-jwt
			credConfig.VCT = constructor.VCTM.VCT
		case "mso_mdoc":
			// Appendix A.2: doctype is format-specific for mso_mdoc
			credConfig.Doctype = constructor.VCTM.VCT // VCT serves as doctype for mdoc
		case "jwt_vc_json", "ldp_vc", "jwt_vc_json-ld":
			// Appendix A.1: credential_definition with type array is format-specific for W3C VC formats
			credConfig.CredentialDefinition = &openid4vci.CredentialDefinition{
				Type: []string{"VerifiableCredential"},
			}
			credConfig.VCT = constructor.VCTM.VCT
		default:
			// For unknown formats, include VCT if available
			credConfig.VCT = constructor.VCTM.VCT
		}

		// Build credential_metadata object (OID4VCI 1.0 Section 12.2.4)
		credMetadata := &openid4vci.CredentialMetadata{}

		// Use VCTM display information
		if len(constructor.VCTM.Display) > 0 {
			credMetadata.Display = make([]openid4vci.CredentialMetadataDisplay, len(constructor.VCTM.Display))
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

				credMetadata.Display[i] = display
			}
		}

		// Only set credential_metadata if it has content
		if len(credMetadata.Display) > 0 || len(credMetadata.Claims) > 0 {
			credConfig.CredentialMetadata = credMetadata
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

	nonceEndpoint, err := url.JoinPath(publicURL, "/nonce")
	if err != nil {
		return nil, fmt.Errorf("failed to construct nonce endpoint URL: %w", err)
	}

	metadataConfig := &openid4vci.MetadataConfig{
		CredentialIssuer:                     publicURL,
		CredentialEndpoint:                   credentialEndpoint,
		NonceEndpoint:                        nonceEndpoint,
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
