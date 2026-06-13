package model

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/pki"
	"github.com/SUNET/vc/pkg/sdjwtvc"
)

// BoolVal safely dereferences a *bool, returning the pointed-to value or
// the supplied fallback when the pointer is nil.
func BoolVal(b *bool, fallback bool) bool {
	if b != nil {
		return *b
	}
	return fallback
}

// BoolPtr returns a pointer to the given bool value.
// Useful for initializing *bool fields in struct literals.
//
//go:fix inline
func BoolPtr(v bool) *bool {
	return new(v)
}

// APIServer holds the HTTP API server configuration
type APIServer struct {
	// Addr is the listen address for the HTTP server
	Addr string `yaml:"addr" validate:"required" default:":8080"`
	// ServedByHeader sets the X-Served-By response header value for HA troubleshooting.
	// Empty (default): header is not set. "hostname": uses os.Hostname().
	// Any other value is used as-is.
	ServedByHeader string  `yaml:"served_by_header,omitempty"`
	TLS            TLS     `yaml:"tls" validate:"omitempty"`
	APIAuth        APIAuth `yaml:"api_auth"`
	CORS           *CORS   `yaml:"cors,omitempty" validate:"omitempty"`
	// TrustProxyTLS forces the Secure flag on session cookies even when TLS is not
	// enabled on this server. Use this when running behind a TLS-terminating reverse proxy.
	TrustProxyTLS bool `yaml:"trust_proxy_tls" default:"false"`
}

// CORS holds the CORS configuration
type CORS struct {
	// AllowedOrigins is the list of allowed CORS origins
	AllowedOrigins []string `yaml:"allowed_origins" validate:"omitempty" default:"[]" doc_example:"[\"https://wallet.sunet.se\", \"https://app.sunet.se\"]"`
}

// TLS holds server-side TLS configuration (presenting a certificate to clients)
type TLS struct {
	// Enable enables TLS
	Enable bool `yaml:"enable" default:"false"`
	// CertFilePath is the path to the TLS certificate
	CertFilePath string `yaml:"cert_file_path" validate:"required_if=Enable true"`
	// KeyFilePath is the path to the TLS private key
	KeyFilePath string `yaml:"key_file_path" validate:"required_if=Enable true"`
}

// MTLS holds mutual TLS configuration for client connections (verifying peer + presenting own cert)
type MTLS struct {
	// Enable enables mTLS for the connection
	Enable bool `yaml:"enable" default:"false"`
	// CACertPath is the path to a CA certificate for verifying the remote peer (optional; uses system roots if empty)
	CACertPath string `yaml:"ca_cert_path,omitempty"`
	// CertFilePath is the path to a client certificate for mutual authentication
	CertFilePath string `yaml:"cert_file_path" validate:"required_if=Enable true"`
	// KeyFilePath is the path to the client private key
	KeyFilePath string `yaml:"key_file_path" validate:"required_if=Enable true"`
	// InsecureSkipVerify disables certificate verification (TESTING ONLY — never use in production)
	InsecureSkipVerify bool `yaml:"insecure_skip_verify" default:"false"`
}

// Mongo holds the MongoDB configuration
type Mongo struct {
	// URI is the MongoDB connection URI
	URI string `yaml:"uri" validate:"required" doc_example:"\"mongodb://user:password@mongo:27017/vc\""`
	// TLS enables TLS for the MongoDB connection.
	// Can also be enabled via the connection URI parameter "tls=true".
	TLS bool `yaml:"tls" default:"false"`
	// CAFilePath is the path to a PEM-encoded CA certificate used to verify
	// the MongoDB server's certificate. When empty, the system root CAs are used.
	CAFilePath string `yaml:"ca_file_path" validate:"omitempty"`
	// CertFilePath is the path to a PEM-encoded client certificate for mutual TLS (mTLS).
	// Must be set together with KeyFilePath.
	CertFilePath string `yaml:"cert_file_path" validate:"required_with=KeyFilePath"`
	// KeyFilePath is the path to a PEM-encoded client private key for mutual TLS (mTLS).
	// Must be set together with CertFilePath.
	KeyFilePath string `yaml:"key_file_path" validate:"required_with=CertFilePath"`
}

// HAConfig holds the high-availability configuration
type HAConfig struct {
	// Enable enables HA mode; when true caches are backed by MongoDB instead of in-memory storage.
	Enable bool `yaml:"enable" default:"false"`
	// CacheDatabaseName is the MongoDB database name used for caches.
	CacheDatabaseName string `yaml:"cache_database_name" default:"vc_cache"`
}

// Kafka holds the Kafka message broker configuration
type Kafka struct {
	// Enable enables Kafka integration
	Enable bool `yaml:"enable" default:"false"`
	// Brokers is the list of Kafka broker addresses
	Brokers []string `yaml:"brokers" validate:"required_if=Enable true" doc_example:"[\"kafka0:9092\", \"kafka1:9092\"]"`
	// SASL configures SASL authentication for Kafka connections
	SASL *KafkaSASL `yaml:"sasl,omitempty"`
	// MTLS configures mutual TLS (mTLS) for Kafka broker connections
	MTLS MTLS `yaml:"mtls" validate:"omitempty"`
}

// KafkaSASL holds SASL authentication settings for Kafka
type KafkaSASL struct {
	// Enable activates SASL authentication
	Enable bool `yaml:"enable" default:"false"`
	// Mechanism is the SASL mechanism (PLAIN, SCRAM-SHA-256, SCRAM-SHA-512)
	Mechanism string `yaml:"mechanism" validate:"required_if=Enable true,omitempty,oneof=PLAIN SCRAM-SHA-256 SCRAM-SHA-512" default:"SCRAM-SHA-512"`
	// Username is the SASL username
	Username string `yaml:"username" validate:"required_if=Enable true"`
	// Password is the SASL password
	Password string `yaml:"password" validate:"required_if=Enable true"`
}

// Log holds the logging configuration
type Log struct {
	// FolderPath is the path to the log folder
	FolderPath string `yaml:"folder_path" doc_example:"\"/var/log/vc\""`
}

// Common holds the shared configuration used across all services
type Common struct {
	// Production enables production mode
	Production *bool `yaml:"production" default:"true"`
	// Log is the logging configuration
	Log Log `yaml:"log"`
	// Mongo is the MongoDB configuration
	Mongo Mongo `yaml:"mongo" validate:"omitempty"`
	// Tracing is the OpenTelemetry tracing configuration
	Tracing OTEL `yaml:"tracing" validate:"omitempty"`
	// Kafka is the Kafka message broker configuration
	Kafka Kafka `yaml:"kafka" validate:"omitempty"`
	// SecretFilePath is the path to a separate YAML file containing secrets; when set, secret values in config.yaml are cleared and only non-empty fields from the secrets file are applied.
	SecretFilePath string `yaml:"secret_file_path,omitempty" doc_example:"\"/etc/vc/secrets.yaml\""`
	// HA configures high-availability mode. When Enable is true, caches use MongoDB
	// (Common.Mongo.URI) instead of in-memory storage so state is shared across instances.
	HA HAConfig `yaml:"ha" validate:"omitempty"`

	// Branding holds custom branding configuration (logo and favicon paths)
	Branding Branding `yaml:"branding"`

	// CredentialMetadata maps OAuth2 scope values to their credential configuration, required by apigw, issuer, and verifier
	// Key: OAuth2 scope (e.g., "pid", "ehic", "diploma") - matches AuthorizationContext.Scope
	// Each entry contains the VCTM reference, format, and other configuration for that credential type
	CredentialMetadata map[string]*CredentialMetadata `yaml:"credential_metadata" validate:"omitempty,dive" doc_key:"credential scope"`
}

// Branding holds custom branding paths for logo and favicon
type Branding struct {
	// LogoPath is the file path to a custom logo PNG image; when empty, the built-in SUNET logo is used
	LogoPath string `yaml:"logo_path,omitempty" validate:"omitempty,image_png"`
	// FaviconPath is the file path to a custom favicon PNG image; when empty, the built-in SUNET favicon is used
	FaviconPath string `yaml:"favicon_path,omitempty" validate:"omitempty,image_png"`
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
	AllowedClientFingerprints map[string]string `yaml:"allowed_client_fingerprints" doc_example:"a1b2c3...: issuer-prod"`                 // SHA256 fingerprint -> friendly name
	AllowedClientDNs          map[string]string `yaml:"allowed_client_dns" doc_example:"apigw-prod: CN=apigw,O=SUNET"`                    // Friendly name -> Certificate Subject DN
}

// JWTAttribute holds the jwt attribute configuration.
// In a later state this should be placed under authentic source in order to issue credentials based on that configuration.
type JWTAttribute struct {
	// Issuer of the token
	Issuer string `yaml:"issuer" validate:"required" doc_example:"https://issuer.sunet.se"`

	// StaticHost is the static host of the issuer, expose static files, like pictures.
	StaticHost string `yaml:"static_host" validate:"omitempty"`

	// EnableNotBefore states the time not before which the token is valid
	EnableNotBefore bool `yaml:"enable_not_before" default:"false"`

	// Valid duration of the token in seconds
	ValidDuration int64 `yaml:"valid_duration" validate:"required_with=EnableNotBefore" default:"3600"`

	// VerifiableCredentialType URL
	VerifiableCredentialType string `yaml:"verifiable_credential_type" validate:"required" doc_example:"https://credential.sunet.se/identity_credential"`

	// Status status of the Verifiable Credential
	Status string `yaml:"status"`

	// Kid key id of the signing key
	Kid string `yaml:"kid"`
}

// SAMLSP holds SAML Service Provider configuration for the issuer
type SAMLSP struct {
	// Enable turns on SAML support (default: false)
	Enable bool `yaml:"enable" default:"false"`

	// EntityID is the SAML SP entity identifier (typically the metadata URL)
	EntityID string `yaml:"entity_id" validate:"required_if=Enable true" doc_example:"\"https://issuer.sunet.se/saml/metadata\""`

	// MetadataURL is the public URL where SP metadata is served (optional, auto-generated if empty)
	MetadataURL string `yaml:"metadata_url,omitempty"`

	// MDQServer is the base URL for MDQ (Metadata Query Protocol) server (must end with /)
	// Mutually exclusive with StaticIDPMetadata
	MDQServer string `yaml:"mdq_server,omitempty" doc_example:"\"https://md.sunet.se/entities/\""`

	// StaticIDPMetadata configures a single static IdP as alternative to MDQ
	// Mutually exclusive with MDQServer
	StaticIDPMetadata *StaticIDPConfig `yaml:"static_idp_metadata,omitempty"`

	// CertificatePath is the path to X.509 certificate for SAML signing/encryption
	// TODO(pki): Migrate to pki.KeyConfig for consistency with other services and
	// to enable HSM-backed SAML signing keys in the future.
	CertificatePath string `yaml:"certificate_path" validate:"required_if=Enable true"`

	// PrivateKeyPath is the path to private key for SAML signing/encryption
	// TODO(pki): See CertificatePath TODO — both fields would be replaced by a single KeyConfig.
	PrivateKeyPath string `yaml:"private_key_path" validate:"required_if=Enable true"`

	// ACSEndpoint is the Assertion Consumer Service URL where IdP sends SAML responses
	ACSEndpoint string `yaml:"acs_endpoint" validate:"required_if=Enable true" doc_example:"\"https://issuer.sunet.se/saml/acs\""`

	// SessionDuration is the maximum time in seconds an in-flight SAML authentication flow
	// (AuthnRequest → Response) may remain active before it expires
	SessionDuration int `yaml:"session_duration" validate:"required" default:"300"`

	// AttributeMapping normalizes provider-specific attribute names (e.g. SAML OIDs)
	// to canonical claim names. Applied to ALL attributes in the assertion.
	// Which normalized attributes are used depends on the data source:
	//   - assertion: VCTM determines which go into the credential
	//   - datastore: auth_claims determines which are used for DB identity lookup
	AttributeMapping AttributeMapping `yaml:"attribute_mapping" validate:"required_if=Enable true" doc_key:"attribute"`

	// MetadataSigningCertPath is the path to the X.509 certificate used to verify
	// metadata signatures. When set, all fetched metadata (MDQ and static) must
	// carry a valid XML signature from this certificate.
	MetadataSigningCertPath string `yaml:"metadata_signing_cert_path,omitempty"`

	// AllowUnsignedMetadata permits MDQ/URL metadata without signature verification.
	// This is INSECURE (MITM → fake IdP) and should only be used in development.
	// When false (default), MDQ and URL metadata sources require MetadataSigningCertPath.
	// Local metadata files are allowed unsigned regardless (with a startup warning).
	AllowUnsignedMetadata bool `yaml:"allow_unsigned_metadata" default:"false"`

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

// OIDCRP holds OIDC Relying Party configuration for credential issuance.
type OIDCRP struct {
	// Enable turns on OIDC RP support (default: false)
	Enable bool `yaml:"enable" default:"false"`

	// Registration configures how the client obtains credentials from the OIDC Provider.
	// Exactly one of preconfigured or dynamic must be set:
	//   - preconfigured: pre-registered client_id and client_secret
	//   - dynamic: RFC 7591 dynamic client registration (credentials obtained at startup)
	Registration *OIDCRPRegistrationConfig `yaml:"registration" validate:"required_if=Enable true"`

	// RedirectURI is the callback URL where the OIDC Provider sends the authorization response
	RedirectURI string `yaml:"redirect_uri" validate:"required_if=Enable true" doc_example:"\"https://issuer.sunet.se/oidcrp/callback\""`

	// IssuerURL is the OIDC Provider's issuer URL for discovery
	// Used for .well-known/openid-configuration discovery
	IssuerURL string `yaml:"issuer_url" validate:"required_if=Enable true" doc_example:"\"https://accounts.google.com\""`

	// Scopes are the OAuth2/OIDC scopes to request (at least one scope is required, e.g. "openid")
	Scopes []string `yaml:"scopes" validate:"required,min=1,dive,required" default:"[\"openid\", \"profile\", \"email\"]"`

	// SessionDuration is the maximum time in seconds an in-flight OIDC authorization flow
	// (state, nonce, PKCE verifier) may remain active before it expires
	SessionDuration int `yaml:"session_duration" validate:"required" default:"300"`

	// ClientName is a human-readable name for the OIDC client, shown during dynamic registration or consent
	ClientName string `yaml:"client_name,omitempty"`
	// ClientURI is a URL to the client's homepage, used for display during consent
	ClientURI string `yaml:"client_uri,omitempty"`
	// LogoURI is a URL to the client's logo image, shown during consent screens
	LogoURI string `yaml:"logo_uri,omitempty"`
	// Contacts is a list of email addresses for responsible parties of this client
	Contacts []string `yaml:"contacts,omitempty"`
	// TosURI is a URL to the client's Terms of Service document
	TosURI string `yaml:"tos_uri,omitempty"`
	// PolicyURI is a URL to the client's Privacy Policy document
	PolicyURI string `yaml:"policy_uri,omitempty"`

	// AttributeMapping normalizes OIDC claim names to canonical claim names.
	// Optional: when omitted, OIDC claims pass through as-is (standard names already match).
	// Which normalized attributes are used depends on the data source:
	//   - assertion: VCTM determines which go into the credential
	//   - datastore: auth_claims determines which are used for DB identity lookup
	AttributeMapping AttributeMapping `yaml:"attribute_mapping,omitempty" doc_key:"attribute"`
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

// AttributeMapping maps external attribute names to claim configurations.
// Keys are protocol-specific identifiers (SAML OIDs, OIDC claim names, etc.),
// values define how each attribute maps to a credential claim.
type AttributeMapping map[string]AttributeConfig

// AttributeConfig defines how a single external attribute maps to a credential claim
// Generic across protocols (SAML, OIDC, etc.) - uses protocol-specific identifiers as keys
type AttributeConfig struct {
	// Claim is the target claim name (supports dot-notation for nesting)
	Claim string `yaml:"claim" validate:"required" doc_example:"\"identity.given_name\""`

	// Required indicates if this attribute must be present in the assertion/response
	Required bool `yaml:"required" default:"false"`

	// Transform is an optional transformation to apply
	// Supported: "lowercase", "uppercase", "trim", "country_alpha2", "country_alpha3"
	Transform string `yaml:"transform,omitempty" validate:"omitempty,oneof=lowercase uppercase trim country_alpha2 country_alpha3"`

	// Default is an optional default value if attribute is missing
	Default string `yaml:"default,omitempty"`

	// AsArray wraps a scalar value in a single-element array before setting the claim.
	// No-op when the value is already a slice (e.g. multi-valued OIDC claim).
	AsArray bool `yaml:"as_array,omitempty"`
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
	IssuerURL string `yaml:"issuer_url" validate:"required" doc_example:"\"https://issuer.sunet.se\""`
	// RegistryClient is the registry gRPC client config
	RegistryClient GRPCClientTLS `yaml:"registry_client" validate:"omitempty"`
	// MDoc holds mDL/mdoc configuration
	MDoc *MDocConfig `yaml:"mdoc" validate:"omitempty"`
	// AuditLog holds audit log configuration
	AuditLog *AuditLog `yaml:"audit_log" validate:"omitempty"`
	// SignMetadataRateLimit configures the rate limiter for the SignMetadata gRPC endpoint.
	// In HA setups each APIGW node refreshes two documents (VCI+OAuth2), so the defaults
	// should accommodate the expected cluster size. Default: 2 req/s, burst 20.
	SignMetadataRateLimit SignMetadataRateLimitConfig `yaml:"sign_metadata_rate_limit"`
}

// SignMetadataRateLimitConfig configures the SignMetadata gRPC rate limiter.
type SignMetadataRateLimitConfig struct {
	// RequestsPerSecond is the sustained rate limit in requests per second. Default: 2
	RequestsPerSecond float64 `yaml:"requests_per_second" default:"2" validate:"gt=0"`
	// Burst is the maximum number of requests allowed in a single burst. Default: 20
	Burst int `yaml:"burst" default:"20" validate:"gt=0"`
}

// AuditLog holds audit log configuration for multiple destinations
type AuditLog struct {
	// Enable enables audit logging
	Enable bool `yaml:"enable" default:"false"`
	// Destinations is the list of log destinations (console/stdout, file path, or HTTP URL)
	Destinations []string `yaml:"destinations" validate:"required_if=Enable true,min=1" doc_example:"[\"stdout\", \"/var/log/audit.log\", \"https://audit.sunet.se/webhook\"]"`
	// FileSyncInterval controls fsync behavior for file destinations.
	// 0 = fsync after every write (strict durability, lower throughput).
	// >0 = periodic batched fsync at the given interval (better throughput, bounded data-loss window).
	// Has no effect on console or webhook destinations.
	FileSyncInterval time.Duration `yaml:"file_sync_interval" default:"5s"`
}

// MDocConfig holds mDL (ISO 18013-5) issuer configuration
type MDocConfig struct {
	// CertificateChainPath is the path to the PEM certificate chain
	// TODO(pki): Consider folding into pki.KeyConfig.ChainPath to unify certificate
	// chain loading with the standard key material configuration pattern.
	CertificateChainPath string `yaml:"certificate_chain_path" validate:"required"`
	// DefaultValidity is the default credential validity (default: 365 days)
	DefaultValidity time.Duration `yaml:"default_validity" default:"8760h"`
	// DigestAlgorithm is the digest algorithm: "SHA-256", "SHA-384", or "SHA-512"
	DigestAlgorithm string `yaml:"digest_algorithm" default:"SHA-256"`
}

// GRPCClientTLS holds mTLS configuration for gRPC client connections
type GRPCClientTLS struct {
	// Addr is the gRPC server address
	Addr string `yaml:"addr" validate:"required" doc_example:"\"issuer:8090\""`
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
	PublicURL string `yaml:"public_url" validate:"required,httpurl" doc_example:"\"https://registry.sunet.se\""`
	// GRPCServer is the gRPC server configuration
	GRPCServer GRPCServer `yaml:"grpc_server" validate:"required"`
	// TokenStatusLists holds the Token Status List configuration
	TokenStatusLists *TokenStatusLists `yaml:"token_status_lists" validate:"required"`
	// AdminGUI holds the admin GUI configuration
	AdminGUI AdminGUI `yaml:"admin_gui,omitempty" validate:"omitempty"`
}

// AdminGUI holds the admin GUI configuration
type AdminGUI struct {
	// Enable enables the admin GUI
	Enable *bool `yaml:"enable" default:"false"`
	// Username is the admin username
	Username string `yaml:"username" validate:"required_if=Enable true" default:"admin"`
	// Password is the admin password
	Password string `yaml:"password" validate:"required_if=Enable true"`
}

// VerificationPreset is a map of scope name to optional credential query overrides.
// The preset's map key (in the parent Presets map) serves as the human-readable label.
// Each key in this map references a credential_metadata scope (e.g., "pid", "ehic").
// A nil value means "request all VCTM claims with no overrides".
type VerificationPreset map[string]*VerificationPresetScope

// VerificationPresetScope defines optional overrides for a credential query within a preset.
type VerificationPresetScope struct {
	// Claims lists specific claims to request. If empty, all VCTM claims are used.
	Claims []VerificationPresetClaim `yaml:"claims,omitempty" validate:"omitempty,dive"`
	// ExcludeClaims lists claims to exclude from the DCQL query.
	ExcludeClaims []VerificationPresetClaim `yaml:"exclude_claims,omitempty" validate:"omitempty,dive"`
	// Validations are optional rules applied server-side after claims extraction
	Validations []openid4vp.ClaimValidation `yaml:"validations,omitempty" validate:"omitempty,dive"`
}

// VerificationPresetClaim defines a claim path to request within a credential.
type VerificationPresetClaim struct {
	// Path is the claim path segments
	Path []string `yaml:"path" validate:"required,min=1,dive,required" doc_example:"[\"birthdate\"], [\"address\", \"locality\"]"`
}

// VerifierInbound groups inbound credential verification configuration
type VerifierInbound struct {
	// OpenID4VP holds the OpenID4VP configuration for accepting wallet presentations
	OpenID4VP *OpenID4VPConfig `yaml:"openid4vp" validate:"required"`
}

// VerifierOutbound groups outbound identity assertion configuration
type VerifierOutbound struct {
	// OIDCProvider holds the OIDC Provider configuration for asserting verified identity to downstream RPs
	OIDCProvider *OIDCOP `yaml:"oidc_provider,omitempty" validate:"omitempty"`
}

// Verifier holds the configuration for the Verifier service that verifies credentials and acts as an OIDC Provider
type Verifier struct {
	// APIServer is the HTTP API server configuration
	APIServer APIServer `yaml:"api_server" validate:"required"`
	// PublicURL is the public URL of this service (must be valid HTTP/HTTPS URL)
	PublicURL string `yaml:"public_url" validate:"required,httpurl" doc_example:"\"https://verifier.sunet.se\""`
	// KeyConfig is the signing key configuration
	KeyConfig *pki.KeyConfig `yaml:"key_config" validate:"required"`
	// PreferredVPFormats specifies informational VP formats and algorithms supported by wallets
	PreferredVPFormats *openid4vp.VPFormatsSupported `yaml:"preferred_vp_formats,omitempty"`
	// SupportedWallets holds supported wallet configurations
	SupportedWallets map[string]string `yaml:"supported_wallets" validate:"omitempty"`
	// Inbound groups inbound credential verification
	Inbound VerifierInbound `yaml:"inbound,omitempty"`
	// Outbound groups outbound identity assertion
	Outbound VerifierOutbound `yaml:"outbound,omitempty"`
	// DigitalCredentials holds the W3C Digital Credentials API configuration
	DigitalCredentials DigitalCredentialsConfig `yaml:"digital_credentials,omitempty"`
	// AuthorizationPageCSS holds the authorization page styling configuration
	AuthorizationPageCSS AuthorizationPageCSSConfig `yaml:"authorization_page_css,omitempty"`
	// CredentialDisplay holds the credential display settings
	CredentialDisplay CredentialDisplayConfig `yaml:"credential_display,omitempty"`
	// Trust holds the trust evaluation configuration
	Trust TrustConfig `yaml:"trust,omitempty"`
	// Presets holds predefined verification request presets shown in the UI.
	// The map key is the human-readable label (e.g., "PID", "PID + EHIC").
	// Each preset maps credential_metadata scopes to optional claim overrides.
	// A nil scope value requests all VCTM claims; use claims/exclude_claims to narrow.
	Presets map[string]VerificationPreset `yaml:"presets,omitempty" validate:"omitempty,dive,dive" doc_key:"preset label" doc_value_key:"scope" doc_example:"\"PID\":{\"pid\":null},\"PID + EHIC\":{\"pid\":null,\"ehic\":null}"`
}

// TrustConfig holds configuration for key resolution and trust evaluation via go-trust.
// This is used for validating W3C VC Data Integrity proofs and other trust-related operations.
//
// Trust evaluation operates in one of two modes:
//   - When PDPURL is configured: "default deny" mode - all trust decisions go through the PDP
//   - When PDPURL is empty: "allow all" mode - keys are resolved but always considered trusted
type TrustConfig struct {
	// PDPURL is the URL of the AuthZEN PDP (Policy Decision Point) service for trust evaluation.
	// When set, operates in "default deny" mode - trust decisions require PDP approval.
	// When empty, operates in "allow all" mode - resolved keys are always considered trusted.
	PDPURL string `yaml:"pdp_url,omitempty" doc_example:"\"https://trust.sunet.se/pdp\""`

	// LocalDIDMethods specifies which DID methods can be resolved locally without go-trust.
	// Self-contained methods like "did:key" and "did:jwk" are always resolved locally.
	LocalDIDMethods []string `yaml:"local_did_methods,omitempty" default:"[\"did:key\", \"did:jwk\"]"`

	// TrustPolicies configures per-role trust evaluation policies.
	// The key is the role (e.g., "issuer", "verifier") and the value contains policy settings.
	TrustPolicies map[string]TrustPolicyConfig `yaml:"trust_policies,omitempty" doc_key:"role"`

	// AllowedSignatureAlgorithms restricts which JWT signature algorithms are accepted.
	// If empty, defaults to a secure set: ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384, PS512, EdDSA.
	// The "none" algorithm is NEVER allowed regardless of configuration.
	AllowedSignatureAlgorithms []string `yaml:"allowed_signature_algorithms,omitempty" doc_example:"[\"ES256\", \"ES384\", \"ES512\", \"EdDSA\"]"`
}

// TrustPolicyConfig defines trust policy settings for a specific role.
type TrustPolicyConfig struct {
	// TrustFrameworks lists the accepted trust frameworks for this role.
	TrustFrameworks []string `yaml:"trust_frameworks,omitempty" doc_example:"[\"did:web\", \"did:ebsi\", \"etsi-tl\", \"openid-federation\", \"x509\"]"`

	// TrustAnchors specifies trusted root entities for this role.
	// Format depends on the trust framework (e.g., DID for did:web, federation entity for OpenID Fed).
	TrustAnchors []string `yaml:"trust_anchors,omitempty"`

	// RequireRevocationCheck enforces revocation status checking for this role.
	// Default: false
	RequireRevocationCheck bool `yaml:"require_revocation_check,omitempty" default:"false"`
}

// StaticOIDCClient defines a pre-configured OIDC client for the verifier's OIDC Provider.
// Static clients are configured in YAML and do not require dynamic registration.
// These clients are checked in addition to dynamically registered clients stored in the database.
type StaticOIDCClient struct {
	// ClientID is the unique identifier for the client
	ClientID string `yaml:"client_id" validate:"required"`
	// ClientSecret is the client secret for authentication.
	// Can be defined in the secrets file under verifier.oidc_op.static_clients
	// as a map of client_id to client_secret.
	// Required unless TokenEndpointAuthMethod is "none" (public client).
	ClientSecret string `yaml:"client_secret" validate:"required_unless=TokenEndpointAuthMethod none"`
	// RedirectURIs is the list of allowed redirect URIs for this client
	RedirectURIs []string `yaml:"redirect_uris" validate:"required,min=1,dive,redirect_uri"`
	// AllowedScopes is the list of scopes this client is allowed to request.
	// If empty, defaults to standard OIDC scopes (openid, profile, email, address, phone).
	AllowedScopes []string `yaml:"allowed_scopes,omitempty"`
	// TokenEndpointAuthMethod is the authentication method for the token endpoint.
	// Supported values: client_secret_basic, client_secret_post, none (public client)
	// Default: "client_secret_basic"
	TokenEndpointAuthMethod string `yaml:"token_endpoint_auth_method,omitempty" default:"client_secret_basic" validate:"omitempty,oneof=client_secret_basic client_secret_post none"`
	// GrantTypes is the list of allowed grant types.
	// Supported values: authorization_code, refresh_token
	// Default: ["authorization_code"]
	GrantTypes []string `yaml:"grant_types,omitempty" default:"[\"authorization_code\"]" validate:"omitempty,dive,oneof=authorization_code refresh_token"`
	// ResponseTypes is the list of allowed response types.
	// Supported values: code
	// Default: ["code"]
	ResponseTypes []string `yaml:"response_types,omitempty" default:"[\"code\"]" validate:"omitempty,dive,oneof=code"`
	// ClientName is an optional human-readable name for the client
	ClientName string `yaml:"client_name,omitempty"`
}

// OIDCConfig holds OIDC-specific configuration for the verifier's role as an OpenID Provider.
// This configures how the verifier issues ID tokens and access tokens to relying parties.
// Note: This is NOT related to verifiable credential issuance (see IssuerConfig for VC issuance).
// The signing key is shared from the parent Verifier.KeyConfig.
type OIDCOP struct {
	// Issuer is the OIDC Provider identifier that appears in ID tokens and discovery metadata.
	// This identifies the verifier as an OpenID Provider.
	// Must match the 'iss' claim in all issued ID tokens.
	Issuer string `yaml:"issuer" validate:"required" doc_example:"\"https://verifier.sunet.se\""`
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
	// EnableUserInfo controls whether the verifier-OP advertises a userinfo_endpoint
	// in its discovery metadata and issues JWT access tokens (RFC 9068 at+jwt).
	// When true (default), the OP advertises userinfo_endpoint in discovery and
	// returns an access token alongside the ID token. The userinfo endpoint
	// is stateless: it validates the JWT signature and returns the embedded claims.
	// When false, only ID tokens are returned — no access_token or userinfo endpoint.
	EnableUserInfo bool `yaml:"enable_userinfo" default:"true"`
	// StaticClients is a list of pre-configured OIDC clients
	// These clients are checked in addition to dynamically registered clients
	StaticClients []StaticOIDCClient `yaml:"static_clients,omitempty"`
}

// OpenID4VPConfig holds OpenID4VP-specific configuration
type OpenID4VPConfig struct {
	// PresentationTimeout is the presentation timeout in seconds
	PresentationTimeout int `yaml:"presentation_timeout" validate:"required" default:"300"`
	// SupportedCredentials holds the supported credential configurations
	SupportedCredentials []SupportedCredentialConfig `yaml:"supported_credentials" validate:"required"`
	// PresentationRequestsDir is an optional directory with presentation request templates
	PresentationRequestsDir string `yaml:"presentation_requests_dir,omitempty"`
	// TokenEndpoint is the OAuth2 token endpoint URL used for VP token exchange
	TokenEndpoint string `yaml:"token_endpoint" validate:"required" doc_example:"\"https://verifier.sunet.se/token\""`
	// Clients holds the OAuth2 client configurations for RP interactions
	Clients oauth2.Clients `yaml:"clients" validate:"required" doc_key:"client id"`
}

// GetSupportedCredentials returns the supported credentials, or nil if the config is nil.
func (c *OpenID4VPConfig) GetSupportedCredentials() []SupportedCredentialConfig {
	if c == nil {
		return nil
	}
	return c.SupportedCredentials
}

// GetPresentationRequestsDir returns the presentation requests directory, or empty string if the config is nil.
func (c *OpenID4VPConfig) GetPresentationRequestsDir() string {
	if c == nil {
		return ""
	}
	return c.PresentationRequestsDir
}

// GenerateMetadata generates OAuth2 metadata from the OpenID4VP configuration.
// Returns unsigned metadata that should be signed on-demand in the endpoint handler for freshness.
func (c *OpenID4VPConfig) GenerateMetadata(ctx context.Context, issuerURL string) *oauth2.AuthorizationServerMetadata {
	return oauth2.GenerateMetadata(&oauth2.MetadataConfig{
		IssuerURL:     issuerURL,
		TokenEndpoint: c.TokenEndpoint,
	})
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
	AllowQRFallback *bool `yaml:"allow_qr_fallback" default:"true"`

	// DeepLinkScheme for mobile wallet integration
	DeepLinkScheme string `yaml:"deep_link_scheme,omitempty" doc_example:"\"eudi-wallet://\""`
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
	PrimaryColor string `yaml:"primary_color,omitempty" doc_example:"\"#667eea\""`

	// SecondaryColor overrides the secondary brand color
	SecondaryColor string `yaml:"secondary_color,omitempty" doc_example:"\"#764ba2\""`

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
	ShowClaims *bool `yaml:"show_claims" default:"true"`

	// AllowEdit allows users to redact certain claims before sending to RP (future feature)
	// Currently not implemented
	AllowEdit bool `yaml:"allow_edit,omitempty" default:"false"`
}

// SupportedCredentialConfig maps credential types to OIDC scopes
type SupportedCredentialConfig struct {
	// VCT is the verifiable credential type
	VCT string `yaml:"vct" validate:"required" doc_example:"\"urn:eudi:pid:1\""`
	// Scopes are the OIDC scopes that grant access to this credential
	Scopes []string `yaml:"scopes" validate:"required"`
}

// APIAuth configures authentication for the API route group (datastore, identity mapping, admin UI)
// JWKS and OIDC are mutually exclusive
// If neither is enabled, no authentication is applied (open access)
//
// When Rules (and/or RulesFile) are configured, each authenticated request is
// checked against a SPOCP engine. A query of the form
//
//	(vc (service <SERVICE>)(method <HTTP_METHOD>)(path <REQUEST_PATH>)(subject <JWT_SUBJECT>)(authentic_source <SOURCE>)(scope <SCOPE>))
//
// is evaluated; the request is allowed only if a matching rule exists.
// All six parts are required in every rule. Use * as wildcard for fields
// you don't want to restrict.
// The <SERVICE> value is supplied by the calling service at middleware
// registration time. When two services share endpoints, rules for one
// service do not grant access to the other.
// When no rules are configured, any valid Bearer JWT grants access.
type APIAuth struct {
	// JWKS holds the static JWKS Bearer token authentication configuration
	// When enabled, requests are validated against a manually configured JWKS URL
	JWKS APIAuthJWKS `yaml:"jwks"`
	// OIDC holds the OIDC Bearer token authentication configuration
	// When enabled, the JWKS endpoint is auto-discovered from the issuer's
	// .well-known/openid-configuration and Bearer JWTs are validated locally
	// The RP fields (client_id, redirect_uri, etc.) also enable the admin UI
	// login flow via OIDC redirect
	OIDC APIAuthOIDC `yaml:"oidc"`
	// Rules are SPOCP S-expression authorization rules loaded into an in-process engine.
	// All six parts (service, method, path, subject, authentic_source, scope) are mandatory
	// in every rule — use * for wildcards.
	// Rules apply regardless of whether JWKS or OIDC is the active auth method
	Rules []string `yaml:"rules,omitempty" doc_example:"[\"(vc (service apigw)(method POST)(path /api/v1/upload)(subject alice)(authentic_source SUNET)(scope eduid))\"]"`
	// RulesFile is an optional path to a file containing SPOCP rules (one per line)
	// Rules from this file are loaded in addition to the inline Rules list
	RulesFile string `yaml:"rules_file,omitempty"`
}

// APIAuthJWKS holds the configuration for static JWKS Bearer token authentication
type APIAuthJWKS struct {
	// Enable enables static JWKS Bearer token authentication
	Enable bool `yaml:"enable" default:"false"`
	// JWKSURL is the URL of the JSON Web Key Set used to validate token signatures.
	// Mutually exclusive with jwks_file_path; exactly one must be set when enable is true
	JWKSURL string `yaml:"jwks_url" validate:"excluded_with=JWKSFilePath,omitempty,url" doc_example:"\"https://auth.example.com/.well-known/jwks.json\""`
	// JWKSFilePath is a local file path to a JWKS JSON file used to validate token signatures.
	// Mutually exclusive with jwks_url; exactly one must be set when enable is true
	JWKSFilePath string `yaml:"jwks_file_path" validate:"excluded_with=JWKSURL,omitempty"`
	// Issuer is the expected "iss" claim. Tokens with a different issuer are rejected
	Issuer string `yaml:"issuer" validate:"required_if=Enable true"`
	// Audience is the expected "aud" claim. Tokens that do not contain this audience are rejected
	Audience string `yaml:"audience" validate:"required_if=Enable true"`
}

// APIAuthOIDC holds the configuration for OIDC-based authentication.
// It serves two purposes:
//   - API auth: Bearer JWTs in Authorization headers are validated locally
//     against the provider's JWKS (auto-discovered from IssuerURL).
//   - Admin UI login: the RP fields (ClientID, RedirectURI, Scopes) enable
//     an authorization-code redirect flow so admins log in via the OIDC provider.
type APIAuthOIDC struct {
	// Enable enables OIDC authentication
	Enable bool `yaml:"enable" default:"false"`
	// IssuerURL is the OIDC provider's issuer URL used for discovery and "iss" claim validation.
	IssuerURL string `yaml:"issuer_url" validate:"required_if=Enable true,omitempty,url" doc_example:"\"https://auth.example.com\""`
	// Audience is the expected "aud" claim. Tokens that do not contain this audience are rejected.
	Audience string `yaml:"audience" validate:"required_if=Enable true"`
	// ClientID is the OAuth2 client identifier registered with the OIDC provider.
	ClientID string `yaml:"client_id" validate:"required_if=Enable true"`
	// ClientSecret is the OAuth2 client secret. May be empty for public clients.
	ClientSecret string `yaml:"client_secret"`
	// RedirectURI is the callback URL for the admin UI OIDC login flow (e.g. "https://apigw.example.com/ui/callback").
	RedirectURI string `yaml:"redirect_uri" validate:"required_if=Enable true,omitempty,url" doc_example:"\"https://apigw.example.com/ui/callback\""`
	// Scopes are the OAuth2/OIDC scopes to request (default: ["openid"]).
	Scopes []string `yaml:"scopes"`
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
	RedirectURI string `yaml:"redirect_uri" validate:"required" doc_example:"\"eudi-wallet://credential-offer\""`
}

// CredentialOffers holds credential offer configurations
type CredentialOffers struct {
	// IssuerURL is the issuer URL for credential offers
	IssuerURL string `yaml:"issuer_url" validate:"required"`
	// Wallets holds wallet redirect configurations
	Wallets map[string]CredentialOfferWallets `yaml:"wallets" validate:"required" doc_key:"wallet name"`
}

// OpenID4VPCredentialAuth holds per-credential OpenID4VP authentication requirements
type OpenID4VPCredentialAuth struct {
	// AuthScopes maps credential scope keys to per-scope auth config (claims to extract)
	AuthScopes map[string]AuthScopeEntry
}

// APIGWDelivery groups credential delivery configuration (wallets, offers).
type APIGWDelivery struct {
	// OpenID4VCI configures the OpenID4VCI Authorization Server for wallet credential issuance
	OpenID4VCI OAuthServer `yaml:"openid4vci" validate:"required"`
	// CredentialOffers holds credential offer wallet configurations
	CredentialOffers CredentialOffers `yaml:"credential_offers" validate:"required"`
}

// APIGWAuthProviders groups the authentication provider configurations.
type APIGWAuthProviders struct {
	// SAML configures the SAML SP auth provider
	SAML SAMLSP `yaml:"saml,omitempty" validate:"omitempty"`
	// OIDC configures the OIDC RP auth provider
	OIDC OIDCRP `yaml:"oidc,omitempty" validate:"omitempty"`
}

// APIGW holds the configuration for the API Gateway service that handles credential issuance requests
type APIGW struct {
	// APIServer is the HTTP API server configuration
	APIServer APIServer `yaml:"api_server" validate:"required"`
	// AdminUIEnable enables the admin web UI. When false (default), the /ui routes are not registered.
	// This must be explicitly set to true to enable the admin interface.
	AdminUIEnable bool `yaml:"admin_ui_enable" default:"false"`
	// KeyConfig is the signing key configuration
	KeyConfig *pki.KeyConfig `yaml:"key_config" validate:"required"`
	// DataSources maps credential types to their data sources
	DataSources DataSources `yaml:"data_sources,omitempty" validate:"required"`
	// AuthProviders configures how users authenticate (SAML, OIDC)
	AuthProviders APIGWAuthProviders `yaml:"auth_providers,omitempty"`
	// Remotes defines named external API connections referenced by DataSources.ExternalAPI
	Remotes map[string]Remote `yaml:"remotes,omitempty" doc_key:"remote name" doc_example:"\"ladok\""`
	// Delivery groups credential delivery to wallets (OpenID4VCI, credential offers)
	Delivery APIGWDelivery `yaml:"delivery" validate:"required"`
	// IssuerMetadata holds the OpenID4VCI issuer metadata
	IssuerMetadata IssuerMetadata `yaml:"issuer_metadata" validate:"omitempty"`
	// PublicURL is the public URL of this service (must be valid HTTP/HTTPS URL)
	PublicURL string `yaml:"public_url" validate:"required,httpurl" doc_example:"\"https://issuer.sunet.se\""`
	// IssuerClient is the gRPC client config for issuer
	IssuerClient GRPCClientTLS `yaml:"issuer_client" validate:"required"`
	// RegistryClient is the gRPC client config for registry
	RegistryClient GRPCClientTLS `yaml:"registry_client" validate:"required"`
	// IdentityMappingImport configures automatic import of identity mappings from JSON files at startup.
	// When configured, APIGW reads JSON files and imports them into the
	// identity mappings collection on first startup (skipped if data already exists).
	IdentityMappingImport *IdentityMappingImport `yaml:"identity_mapping_import,omitempty"`
	// Trust holds the trust evaluation configuration for OpenID4VP credential validation.
	// When configured, credentials presented via VP are validated against a PDP.
	Trust TrustConfig `yaml:"trust,omitempty"`
}

// TokenStatusLists holds the configuration for Token Status List per draft-ietf-oauth-status-list
type TokenStatusLists struct {
	// KeyConfig holds the key configuration for signing Token Status List tokens.
	KeyConfig *pki.KeyConfig `yaml:"key_config" validate:"required"`
	// TokenRefreshInterval is how often (in seconds) new Token Status List tokens are generated. Default: 43200 (12 hours). Min: 301 (>5 minutes), Max: 86400 (24 hours)
	TokenRefreshInterval int64 `yaml:"token_refresh_interval" validate:"min=301,max=86400" default:"43200"`
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
	Addr string `yaml:"addr" validate:"required_if=Enable true" doc_example:"\"jaeger:4318\""`
	// Timeout is the timeout in seconds
	Timeout int64 `yaml:"timeout" default:"10"`
}

// OAuthServer holds the OAuth2 server configuration
type OAuthServer struct {
	// TokenEndpoint is the OAuth2 token endpoint URL
	TokenEndpoint string `yaml:"token_endpoint" validate:"required" doc_example:"\"https://verifier.sunet.se/token\""`
	// Clients holds the OAuth2 client configurations
	Clients oauth2.Clients `yaml:"clients" validate:"required" doc_key:"client id"`
	// AllowUnverifiedClientAssertion enables accepting client_assertion (private_key_jwt)
	// WITHOUT signature verification. This is INSECURE and only intended for conformance
	// testing environments. When false (default), client_assertion is rejected.
	// TODO(security): Remove this flag once full RFC 7523 verification is implemented.
	AllowUnverifiedClientAssertion bool `yaml:"allow_unverified_client_assertion" default:"false"`
}

// Cfg is the main configuration structure for this application
type Cfg struct {
	Common   *Common   `yaml:"common"`
	APIGW    *APIGW    `yaml:"apigw" validate:"omitempty"`
	Issuer   *Issuer   `yaml:"issuer" validate:"omitempty"`
	Verifier *Verifier `yaml:"verifier" validate:"omitempty"`
	Registry *Registry `yaml:"registry" validate:"omitempty"`
}

// LookupCredentialSources returns full data source information for a credential type
// across all data sources where it is configured.
// Returns an error if the credential type is not configured in any DataSource.
func (c *Cfg) LookupCredentialSources(scope string) ([]CredentialSource, error) {
	if c.APIGW == nil {
		return nil, fmt.Errorf("scope %q has no data source configured", scope)
	}
	return c.APIGW.DataSources.LookupCredentialSources(scope)
}

// GetOpenID4VPAuth returns the OpenID4VP authentication config for a credential type, or nil if not found.
func (c *Cfg) GetOpenID4VPAuth(scope string) *OpenID4VPCredentialAuth {
	if c.APIGW == nil {
		return nil
	}
	if cred, ok := c.APIGW.DataSources.Datastore.Scopes[scope]; ok {
		if cred.AuthProvider == AuthProviderOpenID4VP {
			return &OpenID4VPCredentialAuth{
				AuthScopes: cred.AuthScopes,
			}
		}
	}
	return nil
}

// GetCredentialMetadata returns the credential constructor for a given scope
func (c *Cfg) GetCredentialMetadata(scope string) *CredentialMetadata {
	if c.Common == nil {
		return nil
	}
	// Direct lookup by scope (map key)
	if constructor, ok := c.Common.CredentialMetadata[scope]; ok {
		return constructor
	}

	return nil
}

// GetFormatForScope returns the credential format for the given scope key.
// Returns empty string if the scope is not found in credentials.
func (c *Cfg) GetFormatForScope(scope string) string {
	constructor := c.GetCredentialMetadata(scope)
	if constructor == nil {
		return ""
	}
	return constructor.Format
}

// VCTUrlsForScopes resolves a list of scope keys to their resolved VCT URLs.
// Scopes without a loaded VCTM are silently skipped.
func (c *Cfg) VCTUrlsForScopes(scopes []string) []string {
	urls := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		constructor := c.GetCredentialMetadata(scope)
		if constructor == nil {
			continue
		}
		if v := constructor.GetVCTURL(); v != "" {
			urls = append(urls, v)
		}
	}
	return urls
}

// VCTIdentifiersForScopes resolves a list of scope keys to the original VCT
// identifiers from the VCTM (e.g. URNs). Scopes without a loaded VCTM are
// silently skipped.
func (c *Cfg) VCTIdentifiersForScopes(scopes []string) []string {
	ids := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		constructor := c.GetCredentialMetadata(scope)
		if constructor == nil {
			continue
		}
		if vctm := constructor.GetVCTM(); vctm != nil && vctm.VCT != "" {
			ids = append(ids, vctm.VCT)
		}
	}
	return ids
}

type CredentialMetadata struct {
	// VCTMFilePath is the path to a local VCTM JSON file.
	// When set, apigw will publish the VCTM at /type-metadata/:scope.
	// Mutually exclusive with VCTMUrl (one of the two is required).
	VCTMFilePath string `yaml:"vctm_file_path" json:"-" validate:"required_without=VCTMUrl"`
	// VCTMUrl is the URL where the VCTM is already published externally.
	// When set, the VCTM is fetched from this URL at startup for internal use
	// but NOT re-published by apigw.
	// Mutually exclusive with VCTMFilePath (one of the two is required).
	VCTMUrl string `yaml:"vctm_url" json:"-" validate:"required_without=VCTMFilePath,omitempty,url"`

	VCTM *sdjwtvc.VCTM `yaml:"-" json:"-"`
	// Format is the credential format to issue
	Format string `yaml:"format" json:"format" validate:"required" default:"dc+sd-jwt" doc_example:"\"dc+sd-jwt\""`
	// Attributes maps claim names to their source fields and transformation rules for credential issuance
	Attributes map[string]map[string][]*string `yaml:"attributes" json:"attributes_v2" validate:"omitempty,dive,required"`

	// VCTMRaw holds the raw JSON bytes of the VCTM document for serving
	// via /type-metadata/:scope. Only populated for local VCTMs (VCTMFilePath).
	VCTMRaw []byte `yaml:"-" json:"-"`

	// Integrity is the SRI hash of the VCTM document (e.g. "sha256-...").
	// Computed once in LoadVCTMetadata and used for vct#integrity in issued credentials.
	Integrity string `yaml:"-" json:"-"`

	// VCTURL is the published URL where the VCTM is served.
	// Set by ResolveVCTUrls for both local and external VCTMs.
	VCTURL string `yaml:"-" json:"-"`

	// mu guards VCTM, VCTMRaw, Integrity, and Attributes during background refresh.
	mu sync.RWMutex `yaml:"-" json:"-"`
}

// The scope parameter is used only for error messages.
func (c *CredentialMetadata) LoadVCTMetadata(ctx context.Context, scope string) error {
	var (
		rawBytes []byte
		err      error
	)

	switch {
	case c.VCTMFilePath != "":
		data, err := os.ReadFile(c.VCTMFilePath)
		if err != nil {
			return fmt.Errorf("failed to read VCTM file %s for scope %s: %w", c.VCTMFilePath, scope, err)
		}
		rawBytes = data

	case c.VCTMUrl != "":
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.VCTMUrl, nil)
		if err != nil {
			return fmt.Errorf("failed to create request for VCTM URL %s for scope %s: %w", c.VCTMUrl, scope, err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to fetch VCTM from %s for scope %s: %w", c.VCTMUrl, scope, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("VCTM URL %s returned status %d for scope %s", c.VCTMUrl, resp.StatusCode, scope)
		}
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read VCTM response from %s for scope %s: %w", c.VCTMUrl, scope, err)
		}
		rawBytes = data
	}

	var vctm sdjwtvc.VCTM
	if err := json.Unmarshal(rawBytes, &vctm); err != nil {
		return fmt.Errorf("failed to unmarshal VCTM for scope %s: %w", scope, err)
	}

	// Swap cached data under write lock so concurrent readers see a
	// consistent snapshot.
	c.mu.Lock()
	defer c.mu.Unlock()
	c.VCTM = &vctm
	c.Integrity, err = vctm.SRIIntegrity(rawBytes)
	if err != nil {
		return fmt.Errorf("failed to compute VCTM integrity for scope %s: %w", scope, err)
	}
	c.Attributes = vctm.Attributes()

	// Only keep raw bytes for locally-served VCTMs.
	if c.IsLocalVCTM() {
		c.VCTMRaw = rawBytes
	}

	return nil
}

// GetVCTM returns the cached VCTM under a read lock so it is safe to call
// concurrently with the background refresh loop.
func (c *CredentialMetadata) GetVCTM() *sdjwtvc.VCTM {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.VCTM
}

// GetVCTURL returns the published URL where the VCTM is served.
func (c *CredentialMetadata) GetVCTURL() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.VCTURL
}

// GetVCTMRaw returns the raw VCTM JSON bytes under a read lock.
func (c *CredentialMetadata) GetVCTMRaw() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.VCTMRaw
}

// GetAttributes returns the derived attributes under a read lock.
func (c *CredentialMetadata) GetAttributes() map[string]map[string][]*string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Attributes
}

// GetIntegrity returns the SRI integrity hash of the VCTM under a read lock.
func (c *CredentialMetadata) GetIntegrity() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Integrity
}

// IsLocalVCTM returns true when the VCTM is loaded from a local file
// (i.e. apigw should publish it at /type-metadata/:scope).
func (c *CredentialMetadata) IsLocalVCTM() bool {
	return c.VCTMFilePath != ""
}

// ResolveVCTUrls computes the URL-based VCT for each credential metadata entry
// and stores it in VCTURL.  VCTM.VCT, VCTMRaw, and Integrity are left
// unchanged — the served VCTM document preserves the original VCT
// identifier from the VCTM file (e.g. a URN).
// For local VCTMs the URL is built from apigwPublicURL + /type-metadata/{scope}.
// For external VCTMs the VCTMUrl is used.
func (cfg *Cfg) ResolveVCTUrls(apigwPublicURL string) error {
	if cfg.Common == nil {
		return nil
	}
	for scope, constructor := range cfg.Common.CredentialMetadata {
		if constructor == nil || constructor.GetVCTM() == nil {
			continue
		}

		var vctURL string
		switch {
		case constructor.IsLocalVCTM():
			u, err := url.JoinPath(apigwPublicURL, "/type-metadata/", scope)
			if err != nil {
				return fmt.Errorf("failed to build VCT URL for scope %s: %w", scope, err)
			}
			vctURL = u
		case constructor.VCTMUrl != "":
			vctURL = constructor.VCTMUrl
		}

		constructor.mu.Lock()
		constructor.VCTURL = vctURL
		constructor.mu.Unlock()
	}

	// Validate that every constructor got a non-empty VCTURL.
	for scope, constructor := range cfg.Common.CredentialMetadata {
		if constructor == nil || constructor.GetVCTM() == nil {
			continue
		}
		if constructor.GetVCTURL() == "" {
			return fmt.Errorf("VCTURL is empty for scope %q after resolution (check vctm_file_path or vctm_url)", scope)
		}
	}

	return nil
}

// Generate generates issuer metadata from configuration.
// Returns unsigned metadata that should be signed on-demand in the endpoint handler for freshness.
func (cfg *IssuerMetadata) Generate(ctx context.Context, publicURL string, credentials map[string]*CredentialMetadata) (*openid4vci.CredentialIssuerMetadataParameters, error) {
	// Convert CredentialMetadata to CredentialConfigurationsSupported
	credentialConfigs := make(map[string]openid4vci.CredentialConfigurationsSupported)
	for scope, constructor := range credentials {
		if constructor == nil {
			continue
		}
		vctm := constructor.GetVCTM()
		if vctm == nil {
			return nil, fmt.Errorf("credential constructor for scope %q has no VCTM metadata loaded (check vctm_file_path)", scope)
		}

		credConfig := openid4vci.CredentialConfigurationsSupported{
			Format: constructor.Format,
			Scope:  scope,
		}

		// Set format-specific parameters per OID4VCI 1.0 Appendix A
		resolvedVCT := constructor.GetVCTURL()
		switch constructor.Format {
		case "dc+sd-jwt":
			// Appendix A.3: only vct is format-specific for dc+sd-jwt
			credConfig.VCT = resolvedVCT
		case "mso_mdoc":
			// Appendix A.2: doctype is format-specific for mso_mdoc
			credConfig.Doctype = resolvedVCT // VCT serves as doctype for mdoc
		case "jwt_vc_json", "ldp_vc", "jwt_vc_json-ld":
			// Appendix A.1: credential_definition with type array is format-specific for W3C VC formats
			credConfig.CredentialDefinition = &openid4vci.CredentialDefinition{
				Type: []string{"VerifiableCredential"},
			}
			credConfig.VCT = resolvedVCT
		default:
			// For unknown formats, include VCT if available
			credConfig.VCT = resolvedVCT
		}

		// Build credential_metadata object (OID4VCI 1.0 Section 12.2.4)
		credMetadata := &openid4vci.CredentialMetadata{}

		// Use VCTM display information
		if len(vctm.Display) > 0 {
			credMetadata.Display = make([]openid4vci.CredentialMetadataDisplay, len(vctm.Display))
			for i, vctmDisplay := range vctm.Display {
				display := openid4vci.CredentialMetadataDisplay{
					Name:        vctmDisplay.Name,
					Locale:      vctmDisplay.Locale,
					Description: vctmDisplay.Description,
				}

				// Map rendering information from VCTM to OpenID4VCI format
				if vctmDisplay.Rendering != nil && vctmDisplay.Rendering.Simple != nil {
					simple := vctmDisplay.Rendering.Simple
					if simple.BackgroundColor != "" {
						display.BackgroundColor = simple.BackgroundColor
					}
					if simple.TextColor != "" {
						display.TextColor = simple.TextColor
					}
					if simple.Logo != nil && simple.Logo.URI != "" {
						display.Logo = &openid4vci.MetadataLogo{
							URI:     simple.Logo.URI,
							AltText: simple.Logo.AltText,
						}
					}
					if simple.BackgroundImage != nil && simple.BackgroundImage.URI != "" {
						display.BackgroundImage = &openid4vci.MetadataBackgroundImage{
							URI: simple.BackgroundImage.URI,
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
