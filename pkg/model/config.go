package model

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"vc/pkg/oauth2"
	"vc/pkg/openid4vci"
	"vc/pkg/pki"
	"vc/pkg/sdjwtvc"

	"gopkg.in/yaml.v2"
)

// APIServer holds the api server configuration
type APIServer struct {
	Addr         string            `yaml:"addr" validate:"required"`
	ExternalPort string            `yaml:"external_port,omitempty" validate:"omitempty"`
	PublicKeys   map[string]string `yaml:"public_keys"`
	TLS          TLS               `yaml:"tls" validate:"omitempty"`
	BasicAuth    BasicAuth         `yaml:"basic_auth"`
	CORS         CORS              `yaml:"cors" validate:"omitempty"`
}

// CORS holds the CORS configuration
type CORS struct {
	AllowedOrigins []string `yaml:"allowed_origins" validate:"omitempty"`
}

// TLS holds the tls configuration
type TLS struct {
	Enabled      bool   `yaml:"enabled"`
	CertFilePath string `yaml:"cert_file_path" validate:"required"`
	KeyFilePath  string `yaml:"key_file_path" validate:"required"`
}

// Mongo holds the database configuration
type Mongo struct {
	URI string `yaml:"uri" validate:"required"`
}

// Kafka holds the kafka configuration that is common for the entire system
type Kafka struct {
	Enabled bool     `yaml:"enabled"`
	Brokers []string `yaml:"brokers" validate:"required"`
}

// Log holds the log configuration
type Log struct {
	Level      string `yaml:"level"`
	FolderPath string `yaml:"folder_path"`
}

// Common holds the common configuration
type Common struct {
	HTTPProxy       string                `yaml:"http_proxy"`
	Production      bool                  `yaml:"production"`
	Log             Log                   `yaml:"log"`
	Mongo           Mongo                 `yaml:"mongo" validate:"omitempty"`
	Tracing         OTEL                  `yaml:"tracing" validate:"required"`
	Kafka           Kafka                 `yaml:"kafka" validate:"omitempty"`
	CredentialOffer CredentialOfferConfig `yaml:"credential_offer" validate:"omitempty"`
}

type CredentialOfferConfig struct {
	// WalletURL sets the wallet url or "openid-credential-offer://"
	WalletURL string `yaml:"wallet_url"`
	IssuerURL string `yaml:"issuer_url" validate:"required"`
	Type      string `yaml:"type" validate:"required,oneof=credential_offer_uri credential_offer"`
	QR        QRCfg  `yaml:"qr" validate:"omitempty"`
}

// QRCfg holds the qr configuration
type QRCfg struct {
	RecoveryLevel int `yaml:"recovery_level" validate:"required,min=0,max=3"`
	Size          int `yaml:"size" validate:"required"`
}

// GRPCServer holds the rpc configuration
type GRPCServer struct {
	Addr     string  `yaml:"addr" validate:"required"`
	Insecure bool    `yaml:"insecure"`
	TLS      GRPCTLS `yaml:"tls,omitempty"`
}

// GRPCTLS holds the mTLS configuration for gRPC server
type GRPCTLS struct {
	Enabled                   bool              `yaml:"enabled"`
	CertFilePath              string            `yaml:"cert_file_path" validate:"required_if=Enabled true"`              // Server certificate
	KeyFilePath               string            `yaml:"key_file_path" validate:"required_if=Enabled true"`               // Server private key
	ClientCAPath              string            `yaml:"client_ca_path" validate:"required_if=Enabled true"`              // CA to verify client certificates (for mTLS)
	AllowedClientFingerprints map[string]string `yaml:"allowed_client_fingerprints" validate:"required_if=Enabled true"` // SHA256 fingerprint -> friendly name (e.g., "a1b2c3..." -> "issuer-prod")
}

// PDF holds the pdf configuration (special Ladok case)
type PDF struct {
	KeepSignedDuration   int `yaml:"keep_signed_duration"`
	KeepUnsignedDuration int `yaml:"keep_unsigned_duration"`
}

// JWTAttribute holds the jwt attribute configuration.
// In a later state this should be placed under authentic source in order to issue credentials based on that configuration.
type JWTAttribute struct {
	// Issuer of the token example: https://issuer.sunet.se
	Issuer string `yaml:"issuer" validate:"required"`

	// StaticHost is the static host of the issuer, expose static files, like pictures
	StaticHost string `yaml:"static_host" validate:"omitempty"`

	// EnableNotBefore states the time not before which the token is valid
	EnableNotBefore bool `yaml:"enable_not_before"`

	// Valid duration of the token in seconds
	ValidDuration int64 `yaml:"valid_duration" validate:"required_with=EnableNotBefore"`

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
	Enabled bool `yaml:"enabled"`

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
	Enabled bool `yaml:"enabled"`

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
	Scopes []string `yaml:"scopes"`

	// SessionDuration in seconds (default: 3600)
	SessionDuration int `yaml:"session_duration"`

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
	Enabled bool `yaml:"enabled"`

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

	// Ensure scopes includes "openid" at minimum
	if len(c.Scopes) == 0 {
		c.Scopes = []string{"openid", "profile", "email"}
	}

	hasOpenID := false
	for _, scope := range c.Scopes {
		if scope == "openid" {
			hasOpenID = true
			break
		}
	}

	if !hasOpenID {
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
	Required bool `yaml:"required"`

	// Transform is an optional transformation to apply
	// Supported: "lowercase", "uppercase", "trim"
	Transform string `yaml:"transform,omitempty" validate:"omitempty,oneof=lowercase uppercase trim"`

	// Default is an optional default value if attribute is missing
	Default string `yaml:"default,omitempty"`
}

// Issuer holds the issuer configuration
type Issuer struct {
	APIServer      APIServer     `yaml:"api_server" validate:"required"`
	Identifier     string        `yaml:"identifier" validate:"required"`
	GRPCServer     GRPCServer    `yaml:"grpc_server" validate:"required"`
	SigningKeyPath string        `yaml:"signing_key_path" validate:"required_without=PKCS11"`
	PKCS11         *PKCS11       `yaml:"pkcs11" validate:"omitempty"`
	JWTAttribute   JWTAttribute  `yaml:"jwt_attribute" validate:"required"`
	IssuerURL      string        `yaml:"issuer_url" validate:"required"`
	WalletURL      string        `yaml:"wallet_url"`
	RegistryClient GRPCClientTLS `yaml:"registry_client" validate:"omitempty"`
	MDoc           *MDocConfig   `yaml:"mdoc" validate:"omitempty"` // mDL/mdoc configuration
}

// MDocConfig holds mDL (ISO 18013-5) issuer configuration
type MDocConfig struct {
	CertificateChainPath string        `yaml:"certificate_chain_path" validate:"required"` // Path to PEM certificate chain
	DefaultValidity      time.Duration `yaml:"default_validity"`                           // Default credential validity (e.g., "365d")
	DigestAlgorithm      string        `yaml:"digest_algorithm"`                           // "SHA-256", "SHA-384", or "SHA-512"
}

// GRPCClientTLS holds mTLS configuration for gRPC client connections
type GRPCClientTLS struct {
	Addr         string `yaml:"addr" validate:"required"` // Registry gRPC server address
	TLS          bool   `yaml:"tls"`                      // Enable TLS
	CertFilePath string `yaml:"cert_file_path"`           // Client certificate for mTLS
	KeyFilePath  string `yaml:"key_file_path"`            // Client private key for mTLS
	CAFilePath   string `yaml:"ca_file_path"`             // CA certificate to verify server
	ServerName   string `yaml:"server_name"`              // Server name for TLS verification (optional)
}

// PKCS11 holds PKCS#11 HSM configuration
type PKCS11 struct {
	ModulePath string `yaml:"module_path" validate:"required"`
	SlotID     uint   `yaml:"slot_id"`
	PIN        string `yaml:"pin" validate:"required"`
	KeyLabel   string `yaml:"key_label" validate:"required"`
	KeyID      string `yaml:"key_id" validate:"required"`
}

// Registry holds the registry configuration
type Registry struct {
	APIServer         APIServer        `yaml:"api_server" validate:"required"`
	ExternalServerURL string           `yaml:"external_server_url" validate:"required"`
	GRPCServer        GRPCServer       `yaml:"grpc_server" validate:"required"`
	TokenStatusLists  TokenStatusLists `yaml:"token_status_lists,omitempty" validate:"omitempty"`
	AdminGUI          AdminGUI         `yaml:"admin_gui,omitempty" validate:"omitempty"`
}

// AdminGUI holds the admin GUI configuration
type AdminGUI struct {
	Enabled       bool   `yaml:"enabled"`
	Username      string `yaml:"username" validate:"required_if=Enabled true"`
	Password      string `yaml:"password" validate:"required_if=Enabled true"`
	SessionSecret string `yaml:"session_secret" validate:"required_if=Enabled true"` // Secret for session cookies
}

// Persistent holds the persistent storage configuration
type Persistent struct {
	APIServer APIServer `yaml:"api_server" validate:"required"`
}

// MockAS holds the mock as configuration
type MockAS struct {
	APIServer      APIServer `yaml:"api_server" validate:"required"`
	DatastoreURL   string    `yaml:"datastore_url" validate:"required"`
	BootstrapUsers []string  `yaml:"bootstrap_users"`
}

// Verifier holds the verifier configuration
type Verifier struct {
	APIServer         APIServer         `yaml:"api_server" validate:"required"`
	GRPCServer        GRPCServer        `yaml:"grpc_server" validate:"required"`
	ExternalServerURL string            `yaml:"external_server_url" validate:"required"`
	OAuthServer       OAuthServer       `yaml:"oauth_server" validate:"omitempty"`
	IssuerMetadata    IssuerMetadata    `yaml:"issuer_metadata" validate:"omitempty"`
	SupportedWallets  map[string]string `yaml:"supported_wallets" validate:"omitempty"`
}

// VerifierProxy holds the verifier proxy configuration
type VerifierProxy struct {
	APIServer            APIServer                  `yaml:"api_server" validate:"required"`
	ExternalURL          string                     `yaml:"external_url" validate:"required"`
	OIDC                 OIDCConfig                 `yaml:"oidc" validate:"required"`
	OpenID4VP            OpenID4VPConfig            `yaml:"openid4vp" validate:"required"`
	DigitalCredentials   DigitalCredentialsConfig   `yaml:"digital_credentials,omitempty"`
	AuthorizationPageCSS AuthorizationPageCSSConfig `yaml:"authorization_page_css,omitempty"`
	CredentialDisplay    CredentialDisplayConfig    `yaml:"credential_display,omitempty"`
	Trust                TrustConfig                `yaml:"trust,omitempty"`
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
	// Default: ["did:key", "did:jwk"]
	LocalDIDMethods []string `yaml:"local_did_methods,omitempty"`

	// TrustPolicies configures per-role trust evaluation policies.
	// The key is the role (e.g., "issuer", "verifier") and the value contains policy settings.
	TrustPolicies map[string]TrustPolicyConfig `yaml:"trust_policies,omitempty"`

	// Enabled controls whether trust evaluation is enabled.
	// When false, keys are resolved but not validated against trust frameworks.
	// Default: true
	Enabled bool `yaml:"enabled,omitempty"`
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
	RequireRevocationCheck bool `yaml:"require_revocation_check,omitempty"`
}

// OIDCConfig holds OIDC-specific configuration for the verifier-proxy's role as an OpenID Provider.
// This configures how the verifier-proxy issues ID tokens and access tokens to relying parties.
// Note: This is NOT related to verifiable credential issuance (see IssuerConfig for VC issuance).
type OIDCConfig struct {
	// Issuer is the OIDC Provider identifier that appears in ID tokens and discovery metadata.
	// This identifies the verifier-proxy itself as an OpenID Provider.
	// Must match the 'iss' claim in all issued ID tokens.
	Issuer               string `yaml:"issuer" validate:"required"`
	SigningKeyPath       string `yaml:"signing_key_path" validate:"required"`
	SigningAlg           string `yaml:"signing_alg" validate:"required,oneof=RS256 RS384 RS512 ES256 ES384 ES512"`
	SessionDuration      int    `yaml:"session_duration" validate:"required"`       // in seconds
	CodeDuration         int    `yaml:"code_duration" validate:"required"`          // in seconds
	AccessTokenDuration  int    `yaml:"access_token_duration" validate:"required"`  // in seconds
	IDTokenDuration      int    `yaml:"id_token_duration" validate:"required"`      // in seconds
	RefreshTokenDuration int    `yaml:"refresh_token_duration" validate:"required"` // in seconds
	SubjectType          string `yaml:"subject_type" validate:"required,oneof=public pairwise"`
	SubjectSalt          string `yaml:"subject_salt" validate:"required"`
}

// OpenID4VPConfig holds OpenID4VP-specific configuration
type OpenID4VPConfig struct {
	PresentationTimeout     int                         `yaml:"presentation_timeout" validate:"required"`
	SupportedCredentials    []SupportedCredentialConfig `yaml:"supported_credentials" validate:"required"`
	PresentationRequestsDir string                      `yaml:"presentation_requests_dir,omitempty"` // Optional: directory with presentation request templates
}

// DigitalCredentialsConfig holds W3C Digital Credentials API configuration
type DigitalCredentialsConfig struct {
	// Enabled toggles W3C Digital Credentials API support in browser
	Enabled bool `yaml:"enabled"`

	// UseJAR enables JWT Authorization Request (JAR) for wallet communication
	// When true, request objects are signed JWTs instead of plain JSON
	UseJAR bool `yaml:"use_jar"`

	// PreferredFormats specifies the order of preference for credential formats
	// Supported values: "vc+sd-jwt", "dc+sd-jwt", "mso_mdoc"
	// Default: ["vc+sd-jwt", "dc+sd-jwt", "mso_mdoc"]
	PreferredFormats []string `yaml:"preferred_formats,omitempty"`

	// ResponseMode specifies the OpenID4VP response mode for DC API flows
	// Supported values: "dc_api.jwt" (encrypted), "direct_post.jwt" (signed), "direct_post"
	// Default: "dc_api.jwt"
	ResponseMode string `yaml:"response_mode,omitempty" validate:"omitempty,oneof=dc_api.jwt direct_post.jwt direct_post"`

	// AllowQRFallback enables automatic fallback to QR code if DC API is unavailable
	// Default: true
	AllowQRFallback bool `yaml:"allow_qr_fallback"`

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
	Theme string `yaml:"theme,omitempty" validate:"omitempty,oneof=light dark blue purple"`

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
	Enabled bool `yaml:"enabled"`

	// RequireConfirmation forces users to review credentials before proceeding
	// When true, the credential display step is mandatory (checkbox is pre-checked and disabled)
	RequireConfirmation bool `yaml:"require_confirmation"`

	// ShowRawCredential displays the raw VP token/credential in the display page
	// Useful for debugging and technical users
	ShowRawCredential bool `yaml:"show_raw_credential"`

	// ShowClaims displays the parsed claims that will be sent to the RP
	// Recommended for transparency and user consent
	ShowClaims bool `yaml:"show_claims"`

	// AllowEdit allows users to redact certain claims before sending to RP (future feature)
	// Currently not implemented
	AllowEdit bool `yaml:"allow_edit,omitempty"`
}

// SupportedCredentialConfig maps credential types to OIDC scopes
type SupportedCredentialConfig struct {
	VCT    string   `yaml:"vct" validate:"required"`
	Scopes []string `yaml:"scopes" validate:"required"`
}

// Datastore holds the datastore configuration
type Datastore struct {
	APIServer  APIServer  `yaml:"api_server" validate:"required"`
	GRPCServer GRPCServer `yaml:"grpc_server" validate:"required"`
}

// BasicAuth holds the basic auth configuration
type BasicAuth struct {
	Users   map[string]string `yaml:"users"`
	Enabled bool              `yaml:"enabled"`
}

type IssuerMetadata struct {
	Path             string `yaml:"path" validate:"required"`
	SigningKeyPath   string `yaml:"signing_key_path" validate:"required"`
	SigningChainPath string `yaml:"signing_chain_path" validate:"required"`
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
	CredentialOffers  CredentialOffers `yaml:"credential_offers" validate:"omitempty"`
	OauthServer       OAuthServer      `yaml:"oauth_server" validate:"omitempty"`
	IssuerMetadata    IssuerMetadata   `yaml:"issuer_metadata" validate:"omitempty"`
	ExternalServerURL string           `yaml:"external_server_url" validate:"required"`
	SAML              SAMLConfig       `yaml:"saml,omitempty" validate:"omitempty"`
	OIDCRP            OIDCRPConfig     `yaml:"oidcrp,omitempty" validate:"omitempty"`
	IssuerClient      GRPCClientTLS    `yaml:"issuer_client" validate:"required"`   // gRPC client config for issuer
	RegistryClient    GRPCClientTLS    `yaml:"registry_client" validate:"required"` // gRPC client config for registry
}

// TokenStatusLists holds the configuration for Token Status List per draft-ietf-oauth-status-list
type TokenStatusLists struct {
	// SigningKeyPath is the path to the ECDSA P-256 private key for signing Token Status List tokens.
	SigningKeyPath string `yaml:"signing_key_path" validate:"required"`
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
	Type    string `yaml:"type" validate:"required"`
	Timeout int64  `yaml:"timeout" default:"10"`
}

// OAuthServer holds the oauth server configuration
type OAuthServer struct {
	TokenEndpoint string         `yaml:"token_endpoint" validate:"required"`
	Clients       oauth2.Clients `yaml:"clients" validate:"required"`
	Metadata      OAuthMetadata  `yaml:"metadata" validate:"required"`
}

type OAuthMetadata struct {
	Path             string `yaml:"path" validate:"required"`
	SigningKeyPath   string `yaml:"signing_key_path" validate:"required"`
	SigningChainPath string `yaml:"signing_chain_path" validate:"required"`
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

// CredentialType holds the configuration for the credential type
type CredentialType struct {
	Profile string `yaml:"profile" validate:"required"`
}

// NotificationEndpoint holds the configuration for the notification endpoint
type NotificationEndpoint struct {
	URL string `yaml:"url" validate:"required"`
}

// AuthenticSourceEndpoint holds the configuration for the authentic source
type AuthenticSourceEndpoint struct {
	URL string `yaml:"url" validate:"required"`
}

// SignatureServiceEndpoint holds the configuration for the signature service
type SignatureServiceEndpoint struct {
	URL string `yaml:"url" validate:"required"`
}

// RevocationServiceEndpoint holds the configuration for the revocation service
type RevocationServiceEndpoint struct {
	URL string `yaml:"url" validate:"required"`
}

// AuthenticSource holds the configuration for the authentic source
type AuthenticSource struct {
	CountryCode               string                    `yaml:"country_code" validate:"required,iso3166_1_alpha2"`
	NotificationEndpoint      NotificationEndpoint      `yaml:"notification_endpoint" validate:"required"`
	AuthenticSourceEndpoint   AuthenticSourceEndpoint   `yaml:"authentic_source_endpoint" validate:"required"`
	SignatureServiceEndpoint  SignatureServiceEndpoint  `yaml:"signature_service_endpoint" validate:"required"`
	RevocationServiceEndpoint RevocationServiceEndpoint `yaml:"revocation_service_endpoint" validate:"required"`
	CredentialTypes           map[string]CredentialType `yaml:"credential_types" validate:"required"`
}

// Cfg is the main configuration structure for this application
type Cfg struct {
	Common           *Common                    `yaml:"common"`
	AuthenticSources map[string]AuthenticSource `yaml:"authentic_sources" validate:"omitempty"`
	APIGW            *APIGW                     `yaml:"apigw" validate:"omitempty"`
	Issuer           *Issuer                    `yaml:"issuer" validate:"omitempty"`
	Verifier         *Verifier                  `yaml:"verifier" validate:"omitempty"`
	VerifierProxy    *VerifierProxy             `yaml:"verifier_proxy" validate:"omitempty"`
	Datastore        *Datastore                 `yaml:"datastore" validate:"omitempty"`
	Registry         *Registry                  `yaml:"registry" validate:"omitempty"`
	Persistent       *Persistent                `yaml:"persistent" validate:"omitempty"`
	MockAS           *MockAS                    `yaml:"mock_as" validate:"omitempty"`
	UI               *UI                        `yaml:"ui" validate:"omitempty"`
	// CredentialConstructor maps OAuth2 scope values to their constructor configuration
	// Key: OAuth2 scope (e.g., "pid", "ehic", "diploma") - matches AuthorizationContext.Scope
	// The constructor contains the VCT URN and other configuration for issuing that credential type
	CredentialConstructor map[string]*CredentialConstructor `yaml:"credential_constructor" validate:"omitempty"`
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

type CredentialConstructor struct {
	VCT          string                         `yaml:"vct" json:"vct" validate:"required"`
	VCTMFilePath string                         `yaml:"vctm_file_path" json:"vctm_file_path" validate:"required"`
	VCTM         *sdjwtvc.VCTM                  `yaml:"-" json:"-"`
	AuthMethod   string                         `yaml:"auth_method" json:"auth_method" validate:"required,oneof=basic pid_auth"`
	Attributes   map[string]map[string][]string `yaml:"attributes" json:"attributes_v2" validate:"omitempty,dive,required"`
}

// LoadVCTMetadata loads and parses the Verifiable Credential Type Metadata (VCTM) file.
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

	return nil
}

// LoadAndSign loads and signs metadata the issuing metadata from
func (cfg *IssuerMetadata) LoadAndSign(ctx context.Context) (*openid4vci.CredentialIssuerMetadataParameters, any, *x509.Certificate, []string, error) {
	fileByte, err := os.ReadFile(cfg.Path)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	metadata := &openid4vci.CredentialIssuerMetadataParameters{}

	switch filepath.Ext(cfg.Path) {
	case ".json":
		if err := json.Unmarshal(fileByte, &metadata); err != nil {
			return nil, nil, nil, nil, err
		}

	case ".yaml", ".yml":
		if err := yaml.Unmarshal(fileByte, &metadata); err != nil {
			return nil, nil, nil, nil, err
		}

	default:
		return nil, nil, nil, nil, errors.New("unsupported file type")
	}

	// ensure that the metadata is empty, should be procured/signed by the request or other automated process
	metadata.SignedMetadata = ""

	privateKey, err := pki.ParseKeyFromFile(cfg.SigningKeyPath)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	cert, chain, err := pki.ParseX509CertificateFromFile(cfg.SigningChainPath)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	chainBase64Encoded := []string{}
	for _, c := range chain {
		chainBase64Encoded = append(chainBase64Encoded, pki.Base64EncodeCertificate(c))
	}

	return metadata, privateKey, cert, chainBase64Encoded, nil
}

// LoadOAuth2Metadata loads OAuth2 metadata from file
func (cfg *OAuthServer) LoadOAuth2Metadata(ctx context.Context) (*oauth2.AuthorizationServerMetadata, any, []string, error) {
	fileByte, err := os.ReadFile(cfg.Metadata.Path)
	if err != nil {
		return nil, nil, nil, err
	}

	metadata := &oauth2.AuthorizationServerMetadata{}

	switch filepath.Ext(cfg.Metadata.Path) {
	case ".json":
		if err := json.Unmarshal(fileByte, &metadata); err != nil {
			return nil, nil, nil, err
		}

	// Not implemented yet
	//case "yaml", ".yml":
	//	if err := yaml.Unmarshal(fileByte, &metadata); err != nil {
	//		return nil, nil, nil, err
	//	}

	default:
		return nil, nil, nil, errors.New("unsupported file type")
	}

	// ensure that the metadata is empty, should be procured/signed by the request or other automated process
	metadata.SignedMetadata = ""

	privateKey, err := pki.ParseKeyFromFile(cfg.Metadata.SigningKeyPath)
	if err != nil {
		return nil, nil, nil, err
	}

	_, chain, err := pki.ParseX509CertificateFromFile(cfg.Metadata.SigningChainPath)
	if err != nil {
		return nil, nil, nil, err
	}

	chainBase64Encoded := []string{}
	for _, c := range chain {
		chainBase64Encoded = append(chainBase64Encoded, pki.Base64EncodeCertificate(c))
	}

	return metadata, privateKey, chainBase64Encoded, nil
}
