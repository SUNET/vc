package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v2"
)

// Config is the top-level wallet test configuration.
// Each wallet instance runs one test scenario defined here.
type Config struct {
	// Wallet identity and key material
	Wallet WalletIdentity `yaml:"wallet"`

	// APIServer configures the wallet's HTTP API for triggering and inspecting test runs
	APIServer APIServer `yaml:"api_server"`

	// Scenarios lists the test flows to execute
	Scenarios []Scenario `yaml:"scenarios"`
}

// WalletIdentity holds the wallet's key material and DID
type WalletIdentity struct {
	// KeyPath is the path to the wallet's private key PEM file
	KeyPath string `yaml:"key_path"`
	// KeyAlgorithm is the signing algorithm (ES256, RS256, etc.)
	KeyAlgorithm string `yaml:"key_algorithm" default:"ES256"`
	// DID is the wallet's DID (optional, derived from key if empty)
	DID string `yaml:"did,omitempty"`
	// ClientID is the wallet's OAuth2 client_id
	ClientID string `yaml:"client_id"`
}

// APIServer configures the wallet's HTTP listener
type APIServer struct {
	Addr string `yaml:"addr" default:":8080"`
}

// Scenario defines a single test flow to execute
type Scenario struct {
	// Name is a human-readable name for this scenario
	Name string `yaml:"name"`
	// Type is the scenario type: "vci" or "vp"
	Type string `yaml:"type"`
	// VCI holds VCI-specific test parameters (when type=vci)
	VCI *VCIScenario `yaml:"vci,omitempty"`
	// VP holds VP-specific test parameters (when type=vp)
	VP *VPScenario `yaml:"vp,omitempty"`
	// AutoRun starts the scenario automatically on startup
	AutoRun bool `yaml:"auto_run"`
	// DelayBefore adds a delay before running (useful for sequencing)
	DelayBefore time.Duration `yaml:"delay_before,omitempty"`
}

// VCIScenario defines parameters for an OpenID4VCI credential issuance test
type VCIScenario struct {
	// CredentialOfferURI is the credential_offer_uri to start from (mutually exclusive with CredentialOffer)
	CredentialOfferURI string `yaml:"credential_offer_uri,omitempty"`
	// CredentialOffer is an inline credential offer JSON (mutually exclusive with CredentialOfferURI)
	CredentialOffer string `yaml:"credential_offer,omitempty"`
	// IssuerURL is the issuer's base URL (used to fetch metadata if not starting from offer)
	IssuerURL string `yaml:"issuer_url,omitempty"`
	// Scope is the OAuth2 scope to request
	Scope string `yaml:"scope,omitempty"`
	// RedirectURI for the authorization code flow
	RedirectURI string `yaml:"redirect_uri,omitempty"`
	// UsePAR uses Pushed Authorization Requests
	UsePAR bool `yaml:"use_par"`
	// UseDPoP uses DPoP token binding
	UseDPoP bool `yaml:"use_dpop"`
	// PreAuthorizedCode is set for pre-authorized code flow (skips authorization)
	PreAuthorizedCode string `yaml:"pre_authorized_code,omitempty"`
	// TXCode is the transaction code for pre-auth flow
	TXCode string `yaml:"tx_code,omitempty"`
	// CredentialConfigurationID specifies which credential config to request
	CredentialConfigurationID string `yaml:"credential_configuration_id,omitempty"`
	// ProofType is the proof type to include: "jwt", "none"
	ProofType string `yaml:"proof_type" default:"jwt"`
	// RequestEncryption enables credential response encryption
	RequestEncryption bool `yaml:"request_encryption"`
	// DeferredPolling enables polling for deferred credentials
	DeferredPolling bool `yaml:"deferred_polling"`
	// DeferredPollInterval is the interval between deferred polling attempts
	DeferredPollInterval time.Duration `yaml:"deferred_poll_interval,omitempty"`
	// DeferredPollMaxAttempts is the maximum number of deferred polling attempts
	DeferredPollMaxAttempts int `yaml:"deferred_poll_max_attempts,omitempty"`
	// SendNotification sends a notification after credential receipt
	SendNotification bool `yaml:"send_notification"`
	// NotificationEvent is the notification event type to send
	NotificationEvent string `yaml:"notification_event,omitempty"`
	// ExpectError is the expected error code (for negative testing)
	ExpectError string `yaml:"expect_error,omitempty"`
}

// VPScenario defines parameters for an OpenID4VP presentation test
type VPScenario struct {
	// AuthorizationRequestURI is the openid4vp:// URI to process
	AuthorizationRequestURI string `yaml:"authorization_request_uri,omitempty"`
	// RequestURI is the request_uri to fetch the request object from
	RequestURI string `yaml:"request_uri,omitempty"`
	// VerifierURL is the verifier's URL for fetching request objects
	VerifierURL string `yaml:"verifier_url,omitempty"`
	// CredentialFilter selects which stored credentials to present
	CredentialFilter *CredentialFilter `yaml:"credential_filter,omitempty"`
	// ResponseMode overrides the verifier's requested response_mode
	ResponseMode string `yaml:"response_mode,omitempty"`
	// SkipConsentCheck simulates auto-consent (no user interaction)
	SkipConsentCheck bool `yaml:"skip_consent_check"`
	// MalformedVP intentionally creates a malformed VP token (negative testing)
	MalformedVP bool `yaml:"malformed_vp"`
	// WrongSignature uses wrong key to sign the VP (negative testing)
	WrongSignature bool `yaml:"wrong_signature"`
	// ExpectError is the expected error from the verifier (for negative testing)
	ExpectError string `yaml:"expect_error,omitempty"`
	// SendCredentialIDs is a list of stored credential IDs to present
	SendCredentialIDs []string `yaml:"send_credential_ids,omitempty"`
}

// CredentialFilter selects credentials from the wallet's store
type CredentialFilter struct {
	// VCT filters by verifiable credential type
	VCT string `yaml:"vct,omitempty"`
	// Format filters by credential format (e.g., "vc+sd-jwt")
	Format string `yaml:"format,omitempty"`
}

// Load reads the wallet config from a YAML file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading wallet config %q: %w", path, err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing wallet config %q: %w", path, err)
	}

	// Apply defaults
	if cfg.APIServer.Addr == "" {
		cfg.APIServer.Addr = ":8080"
	}
	if cfg.Wallet.KeyAlgorithm == "" {
		cfg.Wallet.KeyAlgorithm = "ES256"
	}

	return cfg, nil
}
