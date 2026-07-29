package model

// Secrets defines the structure of the separate secrets file.
// When Common.SecretFilePath is set, ApplySecrets merges these values
// into the main config: the Mongo URI is only used when the main config
// has none. For each service section (apigw, registry, verifier) that
// is present in the secrets file, the corresponding secret fields in
// the main config are cleared and replaced by the secrets-file values.
// Sections omitted from the secrets file are left untouched.
type Secrets struct {
	Common   *CommonSecrets   `yaml:"common,omitempty"`
	APIGW    *APIGWSecrets    `yaml:"apigw,omitempty"`
	Registry *RegistrySecrets `yaml:"registry,omitempty"`
	Verifier *VerifierSecrets `yaml:"verifier,omitempty"`
}

// CommonSecrets holds secrets from the common section
type CommonSecrets struct {
	Mongo MongoSecrets `yaml:"mongo,omitempty"`
}

// MongoSecrets holds the mongo connection URI (may contain credentials)
type MongoSecrets struct {
	// URI is the MongoDB connection string, which may include authentication credentials
	URI string `yaml:"uri"`
}

// APIGWSecrets holds API gateway secrets
type APIGWSecrets struct {
	APIServer     APIServerSecrets     `yaml:"api_server,omitempty"`
	AuthProviders AuthProvidersSecrets `yaml:"auth_providers,omitempty"`
}

// AuthProvidersSecrets holds secrets for auth providers
type AuthProvidersSecrets struct {
	OIDC OIDCRPSecrets `yaml:"oidc,omitempty"`
}

// APIServerSecrets holds API server secrets (basic auth passwords)
type APIServerSecrets struct {
	APIAuth APIAuthSecrets `yaml:"api_auth,omitempty"`
}

// APIAuthSecrets holds secrets for the api_auth section
type APIAuthSecrets struct {
	OIDC OIDCAuthSecrets `yaml:"oidc,omitempty"`
}

// OIDCAuthSecrets holds OIDC client secret for API auth
type OIDCAuthSecrets struct {
	// ClientSecret is the OAuth2 client secret for the OIDC provider
	ClientSecret string `yaml:"client_secret,omitempty"`
}

// OIDCRPSecrets holds OIDC Relying Party secrets
type OIDCRPSecrets struct {
	Registration OIDCRPRegistrationSecrets `yaml:"registration,omitempty"`
}

// OIDCRPRegistrationSecrets holds registration secrets
type OIDCRPRegistrationSecrets struct {
	Preconfigured *OIDCRPPreconfiguredSecrets `yaml:"preconfigured,omitempty"`
	Dynamic       *OIDCRPDynamicSecrets       `yaml:"dynamic,omitempty"`
}

// OIDCRPPreconfiguredSecrets holds pre-registered client secrets
type OIDCRPPreconfiguredSecrets struct {
	// ClientSecret is the shared secret for the pre-configured OIDC RP client
	ClientSecret string `yaml:"client_secret"`
}

// OIDCRPDynamicSecrets holds dynamic registration secrets
type OIDCRPDynamicSecrets struct {
	// InitialAccessToken is the bearer token required by the OP for dynamic client registration
	InitialAccessToken string `yaml:"initial_access_token"`
}

// RegistrySecrets holds registry secrets
type RegistrySecrets struct {
	AdminGUI AdminGUISecrets `yaml:"admin_gui,omitempty"`
}

// AdminGUISecrets holds admin GUI secrets
type AdminGUISecrets struct {
	// Password is the admin GUI login password
	Password string `yaml:"password"`
}

// VerifierSecrets holds verifier secrets
type VerifierSecrets struct {
	Outbound VerifierOutboundSecrets `yaml:"outbound,omitempty"`
}

// VerifierOutboundSecrets holds outbound OIDC provider secrets
type VerifierOutboundSecrets struct {
	OIDCProvider OIDCOPSecrets `yaml:"oidc_provider,omitempty"`
}

// OIDCOPSecrets holds OIDC OP configuration secrets
type OIDCOPSecrets struct {
	// SubjectSalt is a secret value used to derive pairwise subject identifiers for OIDC clients
	SubjectSalt string `yaml:"subject_salt"`
	// StaticClients maps client_id to client_secret for static OIDC clients.
	// Only clients listed here will have their secrets applied; clients not
	// present in this map keep whatever value the main config provides (which
	// will be empty after ApplySecrets clears them).
	StaticClients map[string]string `yaml:"static_clients,omitempty" doc_example:"<client_id>: \"<client_secret>\""`
}

// ApplySecrets updates the configuration with values from the secrets file.
// Secret fields (OIDC client secrets, passwords, salts) in the main config
// are cleared and replaced by values from the secrets file.
// The Mongo URI is only set from the secrets file when the main config
// leaves it empty; TLS and certificate paths are not secrets and should
// always be defined in the main config file.
func (cfg *Cfg) ApplySecrets(secrets *Secrets) {
	if secrets == nil {
		return
	}

	// Mongo URI: fill from secrets only when the main config has none.
	if secrets.Common != nil {
		if cfg.Common == nil {
			cfg.Common = &Common{}
		}
		if cfg.Common.Mongo.URI == "" && secrets.Common.Mongo.URI != "" {
			cfg.Common.Mongo.URI = secrets.Common.Mongo.URI
		}
	}

	if secrets.APIGW != nil {
		if cfg.APIGW == nil {
			cfg.APIGW = &APIGW{}
		}
		// Clear secret fields first, then apply from secrets file.
		cfg.APIGW.APIServer.APIAuth.OIDC.ClientSecret = ""
		if cfg.APIGW.AuthProviders.OIDC.Registration != nil && cfg.APIGW.AuthProviders.OIDC.Registration.Preconfigured != nil {
			cfg.APIGW.AuthProviders.OIDC.Registration.Preconfigured.ClientSecret = ""
		}
		if cfg.APIGW.AuthProviders.OIDC.Registration != nil && cfg.APIGW.AuthProviders.OIDC.Registration.Dynamic != nil {
			cfg.APIGW.AuthProviders.OIDC.Registration.Dynamic.InitialAccessToken = ""
		}

		if secrets.APIGW.APIServer.APIAuth.OIDC.ClientSecret != "" {
			cfg.APIGW.APIServer.APIAuth.OIDC.ClientSecret = secrets.APIGW.APIServer.APIAuth.OIDC.ClientSecret
		}
		if secrets.APIGW.AuthProviders.OIDC.Registration.Preconfigured != nil && secrets.APIGW.AuthProviders.OIDC.Registration.Preconfigured.ClientSecret != "" {
			if cfg.APIGW.AuthProviders.OIDC.Registration == nil {
				cfg.APIGW.AuthProviders.OIDC.Registration = &OIDCRPRegistrationConfig{}
			}
			if cfg.APIGW.AuthProviders.OIDC.Registration.Preconfigured == nil {
				cfg.APIGW.AuthProviders.OIDC.Registration.Preconfigured = &OIDCRPPreconfiguredConfig{}
			}
			cfg.APIGW.AuthProviders.OIDC.Registration.Preconfigured.ClientSecret = secrets.APIGW.AuthProviders.OIDC.Registration.Preconfigured.ClientSecret
		}
		if secrets.APIGW.AuthProviders.OIDC.Registration.Dynamic != nil && secrets.APIGW.AuthProviders.OIDC.Registration.Dynamic.InitialAccessToken != "" {
			if cfg.APIGW.AuthProviders.OIDC.Registration == nil {
				cfg.APIGW.AuthProviders.OIDC.Registration = &OIDCRPRegistrationConfig{}
			}
			if cfg.APIGW.AuthProviders.OIDC.Registration.Dynamic == nil {
				cfg.APIGW.AuthProviders.OIDC.Registration.Dynamic = &OIDCRPDynamicRegistrationConfig{}
			}
			cfg.APIGW.AuthProviders.OIDC.Registration.Dynamic.InitialAccessToken = secrets.APIGW.AuthProviders.OIDC.Registration.Dynamic.InitialAccessToken
		}
	}

	if secrets.Registry != nil {
		if cfg.Registry == nil {
			cfg.Registry = &Registry{}
		}
		cfg.Registry.AdminGUI.Password = ""
		if secrets.Registry.AdminGUI.Password != "" {
			cfg.Registry.AdminGUI.Password = secrets.Registry.AdminGUI.Password
		}
	}

	if secrets.Verifier != nil {
		if cfg.Verifier == nil {
			cfg.Verifier = &Verifier{}
		}
		// Clear verifier secret fields first.
		if cfg.Verifier.Outbound.OIDCProvider != nil {
			cfg.Verifier.Outbound.OIDCProvider.SubjectSalt = ""
			for i := range cfg.Verifier.Outbound.OIDCProvider.StaticClients {
				cfg.Verifier.Outbound.OIDCProvider.StaticClients[i].ClientSecret = ""
			}
		}
		if secrets.Verifier.Outbound.OIDCProvider.SubjectSalt != "" || len(secrets.Verifier.Outbound.OIDCProvider.StaticClients) > 0 {
			if cfg.Verifier.Outbound.OIDCProvider == nil {
				cfg.Verifier.Outbound.OIDCProvider = &OIDCOP{}
			}
			if secrets.Verifier.Outbound.OIDCProvider.SubjectSalt != "" {
				cfg.Verifier.Outbound.OIDCProvider.SubjectSalt = secrets.Verifier.Outbound.OIDCProvider.SubjectSalt
			}
			for i := range cfg.Verifier.Outbound.OIDCProvider.StaticClients {
				if secret, ok := secrets.Verifier.Outbound.OIDCProvider.StaticClients[cfg.Verifier.Outbound.OIDCProvider.StaticClients[i].ClientID]; ok {
					cfg.Verifier.Outbound.OIDCProvider.StaticClients[i].ClientSecret = secret
				}
			}
		}
	}
}
