package model

// Secrets defines the structure of the separate secrets file.
// When Common.SecretFilePath is set, secret values in config.yaml are
// cleared; only non-empty fields from this file are applied.
// Fields omitted or left empty here remain at their zero value.
type Secrets struct {
	Common   *CommonSecrets   `yaml:"common,omitempty"`
	APIGW    *APIGWSecrets    `yaml:"apigw,omitempty"`
	Registry *RegistrySecrets `yaml:"registry,omitempty"`
	Verifier *VerifierSecrets `yaml:"verifier,omitempty"`
	UI       *UISecrets       `yaml:"ui,omitempty"`
}

// CommonSecrets holds secrets from the common section
type CommonSecrets struct {
	Mongo MongoSecrets `yaml:"mongo,omitempty"`
}

// MongoSecrets holds the mongo connection URI (may contain credentials)
type MongoSecrets struct {
	URI string `yaml:"uri"`
}

// APIGWSecrets holds API gateway secrets
type APIGWSecrets struct {
	APIServer APIServerSecrets `yaml:"api_server,omitempty"`
	OIDCRP    OIDCRPSecrets    `yaml:"oidc_rp,omitempty"`
}

// APIServerSecrets holds API server secrets (basic auth passwords)
type APIServerSecrets struct {
	APIAuth APIAuthSecrets `yaml:"api_auth,omitempty"`
}

// APIAuthSecrets holds secrets for the api_auth section
type APIAuthSecrets struct {
	BasicAuth BasicAuthSecrets `yaml:"basic_auth,omitempty"`
}

// BasicAuthSecrets holds basic auth user/password pairs
type BasicAuthSecrets struct {
	Users map[string]string `yaml:"users,omitempty"`
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
	ClientSecret string `yaml:"client_secret"`
}

// OIDCRPDynamicSecrets holds dynamic registration secrets
type OIDCRPDynamicSecrets struct {
	InitialAccessToken string `yaml:"initial_access_token"`
}

// RegistrySecrets holds registry secrets
type RegistrySecrets struct {
	AdminGUI AdminGUISecrets `yaml:"admin_gui,omitempty"`
}

// AdminGUISecrets holds admin GUI secrets
type AdminGUISecrets struct {
	Password string `yaml:"password"`
}

// VerifierSecrets holds verifier secrets
type VerifierSecrets struct {
	OIDCOP OIDCOPSecrets `yaml:"oidc_op,omitempty"`
}

// OIDCOPSecrets holds OIDC OP configuration secrets
type OIDCOPSecrets struct {
	SubjectSalt string `yaml:"subject_salt"`
	// StaticClients maps client_id to client_secret for static OIDC clients.
	// Only clients listed here will have their secrets applied; clients not
	// present in this map keep whatever value the main config provides (which
	// will be empty after ClearSecrets).
	StaticClients map[string]string `yaml:"static_clients,omitempty"`
}

// UISecrets holds UI secrets
type UISecrets struct {
	Password string `yaml:"password"`
}

// ClearSecrets zeroes out all secret fields in the main config.
// Called when a secret file is used, to ensure config.yaml secrets are not used.
func (cfg *Cfg) ClearSecrets() {
	if cfg.Common != nil && cfg.Common.Mongo.URI != "" {
		cfg.Common.Mongo.URI = ""
	}

	if cfg.APIGW != nil {
		cfg.APIGW.APIServer.APIAuth.BasicAuth.Users = nil
		if cfg.APIGW.OIDCRP.Registration != nil && cfg.APIGW.OIDCRP.Registration.Preconfigured != nil {
			cfg.APIGW.OIDCRP.Registration.Preconfigured.ClientSecret = ""
		}
		if cfg.APIGW.OIDCRP.Registration != nil && cfg.APIGW.OIDCRP.Registration.Dynamic != nil {
			cfg.APIGW.OIDCRP.Registration.Dynamic.InitialAccessToken = ""
		}
	}

	if cfg.Registry != nil {
		cfg.Registry.AdminGUI.Password = ""
	}

	if cfg.Verifier != nil && cfg.Verifier.OIDCOP != nil {
		cfg.Verifier.OIDCOP.SubjectSalt = ""
		for i := range cfg.Verifier.OIDCOP.StaticClients {
			cfg.Verifier.OIDCOP.StaticClients[i].ClientSecret = ""
		}
	}

	if cfg.UI != nil {
		cfg.UI.Password = ""
	}
}

// ApplySecrets applies secret values from the Secrets struct onto the Cfg.
// Only non-empty secret values are applied.
func (cfg *Cfg) ApplySecrets(secrets *Secrets) {
	if secrets == nil {
		return
	}

	if secrets.Common != nil {
		if cfg.Common == nil {
			cfg.Common = &Common{}
		}
		if secrets.Common.Mongo.URI != "" {
			cfg.Common.Mongo.URI = secrets.Common.Mongo.URI
		}
	}

	if secrets.APIGW != nil {
		if cfg.APIGW == nil {
			cfg.APIGW = &APIGW{}
		}
		if len(secrets.APIGW.APIServer.APIAuth.BasicAuth.Users) > 0 {
			cfg.APIGW.APIServer.APIAuth.BasicAuth.Users = secrets.APIGW.APIServer.APIAuth.BasicAuth.Users
		}
		if secrets.APIGW.OIDCRP.Registration.Preconfigured != nil && secrets.APIGW.OIDCRP.Registration.Preconfigured.ClientSecret != "" {
			if cfg.APIGW.OIDCRP.Registration == nil {
				cfg.APIGW.OIDCRP.Registration = &OIDCRPRegistrationConfig{}
			}
			if cfg.APIGW.OIDCRP.Registration.Preconfigured == nil {
				cfg.APIGW.OIDCRP.Registration.Preconfigured = &OIDCRPPreconfiguredConfig{}
			}
			cfg.APIGW.OIDCRP.Registration.Preconfigured.ClientSecret = secrets.APIGW.OIDCRP.Registration.Preconfigured.ClientSecret
		}
		if secrets.APIGW.OIDCRP.Registration.Dynamic != nil && secrets.APIGW.OIDCRP.Registration.Dynamic.InitialAccessToken != "" {
			if cfg.APIGW.OIDCRP.Registration == nil {
				cfg.APIGW.OIDCRP.Registration = &OIDCRPRegistrationConfig{}
			}
			if cfg.APIGW.OIDCRP.Registration.Dynamic == nil {
				cfg.APIGW.OIDCRP.Registration.Dynamic = &OIDCRPDynamicRegistrationConfig{}
			}
			cfg.APIGW.OIDCRP.Registration.Dynamic.InitialAccessToken = secrets.APIGW.OIDCRP.Registration.Dynamic.InitialAccessToken
		}
	}

	if secrets.Registry != nil {
		if cfg.Registry == nil {
			cfg.Registry = &Registry{}
		}
		if secrets.Registry.AdminGUI.Password != "" {
			cfg.Registry.AdminGUI.Password = secrets.Registry.AdminGUI.Password
		}
	}

	if secrets.Verifier != nil {
		if cfg.Verifier == nil {
			cfg.Verifier = &Verifier{}
		}
		if secrets.Verifier.OIDCOP.SubjectSalt != "" || len(secrets.Verifier.OIDCOP.StaticClients) > 0 {
			if cfg.Verifier.OIDCOP == nil {
				cfg.Verifier.OIDCOP = &OIDCOPConfig{}
			}
			if secrets.Verifier.OIDCOP.SubjectSalt != "" {
				cfg.Verifier.OIDCOP.SubjectSalt = secrets.Verifier.OIDCOP.SubjectSalt
			}
			for i := range cfg.Verifier.OIDCOP.StaticClients {
				if secret, ok := secrets.Verifier.OIDCOP.StaticClients[cfg.Verifier.OIDCOP.StaticClients[i].ClientID]; ok {
					cfg.Verifier.OIDCOP.StaticClients[i].ClientSecret = secret
				}
			}
		}
	}

	if secrets.UI != nil {
		if cfg.UI == nil {
			cfg.UI = &UI{}
		}
		if secrets.UI.Password != "" {
			cfg.UI.Password = secrets.UI.Password
		}
	}
}
