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
	OIDCRP    OIDCRPSecrets    `yaml:"oidcrp,omitempty"`
}

// APIServerSecrets holds API server secrets (basic auth passwords)
type APIServerSecrets struct {
	BasicAuth BasicAuthSecrets `yaml:"basic_auth,omitempty"`
}

// BasicAuthSecrets holds basic auth user/password pairs
type BasicAuthSecrets struct {
	Users map[string]string `yaml:"users,omitempty"`
}

// OIDCRPSecrets holds OIDC Relying Party secrets
type OIDCRPSecrets struct {
	ClientSecret string `yaml:"client_secret"`
}

// RegistrySecrets holds registry secrets
type RegistrySecrets struct {
	AdminGUI AdminGUISecrets `yaml:"admin_gui,omitempty"`
}

// AdminGUISecrets holds admin GUI secrets
type AdminGUISecrets struct {
	Password      string `yaml:"password"`
	SessionSecret string `yaml:"session_secret"`
}

// VerifierSecrets holds verifier secrets
type VerifierSecrets struct {
	OIDC OIDCSecrets `yaml:"oidc,omitempty"`
}

// OIDCSecrets holds OIDC configuration secrets
type OIDCSecrets struct {
	SubjectSalt string `yaml:"subject_salt"`
}

// UISecrets holds UI secrets
type UISecrets struct {
	Password                       string `yaml:"password"`
	SessionCookieAuthenticationKey string `yaml:"session_cookie_authentication_key"`
	SessionStoreEncryptionKey      string `yaml:"session_store_encryption_key"`
}

// ClearSecrets zeroes out all secret fields in the main config.
// Called when a secret file is used, to ensure config.yaml secrets are not used.
func (cfg *Cfg) ClearSecrets() {
	if cfg.Common != nil && cfg.Common.Mongo.URI != "" {
		cfg.Common.Mongo.URI = ""
	}

	if cfg.APIGW != nil {
		cfg.APIGW.APIServer.BasicAuth.Users = nil
		cfg.APIGW.OIDCRP.ClientSecret = ""
	}

	if cfg.Registry != nil {
		cfg.Registry.AdminGUI.Password = ""
		cfg.Registry.AdminGUI.SessionSecret = ""
	}

	if cfg.Verifier != nil {
		cfg.Verifier.OIDC.SubjectSalt = ""
	}

	if cfg.UI != nil {
		cfg.UI.Password = ""
		cfg.UI.SessionCookieAuthenticationKey = ""
		cfg.UI.SessionStoreEncryptionKey = ""
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
		if len(secrets.APIGW.APIServer.BasicAuth.Users) > 0 {
			cfg.APIGW.APIServer.BasicAuth.Users = secrets.APIGW.APIServer.BasicAuth.Users
		}
		if secrets.APIGW.OIDCRP.ClientSecret != "" {
			cfg.APIGW.OIDCRP.ClientSecret = secrets.APIGW.OIDCRP.ClientSecret
		}
	}

	if secrets.Registry != nil {
		if cfg.Registry == nil {
			cfg.Registry = &Registry{}
		}
		if secrets.Registry.AdminGUI.Password != "" {
			cfg.Registry.AdminGUI.Password = secrets.Registry.AdminGUI.Password
		}
		if secrets.Registry.AdminGUI.SessionSecret != "" {
			cfg.Registry.AdminGUI.SessionSecret = secrets.Registry.AdminGUI.SessionSecret
		}
	}

	if secrets.Verifier != nil {
		if cfg.Verifier == nil {
			cfg.Verifier = &Verifier{}
		}
		if secrets.Verifier.OIDC.SubjectSalt != "" {
			cfg.Verifier.OIDC.SubjectSalt = secrets.Verifier.OIDC.SubjectSalt
		}
	}

	if secrets.UI != nil {
		if cfg.UI == nil {
			cfg.UI = &UI{}
		}
		if secrets.UI.Password != "" {
			cfg.UI.Password = secrets.UI.Password
		}
		if secrets.UI.SessionCookieAuthenticationKey != "" {
			cfg.UI.SessionCookieAuthenticationKey = secrets.UI.SessionCookieAuthenticationKey
		}
		if secrets.UI.SessionStoreEncryptionKey != "" {
			cfg.UI.SessionStoreEncryptionKey = secrets.UI.SessionStoreEncryptionKey
		}
	}
}
