package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClearSecrets(t *testing.T) {
	cfg := &Cfg{
		Common: &Common{
			Mongo: Mongo{URI: "mongodb://user:pass@host:27017"}, //NOSONAR
		},
		APIGW: &APIGW{
			APIServer: APIServer{
				APIAuth: APIAuth{
					BasicAuth: APIAuthBasic{
						Users: map[string]string{"admin": "secret123"}, //NOSONAR
					},
				},
			},
			OIDCRP: OIDCRPConfig{
				Registration: &OIDCRPRegistrationConfig{
					Preconfigured: &OIDCRPPreconfiguredConfig{
						ClientSecret: "my-client-secret", //NOSONAR
					},
					Dynamic: &OIDCRPDynamicRegistrationConfig{
						Enable:             true,
						InitialAccessToken: "my-initial-token", //NOSONAR
					},
				},
			},
		},
		Registry: &Registry{
			AdminGUI: AdminGUI{
				Password: "admin-pass", //NOSONAR
			},
		},
		Verifier: &Verifier{
			OIDC: &OIDCConfig{
				SubjectSalt: "salt-value", //NOSONAR
			},
		},
		UI: &UI{
			Password: "ui-pass", //NOSONAR
		},
	}

	cfg.ClearSecrets()

	assert.Empty(t, cfg.Common.Mongo.URI, "Common.Mongo.URI should be cleared")                                                                         //NOSONAR
	assert.Nil(t, cfg.APIGW.APIServer.APIAuth.BasicAuth.Users, "APIGW.APIServer.APIAuth.BasicAuth.Users should be nil")                                 //NOSONAR
	assert.Empty(t, cfg.APIGW.OIDCRP.Registration.Preconfigured.ClientSecret, "APIGW.OIDCRP.Registration.Preconfigured.ClientSecret should be cleared") //NOSONAR
	assert.Empty(t, cfg.APIGW.OIDCRP.Registration.Dynamic.InitialAccessToken, "APIGW.OIDCRP.Registration.Dynamic.InitialAccessToken should be cleared") //NOSONAR
	assert.Empty(t, cfg.Registry.AdminGUI.Password, "Registry.AdminGUI.Password should be cleared")                                                     //NOSONAR
	assert.Empty(t, cfg.Verifier.OIDC.SubjectSalt, "Verifier.OIDC.SubjectSalt should be cleared")                                                       //NOSONAR
	assert.Empty(t, cfg.UI.Password, "UI.Password should be cleared")                                                                                   //NOSONAR
}

func TestClearSecrets_NilSections(t *testing.T) {
	cfg := &Cfg{
		Common: &Common{},
	}
	assert.NotPanics(t, func() { cfg.ClearSecrets() })
}

func TestApplySecrets(t *testing.T) {
	cfg := &Cfg{
		Common:   &Common{},
		APIGW:    &APIGW{},
		Registry: &Registry{},
		Verifier: &Verifier{},
		UI:       &UI{},
	}

	secrets := &Secrets{
		Common: &CommonSecrets{
			Mongo: MongoSecrets{URI: "mongodb://secret-user:secret-pass@host:27017"}, //NOSONAR
		},
		APIGW: &APIGWSecrets{
			APIServer: APIServerSecrets{
				APIAuth: APIAuthSecrets{
					BasicAuth: BasicAuthSecrets{
						Users: map[string]string{"admin": "from-secrets-file"}, //NOSONAR
					},
				},
			},
			OIDCRP: OIDCRPSecrets{
				Registration: OIDCRPRegistrationSecrets{
					Preconfigured: &OIDCRPPreconfiguredSecrets{
						ClientSecret: "secret-client-secret", //NOSONAR
					},
					Dynamic: &OIDCRPDynamicSecrets{
						InitialAccessToken: "secret-initial-token", //NOSONAR
					},
				},
			},
		},
		Registry: &RegistrySecrets{
			AdminGUI: AdminGUISecrets{
				Password: "secret-admin-pass", //NOSONAR
			},
		},
		Verifier: &VerifierSecrets{
			OIDC: OIDCSecrets{
				SubjectSalt: "secret-salt", //NOSONAR
			},
		},
		UI: &UISecrets{
			Password: "secret-ui-pass", //NOSONAR
		},
	}

	cfg.ApplySecrets(secrets)

	assert.Equal(t, "mongodb://secret-user:secret-pass@host:27017", cfg.Common.Mongo.URI)             //NOSONAR
	assert.Equal(t, "from-secrets-file", cfg.APIGW.APIServer.APIAuth.BasicAuth.Users["admin"])        //NOSONAR
	assert.Equal(t, "secret-client-secret", cfg.APIGW.OIDCRP.Registration.Preconfigured.ClientSecret) //NOSONAR
	assert.Equal(t, "secret-initial-token", cfg.APIGW.OIDCRP.Registration.Dynamic.InitialAccessToken) //NOSONAR
	assert.Equal(t, "secret-admin-pass", cfg.Registry.AdminGUI.Password)                              //NOSONAR
	assert.Equal(t, "secret-salt", cfg.Verifier.OIDC.SubjectSalt)                                     //NOSONAR
	assert.Equal(t, "secret-ui-pass", cfg.UI.Password)                                                //NOSONAR
}

func TestApplySecrets_NilSecrets(t *testing.T) {
	cfg := &Cfg{
		Common: &Common{
			Mongo: Mongo{URI: "original-uri"}, //NOSONAR
		},
	}
	cfg.ApplySecrets(nil)

	assert.Equal(t, "original-uri", cfg.Common.Mongo.URI) //NOSONAR
}

func TestApplySecrets_PartialSecrets(t *testing.T) {
	cfg := &Cfg{
		Common: &Common{},
		UI:     &UI{},
	}

	secrets := &Secrets{
		UI: &UISecrets{
			Password: "only-password", //NOSONAR
		},
	}

	cfg.ApplySecrets(secrets)

	assert.Equal(t, "only-password", cfg.UI.Password) //NOSONAR
}

func TestApplySecrets_CreatesNilSections(t *testing.T) {
	cfg := &Cfg{}

	secrets := &Secrets{
		Common: &CommonSecrets{
			Mongo: MongoSecrets{URI: "mongodb://new-host:27017"}, //NOSONAR
		},
		UI: &UISecrets{
			Password: "new-password",
		},
	}

	cfg.ApplySecrets(secrets)

	require.NotNil(t, cfg.Common, "Common should be created")
	assert.Equal(t, "mongodb://new-host:27017", cfg.Common.Mongo.URI) //NOSONAR
	require.NotNil(t, cfg.UI, "UI should be created")
	assert.Equal(t, "new-password", cfg.UI.Password)
}

func TestClearAndApplySecrets_EndToEnd(t *testing.T) {
	cfg := &Cfg{
		Common: &Common{
			Mongo: Mongo{URI: "mongodb://config-user:config-pass@host:27017"}, //NOSONAR
		},
		APIGW: &APIGW{
			APIServer: APIServer{
				APIAuth: APIAuth{
					BasicAuth: APIAuthBasic{
						Users: map[string]string{"admin": "config-password"}, //NOSONAR
					},
				},
			},
			OIDCRP: OIDCRPConfig{
				Registration: &OIDCRPRegistrationConfig{
					Preconfigured: &OIDCRPPreconfiguredConfig{
						ClientSecret: "config-client-secret", //NOSONAR
					},
					Dynamic: &OIDCRPDynamicRegistrationConfig{
						Enable:             true,
						InitialAccessToken: "config-initial-token", //NOSONAR
					},
				},
			},
		},
		Registry: &Registry{
			AdminGUI: AdminGUI{
				Password: "config-admin-pass", //NOSONAR
			},
		},
		Verifier: &Verifier{
			OIDC: &OIDCConfig{
				SubjectSalt: "config-salt", //NOSONAR
			},
		},
		UI: &UI{
			Password: "config-ui-pass", //NOSONAR
		},
	}

	// Step 1: Clear secrets from config
	cfg.ClearSecrets()

	assert.Empty(t, cfg.Common.Mongo.URI, "after clear: Mongo URI should be empty")
	assert.Empty(t, cfg.UI.Password, "after clear: UI Password should be empty")

	// Step 2: Apply secrets from external file
	secrets := &Secrets{
		Common: &CommonSecrets{
			Mongo: MongoSecrets{URI: "mongodb://secret-user:secret-pass@host:27017"}, //NOSONAR
		},
		APIGW: &APIGWSecrets{
			APIServer: APIServerSecrets{
				APIAuth: APIAuthSecrets{
					BasicAuth: BasicAuthSecrets{
						Users: map[string]string{"admin": "secret-password"}, //NOSONAR
					},
				},
			},
			OIDCRP: OIDCRPSecrets{
				Registration: OIDCRPRegistrationSecrets{
					Preconfigured: &OIDCRPPreconfiguredSecrets{
						ClientSecret: "secret-client-secret", //NOSONAR
					},
					Dynamic: &OIDCRPDynamicSecrets{
						InitialAccessToken: "secret-initial-token", //NOSONAR
					},
				},
			},
		},
		Registry: &RegistrySecrets{
			AdminGUI: AdminGUISecrets{
				Password: "secret-admin-pass", //NOSONAR
			},
		},
		Verifier: &VerifierSecrets{
			OIDC: OIDCSecrets{
				SubjectSalt: "secret-salt", //NOSONAR
			},
		},
		UI: &UISecrets{
			Password: "secret-ui-pass", //NOSONAR
		},
	}
	cfg.ApplySecrets(secrets)

	assert.Equal(t, "mongodb://secret-user:secret-pass@host:27017", cfg.Common.Mongo.URI)             //NOSONAR
	assert.Equal(t, "secret-password", cfg.APIGW.APIServer.APIAuth.BasicAuth.Users["admin"])          //NOSONAR
	assert.Equal(t, "secret-client-secret", cfg.APIGW.OIDCRP.Registration.Preconfigured.ClientSecret) //NOSONAR
	assert.Equal(t, "secret-initial-token", cfg.APIGW.OIDCRP.Registration.Dynamic.InitialAccessToken) //NOSONAR
	assert.Equal(t, "secret-admin-pass", cfg.Registry.AdminGUI.Password)                              //NOSONAR
	assert.Equal(t, "secret-salt", cfg.Verifier.OIDC.SubjectSalt)                                     //NOSONAR
	assert.Equal(t, "secret-ui-pass", cfg.UI.Password)                                                //NOSONAR
}
