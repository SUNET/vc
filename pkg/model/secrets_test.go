package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClearSecrets(t *testing.T) {
	cfg := &Cfg{
		Common: &Common{
			Mongo: Mongo{URI: "mongodb://user:pass@host:27017"}, // #nosec G101
		},
		APIGW: &APIGW{
			APIServer: APIServer{
				APIAuth: APIAuth{
					OIDC: APIAuthOIDC{
						ClientSecret: "oidc-client-secret", //NOSONAR
					},
				},
			},
			AuthProviders: APIGWAuthProviders{
				OIDC: OIDCRP{
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
		},
		Registry: &Registry{
			AdminGUI: AdminGUI{
				Password: "admin-pass", //NOSONAR
			},
		},
		Verifier: &Verifier{
			Outbound: VerifierOutbound{
				OIDCProvider: &OIDCOP{
					SubjectSalt: "salt-value", //NOSONAR
					StaticClients: []StaticOIDCClient{
						{ClientID: "client-a", ClientSecret: "secret-a"}, //NOSONAR
						{ClientID: "client-b", ClientSecret: "secret-b"}, //NOSONAR
					},
				},
			},
		},
	}

	cfg.ClearSecrets()

	assert.Empty(t, cfg.Common.Mongo.URI, "Common.Mongo.URI should be cleared")                                                                                                 //NOSONAR
	assert.Empty(t, cfg.APIGW.APIServer.APIAuth.OIDC.ClientSecret, "APIGW.APIServer.APIAuth.OIDC.ClientSecret should be cleared") //NOSONAR
	assert.Empty(t, cfg.APIGW.AuthProviders.OIDC.Registration.Preconfigured.ClientSecret, "APIGW.AuthProviders.OIDC.Registration.Preconfigured.ClientSecret should be cleared") //NOSONAR
	assert.Empty(t, cfg.APIGW.AuthProviders.OIDC.Registration.Dynamic.InitialAccessToken, "APIGW.AuthProviders.OIDC.Registration.Dynamic.InitialAccessToken should be cleared") //NOSONAR
	assert.Empty(t, cfg.Registry.AdminGUI.Password, "Registry.AdminGUI.Password should be cleared")                                                                             //NOSONAR
	assert.Empty(t, cfg.Verifier.Outbound.OIDCProvider.SubjectSalt, "Verifier.Outbound.OIDCProvider.SubjectSalt should be cleared")                                             //NOSONAR
	assert.Empty(t, cfg.Verifier.Outbound.OIDCProvider.StaticClients[0].ClientSecret, "static client-a secret should be cleared")                                               //NOSONAR
	assert.Empty(t, cfg.Verifier.Outbound.OIDCProvider.StaticClients[1].ClientSecret, "static client-b secret should be cleared")                                               //NOSONAR
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
		Verifier: &Verifier{
			Outbound: VerifierOutbound{
				OIDCProvider: &OIDCOP{
					StaticClients: []StaticOIDCClient{
						{ClientID: "client-a"},
						{ClientID: "client-b"},
						{ClientID: "client-c"}, // not in secrets — should stay empty
					},
				},
			},
		},
	}
	secrets := &Secrets{
		Common: &CommonSecrets{
			Mongo: MongoSecrets{URI: "mongodb://secret-user:secret-pass@host:27017"}, //NOSONAR
		},
		APIGW: &APIGWSecrets{
			APIServer: APIServerSecrets{
				APIAuth: APIAuthSecrets{
					OIDC: OIDCAuthSecrets{
						ClientSecret: "from-secrets-file", //NOSONAR
					},
				},
			},
			AuthProviders: AuthProvidersSecrets{
				OIDC: OIDCRPSecrets{
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
		},
		Registry: &RegistrySecrets{
			AdminGUI: AdminGUISecrets{
				Password: "secret-admin-pass", //NOSONAR
			},
		},
		Verifier: &VerifierSecrets{
			Outbound: VerifierOutboundSecrets{
				OIDCProvider: OIDCOPSecrets{
					SubjectSalt: "secret-salt", //NOSONAR
					StaticClients: map[string]string{ //NOSONAR
						"client-a": "secret-for-a",
						"client-b": "secret-for-b",
					},
				},
			},
		},
	}

	cfg.ApplySecrets(secrets)

	assert.Equal(t, "mongodb://secret-user:secret-pass@host:27017", cfg.Common.Mongo.URI)                               //NOSONAR
	assert.Equal(t, "from-secrets-file", cfg.APIGW.APIServer.APIAuth.OIDC.ClientSecret)                          //NOSONAR
	assert.Equal(t, "secret-client-secret", cfg.APIGW.AuthProviders.OIDC.Registration.Preconfigured.ClientSecret)       //NOSONAR
	assert.Equal(t, "secret-initial-token", cfg.APIGW.AuthProviders.OIDC.Registration.Dynamic.InitialAccessToken)       //NOSONAR
	assert.Equal(t, "secret-admin-pass", cfg.Registry.AdminGUI.Password)                                                //NOSONAR
	assert.Equal(t, "secret-salt", cfg.Verifier.Outbound.OIDCProvider.SubjectSalt)                                      //NOSONAR
	assert.Equal(t, "secret-for-a", cfg.Verifier.Outbound.OIDCProvider.StaticClients[0].ClientSecret)                   //NOSONAR
	assert.Equal(t, "secret-for-b", cfg.Verifier.Outbound.OIDCProvider.StaticClients[1].ClientSecret)                   //NOSONAR
	assert.Empty(t, cfg.Verifier.Outbound.OIDCProvider.StaticClients[2].ClientSecret, "client-c should have no secret") //NOSONAR
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
	}

	secrets := &Secrets{
		Registry: &RegistrySecrets{
			AdminGUI: AdminGUISecrets{
				Password: "only-password", //NOSONAR
			},
		},
	}

	cfg.ApplySecrets(secrets)

	assert.Equal(t, "only-password", cfg.Registry.AdminGUI.Password) //NOSONAR
}

func TestApplySecrets_CreatesNilSections(t *testing.T) {
	cfg := &Cfg{}

	secrets := &Secrets{
		Common: &CommonSecrets{
			Mongo: MongoSecrets{URI: "mongodb://new-host:27017"}, //NOSONAR
		},
	}

	cfg.ApplySecrets(secrets)

	require.NotNil(t, cfg.Common, "Common should be created")
	assert.Equal(t, "mongodb://new-host:27017", cfg.Common.Mongo.URI) //NOSONAR
}

func TestClearAndApplySecrets_EndToEnd(t *testing.T) {
	cfg := &Cfg{
		Common: &Common{
			Mongo: Mongo{URI: "mongodb://config-user:config-pass@host:27017"}, // #nosec G101
		},
		APIGW: &APIGW{
			APIServer: APIServer{
				APIAuth: APIAuth{
					OIDC: APIAuthOIDC{
						ClientSecret: "config-client-secret", //NOSONAR
					},
				},
			},
			AuthProviders: APIGWAuthProviders{
				OIDC: OIDCRP{
					Registration: &OIDCRPRegistrationConfig{
						Preconfigured: &OIDCRPPreconfiguredConfig{ // #nosec G101
							ClientSecret: "config-client-secret", //NOSONAR
						},
						Dynamic: &OIDCRPDynamicRegistrationConfig{ // #nosec G101
							Enable:             true,
							InitialAccessToken: "config-initial-token", //NOSONAR
						},
					},
				},
			},
		},
		Registry: &Registry{
			AdminGUI: AdminGUI{ // #nosec G101
				Password: "config-admin-pass", //NOSONAR
			},
		},
		Verifier: &Verifier{
			Outbound: VerifierOutbound{
				OIDCProvider: &OIDCOP{
					SubjectSalt: "config-salt", //NOSONAR
					StaticClients: []StaticOIDCClient{
						{ClientID: "client-x", ClientSecret: "config-secret-x"}, // #nosec G101
					},
				},
			},
		},
	}

	// Step 1: Clear secrets from config
	cfg.ClearSecrets()

	assert.Empty(t, cfg.Common.Mongo.URI, "after clear: Mongo URI should be empty")
	assert.Empty(t, cfg.Verifier.Outbound.OIDCProvider.StaticClients[0].ClientSecret, "after clear: static client secret should be empty") //NOSONAR

	// Step 2: Apply secrets from external file
	secrets := &Secrets{
		Common: &CommonSecrets{
			Mongo: MongoSecrets{URI: "mongodb://secret-user:secret-pass@host:27017"}, //NOSONAR
		},
		APIGW: &APIGWSecrets{
			APIServer: APIServerSecrets{
				APIAuth: APIAuthSecrets{
					OIDC: OIDCAuthSecrets{
						ClientSecret: "secret-password", //NOSONAR
					},
				},
			},
			AuthProviders: AuthProvidersSecrets{
				OIDC: OIDCRPSecrets{
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
		},
		Registry: &RegistrySecrets{
			AdminGUI: AdminGUISecrets{
				Password: "secret-admin-pass", //NOSONAR
			},
		},
		Verifier: &VerifierSecrets{
			Outbound: VerifierOutboundSecrets{
				OIDCProvider: OIDCOPSecrets{
					SubjectSalt: "secret-salt", //NOSONAR
					StaticClients: map[string]string{ //NOSONAR
						"client-x": "secret-for-x",
					},
				},
			},
		},
	}
	cfg.ApplySecrets(secrets)

	assert.Equal(t, "mongodb://secret-user:secret-pass@host:27017", cfg.Common.Mongo.URI)                         //NOSONAR
	assert.Equal(t, "secret-password", cfg.APIGW.APIServer.APIAuth.OIDC.ClientSecret)                      //NOSONAR
	assert.Equal(t, "secret-client-secret", cfg.APIGW.AuthProviders.OIDC.Registration.Preconfigured.ClientSecret) //NOSONAR
	assert.Equal(t, "secret-initial-token", cfg.APIGW.AuthProviders.OIDC.Registration.Dynamic.InitialAccessToken) //NOSONAR
	assert.Equal(t, "secret-admin-pass", cfg.Registry.AdminGUI.Password)                                          //NOSONAR
	assert.Equal(t, "secret-salt", cfg.Verifier.Outbound.OIDCProvider.SubjectSalt)                                //NOSONAR
	assert.Equal(t, "secret-for-x", cfg.Verifier.Outbound.OIDCProvider.StaticClients[0].ClientSecret)             //NOSONAR
}
