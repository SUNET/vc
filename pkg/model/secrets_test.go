package model

import (
	"testing"

	yamlv2 "gopkg.in/yaml.v2"

	"github.com/SUNET/vc/pkg/pubsub"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newFullCfg returns a Cfg populated with every secret-bearing field set to
// deterministic "config-*" values suitable for testing ApplySecrets.
func newFullCfg(clients []StaticOIDCClient) *Cfg {
	return &Cfg{
		Common: &Common{
			Mongo: Mongo{
				URI:          "mongodb://config-user:config-pass@host:27017", // #nosec G101
				TLS:          true,
				CAFilePath:   "/config/ca.crt",
				CertFilePath: "/config/tls.crt",
				KeyFilePath:  "/config/tls.key",
			},
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
		},
		Registry: &Registry{
			AdminGUI: AdminGUI{
				Password: "config-admin-pass", //NOSONAR
			},
		},
		Verifier: &Verifier{
			Outbound: VerifierOutbound{
				OIDCProvider: &OIDCOP{
					SubjectSalt:   "config-salt", //NOSONAR
					StaticClients: clients,
				},
			},
		},
	}
}

// newFullSecrets returns a Secrets struct with every field populated.
// staticClients maps client_id -> client_secret for the verifier section.
func newFullSecrets(staticClients map[string]string) *Secrets {
	return &Secrets{
		Common: &CommonSecrets{
			Mongo: MongoSecrets{
				URI: "mongodb://secret-user:secret-pass@host:27017", //NOSONAR
			},
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
					SubjectSalt:   "secret-salt", //NOSONAR
					StaticClients: staticClients,
				},
			},
		},
	}
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
						{ClientID: "client-c"}, // not in secrets - should stay empty
					},
				},
			},
		},
	}
	secrets := newFullSecrets(map[string]string{"client-a": "secret-for-a", "client-b": "secret-for-b"}) //NOSONAR

	cfg.ApplySecrets(secrets)

	// Mongo URI should be filled from secrets (config had none)
	assert.Equal(t, "mongodb://secret-user:secret-pass@host:27017", cfg.Common.Mongo.URI)                         //NOSONAR
	assert.Equal(t, "secret-password", cfg.APIGW.APIServer.APIAuth.OIDC.ClientSecret)                             //NOSONAR
	assert.Equal(t, "secret-client-secret", cfg.APIGW.AuthProviders.OIDC.Registration.Preconfigured.ClientSecret) //NOSONAR
	assert.Equal(t, "secret-initial-token", cfg.APIGW.AuthProviders.OIDC.Registration.Dynamic.InitialAccessToken) //NOSONAR
	assert.Equal(t, "secret-admin-pass", cfg.Registry.AdminGUI.Password)                                          //NOSONAR
	assert.Equal(t, "secret-salt", cfg.Verifier.Outbound.OIDCProvider.SubjectSalt)                                //NOSONAR
	assert.Equal(t, "secret-for-a", cfg.Verifier.Outbound.OIDCProvider.StaticClients[0].ClientSecret)             //NOSONAR
	assert.Equal(t, "secret-for-b", cfg.Verifier.Outbound.OIDCProvider.StaticClients[1].ClientSecret)             //NOSONAR
	assert.Empty(t, cfg.Verifier.Outbound.OIDCProvider.StaticClients[2].ClientSecret, "client-c should be empty") //NOSONAR
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

func TestApplySecrets_NilSections(t *testing.T) {
	cfg := &Cfg{
		Common: &Common{},
	}
	assert.NotPanics(t, func() { cfg.ApplySecrets(&Secrets{}) })
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

// TestApplySecrets_ClearsAndReplaces verifies that secret fields from
// the main config are cleared and replaced by the secrets file values,
// while non-secret fields (TLS paths) survive untouched.
func TestApplySecrets_ClearsAndReplaces(t *testing.T) {
	cfg := newFullCfg([]StaticOIDCClient{
		{ClientID: "client-x", ClientSecret: "config-secret-x"}, // #nosec G101
	})
	secrets := newFullSecrets(map[string]string{"client-x": "secret-for-x"}) //NOSONAR

	cfg.ApplySecrets(secrets)

	// Mongo URI: config already had one, so secrets value is NOT used
	assert.Equal(t, "mongodb://config-user:config-pass@host:27017", cfg.Common.Mongo.URI) // #nosec G101
	// TLS settings are not secrets and should be untouched
	assert.True(t, cfg.Common.Mongo.TLS)
	assert.Equal(t, "/config/ca.crt", cfg.Common.Mongo.CAFilePath)
	assert.Equal(t, "/config/tls.crt", cfg.Common.Mongo.CertFilePath)
	assert.Equal(t, "/config/tls.key", cfg.Common.Mongo.KeyFilePath)
	// Other secrets should be replaced by the secrets file values
	assert.Equal(t, "secret-password", cfg.APIGW.APIServer.APIAuth.OIDC.ClientSecret)                             //NOSONAR
	assert.Equal(t, "secret-client-secret", cfg.APIGW.AuthProviders.OIDC.Registration.Preconfigured.ClientSecret) //NOSONAR
	assert.Equal(t, "secret-initial-token", cfg.APIGW.AuthProviders.OIDC.Registration.Dynamic.InitialAccessToken) //NOSONAR
	assert.Equal(t, "secret-admin-pass", cfg.Registry.AdminGUI.Password)                                          //NOSONAR
	assert.Equal(t, "secret-salt", cfg.Verifier.Outbound.OIDCProvider.SubjectSalt)                                //NOSONAR
	assert.Equal(t, "secret-for-x", cfg.Verifier.Outbound.OIDCProvider.StaticClients[0].ClientSecret)             //NOSONAR
}

// TestApplySecrets_MongoInConfigSecretsElsewhere reproduces issue #407:
// mongo config is in the main config file, secrets file exists but has no
// mongo section - mongo settings should survive the apply cycle.
func TestApplySecrets_MongoInConfigSecretsElsewhere(t *testing.T) {
	cfg := &Cfg{
		Common: &Common{
			Mongo: Mongo{
				URI:          "mongodb://mongodb-svc:27017/verifier?replicaSet=mongodb&ssl=true&authMechanism=MONGODB-X509",
				TLS:          true,
				CAFilePath:   "/client-cert/ca.crt",
				CertFilePath: "/client-cert/tls.crt",
				KeyFilePath:  "/client-cert/tls.key",
			},
		},
		Verifier: &Verifier{
			Outbound: VerifierOutbound{
				OIDCProvider: &OIDCOP{
					SubjectSalt: "config-salt", //NOSONAR
				},
			},
		},
	}

	// Secrets file only has verifier secrets, no mongo section
	secrets := &Secrets{
		Verifier: &VerifierSecrets{
			Outbound: VerifierOutboundSecrets{
				OIDCProvider: OIDCOPSecrets{
					SubjectSalt: "secret-salt", //NOSONAR
				},
			},
		},
	}

	cfg.ApplySecrets(secrets)

	// Mongo fields should survive because the secrets file has no common section
	assert.Equal(t, "mongodb://mongodb-svc:27017/verifier?replicaSet=mongodb&ssl=true&authMechanism=MONGODB-X509", cfg.Common.Mongo.URI)
	assert.True(t, cfg.Common.Mongo.TLS, "Mongo TLS should survive")
	assert.Equal(t, "/client-cert/ca.crt", cfg.Common.Mongo.CAFilePath)
	assert.Equal(t, "/client-cert/tls.crt", cfg.Common.Mongo.CertFilePath)
	assert.Equal(t, "/client-cert/tls.key", cfg.Common.Mongo.KeyFilePath)

	// Verifier secret should be applied from secrets file
	assert.Equal(t, "secret-salt", cfg.Verifier.Outbound.OIDCProvider.SubjectSalt) //NOSONAR
}

// TestApplySecrets_RedisHABackfillsEmptyFields verifies that Redis / Valkey
// ACL credentials in the secrets file are backfilled into cfg.Common.HA.PubSub
// when the main config leaves the matching field empty (same contract as
// Mongo.URI). Fields set in the main config stay put.
func TestApplySecrets_RedisHABackfillsEmptyFields(t *testing.T) {
	cfg := &Cfg{
		Common: &Common{
			HA: HAConfig{
				PubSub: &pubsub.Config{
					Addrs: []string{"redis:6379"},
					// Username left empty - secrets backfills it.
					// Password already present - secrets must not overwrite.
					Password: "config-password", //NOSONAR
				},
			},
		},
	}
	secrets := &Secrets{
		Common: &CommonSecrets{
			HA: HASecrets{
				PubSub: PubSubSecrets{
					Username: "secret-user",
					Password: "secret-password", //NOSONAR
				},
			},
		},
	}

	cfg.ApplySecrets(secrets)

	assert.Equal(t, "secret-user", cfg.Common.HA.PubSub.Username)
	assert.Equal(t, "config-password", cfg.Common.HA.PubSub.Password, //NOSONAR
		"existing config password must survive")
}

// TestApplySecrets_RedisHANoRedisConfigured verifies that a secrets file
// with Redis ACL creds does not panic / inject a Redis config when the main
// config leaves HA.PubSub unset.
func TestApplySecrets_RedisHANoRedisConfigured(t *testing.T) {
	cfg := &Cfg{Common: &Common{}}
	secrets := &Secrets{
		Common: &CommonSecrets{
			HA: HASecrets{
				PubSub: PubSubSecrets{
					Password: "secret-password", //NOSONAR
				},
			},
		},
	}

	assert.NotPanics(t, func() { cfg.ApplySecrets(secrets) })
	assert.Nil(t, cfg.Common.HA.PubSub, "PubSub config must not be auto-created from secrets")
}

// A seed derivation secret belongs in the secrets file like every other
// secret this deployment holds, which is what s-jairl pointed out on
// #793: the inline field followed BBSConfig.SecretKey, and that field is
// itself an exception to the convention rather than an example of it.
//
// Same backfill rule as Mongo, SQL and the HA credentials - the main
// config wins where it has a value - so a deployment can keep this in
// config.yaml, in a mounted file via secret_path, or here.
func TestApplySecretsFillsSeedDerivationSecrets(t *testing.T) {
	const fromSecretsFile = "c2VjcmV0cy1maWxlLXZhbHVlLWF0LWxlYXN0LTMyLWJ5dGVz"

	t.Run("an empty secret is filled from the secrets file", func(t *testing.T) {
		cfg := &Cfg{Issuer: &Issuer{Seeds: map[string]*SeedSource{
			"pseudonym": {Model: "derived"},
		}}}
		cfg.ApplySecrets(&Secrets{Issuer: &IssuerSecrets{
			Seeds: map[string]SeedSourceSecrets{"pseudonym": {Secret: fromSecretsFile}},
		}})
		assert.Equal(t, fromSecretsFile, cfg.Issuer.Seeds["pseudonym"].Secret)
	})

	t.Run("a secret already in the config is left alone", func(t *testing.T) {
		cfg := &Cfg{Issuer: &Issuer{Seeds: map[string]*SeedSource{
			"pseudonym": {Model: "derived", Secret: "config-wins"},
		}}}
		cfg.ApplySecrets(&Secrets{Issuer: &IssuerSecrets{
			Seeds: map[string]SeedSourceSecrets{"pseudonym": {Secret: fromSecretsFile}},
		}})
		assert.Equal(t, "config-wins", cfg.Issuer.Seeds["pseudonym"].Secret,
			"the main config wins, exactly as it does for Mongo and the HA credentials")
	})

	t.Run("a source the main config does not name is not invented", func(t *testing.T) {
		cfg := &Cfg{Issuer: &Issuer{Seeds: map[string]*SeedSource{
			"pseudonym": {Model: "derived", Secret: "config-wins"},
		}}}
		cfg.ApplySecrets(&Secrets{Issuer: &IssuerSecrets{
			Seeds: map[string]SeedSourceSecrets{"not-configured": {Secret: fromSecretsFile}},
		}})
		assert.Len(t, cfg.Issuer.Seeds, 1,
			"a secrets file naming an unknown source is a mistake worth leaving visible; "+
				"inventing the source here would hand a subject a seed from a configuration nobody wrote")
	})

	t.Run("no issuer section, and nothing happens", func(t *testing.T) {
		cfg := &Cfg{Issuer: &Issuer{Seeds: map[string]*SeedSource{"pseudonym": {Model: "derived"}}}}
		cfg.ApplySecrets(&Secrets{})
		assert.Empty(t, cfg.Issuer.Seeds["pseudonym"].Secret)
	})

	t.Run("no issuer in the config at all, and it does not panic", func(t *testing.T) {
		cfg := &Cfg{}
		require.NotPanics(t, func() {
			cfg.ApplySecrets(&Secrets{Issuer: &IssuerSecrets{
				Seeds: map[string]SeedSourceSecrets{"pseudonym": {Secret: fromSecretsFile}},
			}})
		})
	})
}

// The derivation secret is not settable in the main configuration.
//
// It was an inline field and is deliberately not one any more: a secret
// in config.yaml is against the convention everything else here follows,
// and the precedent cited for it - BBSConfig.SecretKey - is the exception
// rather than the rule. The two routes are a mounted file via secret_path
// and the secrets file.
//
// The loader is NOT strict, so a config.yaml that still carries the old
// key is ignored rather than rejected at parse time. That matters: the
// value must not be picked up, and the deployment must not start with a
// seed nobody configured. It gets a startup refusal naming where the
// secret belongs instead.
func TestSeedSecretIsNotSettableInTheMainConfig(t *testing.T) {
	const fromSecretsFile = "c2VjcmV0cy1maWxlLXZhbHVlLWF0LWxlYXN0LTMyLWJ5dGVz"
	const doc = "model: derived\nsecret: " + fromSecretsFile + "\n"

	var source SeedSource
	require.NoError(t, yamlv2.Unmarshal([]byte(doc), &source),
		"the loader is not strict, so an old config still parses")
	assert.Empty(t, source.Secret,
		"an inline secret in config.yaml must not reach the derivation secret")
	assert.Equal(t, "derived", source.Model, "the rest of the source still loads")

	// And the secrets file is the route that does fill it.
	cfg := &Cfg{Issuer: &Issuer{Seeds: map[string]*SeedSource{"pseudonym": {Model: "derived"}}}}
	cfg.ApplySecrets(&Secrets{Issuer: &IssuerSecrets{
		Seeds: map[string]SeedSourceSecrets{"pseudonym": {Secret: fromSecretsFile}},
	}})
	assert.Equal(t, fromSecretsFile, cfg.Issuer.Seeds["pseudonym"].Secret)
}
