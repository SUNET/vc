package configuration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cfgWithStaticClients wraps clients in the nesting the resolvers walk, so a
// test can say what it is about and nothing else.
func cfgWithStaticClients(clients ...model.StaticOIDCClient) *model.Cfg {
	return &model.Cfg{
		Verifier: &model.Verifier{
			Outbound: model.VerifierOutbound{
				OIDCProvider: &model.OIDCOP{StaticClients: clients},
			},
		},
	}
}

// A client_id and a client_secret can each name an environment variable to
// come from, and both are read.
func TestStaticClientIDAndSecretComeFromTheEnvironment(t *testing.T) {
	t.Setenv("VC_RP_ID", "https://rp.example.org")
	t.Setenv("VC_RP_SECRET", "s3cret")

	cfg := cfgWithStaticClients(model.StaticOIDCClient{
		ClientIDEnv:     "VC_RP_ID",
		ClientSecretEnv: "VC_RP_SECRET",
	})

	require.NoError(t, resolveStaticClientIdentities(cfg))
	require.NoError(t, resolveStaticClientSecrets(cfg))

	client := cfg.Verifier.Outbound.OIDCProvider.StaticClients[0]
	assert.Equal(t, "https://rp.example.org", client.ClientID)
	assert.Equal(t, "s3cret", client.ClientSecret)
}

// A client that names no environment variable is left exactly as written.
func TestStaticClientWithoutEnvReferencesIsUntouched(t *testing.T) {
	cfg := cfgWithStaticClients(model.StaticOIDCClient{
		ClientID:     "https://rp.example.org",
		ClientSecret: "from-config",
	})

	require.NoError(t, resolveStaticClientIdentities(cfg))
	require.NoError(t, resolveStaticClientSecrets(cfg))

	client := cfg.Verifier.Outbound.OIDCProvider.StaticClients[0]
	assert.Equal(t, "https://rp.example.org", client.ClientID)
	assert.Equal(t, "from-config", client.ClientSecret)
}

// Naming two sources for one value is refused, rather than one of them
// silently winning. The operator believes two different things about where
// that value comes from, and only one of them can be true.
func TestStaticClientRefusesTwoSourcesForOneValue(t *testing.T) {
	t.Run("client_id", func(t *testing.T) {
		t.Setenv("VC_RP_ID", "https://rp.example.org")
		cfg := cfgWithStaticClients(model.StaticOIDCClient{
			ClientID:    "https://other.example.org",
			ClientIDEnv: "VC_RP_ID",
		})

		err := resolveStaticClientIdentities(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client_id and client_id_env are both set")
		assert.Contains(t, err.Error(), staticClientsPath+"[0]")
	})

	t.Run("client_secret", func(t *testing.T) {
		t.Setenv("VC_RP_SECRET", "s3cret")
		cfg := cfgWithStaticClients(model.StaticOIDCClient{
			ClientID:        "https://rp.example.org",
			ClientSecret:    "from-config",
			ClientSecretEnv: "VC_RP_SECRET",
		})

		err := resolveStaticClientIdentities(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client_secret and client_secret_env are both set")
		assert.Contains(t, err.Error(), `client_id "https://rp.example.org"`)
	})
}

// An unresolvable reference is refused at startup with the variable's name in
// the message, both when the variable is absent and when it is present but
// empty. A Secret key may legitimately hold an empty value.
func TestStaticClientRefusesAnUnresolvableEnvReference(t *testing.T) {
	t.Run("client_id is not set", func(t *testing.T) {
		cfg := cfgWithStaticClients(model.StaticOIDCClient{ClientIDEnv: "VC_RP_ID_ABSENT"})

		err := resolveStaticClientIdentities(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `client_id_env names "VC_RP_ID_ABSENT", which is not set`)
	})

	t.Run("client_id is empty", func(t *testing.T) {
		t.Setenv("VC_RP_ID", "")
		cfg := cfgWithStaticClients(model.StaticOIDCClient{ClientIDEnv: "VC_RP_ID"})

		err := resolveStaticClientIdentities(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `client_id_env names "VC_RP_ID", which is set but empty`)
	})

	t.Run("client_secret is not set", func(t *testing.T) {
		cfg := cfgWithStaticClients(model.StaticOIDCClient{
			ClientID:        "https://rp.example.org",
			ClientSecretEnv: "VC_RP_SECRET_ABSENT",
		})

		err := resolveStaticClientSecrets(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `client_secret_env names "VC_RP_SECRET_ABSENT", which is not set`)
		assert.Contains(t, err.Error(), `client_id "https://rp.example.org"`,
			"the message has to say which client cannot authenticate")
	})

	t.Run("client_secret is empty", func(t *testing.T) {
		t.Setenv("VC_RP_SECRET", "")
		cfg := cfgWithStaticClients(model.StaticOIDCClient{
			ClientID:        "https://rp.example.org",
			ClientSecretEnv: "VC_RP_SECRET",
		})

		err := resolveStaticClientSecrets(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `client_secret_env names "VC_RP_SECRET", which is set but empty`)
	})
}

// Two entries resolving to one client_id is refused. getClientByID returns
// the first match, so the second entry's redirect_uris, scopes and secret
// would be inert - and with injection the collision is nowhere in the YAML.
func TestStaticClientRefusesADuplicateClientID(t *testing.T) {
	t.Run("both from the environment", func(t *testing.T) {
		t.Setenv("VC_RP_A", "https://rp.example.org")
		t.Setenv("VC_RP_B", "https://rp.example.org")

		cfg := cfgWithStaticClients(
			model.StaticOIDCClient{ClientIDEnv: "VC_RP_A"},
			model.StaticOIDCClient{ClientIDEnv: "VC_RP_B"},
		)

		err := resolveStaticClientIdentities(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `entries [0] and [1] both have client_id "https://rp.example.org"`)
	})

	// The same rule applies to a config that never mentions the
	// environment: the shadowing it refuses predates this feature.
	t.Run("both written in the config", func(t *testing.T) {
		cfg := cfgWithStaticClients(
			model.StaticOIDCClient{ClientID: "https://rp.example.org"},
			model.StaticOIDCClient{ClientID: "https://rp.example.org"},
		)

		err := resolveStaticClientIdentities(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `entries [0] and [1] both have client_id`)
	})
}

// An entry that names no source at all is left for the required tag on
// ClientID to report, rather than being claimed as a duplicate of the next
// such entry.
func TestStaticClientWithNoIDAtAllIsNotADuplicate(t *testing.T) {
	cfg := cfgWithStaticClients(model.StaticOIDCClient{}, model.StaticOIDCClient{})

	assert.NoError(t, resolveStaticClientIdentities(cfg))
}

// A service with no verifier-OP configured resolves nothing and does not
// panic walking a config that stops short.
func TestStaticClientResolutionIgnoresAConfigWithoutAVerifierOP(t *testing.T) {
	for name, cfg := range map[string]*model.Cfg{
		"nil config":       nil,
		"no verifier":      {},
		"no oidc_provider": {Verifier: &model.Verifier{}},
	} {
		t.Run(name, func(t *testing.T) {
			assert.NoError(t, resolveStaticClientIdentities(cfg))
			assert.NoError(t, resolveStaticClientSecrets(cfg))
		})
	}
}

// writeStaticClientConfig writes a verifier config that loads, carrying one
// static client built from the given lines.
func writeStaticClientConfig(t *testing.T, dir, name, client, extraCommon string) string {
	t.Helper()

	vctm := filepath.Join(dir, "vctm.json")
	require.NoError(t, os.WriteFile(vctm, []byte(`{"vct":"urn:example:degree","name":"Degree"}`), 0o600))

	path := filepath.Join(dir, "config-"+name+".yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
common:
  mongo:
    uri: mongodb://localhost:27017
  credential_metadata:
    degree:
      format: dc+sd-jwt
      vctm_file_path: `+vctm+`
`+extraCommon+`
verifier:
  public_url: https://verifier.example.org
  key_config:
    chain_path: /pki/signing_ec_chain.pem
    private_key_path: /pki/signing_ec_private.pem
  inbound:
    openid4vp:
      token_endpoint: https://verifier.example.org/token
      clients:
        wallet:
          type: public
          redirect_uri: https://wallet.example.org
          scopes: ["degree"]
      supported_credentials:
        - vct: urn:example:degree
          scopes: ["degree"]
  outbound:
    oidc_provider:
      issuer: https://verifier.example.org
      subject_type: public
      subject_salt: test-salt
      static_clients:
`+client+`
`), 0o600))

	return path
}

// The loader resolves a client's identity BEFORE the secrets file is
// applied, and its secret AFTER.
//
// This drives New rather than the resolvers, because the ordering is the
// thing under test and the resolvers cannot see it: calling them in either
// order passes every test above. Moving either call to the other side of
// ApplySecrets in New compiles, and fails exactly here.
func TestNewResolvesStaticClientIdentityBeforeSecretsAndSecretsAfter(t *testing.T) {
	// The secrets file is keyed by client_id, so a client whose id comes
	// from the environment can only be found in it if the id is already
	// resolved when ApplySecrets runs.
	t.Run("a secrets file finds a client whose id came from the environment", func(t *testing.T) {
		dir := t.TempDir()
		secrets := filepath.Join(dir, "secrets.yaml")
		require.NoError(t, os.WriteFile(secrets, []byte(`
verifier:
  outbound:
    oidc_provider:
      subject_salt: salt-from-the-secrets-file
      static_clients:
        "https://rp.example.org": "from-the-secrets-file"
`), 0o600))

		t.Setenv("VC_RP_ID", "https://rp.example.org")
		t.Setenv("VC_CONFIG_YAML", writeStaticClientConfig(t, dir, "id-from-env",
			`        - client_id_env: "VC_RP_ID"
          redirect_uris: ["https://rp.example.org/callback"]`,
			`  secret_file_path: `+secrets))

		cfg, err := New(t.Context(), "verifier")
		require.NoError(t, err)

		client := cfg.Verifier.Outbound.OIDCProvider.StaticClients[0]
		assert.Equal(t, "https://rp.example.org", client.ClientID)
		assert.Equal(t, "from-the-secrets-file", client.ClientSecret,
			"an id resolved after ApplySecrets would leave the map lookup keyed by the empty string")
	})

	// The environment is the most specific source a deployment can supply,
	// so a file does not get to override it.
	t.Run("the environment is the last word on a secret", func(t *testing.T) {
		dir := t.TempDir()
		secrets := filepath.Join(dir, "secrets.yaml")
		require.NoError(t, os.WriteFile(secrets, []byte(`
verifier:
  outbound:
    oidc_provider:
      subject_salt: salt-from-the-secrets-file
      static_clients:
        "https://rp.example.org": "from-the-secrets-file"
`), 0o600))

		t.Setenv("VC_RP_SECRET", "from-the-environment")
		t.Setenv("VC_CONFIG_YAML", writeStaticClientConfig(t, dir, "secret-from-env",
			`        - client_id: "https://rp.example.org"
          client_secret_env: "VC_RP_SECRET"
          redirect_uris: ["https://rp.example.org/callback"]`,
			`  secret_file_path: `+secrets))

		cfg, err := New(t.Context(), "verifier")
		require.NoError(t, err)

		assert.Equal(t, "from-the-environment",
			cfg.Verifier.Outbound.OIDCProvider.StaticClients[0].ClientSecret)
	})
}

// The refusal reaches the operator from the real loader, not only from the
// resolver's own tests: a check nothing calls changes nothing.
func TestNewRefusesAnUnresolvableStaticClientSecret(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VC_CONFIG_YAML", writeStaticClientConfig(t, dir, "absent-secret",
		`        - client_id: "https://rp.example.org"
          client_secret_env: "VC_RP_SECRET_ABSENT"
          redirect_uris: ["https://rp.example.org/callback"]`, ""))

	_, err := New(t.Context(), "verifier")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `client_secret_env names "VC_RP_SECRET_ABSENT", which is not set`,
		"an unresolved reference must be named, not left to a generic required_unless failure")
}
