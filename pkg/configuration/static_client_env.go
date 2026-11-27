package configuration

import (
	"fmt"
	"os"

	"github.com/SUNET/vc/pkg/model"
)

// staticClientsPath is the configuration path every message below names, so
// that an operator reading one can go straight to the block it is about.
const staticClientsPath = "verifier.outbound.oidc_provider.static_clients"

// servicesServingTheVerifierOP lists the services that actually read
// verifier.outbound.oidc_provider.static_clients.
//
// Only the verifier serves the OP, and only it looks a static client up
// (internal/verifier/apiv1/client.go). Its siblings share one config.yaml -
// see docker-compose.yaml - and already tolerate a verifier block they will
// never use: a static client with no client_secret at all loads cleanly for
// the issuer and the registry today, because validation is scoped and that
// block is not theirs to complete.
//
// Resolution has to be scoped the same way, or a deployment that injects a
// client's credentials into the verifier's pod alone - which is exactly the
// deployment this feature is for - stops the issuer, the registry and the
// apigw on a variable none of them has any reason to hold.
var servicesServingTheVerifierOP = map[string]bool{
	"verifier": true,
}

// staticClients returns the static OIDC clients this service is responsible
// for: none unless it serves the verifier-OP, and none when no verifier-OP
// is configured at all.
func staticClients(cfg *model.Cfg, serviceName string) []model.StaticOIDCClient {
	if !servicesServingTheVerifierOP[serviceName] {
		return nil
	}
	if cfg == nil || cfg.Verifier == nil || cfg.Verifier.Outbound.OIDCProvider == nil {
		return nil
	}
	return cfg.Verifier.Outbound.OIDCProvider.StaticClients
}

// resolveStaticClientIdentities fills in each static client's client_id from
// the environment where client_id_env names a variable, and refuses a
// configuration whose clients cannot be told apart.
//
// Identity before credentials, for two reasons. The secrets file carries
// static_clients as a map keyed BY client_id (pkg/model/secrets.go), so an id
// that arrives from the environment has to be in place before ApplySecrets
// runs or that map can never match it. And the duplicate check below is only
// meaningful once every id is its final value.
//
// The client_secret/client_secret_env conflict is caught here too, before
// ApplySecrets rather than beside the secret's own resolution, because
// ApplySecrets CLEARS every static client's secret on its way in: afterwards
// a secret written in config.yaml is indistinguishable from one never
// written, and the operator who wrote both down would never be told.
func resolveStaticClientIdentities(cfg *model.Cfg, serviceName string) error {
	clients := staticClients(cfg, serviceName)

	for i := range clients {
		c := &clients[i]

		if c.ClientID != "" && c.ClientIDEnv != "" {
			return fmt.Errorf("%s[%d]: client_id and client_id_env are both set; a client's id comes from one place or the other, not both", staticClientsPath, i)
		}
		if c.ClientSecret != "" && c.ClientSecretEnv != "" {
			return fmt.Errorf("%s[%d] (client_id %q): client_secret and client_secret_env are both set; a client's secret comes from one place or the other, not both", staticClientsPath, i, c.ClientID)
		}

		if c.ClientIDEnv == "" {
			continue
		}
		value, err := lookupRequiredEnv(c.ClientIDEnv, fmt.Sprintf("%s[%d]: client_id_env", staticClientsPath, i))
		if err != nil {
			return err
		}
		c.ClientID = value
	}

	// Two entries sharing an id is a configuration nobody can read the
	// intent of: getClientByID (internal/verifier/apiv1/client.go) returns
	// the first match, so the second entry's redirect_uris, scopes and
	// secret are silently inert. Injection makes that reachable without it
	// being visible anywhere in the YAML - two client_id_env values that
	// happen to hold the same string - so the collision is refused rather
	// than resolved by position.
	seen := make(map[string]int, len(clients))
	for i, c := range clients {
		if c.ClientID == "" {
			// Nothing to collide on yet; the required tag on ClientID
			// reports an entry that named no source at all.
			continue
		}
		if first, ok := seen[c.ClientID]; ok {
			return fmt.Errorf("%s: entries [%d] and [%d] both have client_id %q; only the first would ever be used", staticClientsPath, first, i, c.ClientID)
		}
		seen[c.ClientID] = i
	}

	return nil
}

// resolveStaticClientSecrets fills in each static client's client_secret from
// the environment where client_secret_env names a variable.
//
// After the secrets file, deliberately: the environment is the most specific
// source a deployment can supply, and a file should not be able to override
// what a platform injected for one particular client. The conflict between
// client_secret and client_secret_env is caught earlier - see
// resolveStaticClientIdentities for why it cannot be caught here.
func resolveStaticClientSecrets(cfg *model.Cfg, serviceName string) error {
	clients := staticClients(cfg, serviceName)

	for i := range clients {
		c := &clients[i]
		if c.ClientSecretEnv == "" {
			continue
		}
		value, err := lookupRequiredEnv(c.ClientSecretEnv, fmt.Sprintf("%s[%d] (client_id %q): client_secret_env", staticClientsPath, i, c.ClientID))
		if err != nil {
			return err
		}
		c.ClientSecret = value
	}

	return nil
}

// lookupRequiredEnv reads name from the environment and refuses both an unset
// variable and a variable set to the empty string, reporting what pointed at
// it.
//
// Empty is refused rather than accepted because a Kubernetes Secret key may
// legitimately hold an empty value, and an empty client_id or an empty secret
// on a client_secret_basic client is a client that cannot work. Named at
// startup it is a typo in a manifest; accepted here it is a 401 loop in
// production with nothing in the configuration to explain it.
func lookupRequiredEnv(name, where string) (string, error) {
	value, ok := os.LookupEnv(name)
	if !ok {
		return "", fmt.Errorf("%s names %q, which is not set in the environment", where, name)
	}
	if value == "" {
		return "", fmt.Errorf("%s names %q, which is set but empty", where, name)
	}
	return value, nil
}
