package configuration

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/vc20/credential"

	"github.com/creasty/defaults"
	"github.com/kelseyhightower/envconfig"
	"gopkg.in/yaml.v2"
)

type envVars struct {
	ConfigYAML string `envconfig:"VC_CONFIG_YAML" required:"true"`
}

// servicesRequiringVCTM lists services that need credential_constructor and VCTM files.
// The issuer does NOT need credential_constructor — it receives VCTM bytes
// inline over gRPC from the apigw at credential-issuance time.
var servicesRequiringVCTM = map[string]bool{
	"apigw":    true,
	"verifier": true,
}

// servicesResolvingW3CContexts lists services that dereference JSON-LD
// contexts at runtime, and therefore need those contexts pinned and their
// custom types validated before the process starts serving.
//
// Wider than servicesRequiringVCTM on purpose. The issuer is excluded there
// because it receives schemas inline and loads no VCTM - but it is the
// process that resolves contexts while SIGNING, so an issuer whose
// credential_contexts are unreachable or do not define the configured types
// would otherwise discover that one issuance at a time, in production,
// having already told the operator it started cleanly.
var servicesResolvingW3CContexts = map[string]bool{
	"apigw":    true,
	"verifier": true,
	"issuer":   true,
}

// mongoRequirement describes when a service needs common.mongo.uri.
type mongoRequirement int

const (
	// mongoNotRequired is the zero value, and covers every service not
	// listed below - notably the issuer, which opens no database at all
	// (issue #622).
	mongoNotRequired mongoRequirement = iota

	// mongoWhenPrimaryStoreUsesIt covers services that can run on a
	// relational primary store: they need Mongo only when it is the
	// selected backend, or when HA caching pulls it in regardless.
	mongoWhenPrimaryStoreUsesIt

	// mongoAlways covers services that connect to Mongo unconditionally,
	// whatever common.sql.backend says.
	mongoAlways
)

// serviceMongoRequirement maps each service to when it needs the URI.
//
// registry is mongoAlways rather than backend-gated: internal/registry/db
// calls connectMongo unconditionally and has no sqlstore path at all, so
// gating it on the backend would let registry pass validation with a
// relational backend and no URI, then fail when it dialled.
var serviceMongoRequirement = map[string]mongoRequirement{
	"apigw":    mongoWhenPrimaryStoreUsesIt,
	"verifier": mongoWhenPrimaryStoreUsesIt,
	"registry": mongoAlways,
}

// New parses config file from VC_CONFIG_YAML environment variable.
// serviceName identifies the calling service so that steps like VCTM loading
// can be skipped for services that do not use credential constructors (e.g.
// registry).
func New(ctx context.Context, serviceName string) (*model.Cfg, error) {
	log := logger.NewSimple("Configuration")
	log.Info("Read environmental variable")

	env := envVars{}
	if err := envconfig.Process("", &env); err != nil {
		return nil, err
	}

	configPath := env.ConfigYAML

	cfg := &model.Cfg{}

	configFile, err := os.ReadFile(filepath.Clean(configPath))
	if err != nil {
		return nil, err
	}

	fileInfo, err := os.Stat(configPath)
	if err != nil {
		return nil, err
	}

	if fileInfo.IsDir() {
		return nil, errors.New("config is a folder")
	}

	if err := yaml.Unmarshal(configFile, cfg); err != nil {
		return nil, err
	}

	// Apply defaults AFTER unmarshalling so that nested structs inside
	// pointer fields (e.g. Issuer.APIServer.Addr) receive their default
	// values. creasty/defaults only sets zero-value fields, so explicit
	// YAML values are never overwritten.
	if err := defaults.Set(cfg); err != nil {
		return nil, err
	}

	// If a secret file path is configured, load secrets from that file
	// and apply secrets to the config (clearing secret fields first).
	if cfg.Common != nil && cfg.Common.SecretFilePath != "" {
		secrets, err := LoadSecrets(cfg.Common.SecretFilePath, cfg.Common.SkipSecretsPermCheck)
		if err != nil {
			return nil, fmt.Errorf("failed to load secrets file: %w", err)
		}
		cfg.ApplySecrets(secrets)
		log.Info("Secrets loaded from external file", "path", cfg.Common.SecretFilePath)
	}

	// W3C context work is gated separately from VCTM loading: the issuer
	// needs the former and not the latter. Both are no-ops when nothing
	// W3C is configured, so this costs a non-W3C deployment nothing.
	if servicesResolvingW3CContexts[serviceName] {
		if err := checkW3CTypeConsistency(cfg); err != nil {
			return nil, err
		}

		if err := resolveW3CContexts(cfg, log); err != nil {
			return nil, err
		}
	}

	// Only services that depend on credentials need VCTM loading
	// and the requirement check. Other services (registry) share
	// the same config file but do not use credential constructors at all.
	if servicesRequiringVCTM[serviceName] {
		if cfg.Common == nil || len(cfg.Common.CredentialMetadata) == 0 {
			return nil, fmt.Errorf("common.credential_metadata is required for the %s service", serviceName)
		}

		// Registry is nil unless Common.CredentialRegistry.Enable is true -
		// scopes with a vctm_file_path/vctm_url/mddl_file_path/mddl_url
		// configured never consult it either way.
		registry, err := cfg.Common.CredentialRegistry.NewClient()
		if err != nil {
			return nil, fmt.Errorf("failed to build credential registry client: %w", err)
		}

		if err := checkCredentialMetadataEntries(cfg); err != nil {
			return nil, err
		}

		// Load VCTM data and derive Attributes before validation. No nil
		// guard: checkCredentialMetadataEntries above has refused those.
		for scope, constructor := range cfg.Common.CredentialMetadata {
			if err := constructor.LoadCredentialSchema(ctx, scope, registry); err != nil {
				return nil, fmt.Errorf("failed to load VCTM for scope %q: %w", scope, err)
			}
		}

		// Resolve URL-based VCTs from the APIGW public URL so that issued
		// credentials reference a dereferenceable VCT and the served VCTM
		// document is consistent.
		if cfg.APIGW != nil && cfg.APIGW.PublicURL != "" {
			if err := cfg.ResolveVCTUrls(cfg.APIGW.PublicURL); err != nil {
				return nil, fmt.Errorf("failed to resolve VCT URLs: %w", err)
			}
		}

	}

	// Nil out service sections this service doesn't own so that a shared
	// config file won't fail validation on incomplete sibling stanzas.
	if serviceName == "apigw" {
		cfg.SeedDashboardDefaults()
	}
	switch serviceName {
	case "issuer":
		cfg.APIGW, cfg.Verifier, cfg.Registry = nil, nil, nil
	case "verifier":
		cfg.APIGW, cfg.Issuer, cfg.Registry = nil, nil, nil
	case "registry":
		cfg.APIGW, cfg.Issuer, cfg.Verifier = nil, nil, nil
	case "apigw":
		cfg.Issuer, cfg.Verifier, cfg.Registry = nil, nil, nil
	}

	if err := helpers.Check(ctx, cfg, cfg, log); err != nil {
		return nil, err
	}

	if err := checkMongoRequirement(cfg, serviceName); err != nil {
		return nil, err
	}

	if err := checkCredentialOfferIssuerIdentity(cfg, serviceName); err != nil {
		return nil, err
	}

	return cfg, nil
}

// checkCredentialMetadataEntries refuses a common.credential_metadata key
// whose value is nil.
//
// That is a config typo - a scope written with nothing under it - not an
// absent scope, and skipping it only moves the failure: the verifier's
// Client.New iterates the map and dereferences the entry at startup. Here
// rather than in ResolveVCTUrls because that is gated on an APIGW stanza, so
// a verifier-only config file never reaches it.
func checkCredentialMetadataEntries(cfg *model.Cfg) error {
	if cfg.Common == nil {
		return nil
	}
	var empty []string
	for _, scope := range slices.Sorted(maps.Keys(cfg.Common.CredentialMetadata)) {
		if cfg.Common.CredentialMetadata[scope] == nil {
			empty = append(empty, scope)
		}
	}
	if len(empty) > 0 {
		return fmt.Errorf("common.credential_metadata: no configuration under %s", strings.Join(empty, ", "))
	}
	return nil
}

// checkW3CTypeConsistency refuses a W3C scope that asks for a type it does not
// issue.
//
// credential_type_values is what a verifier constrains by, credential_types is
// what the issuer mints, and credential_contexts is what gives a custom term a
// meaning. Configure the first to narrow past the base type without the other
// two and the deployment issues credentials its own verifier refuses: the
// query requires an IRI the credential cannot carry, because the term was
// never minted, or never had a context to expand against.
//
// The three only work as a set, which the field documentation says - this
// makes saying it unnecessary.
func checkW3CTypeConsistency(cfg *model.Cfg) error {
	if cfg.Common == nil {
		return nil
	}
	for _, scope := range slices.Sorted(maps.Keys(cfg.Common.CredentialMetadata)) {
		credential := cfg.Common.CredentialMetadata[scope]
		if credential == nil || !openid4vp.IsW3CVCFormatIdentifier(credential.Format) {
			continue
		}

		// A custom term needs a context WHENEVER it is minted, not only when
		// something requests it by type. Without one the issued credential
		// carries a type that expands to a relative IRI, which identifies
		// nothing - the credential is malformed whether or not this
		// deployment happens to query for it.
		if custom := customTypes(credential.CredentialTypes); len(custom) > 0 && len(credential.CredentialContexts) == 0 {
			return fmt.Errorf("common.credential_metadata.%s: credential_types names %s, which no credential_contexts defines - the issued credential's type would expand to a relative IRI", scope, strings.Join(custom, ", "))
		}

		// type_values are matched as fully expanded IRIs (OpenID4VP 1.0
		// B.3.2). A relative one cannot equal anything a credential expands
		// to - the verifier drops relative IRIs from the credential side for
		// the same reason - so such a query is guaranteed not to match.
		for i, alternative := range credential.CredentialTypeValues {
			for _, t := range alternative {
				if t == "" || strings.Contains(t, ":") {
					continue
				}
				return fmt.Errorf("common.credential_metadata.%s: credential_type_values[%d] contains %q, which is a relative IRI - type_values are matched as fully expanded IRIs, so this can never match a credential", scope, i, t)
			}
		}

		// Only a constraint that narrows past the base type needs a term
		// behind it; an unset or base-only list requests nothing special.
		if len(credential.W3CTypeValuesForCheck()) == 0 {
			continue
		}
		// Unset AND base-only are the same failure: the issuer mints only
		// VerifiableCredential while the query demands more. The missing
		// context is already caught above, for any custom term.
		if len(customTypes(credential.CredentialTypes)) == 0 {
			return fmt.Errorf("common.credential_metadata.%s: credential_type_values narrows the request, but credential_types names no type beyond VerifiableCredential - the issued credential cannot carry what the query demands", scope)
		}
	}
	return nil
}

// customTypes returns the configured types that are not the base type every
// W3C credential carries.
func customTypes(types []string) []string {
	var out []string
	for _, t := range types {
		if t != "" && t != "VerifiableCredential" {
			out = append(out, t)
		}
	}
	return out
}

// resolveW3CContexts pins every configured JSON-LD context and checks that the
// types this deployment issues can actually satisfy the queries it builds.
//
// The structural checks above can only see that the three fields are present
// together. Whether a context DEFINES a term, and whether the resulting IRIs
// are the ones credential_type_values names, is only answerable by expanding
// the types against the contexts - which means resolving them.
//
// Doing that here buys three things beyond the check itself. A broken or
// unreachable context becomes a startup failure rather than an issuance
// failure after the user has reached their wallet. The signing path never
// fetches, because the document is pinned for the life of the process. And
// what a context endpoint does afterwards - redirect, change, disappear -
// cannot affect an issued credential.
//
// The cost is the network dependency at boot, which is the deliberate
// trade-off: a deployment configuring credential_contexts must have those
// hosts reachable when the service starts.
func resolveW3CContexts(cfg *model.Cfg, log *logger.Log) error {
	if cfg.Common == nil {
		return nil
	}
	loader := credential.GetGlobalLoader()

	for _, scope := range slices.Sorted(maps.Keys(cfg.Common.CredentialMetadata)) {
		cm := cfg.Common.CredentialMetadata[scope]
		if cm == nil || !openid4vp.IsW3CVCFormatIdentifier(cm.Format) || len(cm.CredentialContexts) == 0 {
			continue
		}

		for _, contextURL := range cm.CredentialContexts {
			if err := loader.PinRemoteContext(contextURL); err != nil {
				return fmt.Errorf("common.credential_metadata.%s: credential_contexts %q could not be loaded, so credentials of this type cannot be signed: %w", scope, contextURL, err)
			}
			log.Info("pinned JSON-LD context", "scope", scope, "url", contextURL)
		}

		expanded, err := credential.ExpandTypes(cm.CredentialContexts, cm.W3CTypes())
		if err != nil {
			return fmt.Errorf("common.credential_metadata.%s: credential_types could not be expanded against credential_contexts: %w", scope, err)
		}

		// Every configured term must survive expansion. One that does not is
		// undefined by every configured context, and the credential would
		// carry a type identifying nothing.
		if missing := undefinedTypes(cm.W3CTypes(), expanded); len(missing) > 0 {
			return fmt.Errorf("common.credential_metadata.%s: credential_contexts defines none of %s - the issued credential's type would expand to a relative IRI", scope, strings.Join(missing, ", "))
		}

		// And the query this deployment builds has to be answerable by the
		// credential it issues. MatchTypeValues is satisfied by any ONE
		// alternative, so one being satisfiable is enough.
		if alternatives := cm.W3CTypeValuesForCheck(); len(alternatives) > 0 && !anyAlternativeSatisfied(alternatives, expanded) {
			return fmt.Errorf("common.credential_metadata.%s: no credential_type_values alternative is satisfied by the types this scope issues (expanded: %s) - the deployment would issue credentials its own verifier refuses", scope, strings.Join(expanded, ", "))
		}
	}
	return nil
}

// undefinedTypes returns the configured terms that expansion did not turn into
// an IRI, ignoring the base type which the VC 2.0 context always defines.
func undefinedTypes(configured []string, expanded []string) []string {
	if len(configured) <= len(expanded) {
		return nil
	}
	// Expansion drops what it cannot resolve, so a shortfall means some term
	// was undefined; name the custom ones, since the base always resolves.
	return customTypes(configured)
}

// anyAlternativeSatisfied reports whether the credential's types contain all
// of any one alternative, which is how MatchTypeValues decides.
func anyAlternativeSatisfied(alternatives [][]string, credentialTypes []string) bool {
	for _, alternative := range alternatives {
		satisfied := true
		for _, required := range alternative {
			if !slices.Contains(credentialTypes, required) {
				satisfied = false
				break
			}
		}
		if satisfied {
			return true
		}
	}
	return false
}

// checkMongoRequirement enforces common.mongo.uri for the services that
// actually open a MongoDB store.
//
// Mongo is the default primary-store backend, so an unset SQL.Backend means
// Mongo. HA caching has no relational backend yet and always uses Mongo, so
// it pulls the requirement in regardless of the primary store.
func checkMongoRequirement(cfg *model.Cfg, serviceName string) error {
	requirement := serviceMongoRequirement[serviceName]
	if requirement == mongoNotRequired {
		return nil
	}

	// Cfg.Common carries no "required" tag, so a config with no common
	// block at all reaches here. For a service that needs Mongo that is
	// not "nothing to check" - there is no URI, and letting it through
	// only moves the failure to the first dereference.
	if cfg.Common == nil {
		return fmt.Errorf("common is required for the %s service, which needs common.mongo.uri", serviceName)
	}

	if cfg.Common.Mongo.URI != "" {
		return nil
	}

	if requirement == mongoAlways {
		return fmt.Errorf("common.mongo.uri is required for the %s service, which connects to MongoDB regardless of common.sql.backend", serviceName)
	}

	backend := cfg.Common.SQL.Backend
	if backend == "" {
		backend = "mongo"
	}

	switch {
	case backend == "mongo":
		return fmt.Errorf("common.mongo.uri is required for the %s service when common.sql.backend is %q", serviceName, backend)
	case cfg.Common.HA.Enable:
		return fmt.Errorf("common.mongo.uri is required for the %s service because common.ha.enable is set and HA caching has no relational backend", serviceName)
	}

	return nil
}

// checkCredentialOfferIssuerIdentity rejects an apigw config whose
// credential-offer issuer identifier disagrees with the origin this gateway
// actually is.
//
// Every credential offer this service produces publishes
// apigw.delivery.credential_offers.issuer_url as `credential_issuer`, and a
// wallet resolves that identifier to
// {credential_issuer}/.well-known/openid-credential-issuer. But the issuer
// metadata is generated from apigw.public_url and declares THAT as its own
// `credential_issuer` (see APIGW.IssuerMetadata.Generate, called with
// PublicURL in internal/apigw/apiv1/client.go). So when the two differ the
// wallet fetches metadata from an origin that either serves none or serves a
// document naming a different issuer, and discovery fails - for every offer
// route, not just the UI one.
//
// There is no useful deployment on the far side of this: the two fields name
// one thing, and OpenID4VCI requires the metadata's `credential_issuer` to
// match the identifier the wallet resolved - as a string. So this compares
// them exactly rather than normalising: a trailing slash on one of them is
// still two different identifiers once they are published. Refusing at
// startup turns a silent interop failure - visible only in a wallet, at the
// end of a flow - into a message at boot.
func checkCredentialOfferIssuerIdentity(cfg *model.Cfg, serviceName string) error {
	if serviceName != "apigw" || cfg.APIGW == nil {
		return nil
	}

	issuerURL := cfg.APIGW.Delivery.CredentialOffers.IssuerURL
	publicURL := cfg.APIGW.PublicURL
	if issuerURL == "" || publicURL == "" {
		// Absence is the required-tag's business, not this check's.
		return nil
	}

	// Compared EXACTLY, not normalised. Both values are emitted verbatim -
	// the offer sets credential_issuer to issuer_url as written, and
	// IssuerMetadata.Generate sets it to public_url as written, neither
	// trimming anything. Accepting "https://x/" against "https://x" here
	// would let the two publish different strings for one identity, and a
	// wallet comparing issuer identifiers compares strings. Normalising at
	// this check would hide exactly the mismatch it exists to catch.
	if issuerURL != publicURL {
		return fmt.Errorf(
			"apigw.delivery.credential_offers.issuer_url (%q) must be byte-identical to apigw.public_url (%q): "+
				"offers publish the former as credential_issuer and issuer metadata publishes the latter, "+
				"both verbatim, so any difference - a trailing slash included - makes a wallet compare two "+
				"different issuer identifiers and fail discovery",
			issuerURL, publicURL,
		)
	}

	return nil
}

// LoadSecrets reads and parses the secrets YAML file.
func LoadSecrets(path string, skipPermCheck bool) (*model.Secrets, error) {
	cleanPath := filepath.Clean(path)

	fileInfo, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("cannot stat secrets file %q: %w", cleanPath, err)
	}

	if fileInfo.IsDir() {
		return nil, fmt.Errorf("secrets path %q is a directory, not a file", cleanPath)
	}

	// Fail if the secrets file has any group or world permission bits set.
	// Skip this check when skip_secrets_perm_check is set (e.g. Fly.io mounts files as 0755).
	mode := fileInfo.Mode().Perm()
	if mode&0o077 != 0 && !skipPermCheck {
		return nil, fmt.Errorf("secrets file %q has overly permissive mode %04o; no group/world access allowed (e.g. 0600 or 0400)", cleanPath, mode)
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read secrets file %q: %w", cleanPath, err)
	}

	secrets := &model.Secrets{}
	if err := yaml.Unmarshal(data, secrets); err != nil {
		return nil, fmt.Errorf("cannot parse secrets file %q: %w", cleanPath, err)
	}

	return secrets, nil
}
