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

	"github.com/SUNET/vc/pkg/issuance"

	"github.com/SUNET/vc/pkg/credential/primitives"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/nymauth"
	"github.com/SUNET/vc/pkg/nymauth/circuits"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vci"
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

// servicesCheckingW3CTypes lists services whose startup validates the
// STRUCTURAL consistency of the W3C type configuration - that
// credential_types, credential_type_values and credential_contexts agree
// with one another.
//
// This is a pure inspection of the config, with no network access, so every
// service that carries the credential configuration runs it: a scope whose
// issuance list can never satisfy its own query constraint is a mistake
// worth failing on wherever it is noticed.
var servicesCheckingW3CTypes = map[string]bool{
	"apigw":    true,
	"verifier": true,
	"issuer":   true,
}

// servicesResolvingW3CContexts lists services that actually DEREFERENCE
// JSON-LD contexts at runtime, and therefore need them fetched and pinned
// before the process starts serving.
//
// Narrower than servicesCheckingW3CTypes, because this one reaches the
// network. The issuer resolves contexts while SIGNING and the verifier
// while canonicalizing a presentation, so for those two an unreachable
// context is a failure worth having at startup rather than one issuance at
// a time in production.
//
// The apigw is NOT in this list: it never touches the JSON-LD loader, and
// only forwards credential_contexts to the issuer over gRPC. Pinning there
// bought nothing and made an apigw refuse to start whenever a context host
// was unreachable - a dependency it does not otherwise have.
var servicesResolvingW3CContexts = map[string]bool{
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
	// values.
	//
	// creasty/defaults fills any field still at its ZERO value, which is
	// not the same as any field the YAML left unset - and for a value an
	// operator writes deliberately, the difference is the whole point.
	// `enabled: false` on a plain bool, `clock_skew_seconds: 0` on a plain
	// int, an explicitly empty string: each unmarshals to the zero value,
	// is indistinguishable from absent by the time this runs, and gets
	// overwritten by the default.
	//
	// So a field whose default is anything other than its zero value must
	// be a POINTER if an operator is to be able to choose the zero value.
	// Nil means absent and takes the default; a written zero survives. See
	// model.BoolVal and pkg/configuration/defaulted_bools_test.go, which
	// fails if a plain bool is given a default of true.
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

	// Before anything else looks at the config: a deployment still carrying
	// the hand-written credential_response_encryption block gets the
	// migration message and nothing else.
	//
	// Ordering, not taste. That block's own fields carry required tags, so
	// helpers.Check below refuses an incomplete one with a generic
	// validation error - and the VCTM requirement a few lines down refuses
	// an apigw config for an unrelated reason before that. Either way the
	// operator is told something true and useless instead of being told
	// which setting replaced theirs. The check that can say that has to run
	// first.
	if err := checkLegacyCredentialResponseEncryption(cfg); err != nil {
		return nil, err
	}

	// W3C context work is gated separately from VCTM loading: the issuer
	// needs the former and not the latter. Both are no-ops when nothing
	// W3C is configured, so this costs a non-W3C deployment nothing.
	if servicesCheckingW3CTypes[serviceName] {
		if err := checkW3CTypeConsistency(cfg); err != nil {
			return nil, err
		}
	}

	// Before the service switch below nils out sibling stanzas, since the
	// allowlist lives in the issuer's.
	if err := w3cStartupChecks(ctx, cfg, serviceName, log); err != nil {
		return nil, err
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

		// Needs the schemas, so it runs after the loop above.
		if err := checkAuxiliaryData(cfg, serviceName); err != nil {
			return nil, err
		}
		deriveAuxiliaryDataRequired(cfg)

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

	// An auth stanza left behind by a deployment that has since closed
	// dynamic client registration is dropped rather than validated. Its
	// required_if rules, and the struct-level check that refuses auth
	// settings with no mode to activate them, exist to stop a half-written
	// policy from leaving /register open. With registration closed there is
	// no /register to leave open, and holding the operator to a policy for
	// a capability they have switched off means maintaining configuration
	// for a feature that does nothing - including keeping a retired token
	// file on disk to satisfy required_if.
	//
	// Same reason the stanzas above are nilled out: validation should not
	// refuse a config over a section this process will never read. Flip
	// registration back on and the stanza is kept and checked again, at the
	// startup where it decides something.
	dropInertRegistrationAuth(cfg, log)

	if err := helpers.Check(ctx, cfg, cfg, log); err != nil {
		return nil, err
	}

	if err := checkMongoRequirement(cfg, serviceName); err != nil {
		return nil, err
	}

	if err := checkCredentialOfferIssuerIdentity(cfg, serviceName); err != nil {
		return nil, err
	}

	if err := checkIssuableCredentialFormats(cfg, serviceName); err != nil {
		return nil, err
	}

	if err := checkIssuancePolicies(cfg, serviceName); err != nil {
		return nil, err
	}

	if err := checkInteractiveAuthorization(cfg, serviceName); err != nil {
		return nil, err
	}

	if err := checkPreAuthOfferExposure(cfg, serviceName); err != nil {
		return nil, err
	}

	if err := checkPresentationScopeFromScope(cfg, serviceName); err != nil {
		return nil, err
	}

	if err := checkRandomDerivations(cfg); err != nil {
		return nil, err
	}

	if err := checkNymAuthVerifier(cfg); err != nil {
		return nil, err
	}

	if err := checkCredentialEncryption(cfg); err != nil {
		return nil, err
	}

	if err := checkAuthScopes(cfg); err != nil {
		return nil, err
	}

	if err := checkPolicyClaimsAreNotCallerTemplated(cfg); err != nil {
		return nil, err
	}

	if err := checkPresetValidationProfiles(cfg); err != nil {
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

// checkAuxiliaryData refuses auxiliary_data this issuer cannot honour.
func checkAuxiliaryData(cfg *model.Cfg, serviceName string) error {
	for _, scope := range slices.Sorted(maps.Keys(cfg.Common.CredentialMetadata)) {
		if err := checkAuxiliaryDataEntries(scope, cfg.Common.CredentialMetadata[scope]); err != nil {
			return err
		}
	}
	if serviceName != "apigw" || cfg.APIGW == nil {
		return nil
	}
	if err := checkToWalletEncryption(cfg); err != nil {
		return err
	}
	return checkSourceOpenings(cfg)
}

// checkSourceOpenings checks the hash_commitment derivations of each data
// source scope against its credential's to_wallet entries.
func checkSourceOpenings(cfg *model.Cfg) error {
	for _, src := range cfg.APIGW.DataSources.SourceScopes() {
		meta := cfg.Common.CredentialMetadata[src.Scope]
		if err := checkHashCommitmentDerivations(src, toWalletPaths(meta)); err != nil {
			return err
		}
		if err := checkOpeningClaims(src, meta); err != nil {
			return err
		}
	}
	return nil
}

// checkToWalletEncryption requires a credential encryption key for a
// credential with to_wallet entries. Their openings travel only in an
// encrypted Credential Response, and the Credential Endpoint refuses
// credential_response_encryption without a key.
func checkToWalletEncryption(cfg *model.Cfg) error {
	if len(cfg.APIGW.IssuerMetadata.CredentialEncryption.Keys) > 0 {
		return nil
	}
	for _, scope := range slices.Sorted(maps.Keys(cfg.Common.CredentialMetadata)) {
		if len(toWalletPaths(cfg.Common.CredentialMetadata[scope])) > 0 {
			return fmt.Errorf("common.credential_metadata.%s.auxiliary_data.to_wallet: an opening travels only in an encrypted Credential Response, which needs a key under apigw.issuer_metadata.credential_encryption.keys", scope)
		}
	}
	return nil
}

// checkAuxiliaryDataEntries checks every entry of a credential's
// auxiliary_data, and that no path has two.
func checkAuxiliaryDataEntries(scope string, meta *model.CredentialMetadata) error {
	if meta == nil || meta.AuxiliaryData == nil {
		return nil
	}
	where := fmt.Sprintf("common.credential_metadata.%s.auxiliary_data", scope)
	seen := map[string]bool{}
	if err := checkAuxiliaryDataList(meta, where+".to_wallet", meta.AuxiliaryData.ToWallet, seen); err != nil {
		return err
	}
	return checkAuxiliaryDataList(meta, where+".to_issuer", meta.AuxiliaryData.ToIssuer, seen)
}

func checkAuxiliaryDataList(meta *model.CredentialMetadata, where string, entries []openid4vci.AuxiliaryDataEntry, seen map[string]bool) error {
	for i, entry := range entries {
		if err := checkHashCommitmentEntry(meta, entry); err != nil {
			return fmt.Errorf("%s[%d]: %w", where, i, err)
		}
		key := claimsPathKey(entry.Path)
		if seen[key] {
			return fmt.Errorf("%s[%d]: a second entry for path %q", where, i, entry.Path)
		}
		seen[key] = true
	}
	return nil
}

// checkHashCommitmentEntry accepts a sha-256 hash_commitment entry whose
// path names a claim the credential's format can carry a commitment in.
func checkHashCommitmentEntry(meta *model.CredentialMetadata, entry openid4vci.AuxiliaryDataEntry) error {
	switch {
	case entry.Type != openid4vci.AuxiliaryDataTypeHashCommitment:
		return fmt.Errorf("type %q; this issuer implements %q", entry.Type, openid4vci.AuxiliaryDataTypeHashCommitment)
	case entry.Alg != openid4vci.HashCommitmentAlgSHA256:
		return fmt.Errorf("alg %q; this issuer implements %q", entry.Alg, openid4vci.HashCommitmentAlgSHA256)
	case len(entry.Path) == 0:
		return errors.New("the path is empty; it names the claim that holds the commitment")
	case entry.Opening != "" || entry.Commitment != "":
		return errors.New("metadata carries no opening or commitment")
	case entry.Required:
		return errors.New("required comes from the type metadata's mandatory flag")
	}
	return checkCommitmentClaim(meta, entry)
}

// deriveAuxiliaryDataRequired sets each to_issuer entry's required from the
// mandatory flag the type metadata gives its claim.
func deriveAuxiliaryDataRequired(cfg *model.Cfg) {
	for _, meta := range cfg.Common.CredentialMetadata {
		if meta == nil || meta.AuxiliaryData == nil {
			continue
		}
		for i, entry := range meta.AuxiliaryData.ToIssuer {
			meta.AuxiliaryData.ToIssuer[i].Required = claimMandatory(meta, entry.Path)
		}
	}
}

// toWalletPaths returns the to_wallet paths of a credential, by
// claimsPathKey.
func toWalletPaths(meta *model.CredentialMetadata) map[string][]string {
	paths := map[string][]string{}
	if meta == nil || meta.AuxiliaryData == nil {
		return paths
	}
	for _, entry := range meta.AuxiliaryData.ToWallet {
		paths[claimsPathKey(entry.Path)] = entry.Path
	}
	return paths
}

// checkHashCommitmentDerivations requires a source scope to fulfil each
// to_wallet path with exactly one hash_commitment derivation.
func checkHashCommitmentDerivations(src model.SourceScope, toWallet map[string][]string) error {
	fulfilled := map[string]bool{}
	for i, d := range src.Derivations {
		if d.HashCommitment == nil {
			continue
		}
		if err := checkHashCommitmentDerivation(d.HashCommitment, toWallet, fulfilled); err != nil {
			return fmt.Errorf("%s.derivations[%d].hash_commitment: %w", src.Where(), i, err)
		}
	}
	for _, key := range slices.Sorted(maps.Keys(toWallet)) {
		if !fulfilled[key] {
			return fmt.Errorf("%s: no hash_commitment derivation fulfils to_wallet path %q of common.credential_metadata.%s.auxiliary_data",
				src.Where(), toWallet[key], src.Scope)
		}
	}
	return nil
}

func checkHashCommitmentDerivation(hc *primitives.HashCommitmentArgs, toWallet map[string][]string, fulfilled map[string]bool) error {
	key := claimsPathKey(hc.Path)
	if _, ok := toWallet[key]; !ok {
		return fmt.Errorf("path %q is no to_wallet entry of the credential's auxiliary_data", hc.Path)
	}
	if fulfilled[key] {
		return fmt.Errorf("path %q is fulfilled twice", hc.Path)
	}
	fulfilled[key] = true
	if err := hc.Opening.Validate(); err != nil {
		return fmt.Errorf("opening: %w", err)
	}
	return nil
}

// claimsPathKey is a map key for a claims path pointer.
func claimsPathKey(path []string) string {
	return strings.Join(path, "\x00")
}

// checkRandomDerivations refuses the random primitive on a presentation
// source, where it would show one value at consent and issue another.
//
// Derivations run twice there, from the same verified claims and with
// nothing carried between them: once in finalisePresentationVerification to
// build the preview the consent page renders, and again in
// buildPresentationDocument to build the credential. Every other primitive
// is a function of its input, so both runs agree. random is not, so the
// identifier the holder approves is not the identifier they receive - which
// for a document identifier is worse than not having the feature.
//
// The other sources are fine and are where the feature is wanted
// (SUNET/vc#736): assertion sources run derivations once, in the SAML ACS or
// OIDC callback, before the document is cached, so one value covers consent
// and every credential issued from that session.
//
// Refusing at config load rather than at issuance: the failure is otherwise
// invisible - nothing errors, the two values simply differ.
func checkRandomDerivations(cfg *model.Cfg) error {
	if cfg == nil || cfg.APIGW == nil {
		return nil
	}
	for _, src := range cfg.APIGW.DataSources.SourceScopes() {
		if src.Source != model.DataSourcePresentation {
			continue
		}
		for i, derivation := range src.Derivations {
			if derivation.Random != nil {
				return fmt.Errorf("%s.derivations[%d]: "+
					"the random primitive is not supported on a presentation source, because derivations run "+
					"once for the consent preview and again for issuance, so the generated value would differ "+
					"between what the holder approves and what they receive", src.Where(), i)
			}
		}
	}
	return nil
}

// checkLegacyCredentialResponseEncryption refuses the hand-written
// apigw.issuer_metadata.credential_response_encryption, which used to publish
// algorithms nothing implemented (SUNET/vc#707).
//
// Refusing rather than ignoring: an operator who wrote those algorithms down
// meant for responses to be encrypted, and silently dropping that is the same
// class of failure the configuration is replacing.
//
// Separate from checkCredentialEncryption, and called before generic
// validation, because this message only helps if it is the one the operator
// sees. See the call site in New.
func checkLegacyCredentialResponseEncryption(cfg *model.Cfg) error {
	if cfg == nil || cfg.APIGW == nil {
		return nil
	}

	if cfg.APIGW.IssuerMetadata.CredentialResponseEncryption != nil {
		return fmt.Errorf("apigw.issuer_metadata.credential_response_encryption is no longer configured by hand: " +
			"the algorithms are now derived from the keys under apigw.issuer_metadata.credential_encryption.keys, " +
			"so the metadata cannot advertise what the Credential Endpoint will not do. Remove this block and " +
			"configure a key instead")
	}

	return nil
}

// checkNymAuthVerifier refuses a nym_auth verifier configuration that
// cannot be honoured.
//
// At config load, because every failure it catches would otherwise
// surface as a REFUSED PROOF: an allowlist with two builds for one
// configuration, an artifact that is not the one allowed, a
// verifier_id in neither of the two forms rulebook v0.4 defines.
// Each of those produces a pseudonym nobody reports or a circuit that
// will not load, and an operator looking at a failed presentation has
// no reason to suspect the configuration.
func checkNymAuthVerifier(cfg *model.Cfg) error {
	if cfg == nil || cfg.Verifier == nil {
		return nil
	}
	// The pre-v0.4 format and member names, refused BEFORE the enable
	// check: a configuration carrying them was written against the
	// old wire shape, and starting with it silently ignored is the
	// failure this refuses. They land in Extra rather than erroring
	// on their own, so nothing else would notice.
	//
	// Named individually, with the replacement, because an operator
	// reading "unknown member" would reasonably go looking for a typo
	// rather than for a rename.
	if err := refuseLegacyZkpReqKeys(cfg.Verifier.PreferredVPFormats); err != nil {
		return err
	}
	if !cfg.Verifier.NymAuth.Enable {
		return nil
	}

	if err := nymauth.CheckVerifierID(cfg.Verifier.NymAuth.VerifierID); err != nil {
		return fmt.Errorf("verifier.nym_auth.verifier_id: %w", err)
	}
	if len(cfg.Verifier.NymAuth.Circuits.Allow) == 0 {
		// Enabled with nothing allowed verifies nothing. Refused
		// rather than started, because "on" and "cannot check a
		// single proof" is a state nobody means to configure.
		return fmt.Errorf("verifier.nym_auth is enabled but verifier.nym_auth.circuits.allow is empty, so no proof could be verified")
	}
	allowlist, err := circuits.NewAllowlist(cfg.Verifier.NymAuth.Circuits)
	if err != nil {
		return err
	}
	// And the ARTIFACTS, not only the entries describing them. An
	// entry can be perfectly well-formed and name a file that is not
	// there, or one whose digest moved when it was rebuilt - and both
	// of those would otherwise surface as a refused proof.
	if err := allowlist.Preload(context.Background()); err != nil {
		return err
	}
	return nil
}

// checkCredentialEncryption verifies that the configured encryption keys can
// actually be loaded.
func checkCredentialEncryption(cfg *model.Cfg) error {
	if cfg == nil || cfg.APIGW == nil {
		return nil
	}

	// Loading here rather than at first use: a key that cannot perform
	// ECDH-ES must not become a 500 on a wallet's credential request, and the
	// metadata is generated from the same call.
	if _, err := cfg.APIGW.IssuerMetadata.CredentialEncryption.Load(); err != nil {
		return fmt.Errorf("apigw.issuer_metadata.credential_encryption: %w", err)
	}

	return nil
}

// unissuableFormats names credential formats that issuer metadata would
// advertise but no issuance path can mint.
//
// "jwt_vc_json" and "jwt_vc_json-ld" are JWT-encoded W3C VCs. They are real
// OpenID4VCI formats and the metadata generator used to put them in its W3C
// branch, complete with the credential_definition Appendix A.1 requires -
// but handlers_issuer.go dispatches W3C issuance on "ldp_vc" and
// "vc+ld+json" only, so a scope configured with either spelling was
// advertised as issuable and failed with "unsupported or missing credential
// format" when a wallet asked for it (SUNET/vc#686).
//
// Refusing at config load rather than silently dropping the scope from the
// metadata: a deployment that configured one of these meant to offer that
// credential, and a scope that quietly disappears from the advertised set
// is harder to notice than a startup error naming it.
var unissuableFormats = map[string]string{
	"jwt_vc_json":    "JWT-encoded W3C VCs are not implemented; use ldp_vc for a Data Integrity W3C VC",
	"jwt_vc_json-ld": "JWT-encoded W3C VCs are not implemented; use ldp_vc for a Data Integrity W3C VC",
}

// checkIssuableCredentialFormats refuses a credential_metadata scope whose
// format the issuer advertises but cannot issue.
//
// The apigw only. common.credential_metadata is shared, but it means
// different things to different services: the apigw ISSUES these credentials
// and advertises them in its issuer metadata, while the verifier and the
// registry read the same stanza to describe credentials somebody else
// issued. A verifier asking for a jwt_vc_json credential from an external
// issuer is exactly the case #686 means to keep working, so the check that
// protects the issuance path must not reach it.
func checkIssuableCredentialFormats(cfg *model.Cfg, serviceName string) error {
	if cfg.Common == nil || serviceName != "apigw" {
		return nil
	}
	for _, scope := range slices.Sorted(maps.Keys(cfg.Common.CredentialMetadata)) {
		constructor := cfg.Common.CredentialMetadata[scope]
		if constructor == nil {
			continue
		}
		if why, bad := unissuableFormats[constructor.Format]; bad {
			return fmt.Errorf("common.credential_metadata.%s: format %q cannot be issued by this build - %s",
				scope, constructor.Format, why)
		}
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
		cm := cfg.Common.CredentialMetadata[scope]
		if cm == nil || !openid4vp.IsW3CVCFormatIdentifier(cm.Format) {
			continue
		}

		// A custom term needs a context WHENEVER it is minted, not only when
		// something requests it by type. Without one the issued credential
		// carries a type that expands to a relative IRI, which identifies
		// nothing - the credential is malformed whether or not this
		// deployment happens to query for it.
		if custom := customTypes(cm.CredentialTypes); len(custom) > 0 && len(cm.CredentialContexts) == 0 {
			return fmt.Errorf("common.credential_metadata.%s: credential_types names %s, which no credential_contexts defines - the issued credential's type would expand to a relative IRI", scope, strings.Join(custom, ", "))
		}

		// type_values are matched as fully expanded IRIs (OpenID4VP 1.0
		// B.3.2). A relative one cannot equal anything a credential expands
		// to - the verifier drops relative IRIs from the credential side for
		// the same reason - so such a query is guaranteed not to match.
		for i, alternative := range cm.CredentialTypeValues {
			for _, t := range alternative {
				// Strict: see credential.IsAbsoluteIRI. "/relative:Type"
				// contains a colon and is still relative.
				if t == "" || credential.IsAbsoluteIRI(t) {
					continue
				}
				return fmt.Errorf("common.credential_metadata.%s: credential_type_values[%d] contains %q, which is a relative IRI - type_values are matched as fully expanded IRIs, so this can never match a credential", scope, i, t)
			}
		}

		// Only a constraint that narrows past the base type needs a term
		// behind it; an unset or base-only list requests nothing special.
		if len(cm.W3CTypeValuesForCheck()) == 0 {
			continue
		}
		// Unset AND base-only are the same failure: the issuer mints only
		// VerifiableCredential while the query demands more. The missing
		// context is already caught above, for any custom term.
		if len(customTypes(cm.CredentialTypes)) == 0 {
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

// w3cStartupChecks runs the W3C configuration gates, in the order they have
// to run in.
//
// The allowlist is an OUTBOUND-FETCH BOUNDARY, so it is enforced before
// anything dereferences a context. resolveW3CContexts pins every configured
// credential_contexts URL, so running it first contacted a host the operator
// had deliberately left out of the allowlist and only then refused it - by
// which time the request had been made.
//
// Separate gate for the second half: the first reads config, the second
// reaches the network. See servicesResolvingW3CContexts.
func w3cStartupChecks(ctx context.Context, cfg *model.Cfg, serviceName string, log *logger.Log) error {
	if err := checkJSONLDContextSources(cfg); err != nil {
		return err
	}
	if serviceName == "issuer" {
		if err := checkIssuerContextAllowlist(cfg); err != nil {
			return err
		}
	}
	if servicesResolvingW3CContexts[serviceName] {
		return resolveW3CContexts(ctx, cfg, serviceName, log)
	}
	return nil
}

// checkJSONLDContextSources refuses a common.jsonld_contexts.sources entry
// that cannot name a document.
//
// Checked for EVERY service, not only the two that resolve contexts: the
// stanza is in the shared config file, and a typo an apigw silently ignores
// is one the operator finds out about when the verifier restarts.
func checkJSONLDContextSources(cfg *model.Cfg) error {
	if cfg.Common == nil {
		return nil
	}
	var problems []string
	for _, url := range slices.Sorted(maps.Keys(cfg.Common.JSONLDContexts.Sources)) {
		source := cfg.Common.JSONLDContexts.Sources[url]
		switch {
		case source.File == "" && source.URL == "":
			problems = append(problems, fmt.Sprintf("common.jsonld_contexts.sources.%s: set either file or url", url))
		case source.File != "" && source.URL != "":
			// Refused rather than resolved by precedence. Both are
			// deliberate acts by the operator, and silently using one
			// means the vetted copy they meant to serve may be the one
			// that was ignored.
			problems = append(problems, fmt.Sprintf("common.jsonld_contexts.sources.%s: file and url are alternatives, set one", url))
		case source.File != "":
			// Read at startup anyway under required and best_effort, but
			// not under lazy - where an unreadable path would otherwise
			// surface at the first presentation that needed it.
			//
			// OPENED, not stat'd. os.Stat answers only that the path
			// resolves: a directory passes it, and so does a file whose
			// mode or owner stops this process reading it. Either one
			// then failed at the first credential that needed the
			// context, which is the moment this check exists to move
			// away from.
			if err := checkReadableFile(source.File); err != nil {
				problems = append(problems, fmt.Sprintf("common.jsonld_contexts.sources.%s: file %q cannot be read: %v", url, source.File, err))
			}
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// checkReadableFile reports whether a path names a regular file this
// process can actually open and read.
func checkReadableFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.IsDir() {
		return errors.New("is a directory, not a JSON-LD document")
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("is not a regular file (mode %s)", info.Mode())
	}
	return nil
}

// checkIssuerContextAllowlist refuses an issuer whose W3C scopes name
// contexts its own allowlist does not.
//
// The apigw forwards common.credential_metadata.<scope>.credential_contexts
// VERBATIM as additional_contexts on every MakeVC20 request, and
// validateAdditionalContexts matches those literally against
// issuer.jsonld_context_allowlist. A scope whose context is missing from the
// allowlist therefore starts cleanly and fails EVERY issuance of that
// credential - at the point the user has already reached their wallet.
//
// Refused at startup, for the same reason resolveW3CContexts refuses an
// unreachable context there: the failure is certain, and a boot failure is
// under the operator's eye while an issuance failure is not.
//
// Not silently widened into the allowlist instead. Both lists are the
// operator's, but that one says which URLs a REQUEST may name, and quietly
// adding to it would answer a question the operator thought they had
// answered.
//
// Issuer-only on purpose: the verifier and the apigw load the same shared
// config file, neither enforces this allowlist, and the apigw is
// deliberately not even in servicesResolvingW3CContexts - failing them here
// would refuse a valid deployment.
func checkIssuerContextAllowlist(cfg *model.Cfg) error {
	if cfg.Issuer == nil || cfg.Common == nil {
		return nil
	}

	var problems []string
	for _, scope := range slices.Sorted(maps.Keys(cfg.Common.CredentialMetadata)) {
		cm := cfg.Common.CredentialMetadata[scope]
		if cm == nil || !openid4vp.IsW3CVCFormatIdentifier(cm.Format) {
			continue
		}
		for _, contextURL := range cm.CredentialContexts {
			if slices.Contains(cfg.Issuer.JSONLDContextAllowlist, contextURL) {
				continue
			}
			problems = append(problems, fmt.Sprintf(
				"common.credential_metadata.%s: credential_contexts %q is not in issuer.jsonld_context_allowlist, so every issuance of this credential would be refused - add it there",
				scope, contextURL))
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
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
// How hard a failure that is now belongs to the operator, through
// common.jsonld_contexts. The boot dependency above is what "required"
// means and stays the issuer's default, because an issuer that cannot
// resolve a context cannot sign the credential either. A verifier defaults
// to "best_effort": it starts, reports itself NOT READY and names the
// context it is waiting for, and a background loop keeps trying - an
// unreachable context costs it one credential type, which does not justify
// a crash loop that takes every other credential type down with it.
//
// Pinned contexts are also re-fetched on common.jsonld_contexts
// .refresh_interval, keeping the last copy that loaded when a refresh
// fails, so neither a context that changes nor one that disappears can
// stop a running service.
func resolveW3CContexts(ctx context.Context, cfg *model.Cfg, serviceName string, log *logger.Log) error {
	loader := credential.GetGlobalLoader()
	loader.SetContextSources(contextSources(cfg))

	// Every context the issuer may be ASKED to dereference at request time
	// is pinned here too, transitively.
	//
	// issuer.jsonld_context_allowlist names the URLs a MakeVC20 request may
	// put in additional_contexts, and validateAdditionalContexts matches the
	// literal top-level URL against it. Nothing checked what that document
	// then pulled in: json-gold resolves a nested "@context", an "@import"
	// and a Link-header ContextURL through the same loader, so an
	// allowlisted context could make the issuer fetch a public endpoint the
	// operator never listed, per request, for as long as the TTL let it.
	//
	// Pinning the closure at startup answers that without turning the
	// allowlist into a host list. What the graph reaches is fetched ONCE, at
	// boot, from operator-named roots, and fails the boot if it cannot be -
	// and at issuance the loader serves the pinned documents, so the signing
	// path makes no outbound request at all. A context that changes after
	// startup cannot affect an issued credential either.
	//
	// Address policy still applies to every one of those fetches: the dial
	// hook refuses non-public addresses, and it sees redirects and
	// json-gold's own recursion. What is added here is the temporal and
	// operational half - fetched at boot, under the operator's eye, rather
	// than silently at request time.
	//
	// ISSUER ONLY. The verifier loads the same shared config file, and the
	// switch that nils out sibling stanzas has not run yet, so a verifier
	// was pinning every URL in an allowlist it never consults - inheriting
	// the issuer's startup network dependency, and failing to start when an
	// issuer-only context was unavailable. It has no MakeVC20 request to
	// serve and dereferences nothing from this list.
	var groups []credential.PinGroup
	if serviceName == "issuer" && cfg.Issuer != nil && len(cfg.Issuer.JSONLDContextAllowlist) > 0 {
		groups = append(groups, credential.PinGroup{
			Name:        "issuer.jsonld_context_allowlist",
			URLs:        cfg.Issuer.JSONLDContextAllowlist,
			Consequence: "so a request naming it could not be signed",
		})
	}

	if cfg.Common != nil {
		for _, scope := range slices.Sorted(maps.Keys(cfg.Common.CredentialMetadata)) {
			cm := cfg.Common.CredentialMetadata[scope]
			if cm == nil || !openid4vp.IsW3CVCFormatIdentifier(cm.Format) || len(cm.CredentialContexts) == 0 {
				continue
			}
			groups = append(groups, credential.PinGroup{
				Name:        "common.credential_metadata." + scope,
				Field:       "credential_contexts",
				URLs:        cm.CredentialContexts,
				Consequence: contextConsequence(serviceName),
				Verify:      func() error { return checkExpandedTypes(scope, cm) },
			})
		}
	}

	// ExpandTypes always prepends the VC 2.0 base context, and an
	// operator may configure a copy of THAT. Installing the source evicts
	// the embedded document, which is pinned with no expiry, so without
	// this the override would be loaded lazily on the ordinary one-hour
	// TTL - outside the pin and refresh policy that every other context
	// here obeys, and free to expire or change while readiness still
	// passes. Added only when a source is configured for it; otherwise
	// the embedded copy is already pinned and there is nothing to do.
	if hasContextSource(cfg, credential.ContextV2) {
		groups = append(groups, credential.PinGroup{
			Name:        "common.jsonld_contexts.sources",
			URLs:        []string{credential.ContextV2},
			Consequence: "so no W3C credential of any scope can be processed",
		})
	}

	pinner := credential.NewPinner(loader, pinnerOptions(cfg, serviceName, log))
	if err := pinner.Pin(ctx, groups); err != nil {
		return err
	}
	pinner.Start(ctx)
	credential.SetGlobalPinner(pinner)
	return nil
}

// contextConsequence says what THIS service loses when a context will not
// load.
//
// One sentence per service rather than one for both. The text an operator
// reads decides where they look, and telling a verifier operator that
// credentials "cannot be signed" sends them to a service that is not
// running and a key that is not involved - the verifier signs nothing.
func contextConsequence(serviceName string) string {
	if serviceName == "issuer" {
		return "so credentials of this type cannot be signed"
	}
	return "so presentations of this credential type cannot be verified"
}

// hasContextSource reports whether the operator configured their own copy
// of one particular context.
func hasContextSource(cfg *model.Cfg, url string) bool {
	if cfg.Common == nil {
		return false
	}
	_, ok := cfg.Common.JSONLDContexts.Sources[url]
	return ok
}

// contextSources converts the operator's configured copies into the form
// the loader takes.
func contextSources(cfg *model.Cfg) map[string]credential.ContextSource {
	if cfg.Common == nil || len(cfg.Common.JSONLDContexts.Sources) == 0 {
		return nil
	}
	out := make(map[string]credential.ContextSource, len(cfg.Common.JSONLDContexts.Sources))
	for url, source := range cfg.Common.JSONLDContexts.Sources {
		out[url] = credential.ContextSource{File: source.File, URL: source.URL}
	}
	return out
}

// pinnerOptions translates the operator's stanza into the pinner's own
// vocabulary.
func pinnerOptions(cfg *model.Cfg, serviceName string, log *logger.Log) credential.PinnerOptions {
	var jc model.JSONLDContexts
	if cfg.Common != nil {
		jc = cfg.Common.JSONLDContexts
	}
	return credential.PinnerOptions{
		Policy: credential.PinPolicy(jc.PolicyFor(serviceName)),
		Retry: credential.RetryPolicy{
			InitialInterval: jc.Retry.InitialInterval,
			MaxInterval:     jc.Retry.MaxInterval,
			Multiplier:      jc.Retry.Multiplier,
			BootAttempts:    jc.Retry.BootAttempts,
		},
		RefreshInterval: jc.RefreshEvery(),
		Log:             log,
	}
}

// checkExpandedTypes is the half of the W3C configuration check that cannot
// be answered without the context documents: whether the contexts actually
// DEFINE the terms this scope issues, and whether the query this deployment
// builds can be satisfied by them.
//
// Split out of resolveW3CContexts so it can run at the moment the contexts
// become available, which under a non-required startup policy is not
// startup. Under "required" it still runs at boot and still fails it;
// under "best_effort" a failure here is reported through readiness instead,
// because the process has already been allowed to start; under "lazy" it
// does not run at all, which is stated in the log at startup.
func checkExpandedTypes(scope string, cm *model.CredentialMetadata) error {
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

// checkAuthScopes verifies that every openid4vp auth_scopes key names a scope
// that common.credential_metadata actually configures.
//
// The struct-level validation in pkg/helpers sees only the DataSources stanza,
// so a typo'd or stale auth scope started the server and failed at request
// time, where the pre-issuance verifier built a query for a credential that
// does not exist.
//
// Here rather than as a struct rule because it needs the whole Cfg -
// credential_metadata under common, auth_scopes under apigw - and after the
// service switch, so a process with no APIGW stanza has nothing to check.
func checkAuthScopes(cfg *model.Cfg) error {
	if cfg.APIGW == nil {
		return nil
	}

	var problems []string
	for _, scope := range slices.Sorted(maps.Keys(cfg.APIGW.DataSources.Datastore.Scopes)) {
		credential := cfg.APIGW.DataSources.Datastore.Scopes[scope]
		if credential.AuthProvider != model.AuthProviderOpenID4VP {
			continue
		}
		for _, authScope := range slices.Sorted(maps.Keys(credential.AuthScopes)) {
			if cfg.GetCredentialMetadata(authScope) == nil {
				problems = append(problems, fmt.Sprintf("%s.auth_scopes.%s", scope, authScope))
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("apigw.data_sources.datastore.scopes: %s name no scope in common.credential_metadata, so no credential can be requested for them", strings.Join(problems, ", "))
	}
	return nil
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

// checkIssuancePolicies builds every configured issuance policy at startup,
// so a broken one is a boot error rather than a surprise on the first
// authentication callback.
//
// IssuancePolicy's own documentation says a rule with the wrong number or
// order of dimensions "fails startup instead of silently never matching at
// evaluation time". That was not true: BuildEngine ran only from
// GetPolicyEngine, inside the OIDC callback, so a malformed rule sat
// undetected until someone tried to authenticate.
//
// It also refuses a policy that is configured but defines no rules.
// NewPolicyEngine returns (nil, nil) for one, and a nil engine reads to
// every caller as "no policy configured" - so `issuance_policy: {}` on a
// scope disabled the very check it was asked for, which is the opposite of
// the documented behaviour that an unmatched query denies issuance. An
// operator who writes that has made a mistake worth naming at boot.
func checkIssuancePolicies(cfg *model.Cfg, serviceName string) error {
	if serviceName != "apigw" || cfg.APIGW == nil {
		return nil
	}

	type scopePolicy struct {
		kind   string
		scope  string
		policy *model.IssuancePolicy
	}
	var policies []scopePolicy

	ds := cfg.APIGW.DataSources
	for scope, sc := range ds.Datastore.Scopes {
		policies = append(policies, scopePolicy{"datastore", scope, sc.IssuancePolicy})
	}
	for scope, sc := range ds.Assertion.Scopes {
		policies = append(policies, scopePolicy{"assertion", scope, sc.IssuancePolicy})
	}
	for scope, sc := range ds.ExternalAPI.Scopes {
		policies = append(policies, scopePolicy{"external_api", scope, sc.IssuancePolicy})
	}

	slices.SortFunc(policies, func(a, b scopePolicy) int {
		if c := strings.Compare(a.kind, b.kind); c != 0 {
			return c
		}
		return strings.Compare(a.scope, b.scope)
	})

	for _, p := range policies {
		if p.policy == nil {
			continue
		}
		where := fmt.Sprintf("apigw.data_sources.%s.scopes.%s.issuance_policy", p.kind, p.scope)

		// GetPolicyEngine, not NewPolicyEngine: it builds through the same
		// cache the OIDC callback reads, keyed on the policy pointer, so the
		// engine validated here is the engine that later serves requests.
		//
		// Building and discarding meant the first callback parsed the rules
		// file again, and a file edited between boot and that callback would
		// then decide authorization without ever having been validated -
		// either failing at request time despite a clean start, or, worse,
		// quietly enforcing different rules than the ones this check passed.
		// Config pointers are stable for the process lifetime, so priming
		// the cache here also means the rules file is read exactly once.
		//
		// NewPolicyEngine underneath refuses every way of ending up with no
		// rules - no source configured, and a rules_file that parses to
		// nothing - so the only thing left to do here is name the scope.
		if _, err := issuance.GetPolicyEngine(p.policy); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
	}

	return nil
}

// checkCredentialOfferIssuerIdentity rejects an apigw config whose
// credential-offer issuer identifier disagrees with the origin this gateway
// actually is.
//
// Every credential offer this service produces publishes
// apigw.delivery.credential_offers.issuer_url as `credential_issuer`, and a
// wallet resolves that identifier by inserting the well-known suffix at its
// host root per RFC 8615 (openid4vci.WellKnownURL). But the issuer
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

// checkPresentationScopeFromScope rejects an apigw config whose
// presentation-source scopes accept a presented credential scope that has no
// matching common.credential_metadata entry. Without this guard, a typo (e.g.
// from: {eudid: ...} instead of eduid) reaches buildIssuanceAuthDCQL /
// enforceScopeCredentialType and either fails to build a DCQL constraint or
// dereferences a nil CredentialMetadata mid-flow — turning a config error
// into a runtime failure only visible on a wallet round-trip.
func checkPresentationScopeFromScope(cfg *model.Cfg, serviceName string) error {
	if serviceName != "apigw" || cfg.APIGW == nil {
		return nil
	}
	if cfg.Common == nil {
		return nil
	}
	var missing []string
	for _, src := range cfg.APIGW.DataSources.SourceScopes() {
		if src.Source != model.DataSourcePresentation {
			continue
		}
		if _, ok := cfg.Common.CredentialMetadata[src.Presented]; !ok {
			missing = append(missing, src.Where())
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("presentation from references unknown credential_metadata entries: %s", strings.Join(missing, ", "))
	}
	return nil
}

// dropInertRegistrationAuth removes the verifier's dynamic registration auth
// stanza when dynamic client registration is closed, before validation looks
// at it.
//
// Nothing reads it in that state: the middleware that would consult it is not
// built, and the endpoints it would protect are not served.
func dropInertRegistrationAuth(cfg *model.Cfg, log *logger.Log) {
	if cfg.Verifier == nil || cfg.Verifier.Outbound.OIDCProvider == nil {
		return
	}

	oidcProvider := cfg.Verifier.Outbound.OIDCProvider
	if oidcProvider.DynamicRegistrationAuth == nil || oidcProvider.DynamicRegistrationEnabled() {
		return
	}

	oidcProvider.DynamicRegistrationAuth = nil
	log.Info("Ignoring dynamic_registration_auth: dynamic client registration is closed, so nothing it configures is reachable")
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

// checkPreAuthOfferExposure refuses a configuration where
// allow_preauth_offer would be a login bypass.
//
// The flag lets POST /api/v1/datastore/preauth_offer mint an offer for a
// scope that is otherwise login-gated. On a deployment where that
// endpoint has no authenticated principal in front of it, that is an open
// endpoint for minting a credential whose whole point is that it requires
// a login - available to anyone who can reach the port.
//
// Refused here rather than guarded in the handler, for the same reason
// interactive_authorization is: with neither JWKS nor OIDC configured the
// API-auth middleware is a pass-through, and the admin session it would
// otherwise look for is granted anonymously when OIDC is absent. There is
// no authenticated principal to require, so the only honest check is on
// the configuration that left none.
//
// A scope whose auth_provider IS preauth is not covered: nothing is
// bypassed by minting an offer for a credential that has no other way to
// be issued, and that is the behaviour this endpoint already had.
func checkPreAuthOfferExposure(cfg *model.Cfg, serviceName string) error {
	if serviceName != "apigw" || cfg.APIGW == nil {
		return nil
	}

	flagged := []string{}
	for _, scope := range slices.Sorted(maps.Keys(cfg.APIGW.DataSources.Datastore.Scopes)) {
		entry := cfg.APIGW.DataSources.Datastore.Scopes[scope]
		if entry.AllowPreAuthOffer && entry.AuthProvider != model.AuthProviderPreAuth {
			flagged = append(flagged, scope)
		}
	}
	if len(flagged) == 0 {
		return nil
	}
	named := strings.Join(flagged, ", ")

	if !apiAuthenticationConfigured(cfg.APIGW.APIServer.APIAuth) {
		return fmt.Errorf(
			"apigw.data_sources.datastore.scopes sets allow_preauth_offer on login-gated %s "+
				"but apigw.api_server.api_auth configures neither jwks nor oidc: the flag lets "+
				"/api/v1/datastore/preauth_offer mint an offer for a credential this scope "+
				"otherwise gates behind a login, and without API authentication anyone who can "+
				"reach the port may call it", named)
	}

	// Having a Bearer mode configured is not enough on its own, because
	// the admin session is an alternative to it rather than a second check
	// on top of it.
	//
	// With the admin UI on and no OIDC, /ui/login grants a session with
	// admin_subject "anonymous" to anybody who asks, and SessionOrAPIAuth
	// accepts a session INSTEAD of falling through to the Bearer
	// middleware. So a deployment with jwks enabled and the admin UI on
	// still exposes minting to an anonymous caller, unless SPOCP rules
	// exist and none accepts that subject. The JWKS configuration says
	// nothing about it.
	if cfg.APIGW.AdminUIEnable && !cfg.APIGW.APIServer.APIAuth.OIDC.Enable {
		return fmt.Errorf(
			"apigw.data_sources.datastore.scopes sets allow_preauth_offer on login-gated %s "+
				"with apigw.admin_ui_enable true and apigw.api_server.api_auth.oidc disabled: "+
				"the admin UI grants an anonymous session when OIDC is absent, and that session "+
				"is accepted in place of a bearer token - so /api/v1/datastore/preauth_offer "+
				"would be reachable without authenticating anybody. Configure oidc, or turn the "+
				"admin UI off", named)
	}

	return nil
}

// checkInteractiveAuthorization refuses a configuration that advertises
// Interactive Authorization as REQUIRED without offering it.
//
// OpenID4VCI 1.1 says require_interactive_authorization MUST NOT be present
// without authorization_challenge_endpoint, and the reason is practical: a
// wallet reading that document is told the only accepted path to issuance
// is a mechanism this server does not expose, which leaves it nothing to
// do. The metadata itself refuses the pair too - the field carries
// excluded_without - but that refusal arrives at serving time with no
// operator watching. This one arrives at startup, with a message.
func checkInteractiveAuthorization(cfg *model.Cfg, serviceName string) error {
	if serviceName != "apigw" || cfg.APIGW == nil {
		return nil
	}
	ia := cfg.APIGW.Delivery.InteractiveAuthorization
	if model.BoolVal(ia.RequireInteractiveAuthorization, false) && !model.BoolVal(ia.Enable, false) {
		return errors.New(
			"apigw.delivery.interactive_authorization.require_interactive_authorization is true " +
				"but enable is false: a server cannot require a mechanism it does not offer " +
				"(OpenID4VCI 1.1, Authorization Server Metadata)")
	}

	// The two configured metadata member names are free text, and they are
	// written straight into the published document. A name that collides
	// with a member the document already has - "issuer" being the way to do
	// real damage - would replace it; two names configured the same would
	// leave map iteration deciding which of the two survives, so the served
	// document could differ between restarts and stop matching its own
	// signature.
	//
	// The marshaller refuses both, but that refusal arrives when a wallet
	// asks for the document, with nobody watching. This one arrives at
	// startup.
	if err := oauth2.ValidateMetadataNames(ia.MetadataNames()); err != nil {
		return fmt.Errorf("apigw.delivery.interactive_authorization: %w", err)
	}

	// Enabling the mechanism exposes POST /api/v1/issuance/prepare, which
	// prepares an issuance bound to a Holder the CALLER names. On a
	// deployment with no API authentication configured that is an open
	// endpoint for minting credential offers against any identity rule the
	// caller likes - precisely the trusted-portal step the mechanism
	// exists to represent, available to anyone who can reach the port.
	//
	// Refused here rather than guarded in the handler, because the handler
	// has no better answer available: with neither JWKS nor OIDC
	// configured the API-auth middleware is a pass-through, and the admin
	// session it would otherwise look for is granted anonymously when OIDC
	// is absent. There is no authenticated principal to require, so the
	// only honest check is on the configuration that left none.
	if model.BoolVal(ia.Enable, false) {
		if !apiAuthenticationConfigured(cfg.APIGW.APIServer.APIAuth) {
			return errors.New(
				"apigw.delivery.interactive_authorization.enable is true but apigw.api_server.api_auth " +
					"configures neither jwks nor oidc: enabling it exposes /api/v1/issuance/prepare, " +
					"which prepares an issuance for a Holder the caller names, and without API " +
					"authentication anyone who can reach the port may call it")
		}

		// Having a Bearer mode configured is not enough on its own,
		// because the admin session is an alternative to it rather than a
		// second check on top of it.
		//
		// With the admin UI on and no OIDC, /ui/login grants a session
		// with admin_subject "anonymous" to anybody who asks, and
		// SessionOrAPIAuth accepts a session INSTEAD of falling through
		// to the Bearer middleware. So a deployment with jwks enabled and
		// the admin UI on still exposes preparation to an anonymous
		// caller, unless SPOCP rules exist and none accepts that subject.
		// The JWKS configuration says nothing about it.
		if cfg.APIGW.AdminUIEnable && !cfg.APIGW.APIServer.APIAuth.OIDC.Enable {
			return errors.New(
				"apigw.delivery.interactive_authorization.enable is true with apigw.admin_ui_enable " +
					"true and apigw.api_server.api_auth.oidc disabled: the admin UI grants an " +
					"anonymous session when OIDC is absent, and that session is accepted in place " +
					"of a bearer token - so /api/v1/issuance/prepare would be reachable without " +
					"authenticating anybody. Configure oidc, or turn the admin UI off")
		}
	}

	return nil
}

// legacyZkpReqKeys maps every pre-v0.4 name onto the one that
// replaced it. There are no aliases: rulebook v0.4 renamed these on
// the wire, and a verifier that quietly accepted the old spelling
// would send one shape while its operator believed it sent another.
var legacyZkpReqKeys = map[string]string{
	"circuit_id_values":           "system_id_values",
	"circuit_proof_system_values": "proof_system_values",
}

// refuseLegacyZkpReqKeys stops a deployment whose configuration still
// speaks the pre-v0.4 names.
//
// Startup rather than first presentation: the old keys would be
// carried as unknown members, the offered lists would be empty, and
// EVERY presentation would then be refused as naming a system the
// request never offered - which reads as a wallet problem.
func refuseLegacyZkpReqKeys(formats *openid4vp.VPFormatsSupported) error {
	if formats == nil {
		return nil
	}
	if _, legacy := formats.Extra["circuit_zk"]; legacy {
		return fmt.Errorf("verifier.preferred_vp_formats.circuit_zk is the pre-v0.4 name; rename it to zkp_req")
	}
	if formats.ZkpReq == nil {
		return nil
	}
	for old, replacement := range legacyZkpReqKeys {
		if _, legacy := formats.ZkpReq.Extra[old]; legacy {
			return fmt.Errorf("verifier.preferred_vp_formats.zkp_req.%s is the pre-v0.4 name; rename it to %s",
				old, replacement)
		}
	}
	return nil
}

// apiAuthenticationConfigured reports whether a caller reaching the admin
// API has to be anybody in particular.
//
// Only the two Bearer modes count. An admin session does not: it is
// granted anonymously when OIDC is absent, so requiring one would be a
// check that passes for everyone.
func apiAuthenticationConfigured(apiAuth model.APIAuth) bool {
	return apiAuth.JWKS.Enable || apiAuth.OIDC.Enable
}
