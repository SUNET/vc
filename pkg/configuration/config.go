package configuration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

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

// servicesRequiringMongo lists the services that open a MongoDB store, and
// so need common.mongo.uri. The issuer is deliberately absent: it holds no
// database at all, and requiring a connection string it will never dial made
// it impossible to run without one (issue #622).
//
// The check cannot live with the other config validations in
// pkg/helpers/validate.go, because a struct validation on Common has no way
// to know which service is starting.
var servicesRequiringMongo = map[string]bool{
	"apigw":    true,
	"registry": true,
	"verifier": true,
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
		secrets, err := LoadSecrets(cfg.Common.SecretFilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load secrets file: %w", err)
		}
		cfg.ApplySecrets(secrets)
		log.Info("Secrets loaded from external file", "path", cfg.Common.SecretFilePath)
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

		// Load VCTM data and derive Attributes before validation.
		for scope, constructor := range cfg.Common.CredentialMetadata {
			if constructor == nil {
				continue
			}
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

	if err := helpers.Check(ctx, cfg, cfg, log); err != nil {
		return nil, err
	}

	if err := checkMongoRequirement(cfg, serviceName); err != nil {
		return nil, err
	}

	return cfg, nil
}

// checkMongoRequirement enforces common.mongo.uri for the services that
// actually open a MongoDB store.
//
// Mongo is the default primary-store backend, so an unset SQL.Backend means
// Mongo. HA caching has no relational backend yet and always uses Mongo, so
// it pulls the requirement in regardless of the primary store.
func checkMongoRequirement(cfg *model.Cfg, serviceName string) error {
	if !servicesRequiringMongo[serviceName] || cfg.Common == nil {
		return nil
	}

	backend := cfg.Common.SQL.Backend
	if backend == "" {
		backend = "mongo"
	}

	switch {
	case cfg.Common.Mongo.URI != "":
		return nil
	case backend == "mongo":
		return fmt.Errorf("common.mongo.uri is required for the %s service when common.sql.backend is %q", serviceName, backend)
	case cfg.Common.HA.Enable:
		return fmt.Errorf("common.mongo.uri is required for the %s service because common.ha.enable is set and HA caching has no relational backend", serviceName)
	}

	return nil
}

// LoadSecrets reads and parses the secrets YAML file.
func LoadSecrets(path string) (*model.Secrets, error) {
	cleanPath := filepath.Clean(path)

	fileInfo, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("cannot stat secrets file %q: %w", cleanPath, err)
	}

	if fileInfo.IsDir() {
		return nil, fmt.Errorf("secrets path %q is a directory, not a file", cleanPath)
	}

	// Fail if the secrets file has any group or world permission bits set.
	mode := fileInfo.Mode().Perm()
	if mode&0o077 != 0 {
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
