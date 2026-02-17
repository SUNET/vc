package configuration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"vc/pkg/helpers"
	"vc/pkg/logger"
	"vc/pkg/model"

	"github.com/creasty/defaults"
	"github.com/kelseyhightower/envconfig"
	"gopkg.in/yaml.v2"
)

type envVars struct {
	ConfigYAML string `envconfig:"VC_CONFIG_YAML" required:"true"`
}

// New parses config file from VC_CONFIG_YAML environment variable
func New(ctx context.Context) (*model.Cfg, error) {
	log := logger.NewSimple("Configuration")
	log.Info("Read environmental variable")

	env := envVars{}
	if err := envconfig.Process("", &env); err != nil {
		return nil, err
	}

	configPath := env.ConfigYAML

	cfg := &model.Cfg{}

	if err := defaults.Set(cfg); err != nil {
		return nil, err
	}

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

	// If a secret file path is configured, load secrets from that file
	// and clear all secrets from the main config so they are not used.
	if cfg.Common != nil && cfg.Common.SecretFilePath != "" {
		secrets, err := LoadSecrets(cfg.Common.SecretFilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load secrets file: %w", err)
		}
		cfg.ClearSecrets()
		cfg.ApplySecrets(secrets)
		log.Info("Secrets loaded from external file", "path", cfg.Common.SecretFilePath)
	}

	// Require credential_constructor when apigw, issuer, or verifier is configured.
	// These services are non-functional without it.
	if len(cfg.CredentialConstructor) == 0 {
		var missing []string
		if cfg.APIGW != nil {
			missing = append(missing, "apigw")
		}
		if cfg.Issuer != nil {
			missing = append(missing, "issuer")
		}
		if cfg.Verifier != nil {
			missing = append(missing, "verifier")
		}
		if len(missing) > 0 {
			return nil, fmt.Errorf("credential_constructor is required when the following services are configured: %v", missing)
		}
	}

	// Load VCTM data and derive Attributes before validation so the vcts_exist
	// validator can cross-reference auth_methods.vcts against actual VCT values.
	if len(cfg.CredentialConstructor) > 0 {
		for scope, constructor := range cfg.CredentialConstructor {
			if constructor == nil || constructor.VCTMFilePath == "" {
				continue
			}
			if err := constructor.LoadVCTMetadata(ctx, scope); err != nil {
				return nil, fmt.Errorf("failed to load VCTM for scope %q: %w", scope, err)
			}
			constructor.Attributes = constructor.VCTM.Attributes()
		}
	}

	if err := helpers.Check(ctx, cfg, cfg, log); err != nil {
		return nil, err
	}

	return cfg, nil
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
