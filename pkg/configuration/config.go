package configuration

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"vc/pkg/helpers"
	"vc/pkg/logger"
	"vc/pkg/model"

	"github.com/kelseyhightower/envconfig"
	"gopkg.in/yaml.v2"

	"github.com/creasty/defaults"
)

type envVars struct {
	ConfigYAML string `envconfig:"VC_CONFIG_YAML" required:"true"`
}

// New parses config file from VC_CONFIG_YAML environment variable
func New(ctx context.Context) (*model.Cfg, error) {
	return NewForService(ctx, "")
}

// NewForService parses config file and validates only the specified service's configuration
// serviceName can be: "apigw", "issuer", "verifier", "registry", "persistent", "mockas", "ui", or "" for full validation
func NewForService(ctx context.Context, serviceName string) (*model.Cfg, error) {
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

	// Validate only the relevant service configuration
	var toValidate any = cfg
	if serviceName != "" {
		switch serviceName {
		case "apigw":
			toValidate = cfg.APIGW
		case "issuer":
			toValidate = cfg.Issuer
		case "verifier":
			toValidate = cfg.Verifier
		case "registry":
			toValidate = cfg.Registry
		case "persistent":
			toValidate = cfg.Persistent
		case "mockas":
			toValidate = cfg.MockAS
		case "ui":
			toValidate = cfg.UI
		}
		// Always validate Common config as it's shared
		if err := helpers.Check(ctx, cfg, cfg.Common, log); err != nil {
			return nil, err
		}
	}

	if err := helpers.Check(ctx, cfg, toValidate, log); err != nil {
		return nil, err
	}

	return cfg, nil
}
