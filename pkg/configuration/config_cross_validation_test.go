package configuration

import (
	"testing"
	"vc/pkg/model"

	"github.com/stretchr/testify/assert"
)

func TestValidateCrossServiceConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *model.Cfg
		wantErr bool
	}{
		{
			name:    "nil config passes",
			cfg:     nil,
			wantErr: false,
		},
		{
			name: "no issuer passes",
			cfg:  &model.Cfg{},
		},
		{
			name: "issuer without registry client passes",
			cfg: &model.Cfg{
				Issuer: &model.Issuer{},
			},
		},
		{
			name: "registry client configured without registry section fails",
			cfg: &model.Cfg{
				Issuer: &model.Issuer{
					RegistryClient: model.GRPCClientTLS{Addr: "registry:8090"},
				},
			},
			wantErr: true,
		},
		{
			name: "registry client configured with empty public URL fails",
			cfg: &model.Cfg{
				Issuer: &model.Issuer{
					RegistryClient: model.GRPCClientTLS{Addr: "registry:8090"},
				},
				Registry: &model.Registry{},
			},
			wantErr: true,
		},
		{
			name: "registry client configured with public URL passes",
			cfg: &model.Cfg{
				Issuer: &model.Issuer{
					RegistryClient: model.GRPCClientTLS{Addr: "registry:8090"},
				},
				Registry: &model.Registry{PublicURL: "https://registry.sunet.se"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCrossServiceConfig(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "registry.public_url is required")
				return
			}

			assert.NoError(t, err)
		})
	}
}
