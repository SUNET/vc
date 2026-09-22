package configuration

import (
	"testing"

	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckOpaqueWalletSentinel_RejectsReservedID(t *testing.T) {
	cfg := &model.Cfg{APIGW: &model.APIGW{Delivery: model.APIGWDelivery{
		CredentialOffers: model.CredentialOffers{
			Wallets: map[string]model.CredentialOfferWallets{
				"opaque": {Label: "x", RedirectURI: "https://example.com/cb"},
			},
		},
	}}}

	err := checkOpaqueWalletSentinel(cfg, "apigw")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"opaque" is reserved`)
}

func TestCheckOpaqueWalletSentinel_AllowsOtherIDs(t *testing.T) {
	cfg := &model.Cfg{APIGW: &model.APIGW{Delivery: model.APIGWDelivery{
		CredentialOffers: model.CredentialOffers{
			Wallets: map[string]model.CredentialOfferWallets{
				"eudi": {Label: "EUDI", RedirectURI: "https://example.com/cb"},
			},
		},
	}}}

	require.NoError(t, checkOpaqueWalletSentinel(cfg, "apigw"))
}

func TestCheckOpaqueWalletSentinel_IgnoredForOtherServices(t *testing.T) {
	cfg := &model.Cfg{APIGW: &model.APIGW{Delivery: model.APIGWDelivery{
		CredentialOffers: model.CredentialOffers{
			Wallets: map[string]model.CredentialOfferWallets{
				"opaque": {Label: "x", RedirectURI: "https://example.com/cb"},
			},
		},
	}}}

	for _, svc := range []string{"issuer", "verifier", "registry"} {
		t.Run(svc, func(t *testing.T) {
			require.NoError(t, checkOpaqueWalletSentinel(cfg, svc))
		})
	}
}

func TestCheckOpaqueWalletSentinel_NilAPIGW(t *testing.T) {
	require.NoError(t, checkOpaqueWalletSentinel(&model.Cfg{}, "apigw"))
}
