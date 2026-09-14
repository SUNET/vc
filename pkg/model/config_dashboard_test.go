package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSeedDashboardDefaults_NilSafe(t *testing.T) {
	var cfg *Cfg
	assert.NotPanics(t, func() { cfg.SeedDashboardDefaults() })

	cfg = &Cfg{}
	assert.NotPanics(t, func() { cfg.SeedDashboardDefaults() })
}

func TestSeedDashboardDefaults_AutoDiscoversFromSiblings(t *testing.T) {
	cfg := &Cfg{
		APIGW:    &APIGW{PublicURL: "https://apigw.example.com/"},
		Issuer:   &Issuer{IssuerURL: "https://issuer.example.com"},
		Verifier: &Verifier{PublicURL: "https://verifier.example.com"},
		Registry: &Registry{PublicURL: "https://registry.example.com"},
	}

	cfg.SeedDashboardDefaults()

	names := serviceNames(cfg.APIGW.Dashboard.Services)
	assert.ElementsMatch(t, []string{"apigw", "issuer", "verifier", "registry"}, names)

	apigw := findService(cfg.APIGW.Dashboard.Services, "apigw")
	require.NotNil(t, apigw)
	assert.Equal(t, "https://apigw.example.com", apigw.URL, "trailing slash stripped")
	assert.NotEmpty(t, apigw.Links, "auto-discovered links populated")
	for _, link := range apigw.Links {
		assert.Contains(t, []string{"json", "page"}, link.Type, "explicit Type set")
	}
}

func TestSeedDashboardDefaults_OperatorEntryWinsByName(t *testing.T) {
	cfg := &Cfg{
		APIGW: &APIGW{
			PublicURL: "https://apigw.example.com",
			Dashboard: APIGWDashboard{
				Services: []DashboardService{
					{Name: "apigw", URL: "https://custom.example.com"},
				},
			},
		},
		Issuer: &Issuer{IssuerURL: "https://issuer.example.com"},
	}

	cfg.SeedDashboardDefaults()

	require.Len(t, cfg.APIGW.Dashboard.Services, 2)
	apigw := findService(cfg.APIGW.Dashboard.Services, "apigw")
	require.NotNil(t, apigw)
	assert.Equal(t, "https://custom.example.com", apigw.URL, "operator entry preserved")
	assert.NotNil(t, findService(cfg.APIGW.Dashboard.Services, "issuer"), "issuer still auto-discovered")
}

func TestSeedDashboardDefaults_SkipsEmptyURLs(t *testing.T) {
	cfg := &Cfg{
		APIGW: &APIGW{PublicURL: "https://apigw.example.com"},
		// Issuer/Verifier/Registry present but URLs empty
		Issuer:   &Issuer{},
		Verifier: &Verifier{},
		Registry: &Registry{},
	}

	cfg.SeedDashboardDefaults()

	names := serviceNames(cfg.APIGW.Dashboard.Services)
	assert.Equal(t, []string{"apigw"}, names)
}

func TestSeedDashboardDefaults_AdminUIEnableAddsLink(t *testing.T) {
	cfg := &Cfg{
		APIGW: &APIGW{
			PublicURL:     "https://apigw.example.com",
			AdminUIEnable: true,
		},
	}

	cfg.SeedDashboardDefaults()

	apigw := findService(cfg.APIGW.Dashboard.Services, "apigw")
	require.NotNil(t, apigw)
	assert.True(t, hasLinkLabel(apigw.Links, "Admin UI"))
}

func serviceNames(services []DashboardService) []string {
	out := make([]string, 0, len(services))
	for _, s := range services {
		out = append(out, s.Name)
	}
	return out
}

func findService(services []DashboardService, name string) *DashboardService {
	for i := range services {
		if services[i].Name == name {
			return &services[i]
		}
	}
	return nil
}

func hasLinkLabel(links []DashboardLink, label string) bool {
	for _, l := range links {
		if l.Label == label {
			return true
		}
	}
	return false
}
