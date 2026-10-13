package model

import (
	"net/url"
	"sort"
	"strings"
)

// SeedDashboardDefaults appends auto-discovered service entries (apigw,
// issuer, verifier, registry) to cfg.APIGW.Dashboard.Services from the
// currently populated sibling sections. Operator-supplied entries win:
// a Name match in Services skips the corresponding default.
//
// Intended to be called by the config loader before it nils sibling
// service sections, so the /dashboard handler has data to render even
// when it can no longer read cfg.Issuer / cfg.Verifier / cfg.Registry
// directly.
func (cfg *Cfg) SeedDashboardDefaults() {
	if cfg == nil || cfg.APIGW == nil {
		return
	}

	have := map[string]bool{}
	for _, s := range cfg.APIGW.Dashboard.Services {
		have[s.Name] = true
	}
	add := func(s DashboardService) {
		if s.URL == "" || have[s.Name] {
			return
		}
		have[s.Name] = true
		cfg.APIGW.Dashboard.Services = append(cfg.APIGW.Dashboard.Services, s)
	}

	if u := strings.TrimRight(cfg.APIGW.PublicURL, "/"); u != "" {
		links := []DashboardLink{
			{Label: "Health", URL: u + "/health", Type: "json"},
			{Label: "Credential offers", URL: u + "/offers", Type: "page"},
			{Label: "OpenID4VCI metadata", URL: u + "/.well-known/openid-credential-issuer", Type: "json"},
			{Label: "OAuth2 metadata", URL: u + "/.well-known/oauth-authorization-server", Type: "json"},
			{Label: "JWKS", URL: u + "/jwks", Type: "json"},
		}
		if cfg.APIGW.AdminUIEnable {
			links = append(links, DashboardLink{Label: "Admin UI", URL: u + "/ui", Type: "page"})
		}
		if cfg.APIGW.OpenIDFederation != nil {
			links = append(links, DashboardLink{Label: "OpenID federation", URL: u + "/.well-known/openid-federation", Type: "page"})
		}
		add(DashboardService{
			Name:        "apigw",
			URL:         u,
			Description: "API gateway – credential issuance, OAuth2/OIDC, wallet-facing endpoints.",
			Links:       links,
		})
	}

	if cfg.Issuer != nil {
		if u := strings.TrimRight(cfg.Issuer.IssuerURL, "/"); u != "" {
			add(DashboardService{
				Name:        "issuer",
				URL:         u,
				Description: "Credential issuer – signs verifiable credentials.",
				Links: []DashboardLink{
					{Label: "Health", URL: u + "/health", Type: "json"},
					{Label: "JWKS", URL: u + "/jwks", Type: "json"},
				},
			})
		}
	}

	if cfg.Verifier != nil {
		if u := strings.TrimRight(cfg.Verifier.PublicURL, "/"); u != "" {
			add(DashboardService{
				Name:        "verifier",
				URL:         u,
				Description: "Credential verifier – OpenID4VP relying party.",
				Links: []DashboardLink{
					{Label: "Health", URL: u + "/health", Type: "json"},
				},
			})
		}
	}

	if cfg.Registry != nil {
		if u := strings.TrimRight(cfg.Registry.PublicURL, "/"); u != "" {
			links := []DashboardLink{
				{Label: "Health", URL: u + "/health", Type: "json"},
				{Label: "Status lists", URL: u + "/statuslists", Type: "json"},
			}
			if BoolVal(cfg.Registry.AdminGUI.Enable, false) {
				links = append(links, DashboardLink{Label: "Admin GUI", URL: u + "/admin", Type: "page"})
			}
			add(DashboardService{
				Name:        "registry",
				URL:         u,
				Description: "Credential status registry - token status lists.",
				Links:       links,
			})
		}
	}

	cfg.seedDashboardWallets(add)
}

// seedDashboardWallets appends every configured wallet to the dashboard.
// Wallets are collected from the credential-offer redirect targets
// (apigw.delivery.credential_offers.wallets) and the verifier's
// supported_wallets, deduplicated by display name, and sorted for a stable
// order. Each entry's URL is the origin of its configured URI (the wallet's
// human-clickable home); wallets have no health endpoint and the handler
// renders them in their own section without a health status.
func (cfg *Cfg) seedDashboardWallets(add func(DashboardService)) {
	wallets := map[string]string{}
	remember := func(name, rawURL string) {
		if name == "" {
			return
		}
		if _, ok := wallets[name]; ok {
			return
		}
		if u := walletOriginURL(rawURL); u != "" {
			wallets[name] = u
		}
	}

	for _, w := range cfg.APIGW.Delivery.CredentialOffers.Wallets {
		remember(w.Label, w.RedirectURI)
	}
	if cfg.Verifier != nil {
		for name, raw := range cfg.Verifier.SupportedWallets {
			remember(name, raw)
		}
	}

	names := make([]string, 0, len(wallets))
	for n := range wallets {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		add(DashboardService{
			Name:   n,
			URL:    wallets[n],
			Wallet: true,
		})
	}
}

// walletOriginURL reduces a wallet URI (a deep-link redirect or callback) to
// its scheme://host origin, which is the clickable home page a human wants on
// the dashboard. Non-HTTP(S) schemes and unparseable values yield "".
func walletOriginURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
