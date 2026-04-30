package authproviders

import (
	"fmt"

	"github.com/SUNET/vc/pkg/model"
)

// Selector picks the best auth provider for a credential based on what is
// configured and what is actually enabled in the current deployment.
type Selector struct {
	samlEnabled bool
	oidcEnabled bool
}

// NewSelector creates a Selector. Pass true for each auth provider service
// that has been successfully initialised (service != nil).
func NewSelector(samlEnabled, oidcEnabled bool) *Selector {
	return &Selector{
		samlEnabled: samlEnabled,
		oidcEnabled: oidcEnabled,
	}
}

// Select finds the best auth provider for a credential scope by walking the
// data sources. It returns both the chosen auth provider and its credential
// source in one step.
//   - openid4vp is always available (built-in)
//   - saml requires the SAML SP service to be initialised
//   - oidc requires the OIDC RP service to be initialised
func (s *Selector) Select(scope string, ds *model.DataSources) (string, model.CredentialSource, error) {
	sources, err := ds.LookupCredentialSources(scope)
	if err != nil {
		return "", model.CredentialSource{}, err
	}

	for _, src := range sources {
		if s.isEnabled(src.AuthProvider) {
			return src.AuthProvider, src, nil
		}
	}

	return "", model.CredentialSource{}, fmt.Errorf("scope %q: none of the configured auth providers are enabled", scope)
}

func (s *Selector) isEnabled(provider string) bool {
	switch provider {
	case model.AuthProviderOpenID4VP:
		return true
	case model.AuthProviderSAML:
		return s.samlEnabled
	case model.AuthProviderOIDC:
		return s.oidcEnabled
	default:
		return false
	}
}
