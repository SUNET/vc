package authproviders

import (
	"context"

	"github.com/SUNET/vc/internal/apigw/auth_providers/oidcrp"
	"github.com/SUNET/vc/internal/apigw/auth_providers/samlsp"
	"github.com/SUNET/vc/internal/apigw/db"
	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
)

// Service manages all authentication providers (SAML SP, OIDC RP).
// It initialises only the providers that are enabled in the configuration.
type Service struct {
	saml     *samlsp.Service
	oidc     *oidcrp.Service
	selector *Selector
}

// New creates a new auth providers service, starting all enabled providers.
func New(ctx context.Context, cfg *model.APIGWAuthProviders, samlSessionCache pkgcache.Cache[*samlsp.Session], oidcSessionCache pkgcache.Cache[*oidcrp.Session], dbService *db.Service, log *logger.Log) (*Service, error) {
	s := &Service{}

	if cfg.SAML.Enable {
		var err error
		s.saml, err = samlsp.New(ctx, &cfg.SAML, samlSessionCache, log)
		if err != nil {
			return nil, err
		}
		log.Info("SAML service initialized", "entity_id", cfg.SAML.EntityID)
	}

	if cfg.OIDC.Enable {
		var err error
		s.oidc, err = oidcrp.New(ctx, &cfg.OIDC, oidcSessionCache, dbService, log)
		if err != nil {
			return nil, err
		}
		log.Info("OIDC RP service initialized", "issuer_url", cfg.OIDC.IssuerURL)
	}

	s.selector = NewSelector(s.saml != nil, s.oidc != nil)

	return s, nil
}

// SAML returns the SAML SP service, or nil if not enabled.
func (s *Service) SAML() *samlsp.Service { return s.saml }

// OIDC returns the OIDC RP service, or nil if not enabled.
func (s *Service) OIDC() *oidcrp.Service { return s.oidc }

// Selector returns the auth provider selector.
func (s *Service) Selector() *Selector { return s.selector }
