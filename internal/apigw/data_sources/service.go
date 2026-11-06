package datasources

import (
	"context"
	"fmt"
	"time"

	"github.com/SUNET/vc/internal/apigw/data_sources/externalapi"
	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
)

// source is the common contract implemented by every external data source.
type source interface {
	FetchAndStoreForVCI(ctx context.Context, personID, credentialType, vciSessionID string) error
}

// Service manages all external data sources for credential issuance, keyed by
// the remote name they were configured under.
type Service struct {
	sources map[string]source
}

// New creates a new data sources service, starting all enabled sources. Each
// remote becomes its own source and receives the external_api scopes that
// reference it, so per-scope attribute mappings are applied. documentShape
// returns the shape of a scope's document, which a mapping writes.
func New(ctx context.Context, remotes map[string]model.Remote, externalAPI model.ExternalAPIConfig, documentShape func(scope string) (claimpath.Shape, error), docCache pkgcache.Cache[map[string]*model.CompleteDocument], log *logger.Log) (*Service, error) {
	s := &Service{sources: make(map[string]source, len(remotes))}

	for remoteName, remote := range remotes {
		scopes := scopesForRemote(externalAPI, remoteName)
		tokenCache := pkgcache.NewMemoryCache[string](1 * time.Hour)

		switch remote.Type {
		case model.RemoteTypeEduAPI:
			svc, err := externalapi.NewEduAPI(ctx, remote, scopes, documentShape, docCache, tokenCache, log)
			if err != nil {
				return nil, err
			}
			s.sources[remoteName] = svc
			log.Info("Edu-API data source initialized", "remote", remoteName, "base_url", remote.BaseURL)
		case model.RemoteTypeOEAPI:
			svc, err := externalapi.NewOEAPI(ctx, remote, scopes, documentShape, docCache, tokenCache, log)
			if err != nil {
				return nil, err
			}
			s.sources[remoteName] = svc
			log.Info("OEAPI data source initialized", "remote", remoteName, "base_url", remote.BaseURL)
		}
	}

	return s, nil
}

// AnyEnabled returns true if at least one external data source is available.
func (s *Service) AnyEnabled() bool { return len(s.sources) > 0 }

// FetchAndStoreForVCI dispatches the external-API fetch to the data source
// configured under remoteName and stores the resulting VCI document in the
// session cache.
func (s *Service) FetchAndStoreForVCI(ctx context.Context, remoteName, personID, credentialType, vciSessionID string) error {
	src, ok := s.sources[remoteName]
	if !ok {
		return fmt.Errorf("no external API data source enabled for remote %q", remoteName)
	}
	return src.FetchAndStoreForVCI(ctx, personID, credentialType, vciSessionID)
}

// scopesForRemote returns the external_api scopes (keyed by credential type)
// that reference the given remote.
func scopesForRemote(cfg model.ExternalAPIConfig, remoteName string) map[string]model.ExternalAPIScope {
	out := make(map[string]model.ExternalAPIScope)
	for credType, scope := range cfg.Scopes {
		if scope.Remote == remoteName {
			out[credType] = scope
		}
	}
	return out
}
