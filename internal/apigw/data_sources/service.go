package datasources

import (
	"context"
	"time"

	"github.com/SUNET/vc/internal/apigw/data_sources/eduapi"
	pkgcache "github.com/SUNET/vc/pkg/cache"
	pkgeduapi "github.com/SUNET/vc/pkg/eduapi"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
)

// Service manages all external data sources for credential issuance.
type Service struct {
	eduapi *eduapi.Service
}

// New creates a new data sources service, starting all enabled sources.
func New(ctx context.Context, remotes map[string]model.Remote, docCache pkgcache.Cache[map[string]*model.CompleteDocument], log *logger.Log) (*Service, error) {
	s := &Service{}

	for remoteName, remote := range remotes {
		switch remote.Type {
		case model.RemoteTypeEduAPI:
			cfg := pkgeduapi.Config{
				Enable:       true,
				BaseURL:      remote.BaseURL,
				TokenURL:     remote.TokenURL,
				ClientID:     remote.ClientID,
				ClientSecret: remote.ClientSecret,
				Scopes:       remote.Scopes,
				Timeout:      remote.Timeout,
			}
			var err error
			tokenCache := pkgcache.NewMemoryCache[string](1 * time.Hour)
			s.eduapi, err = eduapi.New(ctx, &cfg, docCache, tokenCache, log)
			if err != nil {
				return nil, err
			}
			log.Info("Edu-API data source initialized", "remote", remoteName, "base_url", remote.BaseURL)
		}
	}

	return s, nil
}

// EduAPI returns the Edu-API service, or nil if not configured.
func (s *Service) EduAPI() *eduapi.Service { return s.eduapi }

// EduAPIEnabled returns true if the Edu-API data source is available.
func (s *Service) EduAPIEnabled() bool { return s.eduapi != nil }
