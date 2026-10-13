package datasources

import (
	"context"
	"fmt"
	"time"

	"github.com/SUNET/vc/internal/apigw/data_sources/eduapi"
	"github.com/SUNET/vc/internal/apigw/data_sources/oeapi"
	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
)

// Service manages all external data sources for credential issuance.
type Service struct {
	eduapi *eduapi.Service
	oeapi  *oeapi.Service
}

// New creates a new data sources service, starting all enabled sources.
func New(ctx context.Context, remotes map[string]model.Remote, docCache pkgcache.Cache[map[string]*model.CompleteDocument], log *logger.Log) (*Service, error) {
	s := &Service{}

	for remoteName, remote := range remotes {
		switch remote.Type {
		case model.RemoteTypeEduAPI:
			var err error
			tokenCache := pkgcache.NewMemoryCache[string](1 * time.Hour)
			s.eduapi, err = eduapi.New(ctx, remote, docCache, tokenCache, log)
			if err != nil {
				return nil, err
			}
			log.Info("Edu-API data source initialized", "remote", remoteName, "base_url", remote.BaseURL)
		case model.RemoteTypeOEAPI:
			var err error
			tokenCache := pkgcache.NewMemoryCache[string](1 * time.Hour)
			s.oeapi, err = oeapi.New(ctx, remote, docCache, tokenCache, log)
			if err != nil {
				return nil, err
			}
			log.Info("OEAPI data source initialized", "remote", remoteName, "base_url", remote.BaseURL)
		}
	}

	return s, nil
}

// EduAPI returns the Edu-API service, or nil if not configured.
func (s *Service) EduAPI() *eduapi.Service { return s.eduapi }

// EduAPIEnabled returns true if the Edu-API data source is available.
func (s *Service) EduAPIEnabled() bool { return s.eduapi != nil }

// OEAPI returns the OEAPI service, or nil if not configured.
func (s *Service) OEAPI() *oeapi.Service { return s.oeapi }

// OEAPIEnabled returns true if the OEAPI data source is available.
func (s *Service) OEAPIEnabled() bool { return s.oeapi != nil }

// AnyEnabled returns true if at least one external data source is available.
func (s *Service) AnyEnabled() bool { return s.eduapi != nil || s.oeapi != nil }

// FetchAndStoreForVCI routes the external-API fetch to the data source that owns
// the credential type, falling back to the single enabled source, and stores the
// resulting VCI document in the session cache.
func (s *Service) FetchAndStoreForVCI(ctx context.Context, personID, credentialType, vciSessionID string) error {
	if s.oeapi != nil && ownsType(s.oeapi.GetCredentialTypes(), credentialType) {
		return s.oeapi.FetchAndStoreForVCI(ctx, personID, credentialType, vciSessionID)
	}
	if s.eduapi != nil && ownsType(s.eduapi.GetCredentialTypes(), credentialType) {
		return s.eduapi.FetchAndStoreForVCI(ctx, personID, credentialType, vciSessionID)
	}
	if s.eduapi != nil {
		return s.eduapi.FetchAndStoreForVCI(ctx, personID, credentialType, vciSessionID)
	}
	if s.oeapi != nil {
		return s.oeapi.FetchAndStoreForVCI(ctx, personID, credentialType, vciSessionID)
	}
	return fmt.Errorf("no external API data source enabled")
}

func ownsType(types []string, credentialType string) bool {
	for _, t := range types {
		if t == credentialType {
			return true
		}
	}
	return false
}
