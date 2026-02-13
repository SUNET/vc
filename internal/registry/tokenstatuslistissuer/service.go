package tokenstatuslistissuer

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"vc/internal/registry/cache"
	"vc/internal/registry/db"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/pki"
	"vc/pkg/tokenstatuslist"
)

// Service is the token status list issuer service
type Service struct {
	cfg                     *model.Cfg
	tokenStatusListColl     db.TokenStatusListStore
	tokenStatusListMetadata db.TokenStatusListMetadataStore
	signer                  pki.Signer
	log                     *logger.Log

	cacheService *cache.Service

	// refreshInterval is how often tokens are regenerated
	refreshInterval time.Duration
	// tokenValidity is how long tokens are valid (slightly longer than refresh)
	tokenValidity time.Duration
	// ttl is the TTL claim value in tokens (seconds)
	ttl int64

	// stopCh signals the refresh goroutine to stop
	stopCh chan struct{}
}

// New creates a new token status list issuer service
func New(ctx context.Context, cfg *model.Cfg, cacheService *cache.Service, dbService *db.Service, log *logger.Log) (*Service, error) {
	refreshSeconds := cfg.Registry.TokenStatusLists.TokenRefreshInterval
	if refreshSeconds <= 0 {
		refreshSeconds = 43200 // default 12 hours per spec example (Section 5.1)
	}
	refreshInterval := time.Duration(refreshSeconds) * time.Second
	// Token validity equals refresh interval minus buffer for regeneration time
	tokenValidity := refreshInterval - (5 * time.Minute)

	s := &Service{
		cfg:                     cfg,
		tokenStatusListColl:     dbService.TokenStatusListColl,
		tokenStatusListMetadata: dbService.TokenStatusListMetadata,
		log:                     log.New("token_status_list_issuer"),
		refreshInterval:         refreshInterval,
		tokenValidity:           tokenValidity,
		ttl:                     refreshSeconds,
		stopCh:                  make(chan struct{}),
		cacheService:            cacheService,
	}

	// Load signing key using KeyLoader
	keyLoader := pki.NewKeyLoader()
	km, err := keyLoader.LoadKeyMaterial(cfg.Registry.TokenStatusLists.KeyConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to load Token Status List signing key: %w", err)
	}

	// Create signer that supports any key type (RSA, ECDSA)
	signer := pki.NewKeyMaterialSigner(km)
	s.signer = signer
	s.log.Info("Loaded Token Status List signing key", "algorithm", signer.Algorithm())

	// Initialize database if empty
	if err := s.tokenStatusListColl.InitializeIfEmpty(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize Token Status List database: %w", err)
	}

	// Start the refresh goroutine
	go s.refreshLoop(ctx)

	s.log.Info("Started Token Status List cache refresh", "interval", refreshInterval, "validity", tokenValidity)

	return s, nil
}

// Close closes the status issuer service
func (s *Service) Close(ctx context.Context) error {
	s.log.Info("Closing status issuer service")
	close(s.stopCh)
	return nil
}

// GetCachedJWT returns a cached JWT for the given section, or empty string if not cached
func (s *Service) GetCachedJWT(section int64) string {
	key := strconv.FormatInt(section, 10)
	v, ok := s.cacheService.JWT.Get(context.Background(), key)
	if !ok {
		return ""
	}
	return v
}

// GetCachedCWT returns a cached CWT for the given section, or nil if not cached
func (s *Service) GetCachedCWT(section int64) []byte {
	key := strconv.FormatInt(section, 10)
	v, ok := s.cacheService.CWT.Get(context.Background(), key)
	if !ok {
		return nil
	}
	return v
}

// refreshLoop periodically refreshes all cached status list tokens
func (s *Service) refreshLoop(ctx context.Context) {
	// Do initial refresh immediately
	s.refreshAllSections(ctx)

	ticker := time.NewTicker(s.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.log.Info("Cache refresh loop: context done")
			return
		case <-s.stopCh:
			s.log.Info("Cache refresh loop: stop signal received")
			return
		case <-ticker.C:
			s.refreshAllSections(ctx)
		}
	}
}

// refreshAllSections refreshes the cache for all available sections
func (s *Service) refreshAllSections(ctx context.Context) {
	sections, err := s.tokenStatusListMetadata.GetAllSections(ctx)
	if err != nil {
		s.log.Error(err, "Failed to get sections for cache refresh")
		return
	}

	for _, section := range sections {
		s.refreshSection(ctx, section)
	}

	s.log.Debug("Cache refresh completed", "sections", len(sections))
}

// refreshSection refreshes the cache for a single section
func (s *Service) refreshSection(ctx context.Context, section int64) {
	statuses, err := s.tokenStatusListColl.GetAllStatusesForSection(ctx, section)
	if err != nil {
		s.log.Error(err, "Failed to get statuses for section", "section", section)
		return
	}

	if len(statuses) == 0 {
		return
	}

	key := strconv.FormatInt(section, 10)

	// Get signing method from the signer
	signingMethod := jwt.GetSigningMethod(s.signer.Algorithm())

	// Token config
	subject, err := url.JoinPath(s.cfg.Registry.PublicURL, "/statuslists", key)
	if err != nil {
		s.log.Error(err, "Failed to construct subject URL", "section", section)
		return
	}
	tokenCfg := TokenConfig{
		TokenConfig: tokenstatuslist.TokenConfig{
			Subject:   subject,
			Issuer:    s.cfg.Registry.PublicURL,
			Statuses:  statuses,
			TTL:       s.ttl,
			ExpiresIn: s.tokenValidity,
		},
		SigningMethod: signingMethod,
	}

	// Generate and cache JWT
	jwtToken, err := s.GenerateStatusListTokenJWT(ctx, tokenCfg)
	if err != nil {
		s.log.Error(err, "Failed to generate JWT", "section", section)
	} else {
		s.cacheService.JWT.Set(ctx, key, jwtToken)
	}

	// Generate and cache CWT
	cwtToken, err := s.GenerateStatusListTokenCWT(ctx, tokenCfg)
	if err != nil {
		s.log.Error(err, "Failed to generate CWT", "section", section)
	} else {
		s.cacheService.CWT.Set(ctx, key, cwtToken)
	}
}
