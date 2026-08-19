package tokenstatuslistissuer

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/sync/singleflight"

	"github.com/SUNET/vc/internal/registry/cache"
	"github.com/SUNET/vc/internal/registry/db"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/pki"
	"github.com/SUNET/vc/pkg/tokenstatuslist"
)

// Service is the token status list issuer service
type Service struct {
	cfg                     *model.Cfg
	tokenStatusListColl     db.TokenStatusListStore
	tokenStatusListMetadata db.TokenStatusListMetadataStore
	signer                  pki.Signer
	log                     *logger.Log

	cacheService *cache.Service

	// refreshGroup coalesces concurrent refreshSection calls for the same section
	// (e.g. several credential issuances landing in the same section at once, or an
	// async refresh overlapping with the periodic ticker) into a single underlying
	// full-section fetch + re-sign instead of running them redundantly in parallel.
	refreshGroup singleflight.Group

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
	refreshInterval := time.Duration(cfg.Registry.TokenStatusLists.TokenRefreshInterval) * time.Second
	// Token validity equals refresh interval minus buffer for regeneration time
	tokenValidity := refreshInterval - (5 * time.Minute)

	s := &Service{
		cfg:                     cfg,
		tokenStatusListColl:     dbService.TokenStatusListColl,
		tokenStatusListMetadata: dbService.TokenStatusListMetadata,
		log:                     log.New("token_status_list_issuer"),
		refreshInterval:         refreshInterval,
		tokenValidity:           tokenValidity,
		ttl:                     cfg.Registry.TokenStatusLists.TokenRefreshInterval,
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
func (s *Service) GetCachedJWT(ctx context.Context, section int64) string {
	key := strconv.FormatInt(section, 10)
	v, ok := s.cacheService.JWT.Get(ctx, key)
	if !ok {
		return ""
	}
	return v
}

// GetCachedCWT returns a cached CWT for the given section, or nil if not cached
func (s *Service) GetCachedCWT(ctx context.Context, section int64) []byte {
	key := strconv.FormatInt(section, 10)
	v, ok := s.cacheService.CWT.Get(ctx, key)
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
		s.refreshSectionCoalesced(ctx, section)
	}

	s.log.Debug("Cache refresh completed", "sections", len(sections))
}

// refreshSectionAsync schedules a background refresh of a section's cached Status
// List Token without blocking the caller.
//
// refreshSection performs a full section re-fetch (every entry in the section, up
// to SectionSize, default 1,000,000) plus JWT and CWT re-signing. Measured locally
// against a MongoDB instance with a realistic 1,000,000-entry section (the config
// default), that full fetch alone takes on the order of 15-20 seconds, even though
// the query is fully served by the section+index index (no collection scan) —
// the cost is simply transferring and decoding a million documents, not a missing
// index. Running that inline on AddStatus/UpdateStatus — as this code used to do —
// blocks every single credential issuance (or status update) on a full status-list
// rebuild, which is the root cause of the ~16-20s "minting a credential is slow"
// symptom.
//
// The database write these callers already performed is durable and synchronous,
// and the cached token is already only refreshed periodically (every
// TokenRefreshInterval, default 12h) by refreshLoop, so it is safe to let the
// cache catch up in the background instead of blocking on it here. The context is
// detached from the caller's cancellation (via context.WithoutCancel) so the
// refresh isn't aborted the moment the triggering RPC returns.
//
// Uses refreshGroup.DoChan directly rather than spawning our own goroutine:
// DoChan is itself non-blocking and only starts a new goroutine when no refresh
// for this section is already in flight, so a burst of AddStatus/UpdateStatus
// calls landing while one refresh is running coalesces onto that single
// in-flight call instead of each parking its own goroutine on refreshGroup.Do.
func (s *Service) refreshSectionAsync(ctx context.Context, section int64) {
	ctx = context.WithoutCancel(ctx)
	key := strconv.FormatInt(section, 10)
	s.refreshGroup.DoChan(key, func() (any, error) {
		s.refreshSection(ctx, section)
		return nil, nil
	})
}

// refreshSectionCoalesced refreshes a section's cache, coalescing concurrent calls
// for the same section (from concurrent AddStatus/UpdateStatus callers, or an
// in-flight async refresh overlapping with the periodic ticker) into a single
// underlying refreshSection call rather than running redundant full-section scans
// in parallel.
func (s *Service) refreshSectionCoalesced(ctx context.Context, section int64) {
	key := strconv.FormatInt(section, 10)
	_, _, _ = s.refreshGroup.Do(key, func() (any, error) {
		s.refreshSection(ctx, section)
		return nil, nil
	})
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
