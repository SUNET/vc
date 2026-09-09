package tokenstatuslistissuer

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"

	"github.com/SUNET/vc/pkg/pki"
	"github.com/SUNET/vc/pkg/tokenstatuslist"
)

// TokenConfig embeds tokenstatuslist.TokenConfig and adds signing method configuration.
type TokenConfig struct {
	tokenstatuslist.TokenConfig

	// SigningMethod is the JWT signing method (e.g., jwt.SigningMethodES256)
	SigningMethod jwt.SigningMethod
}

// GenerateStatusListTokenJWT creates a signed Status List Token JWT per Section 5.1
// using the tokenstatuslist package for core Token Status List operations.
func (s *Service) GenerateStatusListTokenJWT(ctx context.Context, cfg TokenConfig) (string, error) {
	// Create StatusList using tokenstatuslist package
	sl := tokenstatuslist.NewWithConfig(cfg.Statuses, cfg.Issuer, cfg.Subject)
	sl.TTL = cfg.TTL
	sl.ExpiresIn = cfg.ExpiresIn
	sl.KeyID = cfg.KeyID
	sl.AggregationURI = cfg.AggregationURI

	// Check that signer is a KeyMaterialSigner
	kmSigner, ok := s.signer.(*pki.KeyMaterialSigner)
	if !ok {
		return "", fmt.Errorf("signer must be a *pki.KeyMaterialSigner, got %T", s.signer)
	}

	// Generate JWT using tokenstatuslist package
	jwtCfg := tokenstatuslist.JWTSigningConfig{
		SigningKey:    kmSigner.PrivateKey(),
		SigningMethod: cfg.SigningMethod,
		PublicKey:     kmSigner.PublicKey(),
	}

	return sl.GenerateJWT(jwtCfg)
}

// GenerateStatusListTokenCWT creates a signed Status List Token CWT per Section 6.1
// using the tokenstatuslist package for core Token Status List operations.
func (s *Service) GenerateStatusListTokenCWT(ctx context.Context, cfg TokenConfig) ([]byte, error) {
	// Create StatusList using tokenstatuslist package
	sl := tokenstatuslist.NewWithConfig(cfg.Statuses, cfg.Issuer, cfg.Subject)
	sl.TTL = cfg.TTL
	sl.ExpiresIn = cfg.ExpiresIn
	sl.KeyID = cfg.KeyID
	sl.AggregationURI = cfg.AggregationURI

	// Check that signer is a KeyMaterialSigner
	kmSigner, ok := s.signer.(*pki.KeyMaterialSigner)
	if !ok {
		return nil, fmt.Errorf("signer must be a *pki.KeyMaterialSigner, got %T", s.signer)
	}

	// Generate CWT using tokenstatuslist package.
	// Algorithm is auto-detected from the key type (ES256 for ECDSA, PS256 for RSA).
	cwtCfg := tokenstatuslist.CWTSigningConfig{
		SigningKey: kmSigner.PrivateKey(),
	}

	return sl.GenerateCWT(cwtCfg)
}

// GetStatusListForSection retrieves all statuses for a given section from the database.
// Returns a slice of status values suitable for encoding into a Status List Token.
func (s *Service) GetStatusListForSection(ctx context.Context, section int64) ([]uint8, error) {
	return s.tokenStatusListColl.GetAllStatusesForSection(ctx, section)
}

// CreateNewSectionIfNeeded checks if the current section has enough decoys and creates a new section if needed.
func (s *Service) CreateNewSectionIfNeeded(ctx context.Context) (int64, error) {
	currentSection, err := s.tokenStatusListMetadata.GetCurrentSection(ctx)
	if err != nil {
		return 0, err
	}

	// Use limited count: we only need to know if decoys > 1000, not the exact total.
	// With 1M+ documents, an unlimited CountDocuments takes ~670ms; with limit 1001 it returns in <1ms.
	numberOfDecoyDocs, err := s.tokenStatusListColl.CountDecoysInSectionWithLimit(ctx, currentSection, 1001)
	if err != nil {
		return 0, err
	}

	if numberOfDecoyDocs <= 1000 {
		newSection := currentSection + 1
		sectionSize := s.cfg.Registry.TokenStatusLists.SectionSize
		if err := s.tokenStatusListColl.CreateNewSection(ctx, newSection, sectionSize); err != nil {
			return 0, err
		}

		if err := s.tokenStatusListMetadata.UpdateCurrentSection(ctx, newSection); err != nil {
			return 0, err
		}
		return newSection, nil
	}

	return currentSection, nil
}

// AddStatus adds a new status to the status list and returns the section and index of the new status record.
func (s *Service) AddStatus(ctx context.Context, status uint8) (int64, int64, error) {
	currentSection, err := s.CreateNewSectionIfNeeded(ctx)
	if err != nil {
		return 0, 0, err
	}

	index, err := s.tokenStatusListColl.Add(ctx, currentSection, status)
	if err != nil {
		return 0, 0, err
	}

	// Refresh the cached Status List Token in the background; see refreshSectionAsync
	// for why this must not run inline on the credential-issuance request path.
	s.refreshSectionAsync(ctx, currentSection)

	return currentSection, index, nil
}

// GetAllSections returns all section IDs for Status List Aggregation (Section 9.3).
func (s *Service) GetAllSections(ctx context.Context) ([]int64, error) {
	return s.tokenStatusListMetadata.GetAllSections(ctx)
}

// UpdateStatus updates the status of an existing entry at the given section and index.
func (s *Service) UpdateStatus(ctx context.Context, section int64, index int64, status uint8) error {
	if err := s.tokenStatusListColl.UpdateStatus(ctx, section, index, status); err != nil {
		return err
	}
	// Refresh the cached Status List Token in the background; see refreshSectionAsync
	// for why this must not run inline on the request path.
	s.refreshSectionAsync(ctx, section)
	return nil
}

// HealthProbe implements the status.Prober contract.
//
// Ready = can accept a request and populate a status entry for a credential.
// That request lifecycle is exactly AddStatus, which requires:
//
//  1. Signing key material loaded — needed to (re)generate the status list
//     JWT/CWT that becomes visible after the new entry is written (see
//     refreshSection at the tail of AddStatus).
//  2. Metadata collection reachable — GetCurrentSection is the very first
//     read of AddStatus (via CreateNewSectionIfNeeded).
//  3. Status list collection reachable — the actual Add write target.
//     A bounded CountDocs is used as a cheap round-trip that proves the
//     collection is queryable without performing a write.
//
// Returning a non-nil error means the service cannot allocate a new status
// entry right now, and the error message names which precondition failed.
func (s *Service) HealthProbe(ctx context.Context) error {
	if s.signer == nil {
		return fmt.Errorf("signing key not loaded")
	}
	section, err := s.tokenStatusListMetadata.GetCurrentSection(ctx)
	if err != nil {
		return fmt.Errorf("current section unavailable: %w", err)
	}
	if _, err := s.tokenStatusListColl.CountDecoysInSectionWithLimit(ctx, section, 1); err != nil {
		return fmt.Errorf("status list collection unavailable: %w", err)
	}
	return nil
}
