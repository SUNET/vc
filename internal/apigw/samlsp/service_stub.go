//go:build !saml

package samlsp

import (
	"context"
	"fmt"

	pkgcache "vc/pkg/cache"
	"vc/pkg/logger"
	"vc/pkg/model"
)

// Service is a stub implementation when SAML is not enabled
type Service struct{}

// New returns an error indicating SAML is not compiled in
func New(ctx context.Context, cfg *model.SAMLConfig, sessionCache pkgcache.Cache[*Session], log *logger.Log) (*Service, error) {
	return nil, fmt.Errorf("SAML support not compiled in. Rebuild with -tags saml")
}

// GetSPMetadata stub
func (s *Service) GetSPMetadata(ctx context.Context) (string, error) {
	return "", fmt.Errorf("SAML support not compiled in")
}

// AuthRequest stub type
type AuthRequest struct {
	ID          string
	RedirectURL string
	RelayState  string
}

// InitiateAuth stub
func (s *Service) InitiateAuth(ctx context.Context, idpEntityID, credentialType string) (*AuthRequest, error) {
	return nil, fmt.Errorf("SAML support not compiled in")
}

// Assertion stub type
type Assertion struct {
	NameID     string
	Attributes map[string][]string
	SessionID  string
}

// ProcessAssertion stub
func (s *Service) ProcessAssertion(ctx context.Context, samlResponseEncoded string, relayState string) (*Assertion, error) {
	return nil, fmt.Errorf("SAML support not compiled in")
}

// MapToClaims is a stub that returns an error
func (s *Service) MapToClaims(ctx context.Context, assertion *Assertion, credentialType string) (map[string]any, error) {
	return nil, fmt.Errorf("SAML support not compiled in")
}

// ClaimTransformer stub type
type ClaimTransformer struct{}

// GetSession stub
func (s *Service) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	return nil, fmt.Errorf("SAML support not compiled in")
}

// BuildTransformer stub
func (s *Service) BuildTransformer() (*ClaimTransformer, error) {
	return nil, fmt.Errorf("SAML support not compiled in")
}

// Close stub
func (s *Service) Close(ctx context.Context) error {
	return nil
}
