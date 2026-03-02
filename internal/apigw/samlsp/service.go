//go:build saml

package samlsp

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"time"

	pkgcache "vc/pkg/cache"
	"vc/pkg/logger"
	"vc/pkg/model"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

// Service provides SAML Service Provider functionality
type Service struct {
	cfg          *model.SAMLConfig
	sp           *saml.ServiceProvider
	mdqClient    *MDQClient
	sessionCache pkgcache.Cache[*Session]
	log          *logger.Log
}

// New creates a new SAML service
func New(ctx context.Context, cfg *model.SAMLConfig, sessionCache pkgcache.Cache[*Session], log *logger.Log) (*Service, error) {
	if !cfg.Enable {
		log.Info("SAML support disabled")
		return nil, nil
	}

	s := &Service{
		cfg:          cfg,
		sessionCache: sessionCache,
		log:          log.New("saml"),
	}

	// Load X.509 key pair for signing/encryption
	keyPair, err := tls.LoadX509KeyPair(cfg.CertificatePath, cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load SAML key pair: %w", err)
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse SAML certificate: %w", err)
	}

	// Parse ACS URL
	acsURL, err := url.Parse(cfg.ACSEndpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid ACS endpoint URL: %w", err)
	}

	// Use metadata URL or fall back to entity ID
	metadataURL := cfg.MetadataURL
	if metadataURL == "" {
		metadataURL = cfg.EntityID
	}
	parsedMetadataURL, err := url.Parse(metadataURL)
	if err != nil {
		return nil, fmt.Errorf("invalid metadata URL: %w", err)
	}

	// Create Service Provider
	s.sp = &saml.ServiceProvider{
		EntityID:          cfg.EntityID,
		Key:               keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:       keyPair.Leaf,
		MetadataURL:       *parsedMetadataURL,
		AcsURL:            *acsURL,
		AuthnNameIDFormat: saml.TransientNameIDFormat,
		AllowIDPInitiated: false,
		SignatureMethod:   "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
	}

	// Initialize MDQ client (either MDQ or static mode)
	if cfg.StaticIDPMetadata != nil {
		// Static IdP mode
		isURL := cfg.StaticIDPMetadata.MetadataURL != ""
		metadataSource := cfg.StaticIDPMetadata.MetadataPath
		if isURL {
			metadataSource = cfg.StaticIDPMetadata.MetadataURL
		}

		s.mdqClient, err = NewStaticMDQClient(
			metadataSource,
			cfg.StaticIDPMetadata.EntityID,
			isURL,
			s.log,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize static IdP metadata: %w", err)
		}

		s.log.Info("SAML service initialized with static IdP",
			"entity_id", cfg.EntityID,
			"idp_entity_id", cfg.StaticIDPMetadata.EntityID)
	} else {
		// MDQ mode
		s.mdqClient = NewMDQClient(cfg.MDQServer, cfg.MetadataCacheTTL, s.log)
		s.log.Info("SAML service initialized with MDQ",
			"entity_id", cfg.EntityID,
			"mdq_server", cfg.MDQServer)
	}

	return s, nil
}

// GetSPMetadata returns the Service Provider metadata XML
func (s *Service) GetSPMetadata(ctx context.Context) (string, error) {
	metadata := s.sp.Metadata()
	xmlBytes, err := xml.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal SP metadata: %w", err)
	}
	return string(xmlBytes), nil
}

// AuthRequest represents a SAML authentication request
type AuthRequest struct {
	ID          string
	RedirectURL string
	RelayState  string
}

// InitiateAuth initiates a SAML authentication flow
func (s *Service) InitiateAuth(ctx context.Context, idpEntityID, credentialType string) (*AuthRequest, error) {
	// Validate credential type exists in configuration
	credMapping, exists := s.cfg.CredentialMappings[credentialType]
	if !exists {
		return nil, fmt.Errorf("unsupported credential type: %s", credentialType)
	}

	// In static IdP mode, use the static entityID if none provided
	if s.mdqClient.IsStaticMode() {
		staticEntityID := s.mdqClient.GetStaticEntityID()
		if idpEntityID == "" {
			idpEntityID = staticEntityID
			s.log.Debug("using static IdP entityID", "entity_id", idpEntityID)
		} else if idpEntityID != staticEntityID {
			s.log.Info("requested IdP differs from static IdP, using static",
				"requested", idpEntityID,
				"static", staticEntityID)
			idpEntityID = staticEntityID
		}
	}

	// Fetch IdP metadata via MDQ or static
	idpMetadata, err := s.mdqClient.GetIDPMetadata(ctx, idpEntityID)
	if err != nil {
		return nil, fmt.Errorf("failed to get IdP metadata: %w", err)
	}

	// Create authentication request
	req, err := s.sp.MakeAuthenticationRequest(
		idpMetadata.IDPSSODescriptors[0].SingleSignOnServices[0].Location,
		saml.HTTPRedirectBinding,
		saml.HTTPPostBinding,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create authentication request: %w", err)
	}

	// Store session
	session := &Session{
		ID:                 req.ID,
		CredentialType:     credentialType,
		CredentialConfigID: credMapping.CredentialConfigID,
		IDPEntityID:        idpEntityID,
		CreatedAt:          time.Now(),
	}
	s.sessionCache.Set(ctx, req.ID, session)

	// Generate redirect URL
	redirectURL, err := req.Redirect("", s.sp)
	if err != nil {
		return nil, fmt.Errorf("failed to create redirect URL: %w", err)
	}

	return &AuthRequest{
		ID:          req.ID,
		RedirectURL: redirectURL.String(),
		RelayState:  req.ID,
	}, nil
}

// Assertion represents a processed SAML assertion
type Assertion struct {
	NameID     string
	Attributes map[string][]string
	SessionID  string
	NotBefore  time.Time
	NotAfter   time.Time
}

// ProcessAssertion processes a SAML response
func (s *Service) ProcessAssertion(ctx context.Context, samlResponseEncoded string, relayState string) (*Assertion, error) {
	// Retrieve session
	session, err := s.getSession(ctx, relayState)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired session: %w", err)
	}

	// Fetch IdP metadata
	idpMetadata, err := s.mdqClient.GetIDPMetadata(ctx, session.IDPEntityID)
	if err != nil {
		return nil, fmt.Errorf("failed to get IdP metadata: %w", err)
	}

	// Set IdP metadata on SP for validation
	s.sp.IDPMetadata = idpMetadata

	// Parse and validate SAML response
	acsURL := s.sp.AcsURL
	samlResp, err := s.sp.ParseResponse(&http.Request{
		URL: &acsURL,
		PostForm: url.Values{
			"SAMLResponse": {samlResponseEncoded},
			"RelayState":   {session.ID},
		},
	}, []string{session.ID})
	if err != nil {
		return nil, fmt.Errorf("failed to parse SAML response: %w", err)
	}

	// Extract attributes
	attributes := make(map[string][]string)
	for _, attrStatement := range samlResp.AttributeStatements {
		for _, attr := range attrStatement.Attributes {
			values := []string{}
			for _, value := range attr.Values {
				values = append(values, value.Value)
			}
			attributes[attr.Name] = values
		}
	}

	return &Assertion{
		NameID:     samlResp.Subject.NameID.Value,
		Attributes: attributes,
		SessionID:  session.ID,
		NotBefore:  samlResp.Conditions.NotBefore,
		NotAfter:   samlResp.Conditions.NotOnOrAfter,
	}, nil
}

// GetSession retrieves a session by ID
func (s *Service) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	return s.getSession(ctx, sessionID)
}

// getSession retrieves a session by ID from the cache.
func (s *Service) getSession(ctx context.Context, id string) (*Session, error) {
	session, ok := s.sessionCache.Get(ctx, id)
	if !ok || session == nil {
		return nil, fmt.Errorf("session not found or expired: %s", id)
	}

	return session, nil
}

// deleteSession removes a session from the cache.
func (s *Service) deleteSession(ctx context.Context, id string) {
	s.sessionCache.Delete(ctx, id)
	s.log.Debug("session deleted", "id", id)
}

// Close cleans up the SAML service
func (s *Service) Close(ctx context.Context) error {
	s.log.Info("SAML service stopped")
	return nil
}

// Middleware returns a Gin middleware for SAML (optional extension point)
func (s *Service) Middleware() samlsp.RequestTracker {
	// Placeholder - could implement custom request tracking if needed
	return nil
}

// BuildTransformer creates a ClaimTransformer from the service's SAML configuration
func (s *Service) BuildTransformer() (*ClaimTransformer, error) {
	return BuildTransformer(s.cfg)
}

// GetStaticIDPEntityID returns the static IdP entityID if configured, empty string otherwise
func (s *Service) GetStaticIDPEntityID() string {
	if s.mdqClient != nil {
		return s.mdqClient.GetStaticEntityID()
	}
	return ""
}

// IsStaticIDPMode returns true if service is configured for static IdP mode
func (s *Service) IsStaticIDPMode() bool {
	if s.mdqClient != nil {
		return s.mdqClient.IsStaticMode()
	}
	return false
}

// BuildTransformer creates a ClaimTransformer from SAML configuration (package-level for testing)
func BuildTransformer(cfg *model.SAMLConfig) (*ClaimTransformer, error) {
	if cfg == nil || !cfg.Enable {
		return nil, fmt.Errorf("SAML not enabled")
	}

	// Convert config mappings to transformer format
	mappings := make(map[string]*CredentialMapping, len(cfg.CredentialMappings))

	for credentialType, credMapping := range cfg.CredentialMappings {
		// Convert config attribute mappings to transformer format
		attributes := make(map[string]*AttributeMapping)

		for attrID, attrCfg := range credMapping.Attributes {
			attributes[attrID] = &AttributeMapping{
				Claim:     attrCfg.Claim,
				Required:  attrCfg.Required,
				Transform: attrCfg.Transform,
				Default:   attrCfg.Default,
			}
		}

		mappings[credentialType] = &CredentialMapping{
			CredentialType:     credentialType,
			CredentialConfigID: credMapping.CredentialConfigID,
			Attributes:         attributes,
			DefaultIdP:         credMapping.DefaultIdP,
		}
	}

	return NewClaimTransformer(mappings), nil
}
