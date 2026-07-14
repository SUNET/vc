package federation

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/SUNET/vc/pkg/pki"
	"github.com/golang-jwt/jwt/v5"
)

// Service produces signed OpenID Federation entity configurations.
type Service struct {
	config    *Config
	signer    *pki.SignerConfig
	entityID  string
	publicURL string
}

// NewService creates a federation service.
// publicURL is used as the entity_id when config.EntityID is empty.
func NewService(cfg *Config, signer *pki.SignerConfig, publicURL string) *Service {
	entityID := cfg.EntityID
	if entityID == "" {
		entityID = publicURL
	}
	return &Service{
		config:    cfg,
		signer:    signer,
		entityID:  entityID,
		publicURL: publicURL,
	}
}

// EntityID returns the resolved entity identifier for this federation service.
func (s *Service) EntityID() string {
	return s.entityID
}

// entityConfigClaims is the JWT claims structure for the entity configuration.
type entityConfigClaims struct {
	jwt.RegisteredClaims
	JWKS           json.RawMessage  `json:"jwks"`
	AuthorityHints []string         `json:"authority_hints,omitempty"`
	Metadata       *EntityMetadata  `json:"metadata,omitempty"`
	TrustMarks     []TrustMark      `json:"trust_marks,omitempty"`
}

// BuildEntityConfiguration produces a signed entity configuration JWT.
// The metadata parameter allows callers to inject service-specific metadata
// (e.g., openid_credential_issuer, openid_relying_party).
func (s *Service) BuildEntityConfiguration(metadata *EntityMetadata) (string, error) {
	// Build JWKS from the signing key
	jwk, err := s.signer.GetJWK()
	if err != nil {
		return "", fmt.Errorf("federation: get signing JWK: %w", err)
	}
	jwks := map[string]any{
		"keys": []any{jwk.Public()},
	}
	jwksBytes, err := json.Marshal(jwks)
	if err != nil {
		return "", fmt.Errorf("federation: marshal JWKS: %w", err)
	}

	// Build trust marks
	var trustMarks []TrustMark
	for _, tm := range s.config.TrustMarks {
		trustMarks = append(trustMarks, TrustMark{
			ID:        tm.ID,
			TrustMark: tm.JWT,
		})
	}

	// Inject federation_entity metadata with org info
	if metadata == nil {
		metadata = &EntityMetadata{}
	}
	if s.config.OrganizationName != "" || s.config.LogoURI != "" {
		if metadata.FederationEntity == nil {
			metadata.FederationEntity = make(map[string]any)
		}
		if s.config.OrganizationName != "" {
			metadata.FederationEntity["organization_name"] = s.config.OrganizationName
		}
		if s.config.LogoURI != "" {
			metadata.FederationEntity["logo_uri"] = s.config.LogoURI
		}
	}

	ttl := s.config.TTL
	if ttl <= 0 {
		ttl = 86400
	}

	now := time.Now()
	claims := entityConfigClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.entityID,
			Subject:   s.entityID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(ttl) * time.Second)),
		},
		JWKS:           jwksBytes,
		AuthorityHints: s.config.AuthorityHints,
		Metadata:       metadata,
		TrustMarks:     trustMarks,
	}

	signed, err := s.signer.SignJWT(claims)
	if err != nil {
		return "", fmt.Errorf("federation: sign entity configuration: %w", err)
	}

	return signed, nil
}
