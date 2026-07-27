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

// cloneMetadata returns a copy of metadata, including fresh copies of its
// map fields, so that mutating the returned value (e.g. injecting
// federation_entity fields) never affects the caller's original
// *EntityMetadata or the maps it holds. A nil metadata yields an empty,
// non-nil *EntityMetadata.
func cloneMetadata(metadata *EntityMetadata) *EntityMetadata {
	if metadata == nil {
		return &EntityMetadata{}
	}
	clone := *metadata
	clone.OpenIDCredentialIssuer = cloneMetadataMap(metadata.OpenIDCredentialIssuer)
	clone.OAuthAuthorizationServer = cloneMetadataMap(metadata.OAuthAuthorizationServer)
	clone.OpenIDRelyingParty = cloneMetadataMap(metadata.OpenIDRelyingParty)
	clone.FederationEntity = cloneMetadataMap(metadata.FederationEntity)
	return &clone
}

// cloneMetadataMap returns a shallow copy of m (a new map with the same
// entries), preserving nil so omitempty JSON marshaling behavior is
// unchanged. Values are not deep-copied, but BuildEntityConfiguration only
// ever adds or overwrites top-level string keys, so a fresh map header is
// sufficient to prevent the caller's map from being mutated.
func cloneMetadataMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// entityConfigClaims is the JWT claims structure for the entity configuration.
type entityConfigClaims struct {
	jwt.RegisteredClaims
	JWKS           json.RawMessage `json:"jwks"`
	AuthorityHints []string        `json:"authority_hints,omitempty"`
	Metadata       *EntityMetadata `json:"metadata,omitempty"`
	TrustMarks     []TrustMark     `json:"trust_marks,omitempty"`
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

	// Inject federation_entity metadata with org info. Clone the caller's
	// metadata (and its maps) first so this function never mutates the
	// caller-owned *EntityMetadata in place -- callers may reuse the same
	// instance across requests, and a "Build" function mutating its input
	// would be a surprising and hard-to-diagnose side effect.
	metadata = cloneMetadata(metadata)
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
