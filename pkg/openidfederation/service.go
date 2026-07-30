package openidfederation

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// Signer is the subset of *pki.SignerConfig's capability that Service needs
// to produce a signed entity configuration. Defined here (consumer side)
// rather than depending on the concrete pki type, so callers can inject
// their own already-constructed signer instead of Service building one.
type Signer interface {
	GetJWK() (*jose.JSONWebKey, error)
	SignJWT(claims jwt.Claims) (string, error)
}

// Service produces signed OpenID Federation entity configurations.
type Service struct {
	config    *Config
	signer    Signer
	entityID  string
	publicURL string
}

// New creates a federation service.
// publicURL is used as the entity_id when config.EntityID is empty.
func New(cfg *Config, signer Signer, publicURL string) *Service {
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

// SigningAlgorithm returns the JWT algorithm this service's signer uses,
// e.g. for advertising request_object_signing_alg in openid_relying_party
// metadata.
func (s *Service) SigningAlgorithm() (string, error) {
	jwk, err := s.signer.GetJWK()
	if err != nil {
		return "", fmt.Errorf("federation: get signing JWK: %w", err)
	}
	return jwk.Algorithm, nil
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
	//
	// Only clone when there's something to put in the result: Clone() on a
	// nil receiver returns a non-nil empty struct, so cloning unconditionally
	// would force "metadata": {} into the JWT even when the caller passed
	// nil and no org/logo injection is configured, defeating omitempty.
	if metadata != nil || s.config.OrganizationName != "" || s.config.LogoURI != "" {
		metadata = metadata.Clone()
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
