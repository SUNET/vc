package apiv1

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"
	"vc/internal/verifier/db"
	"vc/internal/verifier/notify"
	"vc/pkg/configuration"
	"vc/pkg/crypto"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/oauth2"
	"vc/pkg/openid4vp"
	"vc/pkg/pki"
	"vc/pkg/sdjwtvc"
	"vc/pkg/trace"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Client holds the public api object
type Client struct {
	cfg                        *model.Cfg
	db                         *db.Service
	authContextStore           db.AuthorizationContextStore
	log                        *logger.Log
	notify                     *notify.Service
	oauth2Metadata             *oauth2.AuthorizationServerMetadata
	oauth2MetadataSigningKey   any
	oauth2MetadataSigningChain []string
	verifierSigningKey         any
	verifierSigningCert        *x509.Certificate
	verifierSigningChain       []string
	openid4vp                  *openid4vp.Client
	credentialCache            *ttlcache.Cache[string, []sdjwtvc.CredentialCache]
	trustService               *openid4vp.TrustService
	keyLoader                  *pki.KeyLoader

	// OIDC Provider fields (from verifier-proxy merge)
	tracer                      *trace.Tracer
	oidcSigningKey              any
	oidcSigningAlg              string
	ephemeralEncryptionKeyCache *ttlcache.Cache[string, jwk.Key]
	requestObjectCache          *ttlcache.Cache[string, *openid4vp.RequestObject]
	presentationBuilder         *openid4vp.PresentationBuilder
	claimsExtractor             *openid4vp.ClaimsExtractor
}

// New creates a new instance of the public api
func New(ctx context.Context, db *db.Service, notify *notify.Service, cfg *model.Cfg, tracer *trace.Tracer, log *logger.Log) (*Client, error) {
	// Create OpenID4VP client with custom TTL settings
	openid4vpClient, err := openid4vp.New(ctx, &openid4vp.Config{
		EphemeralKeyTTL:  10 * time.Minute,
		RequestObjectTTL: 5 * time.Minute,
	})
	if err != nil {
		return nil, err
	}

	c := &Client{
		cfg:                         cfg,
		db:                          db,
		authContextStore:            db.AuthorizationContextColl,
		log:                         log.New("apiv1"),
		notify:                      notify,
		openid4vp:                   openid4vpClient,
		credentialCache:             ttlcache.New(ttlcache.WithTTL[string, []sdjwtvc.CredentialCache](5 * time.Minute)),
		tracer:                      tracer,
		ephemeralEncryptionKeyCache: ttlcache.New(ttlcache.WithTTL[string, jwk.Key](10 * time.Minute)),
		requestObjectCache:          ttlcache.New(ttlcache.WithTTL[string, *openid4vp.RequestObject](5 * time.Minute)),
		keyLoader:                   pki.NewKeyLoader(),
	}

	// Start caches
	go c.credentialCache.Start()
	go c.ephemeralEncryptionKeyCache.Start()
	go c.requestObjectCache.Start()

	// Load or generate OAuth2 metadata from configuration
	c.oauth2Metadata, c.oauth2MetadataSigningKey, c.oauth2MetadataSigningChain, err = c.cfg.Verifier.OAuthServer.LoadAndSignMetadata(ctx, c.cfg.Verifier.ExternalServerURL, c.cfg.Verifier.KeyConfig)
	if err != nil {
		return nil, err
	}

	// Load verifier signing key and chain for request object signing
	if err := c.loadVerifierSigningKey(); err != nil {
		c.log.Info("Verifier signing key not loaded", "error", err)
	}

	// Load OIDC signing key if configured
	if err := c.loadOIDCSigningKey(); err != nil {
		c.log.Info("OIDC signing key not loaded - OIDC provider features disabled", "error", err)
	}
	c.oidcSigningAlg = "RS256" // Default algorithm

	// Load presentation request templates if configured
	if err := c.loadPresentationTemplates(ctx); err != nil {
		c.log.Info("Failed to load presentation templates", "error", err)
	}

	// Initialize claims extractor
	c.claimsExtractor = openid4vp.NewClaimsExtractor()

	// Load all vct metadata files and populate its data in cfg
	for scope, credentialInfo := range cfg.CredentialConstructor {
		if err := credentialInfo.LoadVCTMetadata(ctx, scope); err != nil {
			c.log.Error(err, "Failed to load credential constructor", "scope", scope)
			return nil, err
		}

		credentialInfo.Attributes = credentialInfo.VCTM.AttributesWithoutObjects()
	}

	c.trustService = &openid4vp.TrustService{}

	c.log.Info("Started")

	return c, nil
}

// loadVerifierSigningKey loads the verifier signing key and chain from configured paths
// This key is used for signing request objects in OpenID4VP flows
func (c *Client) loadVerifierSigningKey() error {
	// Use centralized KeyLoader with KeyConfig from configuration
	km, err := c.keyLoader.LoadKeyMaterial(c.cfg.Verifier.KeyConfig)
	if err != nil {
		return fmt.Errorf("failed to load verifier signing key: %w", err)
	}

	c.verifierSigningKey = km.PrivateKey
	c.verifierSigningCert = km.Cert
	c.verifierSigningChain = km.Chain

	return nil
}

// loadOIDCSigningKey loads the OIDC signing key from the configured path
func (c *Client) loadOIDCSigningKey() error {
	// Use centralized KeyLoader with KeyConfig from configuration
	km, err := c.keyLoader.LoadKeyMaterial(c.cfg.Verifier.KeyConfig)
	if err != nil {
		return fmt.Errorf("failed to load OIDC signing key: %w", err)
	}

	// Create signer to determine algorithm
	signer := pki.NewKeyMaterialSigner(km)

	c.oidcSigningKey = km.PrivateKey
	c.oidcSigningAlg = signer.Algorithm()
	return nil
}

// loadPresentationTemplates loads presentation request templates from configured directory
func (c *Client) loadPresentationTemplates(ctx context.Context) error {
	// Check if templates directory is configured
	templatesDir := c.cfg.Verifier.OpenID4VP.PresentationRequestsDir
	if templatesDir == "" {
		c.log.Info("Presentation requests directory not configured, using legacy scope mapping")
		return nil
	}

	// Load templates from directory
	config, err := configuration.LoadPresentationRequests(ctx, templatesDir)
	if err != nil {
		c.log.Info("Failed to load presentation request templates, falling back to legacy scope mapping", "error", err, "dir", templatesDir)
		return nil
	}

	// Create presentation builder
	c.presentationBuilder = openid4vp.NewPresentationBuilder(config.GetEnabledTemplates())

	templateCount := len(config.Templates)
	enabledCount := len(config.GetEnabledTemplates())
	c.log.Info("Loaded presentation request templates",
		"total", templateCount,
		"enabled", enabledCount,
		"dir", templatesDir)

	return nil
}

// generateSessionID creates a cryptographically random session identifier
func (c *Client) generateSessionID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return oauth2.GenerateCryptographicNonceFixedLength(32)
	}
	return hex.EncodeToString(b)
}

// generateAuthorizationCode creates a cryptographically random authorization code
func (c *Client) generateAuthorizationCode() string {
	token, err := crypto.GenerateSecureToken(0, 32)
	if err != nil {
		c.log.Error(err, "Failed to generate authorization code")
		return ""
	}
	return token
}

// generateAccessToken creates a cryptographically random access token
func (c *Client) generateAccessToken() string {
	token, err := crypto.GenerateSecureToken(0, 32)
	if err != nil {
		c.log.Error(err, "Failed to generate access token")
		return ""
	}
	return token
}

// generateRefreshToken creates a cryptographically random refresh token
func (c *Client) generateRefreshToken() string {
	token, err := crypto.GenerateSecureToken(0, 32)
	if err != nil {
		c.log.Error(err, "Failed to generate refresh token")
		return ""
	}
	return token
}

// generateSubjectIdentifier creates a subject identifier for the user
// This can be either public (same across all RPs) or pairwise (different per RP)
func (c *Client) generateSubjectIdentifier(walletID string, clientID string) string {
	subjectType := c.cfg.Verifier.OIDC.SubjectType

	switch subjectType {
	case "pairwise":
		hash := sha256.New()
		hash.Write([]byte(walletID))
		hash.Write([]byte(clientID))
		hash.Write([]byte(c.cfg.Verifier.OIDC.SubjectSalt))
		return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
	default:
		hash := sha256.New()
		hash.Write([]byte(walletID))
		hash.Write([]byte(c.cfg.Verifier.OIDC.SubjectSalt))
		return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
	}
}

// getSigningMethod returns the JWT signing method based on the configured algorithm
func (c *Client) getSigningMethod() jwt.SigningMethod {
	switch c.oidcSigningAlg {
	case "RS256":
		return jwt.SigningMethodRS256
	case "RS384":
		return jwt.SigningMethodRS384
	case "RS512":
		return jwt.SigningMethodRS512
	case "ES256":
		return jwt.SigningMethodES256
	case "ES384":
		return jwt.SigningMethodES384
	case "ES512":
		return jwt.SigningMethodES512
	default:
		return jwt.SigningMethodRS256
	}
}

// containsOIDC checks if a slice contains a specific string value (for OIDC validations)
func (c *Client) containsOIDC(slice []string, value string) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}

// authenticateClient validates client credentials for the token endpoint
func (c *Client) authenticateClient(ctx context.Context, clientID, clientSecret string) (*db.Client, error) {
	client, err := c.db.Clients.GetByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, ErrInvalidClient
	}

	// Verify client secret using constant-time comparison via hash
	secretHash := sha256.Sum256([]byte(clientSecret))
	storedHash := sha256.Sum256([]byte(client.ClientSecretHash))
	if !hmacEqual(secretHash[:], storedHash[:]) {
		return nil, ErrInvalidClient
	}

	return client, nil
}

// hmacEqual performs constant-time comparison of two byte slices
func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// createDCQLQuery creates a DCQL query based on the requested scopes
func (c *Client) createDCQLQuery(ctx context.Context, scopes []string) (*openid4vp.DCQL, error) {
	// If we have a presentation builder with templates, use it
	if c.presentationBuilder != nil {
		dcql, err := c.presentationBuilder.BuildDCQLQuery(ctx, scopes)
		if err == nil && dcql != nil {
			return dcql, nil
		}
		// Fall through to legacy if template not found
	}

	// Fallback to building DCQL query from credential config
	return c.buildLegacyDCQLQuery(scopes)
}

// buildLegacyDCQLQuery builds a DCQL query using credential constructor config
func (c *Client) buildLegacyDCQLQuery(scopes []string) (*openid4vp.DCQL, error) {
	var credentials []openid4vp.CredentialQuery

	for _, scope := range scopes {
		if scope == "openid" {
			continue
		}

		credInfo, ok := c.cfg.CredentialConstructor[scope]
		if !ok {
			continue
		}

		cred := openid4vp.CredentialQuery{
			ID:     scope,
			Format: "vc+sd-jwt",
			Meta: openid4vp.MetaQuery{
				VCTValues: []string{credInfo.VCT},
			},
			Claims: make([]openid4vp.ClaimQuery, 0),
		}

		// Add claims from credential attributes
		if credInfo.VCTM != nil {
			for attrName := range credInfo.VCTM.AttributesWithoutObjects() {
				cred.Claims = append(cred.Claims, openid4vp.ClaimQuery{
					Path: []string{attrName},
				})
			}
		}

		credentials = append(credentials, cred)
	}

	if len(credentials) == 0 {
		return nil, fmt.Errorf("no valid credentials found for requested scopes")
	}

	return &openid4vp.DCQL{
		Credentials: credentials,
	}, nil
}

// extractAndMapClaims extracts claims from a VP token and maps them to OIDC claims
// using the template that matches the requested scopes
func (c *Client) extractAndMapClaims(ctx context.Context, vpToken string, scopeStr string) (map[string]any, error) {
	// If no claims extractor, return empty claims
	if c.claimsExtractor == nil {
		c.log.Debug("No claims extractor configured, returning empty claims")
		return make(map[string]any), nil
	}

	// If no presentation builder, use basic extraction without mapping
	if c.presentationBuilder == nil {
		c.log.Debug("No presentation builder configured, using basic extraction without mapping")
		return c.claimsExtractor.ExtractClaimsFromVPToken(ctx, vpToken)
	}

	// Parse scopes
	scopes := parseScopes(scopeStr)

	// Find the template that was used for this request
	template := c.presentationBuilder.FindTemplateByScopes(scopes)
	if template == nil {
		c.log.Debug("No template found for scopes, using basic claim extraction", "scopes", scopes)
		return c.claimsExtractor.ExtractClaimsFromVPToken(ctx, vpToken)
	}

	c.log.Debug("Using template for claim extraction", "template_id", template.GetID(), "scopes", scopes)

	// Get claim mappings from template
	claimMappings := openid4vp.GetClaimMappings(template)
	if claimMappings == nil {
		c.log.Debug("Template has no claim mappings, using basic extraction")
		return c.claimsExtractor.ExtractClaimsFromVPToken(ctx, vpToken)
	}

	// Convert ClaimTransform to ClaimTransformDef for the extractor
	transformDefs := make(map[string]openid4vp.ClaimTransformDef)
	if templateWithTransforms, ok := template.(interface {
		GetClaimTransforms() map[string]configuration.ClaimTransform
	}); ok {
		for claimName, transform := range templateWithTransforms.GetClaimTransforms() {
			transformDefs[claimName] = openid4vp.ClaimTransformDef{
				Type:   transform.Type,
				Params: transform.Params,
			}
		}
	}

	// Extract, map, and transform claims
	oidcClaims, err := c.claimsExtractor.ExtractAndMapClaims(ctx, vpToken, claimMappings, transformDefs)
	if err != nil {
		return nil, fmt.Errorf("failed to extract and map claims: %w", err)
	}

	return oidcClaims, nil
}

// parseScopes splits a scope string into individual scopes
func parseScopes(scopeStr string) []string {
	if scopeStr == "" {
		return []string{}
	}
	return strings.Split(scopeStr, " ")
}
