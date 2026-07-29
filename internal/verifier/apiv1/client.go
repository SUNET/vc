package apiv1

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/SUNET/vc/internal/verifier/cache"
	"github.com/SUNET/vc/internal/verifier/db"
	"github.com/SUNET/vc/internal/verifier/notify"
	"github.com/SUNET/vc/pkg/configuration"
	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/pki"
	"github.com/SUNET/vc/pkg/trace"
	"github.com/SUNET/vc/pkg/trust"

	"golang.org/x/crypto/bcrypt"
)

// Client holds the public api object
type Client struct {
	cfg    *model.Cfg
	db     *db.Service
	log    *logger.Log
	tracer *trace.Tracer
	notify *notify.Service

	// Metadata
	oauth2Metadata *oauth2.AuthorizationServerMetadata

	// PKI for signing
	pkiSigner      pki.Signer
	pkiSigningCert *x509.Certificate
	pkiSignerChain []string

	// Clients and services
	openid4vp        *openid4vp.Client
	trustService     *openid4vp.TrustService
	trustEvaluator   trust.TrustEvaluator
	jwksResolver     *trust.JWKSKeyResolver
	jwtTrustVerifier *trust.JWTTrustVerifier

	// Cache
	cacheService *cache.Service

	// OIDC related
	presentationBuilder *openid4vp.PresentationBuilder
	claimsExtractor     *openid4vp.ClaimsExtractor
}

// New creates a new instance of the public api
func New(ctx context.Context, db *db.Service, notify *notify.Service, cacheService *cache.Service, cfg *model.Cfg, tracer *trace.Tracer, log *logger.Log) (*Client, error) {
	// Create OpenID4VP client with custom TTL settings
	openid4vpClient, err := openid4vp.New(ctx, &openid4vp.Config{
		EphemeralKeyTTL:  10 * time.Minute,
		RequestObjectTTL: 5 * time.Minute,
	})
	if err != nil {
		return nil, err
	}

	c := &Client{
		cfg:          cfg,
		db:           db,
		log:          log.New("apiv1"),
		notify:       notify,
		openid4vp:    openid4vpClient,
		tracer:       tracer,
		cacheService: cacheService,
		jwksResolver: trust.NewJWKSKeyResolver(trust.JWKSResolverConfig{
			HTTPClient:          &http.Client{Timeout: 30 * time.Second},
			ParseJWKToPublicKey: jose.ParseJWKToPublicKey,
		}),
	}

	// Load PKI signing key and chain for request object signing and OIDC
	c.pkiSigner, c.pkiSigningCert, c.pkiSignerChain, err = pki.LoadSigner(c.cfg.Verifier.KeyConfig)
	if err != nil {
		c.log.Info("PKI signing key not loaded", "error", err)
	}

	// Load OAuth2 metadata from configuration (unsigned, will be signed on-demand in handler)
	c.oauth2Metadata = c.cfg.Verifier.Inbound.OpenID4VP.GenerateMetadata(ctx, c.cfg.Verifier.PublicURL)

	// Load presentation request templates if configured
	if err := c.loadPresentationTemplates(ctx); err != nil {
		return nil, fmt.Errorf("failed to load presentation request templates: %w", err)
	}

	// Initialize claims extractor
	c.claimsExtractor = openid4vp.NewClaimsExtractor()

	// Use full Attributes (including nested object/array claims) so the UI
	// can render them as a tree and let users select individual sub-fields.
	for _, credentialInfo := range cfg.Common.CredentialMetadata {
		if vctm := credentialInfo.GetVCTM(); vctm != nil {
			credentialInfo.Attributes = vctm.Attributes()
		}
	}

	c.trustService = &openid4vp.TrustService{}

	// Initialize trust evaluator from config
	// If PDPURL is configured, uses AuthZEN PDP for trust decisions ("default deny" mode)
	// If PDPURL is empty/nil, uses AllowAllEvaluator ("allow all" mode)
	pdpURL := cfg.Verifier.Trust.PDPURL
	c.trustEvaluator = trust.NewTrustEvaluatorFromConfig(pdpURL)
	if pdpURL == "" {
		c.log.Warn("Trust evaluation is DISABLED - no pdp_url configured. All credential issuers will be trusted.")
	} else {
		c.log.Info("Trust evaluator initialized", "mode", "authzen", "pdp_url", pdpURL)
	}

	c.jwtTrustVerifier = trust.NewJWTTrustVerifier(trust.JWTTrustVerifierConfig{
		TrustEvaluator:             c.trustEvaluator,
		JWKSResolver:               c.jwksResolver,
		AllowedSignatureAlgorithms: cfg.Verifier.Trust.AllowedSignatureAlgorithms,
		ParseX5C:                   func(x5cRaw any) ([]*x509.Certificate, error) { return jose.ParseX5CHeader(x5cRaw) },
		ParseJWK:                   jose.ParseJWKToPublicKey,
		Log:                        c.log,
	})

	c.log.Info("Started")

	return c, nil
}

// loadPresentationTemplates loads presentation request templates from configured directory
func (c *Client) loadPresentationTemplates(ctx context.Context) error {
	// Check if templates directory is configured
	templatesDir := c.cfg.Verifier.Inbound.OpenID4VP.GetPresentationRequestsDir()
	if templatesDir == "" {
		c.log.Info("Presentation requests directory not configured, using credential config scope mapping")
		return nil
	}

	// Load templates from directory
	config, err := configuration.LoadPresentationRequests(ctx, templatesDir)
	if err != nil {
		return fmt.Errorf("loading templates from %s: %w", templatesDir, err)
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

// generateSubjectIdentifier creates a subject identifier for the user
// This can be either public (same across all RPs) or pairwise (different per RP)
func (c *Client) generateSubjectIdentifier(walletID string, clientID string) string {
	subjectType := c.cfg.Verifier.Outbound.OIDCProvider.SubjectType

	switch subjectType {
	case "pairwise":
		hash := sha256.New()
		hash.Write([]byte(walletID))
		hash.Write([]byte(clientID))
		hash.Write([]byte(c.cfg.Verifier.Outbound.OIDCProvider.SubjectSalt))
		return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
	default:
		hash := sha256.New()
		hash.Write([]byte(walletID))
		hash.Write([]byte(c.cfg.Verifier.Outbound.OIDCProvider.SubjectSalt))
		return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
	}
}

// containsOIDC checks if a slice contains a specific string value (for OIDC validations)
func (c *Client) containsOIDC(slice []string, value string) bool {
	return slices.Contains(slice, value)
}

// verifyPlaintextSecret performs constant-time comparison of plaintext secrets
func verifyPlaintextSecret(provided, stored string) bool {
	return subtle.ConstantTimeCompare([]byte(provided), []byte(stored)) == 1
}

// getClientByID looks up a client by ID, checking both database and static configuration.
// Returns the client and a boolean indicating if it's a static client (plaintext secret).
func (c *Client) getClientByID(ctx context.Context, clientID string) (*db.Client, bool, error) {
	// First, try to find the client in the database (dynamically registered clients)
	client, err := c.db.Clients.GetByClientID(ctx, clientID)
	if err != nil {
		return nil, false, err
	}
	if client != nil {
		return client, false, nil
	}

	// If not found in database, check static clients from configuration
	if c.cfg.Verifier.Outbound.OIDCProvider != nil {
		for _, staticClient := range c.cfg.Verifier.Outbound.OIDCProvider.StaticClients {
			if staticClient.ClientID == clientID {
				// Determine allowed scopes: empty means all scopes allowed
				allowedScopes := staticClient.AllowedScopes
				if len(allowedScopes) == 0 {
					// Default to common OIDC scopes when not specified
					allowedScopes = []string{"openid", "profile", "email", "address", "phone"}
				}

				// Convert static client config to db.Client for consistent handling
				return &db.Client{
					ClientID:                clientID,
					ClientSecretHash:        staticClient.ClientSecret, // Plaintext for static clients
					RedirectURIs:            staticClient.RedirectURIs,
					GrantTypes:              getOrDefault(staticClient.GrantTypes, []string{"authorization_code"}),
					ResponseTypes:           getOrDefault(staticClient.ResponseTypes, []string{"code"}),
					TokenEndpointAuthMethod: getOrDefaultString(staticClient.TokenEndpointAuthMethod, "client_secret_basic"),
					AllowedScopes:           allowedScopes,
					ClientName:              staticClient.ClientName,
				}, true, nil // true = static client (plaintext secret)
			}
		}
	}

	return nil, false, nil
}

// authenticateClient validates client credentials for the token endpoint.
// It first checks dynamically registered clients in the database, then falls back
// to static clients configured in config.yaml.
func (c *Client) authenticateClient(ctx context.Context, clientID, clientSecret string) (*db.Client, error) {
	client, isStatic, err := c.getClientByID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, ErrInvalidClient
	}

	// Public clients don't require secret verification
	if client.TokenEndpointAuthMethod == "none" {
		return client, nil
	}

	// Verify secret based on client type
	if isStatic {
		// Static clients have plaintext secrets in config
		if !verifyPlaintextSecret(clientSecret, client.ClientSecretHash) {
			return nil, ErrInvalidClient
		}
	} else {
		// DB clients have bcrypt-hashed secrets
		if bcrypt.CompareHashAndPassword([]byte(client.ClientSecretHash), []byte(clientSecret)) != nil {
			return nil, ErrInvalidClient
		}
	}

	return client, nil
}

// getOrDefault returns the slice if non-empty, otherwise returns the default value
func getOrDefault(s, defaultVal []string) []string {
	if len(s) > 0 {
		return s
	}
	return defaultVal
}

// getOrDefaultString returns the string if non-empty, otherwise returns the default value
func getOrDefaultString(s, defaultVal string) string {
	if s != "" {
		return s
	}
	return defaultVal
}

// createDCQLQuery creates a DCQL query based on the requested scopes
func (c *Client) createDCQLQuery(ctx context.Context, scopes []string) (*openid4vp.DCQL, error) {
	c.log.Info("Creating DCQL query", "scopes", scopes)

	// If we have a presentation builder with templates, use it
	if c.presentationBuilder != nil {
		dcql, err := c.presentationBuilder.BuildDCQLQuery(ctx, scopes)
		if err == nil && dcql != nil {
			c.log.Info("DCQL query built from presentation template", "credential_count", len(dcql.Credentials))
			return dcql, nil
		}
		c.log.Info("No presentation template matched, falling back to credential config")
	}

	// Fallback to building DCQL query from credential config
	return c.buildDCQLQueryFromConfig(scopes)
}

// buildDCQLQueryFromConfig builds a DCQL query using credential constructor config.
// All scopes are considered for matching, including standard OIDC scopes like "openid".
// Scopes that don't have a corresponding credential configuration are silently skipped,
// making standard OIDC scopes optional - they can match if configured, but are not required.
//
// This is the fallback path used when no presentation request templates are configured
// or when template loading fails (e.g. invalid presentation_requests_dir).
// It does NOT enumerate individual claims from the VCTM — instead it omits the Claims
// field, letting the wallet decide what to disclose. To request specific claims,
// configure presentation request templates with explicit DCQL claim paths.
func (c *Client) buildDCQLQueryFromConfig(scopes []string) (*openid4vp.DCQL, error) {
	var credentials []openid4vp.CredentialQuery

	for _, scope := range scopes {
		credInfo, ok := c.cfg.Common.CredentialMetadata[scope]
		if !ok {
			c.log.Debug("Scope has no credential config, skipping", "scope", scope)
			continue
		}

		vctID := ""
		if vctm := credInfo.GetVCTM(); vctm != nil {
			vctID = vctm.VCT
		}
		c.log.Info("Matched scope to credential", "scope", scope, "vct", vctID, "format", credInfo.Format)

		cred := openid4vp.CredentialQuery{
			ID:     scope,
			Format: credInfo.Format,
			Meta: openid4vp.MetaQuery{
				VCTValues: []string{vctID},
			},
		}

		credentials = append(credentials, cred)
	}

	if len(credentials) == 0 {
		return nil, fmt.Errorf("no valid credentials found for requested scopes")
	}

	dcql := &openid4vp.DCQL{
		Credentials: credentials,
	}

	// Normalize: remove redundant parent paths that are superseded by more
	// specific child or array-element paths (same logic used in UI queries).
	c.augmentDCQLFromVCTM(dcql)

	return dcql, nil
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
