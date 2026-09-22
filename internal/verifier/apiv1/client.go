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
	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/configuration"
	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/metric"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/pki"
	"github.com/SUNET/vc/pkg/revocation"
	"github.com/SUNET/vc/pkg/status"
	"github.com/SUNET/vc/pkg/trace"
	"github.com/SUNET/vc/pkg/trust"

	"golang.org/x/crypto/bcrypt"
)

// Client holds the public api object
type Client struct {
	cfg       *model.Cfg
	db        *db.Service
	log       *logger.Log
	tracer    *trace.Tracer
	vpMetrics *metric.VP
	notify    *notify.Service

	// Metadata
	oauth2Metadata *oauth2.AuthorizationServerMetadata

	// PKI for signing
	pkiSigner      pki.Signer
	pkiSigningCert *x509.Certificate
	pkiSignerChain []string

	// registrationCertificate is the Registrar-issued WRPRC presented to
	// wallets in verifier_info. Nil when none is configured.
	registrationCertificate *model.LoadedRegistrationCertificate

	// Clients and services
	openid4vp          *openid4vp.Client
	trustService       *openid4vp.TrustService
	trustEvaluator     trust.TrustEvaluator
	jwksResolver       *trust.JWKSKeyResolver
	jwtTrustVerifier   *trust.JWTTrustVerifier
	revocationRegistry *revocation.Registry

	// Cache
	cacheService *cache.Service

	// OIDC related
	presentationBuilder *openid4vp.PresentationBuilder
	claimsExtractor     *openid4vp.ClaimsExtractor

	statusAggregator *status.Aggregator
}

// New creates a new instance of the public api
func New(ctx context.Context, db *db.Service, notify *notify.Service, cacheService *cache.Service, cfg *model.Cfg, tracer *trace.Tracer, meter *metric.Meter, log *logger.Log) (*Client, error) {
	// Create OpenID4VP client with custom TTL settings
	openid4vpClient, err := openid4vp.New(ctx, &openid4vp.Config{
		EphemeralKeyTTL:  10 * time.Minute,
		RequestObjectTTL: 5 * time.Minute,
	})
	if err != nil {
		return nil, err
	}

	vpMetrics, err := metric.NewVP(meter.Meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create VP metrics: %w", err)
	}

	c := &Client{
		cfg:          cfg,
		db:           db,
		log:          log.New("apiv1"),
		notify:       notify,
		openid4vp:    openid4vpClient,
		tracer:       tracer,
		vpMetrics:    vpMetrics,
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

	// Fail at startup if the loaded key material cannot satisfy the
	// configured client_id_scheme, rather than emitting requests no wallet
	// can validate. See model.Verifier.ValidateClientIDMaterial.
	if err := c.cfg.Verifier.ValidateClientIDMaterial(c.pkiSigningCert, c.pkiSignerChain); err != nil {
		return nil, err
	}

	// Validate our own certificate against the EUDI WRPAC profile when the
	// deployment opts in. Offline profile conformance only - judging other
	// parties' certificates is a trust decision and belongs to the PDP.
	if err := c.cfg.Verifier.ValidateAccessCertificate(c.pkiSigningCert, time.Now()); err != nil {
		return nil, fmt.Errorf("access certificate validation failed: %w", err)
	}

	// A PublicURL host missing from the certificate's DNS SANs means wallets
	// reject every request object under x509_san_dns. That is fatal when the
	// deployment has opted into access-certificate validation; otherwise it
	// is only warned about, since an existing deployment may already be
	// running this way and a hard failure would take it down on upgrade.
	if err := c.cfg.Verifier.CheckPublicURLMatchesCertificate(c.pkiSigningCert); err != nil {
		if c.cfg.Verifier.AccessCertificate != nil && c.cfg.Verifier.AccessCertificate.Validate {
			return nil, fmt.Errorf("access certificate validation failed: %w", err)
		}
		c.log.Warn("certificate does not cover PublicURL host", "error", err)
	}

	// Load the Registrar-issued registration certificate, if this deployment
	// has one, so it can be presented to wallets in verifier_info.
	c.registrationCertificate, err = c.cfg.Verifier.LoadRegistrationCertificate(c.pkiSigningCert)
	if err != nil {
		return nil, err
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

	// Initialize revocation checker registry (ARF 3.0 §6.6.3.7)
	// The registry is extensible: pass additional Checker implementations to NewRegistry
	// to support future revocation mechanisms (e.g., OCSP, W3C Bitstring Status List).
	if cfg.Verifier.Revocation != nil && cfg.Verifier.Revocation.Enabled {
		cacheTTL := time.Duration(cfg.Verifier.Revocation.CacheTTL) * time.Second
		statusCache := pkgcache.NewMemoryCache[[]uint8](cacheTTL)
		statusListChecker, err := revocation.NewStatusListChecker(
			revocation.WithCache(statusCache),
			revocation.WithHTTPClient(&http.Client{Timeout: 30 * time.Second}),
			revocation.WithKeyResolver(jwksKeyResolverAdapter{resolver: c.jwksResolver}),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create status list checker: %w", err)
		}
		// Register checkers. To add a future mechanism (e.g., OCSP),
		// pass it alongside statusListChecker — each checker provides its own Extract().
		c.revocationRegistry = revocation.NewRegistry(statusListChecker)
		c.log.Info("Revocation checker initialized", "cache_ttl", cacheTTL, "fail_open", cfg.Verifier.Revocation.FailOpen)
	}

	c.statusAggregator = c.buildStatusAggregator()

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
		// TemplateDCQLQuery, not BuildDCQLQuery: the latter answers "no match"
		// with a generic placeholder that reads like success, which made this
		// fallback unreachable for any deployment with templates configured.
		dcql, _, matched := c.presentationBuilder.TemplateDCQLQuery(ctx, scopes)
		if matched {
			if uncovered := c.uncoveredScopes(ctx, dcql, scopes); len(uncovered) > 0 {
				return nil, fmt.Errorf("the presentation template selected for this request does not cover requested scope(s) %v; a wallet would never be asked for them", uncovered)
			}
			c.log.Info("DCQL query built from presentation template", "credential_count", len(dcql.Credentials))
			return dcql, nil
		}
		c.log.Info("No presentation template matched, falling back to credential config")
	}

	// Fallback to building DCQL query from credential config
	return c.buildDCQLQueryFromConfig(scopes)
}

// ScopeQueryIDs pairs each requested scope with the id of the DCQL credential
// query that stands for it, for the pairs where the two differ. It fills
// cache.AuthorizationContext.ScopeQueryIDs.
//
// Pairing is by constraint, not by name: a template names its queries whatever
// its author chose ("eudi_pid" for scope "pid"), so a query stands for a scope
// when it carries that scope's doctype or its vct. Queries
// built from credential_metadata are keyed by the scope already.
//
// W3C scopes are skipped: credential_metadata carries no type list for them
// yet, so a template query cannot be recognised as theirs. They keep the
// scope-keyed lookup.
func (c *Client) ScopeQueryIDs(ctx context.Context, dcql *openid4vp.DCQL, scopes []string) map[string]string {
	resolved := c.resolveScopeQueries(ctx, dcql, scopes)

	// Only the differing pairs are persisted: a scope answered by a query of
	// its own name needs no mapping, and an absent entry means the direct
	// lookup was already right.
	pairs := make(map[string]string, len(resolved))
	for scope, queryID := range resolved {
		if queryID != scope {
			pairs[scope] = queryID
		}
	}
	if len(pairs) == 0 {
		return nil
	}
	return pairs
}

// resolveScopeQueries works out which credential query answers each requested
// scope, and drops any pairing that turns out to be contested.
//
// Uniqueness must hold in both directions. queryIDForConstraint refuses a scope
// matching several queries; here the inverse - several scopes landing on one,
// as aliases sharing a vct do - which would resolve that single VP token once
// per scope, applying each scope's validations to the other's credential.
//
// Identity pairings are tracked for that, though not persisted: a template
// query may be NAMED after a configured scope, so a query "pid" would look
// direct while an alias mapped onto it and the collision went unnoticed.
//
// A contested query cannot be attributed, so both pairings go and those scopes
// fall back to their own key, where uncoveredScopes rejects the request before
// a wallet is involved.
func (c *Client) resolveScopeQueries(ctx context.Context, dcql *openid4vp.DCQL, scopes []string) map[string]string {
	if dcql == nil || c.cfg.Common == nil {
		return nil
	}

	// Which template answered, recomputed rather than carried: selection is a
	// pure function of the requested scopes, and stashing it on the Client
	// would be per-request state on an object every request shares.
	var templateScopes []string
	if c.presentationBuilder != nil {
		_, templateScopes, _ = c.presentationBuilder.TemplateDCQLQuery(ctx, scopes)
	}

	resolved := make(map[string]string, len(scopes))
	claimants := make(map[string][]string, len(scopes))
	for _, scope := range scopes {
		queryID, found := c.queryIDForScope(dcql, scope, templateScopes)
		if !found {
			continue
		}
		resolved[scope] = queryID
		claimants[queryID] = append(claimants[queryID], scope)
	}

	for queryID, scopesClaiming := range claimants {
		if len(scopesClaiming) < 2 {
			continue
		}
		c.log.Error(nil, "not pairing scopes with a shared DCQL query: cannot tell which one it answers",
			"query_id", queryID, "scopes", scopesClaiming)
		for _, scope := range scopesClaiming {
			delete(resolved, scope)
		}
	}
	return resolved
}

// queryIDForScope finds the credential query that answers one requested scope.
//
// A configured scope is matched by its own constraint, which is exact. An
// unconfigured one is matched only when the template declares it AND produced
// exactly one query: half the shipped templates are selected by a scope that is
// not a credential_metadata key (eudi_pid_full on "pid_full", the credential
// configured as "pid"), so skipping those left exactly those templates broken -
// but a template records no mapping from its oidc_scopes to its queries, so
// with several there is nothing to choose on.
func (c *Client) queryIDForScope(dcql *openid4vp.DCQL, scope string, templateScopes []string) (string, bool) {
	if constructor, configured := c.cfg.Common.CredentialMetadata[scope]; configured {
		meta, ok := constructor.DCQLMetaQuery()
		if !ok {
			return "", false
		}
		return queryIDForConstraint(dcql, meta)
	}

	// Never an ordinary OIDC scope: eudi_pid_basic is selected by "pid profile",
	// and a mapped scope counts as a credential scope (credentialScopes), so
	// mapping "profile" would resolve and process the one credential twice -
	// duplicated in scopeCredentials and the cache, with validations,
	// revocation and combined-binding applied over it again.
	if openid4vp.StandardOIDCScopes[scope] {
		return "", false
	}

	// And only a scope the selected template actually declares. A request can
	// name scopes the template says nothing about - "pid something_else" still
	// selects the PID template - and mapping those would key the same
	// credential under a scope the template never claimed. The template's
	// oidc_scopes are the only record of which scopes its queries answer.
	if !slices.Contains(templateScopes, scope) {
		return "", false
	}

	if len(dcql.Credentials) == 1 {
		return dcql.Credentials[0].ID, true
	}
	return "", false
}

// queryIDForConstraint finds the credential query in dcql that carries meta's
// constraint - the same doctype, the same vct, or the same W3C type
// alternative.
//
// Exactly one match, or none. Two scopes can be aliases for one credential
// type, backed by the same VCTM and so carrying the same vct, in which case an
// overlap does not say which query answers this scope. Taking the first would
// key the lookup to the wrong query; an ambiguous scope is left unmapped and
// falls back to its own key.
//
// The type_values arm matches nothing until credential_metadata carries a W3C
// type list.
func queryIDForConstraint(dcql *openid4vp.DCQL, meta openid4vp.MetaQuery) (string, bool) {
	var found string
	for _, cred := range dcql.Credentials {
		var matches bool
		switch {
		case meta.DoctypeValue != "":
			matches = cred.Meta.DoctypeValue == meta.DoctypeValue
		case len(meta.VCTValues) > 0:
			matches = slices.ContainsFunc(cred.Meta.VCTValues, func(v string) bool {
				return slices.Contains(meta.VCTValues, v)
			})
		case len(meta.TypeValues) > 0:
			matches = slices.ContainsFunc(cred.Meta.TypeValues, func(t []string) bool {
				return slices.ContainsFunc(meta.TypeValues, func(want []string) bool {
					return slices.Equal(t, want)
				})
			})
		}
		if !matches {
			continue
		}
		if found != "" {
			return "", false
		}
		found = cred.ID
	}
	return found, found != ""
}

// uncoveredScopes returns the requested scopes the built query cannot answer:
// configured, expressible, and yet with no query to resolve through. Such a
// scope stays in authCtx.Scopes, where direct-post requires a VP token for it -
// so the flow fails only after the user has presented a credential they were
// never asked for. A template covering some scopes and not others does this.
//
// Coverage comes from resolveScopeQueries so this and the mapping direct-post
// uses cannot disagree: a contested query leaves both scopes unanswered, and a
// query merely named after a scope does not count as covering it.
//
// W3C scopes are not reported - a template may legitimately cover one with
// meta.type_values and there is no way to tell yet.
func (c *Client) uncoveredScopes(ctx context.Context, dcql *openid4vp.DCQL, scopes []string) []string {
	if dcql == nil || c.cfg.Common == nil {
		return nil
	}
	resolved := c.resolveScopeQueries(ctx, dcql, scopes)

	var uncovered []string
	for _, scope := range scopes {
		constructor, configured := c.cfg.Common.CredentialMetadata[scope]
		if !configured {
			continue
		}
		if _, ok := constructor.DCQLMetaQuery(); !ok {
			continue
		}
		if _, answered := resolved[scope]; !answered {
			uncovered = append(uncovered, scope)
		}
	}
	return uncovered
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

		// By FORMAT (OpenID4VP 1.0 6.4.1). Emitting vct_values unconditionally
		// sent an mso_mdoc scope out as {"vct_values": [""]}, which no wallet
		// can match since no mdoc carries a vct.
		meta, ok := credInfo.DCQLMetaQuery()
		if !ok {
			// An error, not a skip: dropping the scope leaves it in the
			// request, where direct-post requires a VP token for it, so the
			// flow fails only after the user has presented. GetFormatForScope,
			// not credInfo.Format - the map can hold a nil value.
			return nil, fmt.Errorf("scope %q is configured with format %q, for which no DCQL meta constraint can be built", scope, c.cfg.GetFormatForScope(scope))
		}
		c.log.Info("Matched scope to credential", "scope", scope, "vct_values", meta.VCTValues, "doctype_value", meta.DoctypeValue, "format", credInfo.Format)

		cred := openid4vp.CredentialQuery{
			ID:     scope,
			Format: credInfo.Format,
			Meta:   meta,
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

// jwksKeyResolverAdapter adapts trust.JWKSKeyResolver to revocation.KeyResolver.
type jwksKeyResolverAdapter struct {
	resolver *trust.JWKSKeyResolver
}

func (a jwksKeyResolverAdapter) ResolveKey(ctx context.Context, issuer string, keyID string) (any, error) {
	key, _, err := a.resolver.ResolveKeyByKID(ctx, issuer, keyID)
	return key, err
}
