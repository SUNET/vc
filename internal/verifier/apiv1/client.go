package apiv1

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"maps"
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

	// Before either builder: refuse a request naming a configured credential
	// this verifier cannot ask for. Whichever path builds the query, the
	// request's full scope list is what handler_oidc.go persists as
	// authCtx.Scopes, and VerificationDirectPost requires a VP token for every
	// entry - so a query that quietly covers only some of them fails with
	// "VP token not found for scope" after the user has completed a
	// presentation, naming a scope they were never asked for.
	//
	// The template path needs this as much as the fallback does, and used to
	// lack it: a template selected for "pid" returns a PID-only query while a
	// second configured scope in the same request goes unmentioned.
	if err := c.validateRequestedScopes(scopes); err != nil {
		return nil, err
	}

	// If we have a presentation builder with templates, use it
	if c.presentationBuilder != nil {
		dcql, err := c.presentationBuilder.BuildDCQLQuery(ctx, scopes)
		if err == nil && dcql != nil {
			// Templates take priority over buildDCQLQueryFromConfig, so
			// without this every SUNET/vc#673 fix below would be unreachable
			// for the deployment shape that actually ships: each template in
			// presentation_requests/ names ONE vct, so a template-built query
			// still asked for a single identifier and still missed the wallets
			// matching the other one.
			c.augmentVCTValuesFromConfig(dcql, scopes)
			c.log.Info("DCQL query built from presentation template", "credential_count", len(dcql.Credentials))
			return dcql, nil
		}
		c.log.Info("No presentation template matched, falling back to credential config")
	}

	// Fallback to building DCQL query from credential config
	return c.buildDCQLQueryFromConfig(scopes)
}

// validateRequestedScopes rejects a request naming a configured credential
// whose DCQL constraint cannot be built.
//
// Only CONFIGURED scopes are checked: a requested scope with no
// credential_metadata entry is an ordinary OIDC scope like "profile", which no
// query should mention and whose absence from one is not an error.
func (c *Client) validateRequestedScopes(scopes []string) error {
	if c.cfg.Common == nil {
		return nil
	}
	for _, scope := range scopes {
		constructor, ok := c.cfg.Common.CredentialMetadata[scope]
		if !ok {
			continue
		}
		if _, usable := constructor.DCQLMetaQuery(); !usable {
			return fmt.Errorf("scope %q is configured with format %q, for which no DCQL meta constraint can be built", scope, c.cfg.GetFormatForScope(scope))
		}
	}
	return nil
}

// augmentVCTValuesFromConfig adds the credential type identifiers a wallet
// might match on to a template-built query, without discarding what the
// operator wrote.
//
// A template states one vct per credential (see presentation_requests/*.yaml),
// but deployed wallets disagree about which identifier names a credential type
// - see model.CredentialMetadata.VCTQueryValues. meta.vct_values is an
// acceptable-value list, so the operator's value is kept, in first position,
// and the scope's other identifier is appended.
//
// Matching is by value, not by credential-query id: a template's id is a query
// name ("eudi_pid") and need not be a configured scope ("pid"). A query is
// therefore paired with the scope whose identifiers it already mentions, which
// is exactly the relationship that makes appending the rest correct.
//
// Which credential configuration a query belongs to is settled in two steps,
// because the safe answer and the useful answer are not always the same one.
//
// A requested scope that owns one of the query's identifiers wins: the caller
// named it, so completing from it cannot exceed what was asked for. That covers
// templates whose oidc_scopes are credential scopes, like eudi_pid_basic ("pid").
//
// Otherwise the identifier's sole owner among all configured scopes is used.
// Half the shipped templates need this: eudi_pid_full triggers on the OIDC
// scope "pid_full" while the credential is configured as "pid", and the eduID
// full/age templates do the same, so a requested-scope-only rule silently left
// them un-augmented - the bug this fix exists to remove, still in place for
// those templates.
//
// Sole owner is the condition that makes it safe. ResolveVCTUrls derives VCTURL
// per scope, so aliases backed by one VCTM resolve to different type-metadata
// URLs; if several configured scopes carry the identifier there is no way to
// tell which one the template meant, and guessing would widen the query to
// accept a credential configuration nobody asked for. Ambiguity therefore
// augments nothing and says so.
//
// Queries with no vct_values are left alone: mdoc queries are constrained by
// doctype_value, and a query with no type constraint at all is not something to
// guess at.
func (c *Client) augmentVCTValuesFromConfig(dcql *openid4vp.DCQL, scopes []string) {
	if dcql == nil {
		return
	}
	for i := range dcql.Credentials {
		cred := &dcql.Credentials[i]
		if len(cred.Meta.VCTValues) == 0 {
			continue
		}
		matched, identifiers := c.identifiersForQuery(cred.Meta.VCTValues, scopes)
		if len(matched) == 0 {
			continue
		}
		cred.Meta.VCTValues = appendMissing(cred.Meta.VCTValues, identifiers)
		c.log.Debug("Augmented template vct_values from credential config",
			"credential_id", cred.ID, "scopes", matched, "vct_values", cred.Meta.VCTValues)
	}
}

// identifiersForQuery resolves the credential configuration a template query
// refers to, and returns the scopes it matched with the union of their
// identifiers. See augmentVCTValuesFromConfig for why it prefers a requested
// scope and falls back to a sole owner.
//
// An empty result is the normal case for a template naming a credential type
// this verifier configures no scope for, and for an ambiguous one.
func (c *Client) identifiersForQuery(values []string, scopes []string) ([]string, []string) {
	if c.cfg.Common == nil {
		return nil, nil
	}

	owners := c.scopesOwningAny(values)
	switch {
	case len(owners) == 0:
		return nil, nil
	case len(owners) == 1:
		// Sole owner: unambiguous whether or not it was requested.
	default:
		// Several configured scopes carry the identifier. Prefer the ones the
		// caller actually asked for; without that there is nothing to pick on.
		requested := make([]string, 0, len(owners))
		for _, scope := range owners {
			if slices.Contains(scopes, scope) {
				requested = append(requested, scope)
			}
		}
		if len(requested) == 0 {
			c.log.Info("Not augmenting template vct_values: identifier is shared by several configured scopes and none was requested",
				"scopes", owners, "vct_values", values)
			return nil, nil
		}
		owners = requested
	}

	var identifiers []string
	for _, scope := range owners {
		identifiers = appendMissing(identifiers, c.cfg.Common.CredentialMetadata[scope].VCTQueryValues())
	}
	return owners, identifiers
}

// scopesOwningAny returns, in sorted order, every configured scope whose own
// identifiers include one of values.
func (c *Client) scopesOwningAny(values []string) []string {
	var owners []string
	for _, scope := range slices.Sorted(maps.Keys(c.cfg.Common.CredentialMetadata)) {
		identifiers := c.cfg.Common.CredentialMetadata[scope].VCTQueryValues()
		if slices.ContainsFunc(identifiers, func(id string) bool { return slices.Contains(values, id) }) {
			owners = append(owners, scope)
		}
	}
	return owners
}

// appendMissing appends each of extra not already in base, preserving base's
// order - the operator's own value keeps first position.
func appendMissing(base, extra []string) []string {
	for _, v := range extra {
		if !slices.Contains(base, v) {
			base = append(base, v)
		}
	}
	return base
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

		// The meta constraint follows the credential's FORMAT (OpenID4VP 1.0
		// 6.4.1): doctype_value for mdoc, vct_values - carrying BOTH
		// identifiers, the SUNET/vc#673 fix - for sd-jwt. This used to emit
		// vct_values unconditionally, so an mso_mdoc scope, which has an MDDL
		// and no VCTM at all, went out as {"vct_values": [""]} with no
		// doctype_value: a query no wallet can match and one
		// ValidateCredentialQuery rejects.
		meta, ok := credInfo.DCQLMetaQuery()
		if !ok {
			// A CONFIGURED scope that cannot be expressed is an error, not a
			// skip. Dropping it from the query would still leave it in the
			// OIDC request's scope list, which handler_oidc.go stores as
			// authCtx.Scopes; VerificationDirectPost iterates that list and
			// requires a VP token per entry, so the flow would fail with
			// "VP token not found for scope" only after the user had gone all
			// the way through a presentation. Failing here names what is
			// actually wrong, before anything reaches a wallet.
			//
			// Deliberately narrower than the lookup miss above, which stays a
			// silent skip: an unconfigured scope is an ordinary OIDC scope
			// like "profile", not a credential the caller asked for.
			//
			// GetFormatForScope, not credInfo.Format: the map can hold a nil
			// value for a present key (a credential_metadata entry written
			// with no fields), which is distinct from the key being absent and
			// survives the lookup above. DCQLMetaQuery is nil-safe and lands
			// here; a direct field read would panic while reporting the very
			// config error it is reporting.
			return nil, fmt.Errorf("scope %q is configured with format %q, for which no DCQL meta constraint can be built", scope, c.cfg.GetFormatForScope(scope))
		}
		// Past this point credInfo is non-nil: a nil one cannot produce ok.
		c.log.Info("Matched scope to credential", "scope", scope, "vct_values", meta.VCTValues, "doctype_value", meta.DoctypeValue, "format", credInfo.Format)

		credentials = append(credentials, openid4vp.CredentialQuery{
			ID:     scope,
			Format: credInfo.Format,
			Meta:   meta,
		})
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
