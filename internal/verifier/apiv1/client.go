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

	// If we have a presentation builder with templates, use it
	if c.presentationBuilder != nil {
		// TemplateDCQLQuery, not BuildDCQLQuery: the latter answers "no
		// template matched" with a generic placeholder that constrains nothing
		// and hardcodes one format, which reads exactly like success. This
		// branch used to accept it, so the fallback below was unreachable for
		// every deployment with presentation_requests configured - a
		// configured mso_mdoc scope with no template of its own got an
		// unconstrained vc+sd-jwt query instead of its doctype.
		dcql, _, matched := c.presentationBuilder.TemplateDCQLQuery(ctx, scopes)
		if matched {
			// Templates take priority over buildDCQLQueryFromConfig, so
			// without this every SUNET/vc#673 fix below would be unreachable
			// for the deployment shape that actually ships: each template in
			// presentation_requests/ names ONE vct, so a template-built query
			// still asked for a single identifier and still missed the wallets
			// matching the other one.
			c.augmentVCTValuesFromConfig(dcql, scopes)
			if uncovered := c.uncoveredScopes(ctx, dcql, scopes); len(uncovered) > 0 {
				return nil, fmt.Errorf("the presentation template selected for this request does not cover requested scope(s) %v; a wallet would never be asked for them", uncovered)
			}
			c.log.Info("DCQL query built from presentation template", "credential_count", len(dcql.Credentials))
			return dcql, nil
		}
		c.log.Info("No presentation template matched, falling back to credential config", "scopes", scopes)
	}

	// Fallback to building DCQL query from credential config
	return c.buildDCQLQueryFromConfig(scopes)
}

// ScopeQueryIDs pairs each requested scope with the id of the DCQL credential
// query that stands for it, for the pairs where the two differ. The result is
// what cache.AuthorizationContext.ScopeQueryIDs carries; see that field for why
// it is needed at all.
//
// Pairing is by CONSTRAINT, since a template names its queries whatever its
// author chose ("eudi_pid" for scope "pid"): a query stands for a scope when it
// carries that scope's doctype, or one of its vct identifiers. Queries built
// from credential_metadata are keyed by the scope already and produce no entry.
//
// A requested scope that configures no credential is handled too - see
// queryIDForScope, since half the shipped templates are selected by one.
//
// A scope whose constraint this repo cannot express - a W3C VC one, see
// model.CredentialMetadata.DCQLMetaQuery - is skipped rather than guessed at:
// a template may well cover it with meta.type_values, but nothing in
// credential_metadata says which types are its, so there is no honest way to
// recognise the query. Those scopes keep today's scope-keyed lookup until
// SUNET/vc#680 gives them a constraint to match on.
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
// scope, including the scopes answered by a query of their own name, and drops
// any pairing that turns out to be contested.
//
// One query answers one scope, and uniqueness has to hold in both directions.
// queryIDForConstraint already refuses a scope matching several queries. Here
// the inverse: several scopes can land on one query - aliases sharing a
// credential's vct - and keeping those would have VerificationDirectPost
// resolve that single VP token once per scope, caching it twice and applying
// each scope's validations to the other's credential.
//
// Identity pairings are tracked for that purpose even though they are not
// persisted, because a template query is free to be NAMED after a configured
// scope: with a query called "pid" and an alias sharing its constraint, "pid"
// would look direct while the alias mapped onto it, and the collision would go
// unnoticed.
//
// Nothing here can say which scope a contested query was meant for, so both
// pairings go and those scopes fall back to their own key - where they fail
// loudly, and where uncoveredScopes sees them as unanswered and rejects the
// request before a wallet is ever involved.
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
// A configured scope is matched by its own constraint, which is exact.
//
// An UNCONFIGURED scope is matched to the query only when the request produced
// exactly one. That case is not an oddity: half the shipped templates are
// selected by a scope that is not a credential_metadata key at all -
// eudi_pid_full triggers on "pid_full" while the credential is configured as
// "pid", and the eduID full/age templates do the same. Such a scope has no
// constraint of its own to match on, yet it is what lands in authCtx.Scopes and
// what the response is looked up by, so skipping it left exactly those
// templates as broken as before.
//
// Even then, only a scope the selected template declares, and only when the
// request produced one query: a template's queries carry no record of which of
// its oidc_scopes each answers, so with several there is nothing to choose on
// and the scope is left unmapped rather than guessed at.
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
// constraint - the same doctype, one of the same vct identifiers, or the same
// W3C type alternative.
//
// Exactly one match, or none. Two configured scopes can share a credential's
// embedded vct while resolving to different type-metadata URLs - aliases for
// one type - so with several queries in the request an overlap on the shared
// URN does not say which query answers this scope. Taking the first would key
// the response lookup to the wrong query and lose the wallet's answer, which is
// the failure this whole change exists to remove. An ambiguous scope is left
// unmapped and falls back to its own key.
//
// The type_values arm matches nothing today, because DCQLMetaQuery has no W3C
// constraint to return yet. It is here so this pairs correctly the moment
// SUNET/vc#680 gives those scopes a type list rather than silently leaving W3C
// requests unmapped.
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

// uncoveredScopes returns the requested scopes the built query cannot actually
// answer: configured, with a constraint this repo can express, and yet with no
// query of their own to be resolved through.
//
// Such a scope is a request the verifier cannot fulfil. It stays in
// authCtx.Scopes, VerificationDirectPost requires a VP token for every entry
// there, and the wallet was never asked for this one - so the flow fails only
// after the user has completed a presentation, naming a credential they were
// never prompted for. A template covering some of a request's scopes and not
// others is how that happens.
//
// Coverage is decided by resolveScopeQueries, deliberately, so this and the
// mapping direct-post later resolves through cannot disagree. Two things follow
// from sharing it. A contested query - two aliases sharing a vct against a
// template with one credential - leaves both scopes unanswered here, so the
// request is refused before a wallet is involved rather than failing after the
// presentation. And a scope is answered only when a query's CONSTRAINT matches
// it: a template query merely NAMED after a configured scope, while
// constrained for some other type, no longer passes as covering it and then
// resolves that scope's token under the wrong validations.
//
// Scopes whose constraint cannot be expressed are not reported: a template may
// legitimately cover a W3C scope with meta.type_values, and there is no way to
// tell yet (SUNET/vc#680). Rejecting them here would break a working
// deployment, which is why an earlier, blunter version of this check was
// reverted.
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

// augmentVCTValuesFromConfig completes a template-built query with the other
// identifiers a wallet might match the same credential type by, without
// discarding what the template author wrote.
//
// A template names one vct per credential (see presentation_requests/*.yaml),
// but deployed wallets disagree about which identifier names a credential type
// - see model.CredentialMetadata.VCTQueryValues. meta.vct_values is an
// acceptable-value list, so the operator's value keeps first position and the
// rest are appended.
//
// Queries with no vct_values are left alone: an mdoc query is constrained by
// doctype_value, and a query with no type constraint is not one to guess at.
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

// identifiersForQuery works out which credential configuration a template query
// refers to, since a template's credential id is a query name ("eudi_pid") and
// need not be a configured scope ("pid"). The query is paired with the scope
// whose identifiers it already names - the relationship that makes completing
// it from that scope correct - and matched returns those scopes, identifiers
// their union.
//
// Two steps, because the safe answer and the useful answer are not always the
// same one:
//
//   - A REQUESTED scope owning one of the identifiers wins. The caller named
//     it, so completing from it cannot exceed what was asked for.
//   - Otherwise the identifier's SOLE owner among all configured scopes is
//     used. Half the shipped templates need this: eudi_pid_full triggers on
//     OIDC scope "pid_full" while the credential is configured as "pid", and
//     the eduID full/age templates do the same, so a requested-scope-only rule
//     left exactly the templates this fix exists for un-augmented.
//
// Sole ownership is what makes that fallback safe. ResolveVCTUrls derives
// VCTURL per scope, so aliases backed by one VCTM resolve to different
// type-metadata URLs; with several owners there is nothing to tell which the
// template meant, and guessing would widen the query to accept a credential
// configuration nobody asked for. Ambiguity therefore augments nothing.
//
// Empty results are normal: a template may name a credential type this verifier
// configures no scope for.
func (c *Client) identifiersForQuery(values, scopes []string) (matched, identifiers []string) {
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

	for _, scope := range owners {
		identifiers = appendMissing(identifiers, c.vctValuesFor(scope))
	}
	return owners, identifiers
}

// scopesOwningAny returns, in sorted order, every configured scope whose own
// identifiers include one of values.
//
// Ownership is judged by DCQLMetaQuery's vct_values, not by VCTQueryValues:
// the latter only withholds identifiers for mdoc, so a W3C scope carrying a
// VCTM - which credential_metadata permits, and this repo's own fixtures do -
// would be counted as an owner and have its type-metadata URL appended to an
// SD-JWT query naming the same type. That would widen the query with an
// identifier belonging to a format this package says has no vct constraint at
// all. Only scopes whose own DCQL constraint IS a vct_values list can
// contribute to one.
func (c *Client) scopesOwningAny(values []string) []string {
	var owners []string
	for _, scope := range slices.Sorted(maps.Keys(c.cfg.Common.CredentialMetadata)) {
		if slices.ContainsFunc(c.vctValuesFor(scope), func(id string) bool { return slices.Contains(values, id) }) {
			owners = append(owners, scope)
		}
	}
	return owners
}

// vctValuesFor returns the scope's identifiers when its DCQL constraint is a
// vct_values list, and nothing otherwise.
func (c *Client) vctValuesFor(scope string) []string {
	meta, ok := c.cfg.Common.CredentialMetadata[scope].DCQLMetaQuery()
	if !ok {
		return nil
	}
	return meta.VCTValues
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
