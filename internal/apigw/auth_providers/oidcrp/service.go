package oidcrp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"text/template"
	"time"

	"github.com/SUNET/vc/internal/apigw/db"
	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/crypto"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	pkgoauth2 "github.com/SUNET/vc/pkg/oauth2"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	oidcRPRetryBase = 5 * time.Second
	oidcRPRetryMax  = 2 * time.Minute

	// clientSecretRenewBefore is how long before expiry a dynamically
	// registered client secret is replaced. Renewing exactly at expiry would
	// race the OP's own clock, and a token exchange started just inside the
	// window has to finish on the old secret.
	clientSecretRenewBefore = 5 * time.Minute

	// clientRenewLockTTL bounds how long the cross-replica renewal lock is
	// held. It only needs to cover one registration round-trip plus the time
	// a losing replica takes to read the winner's result back; the key is the
	// expiring client id, so a lock lingering past that is harmless because
	// renewal has already moved every replica to the new client.
	clientRenewLockTTL = 2 * time.Minute
)

// Service provides OIDC Relying Party functionality
type Service struct {
	cfg          *model.OIDCRP
	provider     *oidc.Provider
	creds        *credentialSet
	sessionCache pkgcache.Cache[*Session]
	dbService    *db.Service
	httpClient   *http.Client
	log          *logger.Log

	// renewalLock serialises re-registration across HA replicas. Nil means
	// in-process single-flight only (s.mu), which is all a single replica
	// needs; the shared lock is what stops N replicas each registering a new
	// client when the same secret ages out.
	renewalLock pkgcache.Locker

	// Lazy-init state
	mu           sync.RWMutex
	ready        bool
	retryAfter   time.Time
	retryBackoff time.Duration

	// Re-registration backoff. The credentials themselves live in creds,
	// which has its own lock because request handlers read it.
	credentialRetryAfter time.Time
	credentialBackoff    time.Duration
}

// New creates a new OIDC RP service
func New(ctx context.Context, cfg *model.OIDCRP, sessionCache pkgcache.Cache[*Session], dbService *db.Service, renewalLock pkgcache.Locker, log *logger.Log) (*Service, error) {
	if !cfg.Enable {
		log.Info("OIDC RP support disabled")
		return nil, nil
	}

	s := &Service{
		cfg:          cfg,
		sessionCache: sessionCache,
		dbService:    dbService,
		renewalLock:  renewalLock,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		log:          log.New("oidcrp"),
		// A superseded registration stays usable for as long as a flow can
		// take, which is the session lifetime.
		creds: newCredentialSet(time.Duration(cfg.SessionDuration) * time.Second),
	}

	// Attempt eager initialization; if the IdP is unreachable, defer to lazy retry.
	if err := s.initialize(ctx); err != nil {
		s.log.Error(err, "oidcrp_init_failed_will_retry", "issuer", cfg.IssuerURL)
		s.retryBackoff = oidcRPRetryBase
		s.retryAfter = time.Now().Add(s.retryBackoff)
		go s.backgroundDiscovery(ctx)
	}

	return s, nil
}

// initialize performs OIDC discovery and sets up the oauth2 config and verifier.
func (s *Service) initialize(ctx context.Context) error {
	provider, err := oidc.NewProvider(ctx, s.cfg.IssuerURL)
	if err != nil {
		return fmt.Errorf("failed to discover OIDC provider at %s: %w", s.cfg.IssuerURL, err)
	}
	s.provider = provider

	// Resolve client credentials based on registration method
	var (
		clientID              string
		clientSecret          string
		clientSecretExpiresAt int64
	)

	if s.cfg.Registration.Preconfigured != nil && s.cfg.Registration.Preconfigured.Enable {
		clientID = s.cfg.Registration.Preconfigured.ClientID
		clientSecret = s.cfg.Registration.Preconfigured.ClientSecret
	} else if s.cfg.Registration.Dynamic != nil && s.cfg.Registration.Dynamic.Enable {
		s.log.Info("Dynamic client registration enabled, attempting registration")

		// Check if we have stored credentials
		storedCreds, err := s.dbService.DynamicRegistrationColl.Get(ctx)
		if err != nil {
			s.log.Info("Failed to load dynamic registration credentials", "error", err)
		}
		if storedCreds != nil {
			s.log.Info("Using stored dynamic registration credentials", "client_id", storedCreds.ClientID)
			clientID = storedCreds.ClientID
			clientSecret = storedCreds.ClientSecret
			clientSecretExpiresAt = storedCreds.ClientSecretExpiresAt
		} else {
			// Perform dynamic registration
			regReq := s.buildRegistrationRequest()

			// Get registration endpoint from provider metadata
			var providerJSON struct {
				RegistrationEndpoint string `json:"registration_endpoint"`
			}
			if err := provider.Claims(&providerJSON); err != nil {
				return fmt.Errorf("failed to get provider metadata: %w", err)
			}

			if providerJSON.RegistrationEndpoint == "" {
				return fmt.Errorf("OIDC provider does not support dynamic client registration (no registration_endpoint in metadata)")
			}

			regResp, err := s.dynamicClientRegistration(ctx, providerJSON.RegistrationEndpoint, regReq, s.cfg.Registration.Dynamic.InitialAccessToken)
			if err != nil {
				return fmt.Errorf("dynamic client registration failed: %w", err)
			}

			clientID = regResp.ClientID
			clientSecret = regResp.ClientSecret
			clientSecretExpiresAt = regResp.ClientSecretExpiresAt

			s.log.Info("Dynamic client registration successful",
				"client_id", clientID,
				"registration_access_token_present", regResp.RegistrationAccessToken != "")

			// Persist before publishing, the same rule renewCredentials
			// follows: sessions record the client id, and a callback on
			// another HA replica resolves it through the shared store, so a
			// registration nobody can look up cannot redeem its own codes.
			// Failing here leaves the service unready and retrying, which
			// is recoverable; starting flows on an unresolvable client is
			// not.
			if err := s.dbService.DynamicRegistrationColl.Save(ctx, &db.DynamicRegistrationCredentials{
				ClientID:                regResp.ClientID,
				ClientSecret:            regResp.ClientSecret,
				RegistrationAccessToken: regResp.RegistrationAccessToken,
				RegistrationClientURI:   regResp.RegistrationClientURI,
				ClientSecretExpiresAt:   regResp.ClientSecretExpiresAt,
			}); err != nil {
				return fmt.Errorf("storing the dynamic client registration: %w", err)
			}
		}
	}

	s.applyCredentials(clientID, clientSecret, clientSecretExpiresAt)

	s.ready = true
	s.retryBackoff = 0

	s.log.Info("OIDC RP service initialized",
		"issuer", s.cfg.IssuerURL,
		"client_id", clientID,
		"redirect_uri", s.cfg.RedirectURI,
		"dynamic_registration", s.cfg.Registration.Dynamic != nil && s.cfg.Registration.Dynamic.Enable)

	return nil
}

// applyCredentials installs a client id and secret, rebuilding both the
// oauth2 config and the ID token verifier. The verifier is rebuilt and not
// just the config: it checks the `aud` claim against the client id, and a
// re-registration may return a different one.
//
// expiresAtUnix is the OP's client_secret_expires_at; 0 means never, which
// RFC 7591 §3.2.1 defines and which is also the preconfigured case.
//
// Callers hold s.mu for writing, or are in New before the service is shared.
func (s *Service) applyCredentials(clientID, clientSecret string, expiresAtUnix int64) {
	s.creds.store(s.buildCredentials(clientID, clientSecret, expiresAtUnix))
}

// buildCredentials assembles one registration. The oauth2 config and the
// verifier are built together because they have to agree: the verifier
// checks `aud` against the client id the config authenticates with.
func (s *Service) buildCredentials(clientID, clientSecret string, expiresAtUnix int64) *credentials {
	c := &credentials{
		clientID: clientID,
		verifier: s.provider.Verifier(&oidc.Config{ClientID: clientID}),
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  s.cfg.RedirectURI,
			Endpoint:     s.provider.Endpoint(),
			Scopes:       s.cfg.Scopes,
		},
	}

	if expiresAtUnix > 0 {
		c.expiresAt = time.Unix(expiresAtUnix, 0)

		// Do not renew again immediately. An OP handing out secrets that
		// live for less than the renewal lead time would otherwise never
		// produce one this service calls fresh, and every request would
		// register another client. Half the remaining lifetime is a
		// compromise between that and renewing in good time.
		if remaining := time.Until(c.expiresAt); remaining < clientSecretRenewBefore*2 {
			c.renewNotBefore = time.Now().Add(remaining / 2)
		}
	}

	return c
}

// credentialsForSession resolves the registration a flow started under.
//
// In HA the session store is shared but credentialSet is per process, so a
// callback can land on a replica that never saw the registration its flow
// began on - renewal happened on another one. Falling back to this
// replica's current client would exchange the code with the wrong client
// and fail, so the stored registration is read instead. The row is there
// to be read because pruning removes only registrations whose secret has
// expired - one that a flow can still be using never has.
func (s *Service) credentialsForSession(ctx context.Context, clientID string) (*credentials, error) {
	if c := s.creds.forClient(clientID); c != nil && (clientID == "" || c.clientID == clientID) {
		return c, nil
	}

	if clientID != "" && s.dbService != nil && s.dbService.DynamicRegistrationColl != nil {
		stored, err := s.dbService.DynamicRegistrationColl.GetByClientID(ctx, clientID)
		if err != nil {
			// Returned, not swallowed into the refusal below. A database
			// that cannot be read and a client that was never registered
			// are different situations with different fixes, and in HA the
			// first is the common one - collapsing them tells an operator
			// chasing a wave of failed callbacks to go looking for a
			// registration problem that does not exist. The caller deletes
			// the session on an exchange failure, so saying which it was
			// is the only chance anyone gets.
			s.log.Error(err, "oidcrp_session_registration_lookup_failed", "client_id", clientID)
			return nil, fmt.Errorf("looking up the client registration for %q: %w", clientID, err)
		}
		if stored != nil {
			s.log.Debug("resolved a session's client registration from the store",
				"client_id", clientID)
			c := s.buildCredentials(stored.ClientID, stored.ClientSecret, stored.ClientSecretExpiresAt)
			s.creds.retain(c)
			return c, nil
		}
	}

	// A session naming a client nobody can resolve must not fall back. Both
	// lookups above have established that the current registration is a
	// different client, so exchanging with it is guaranteed to fail - and
	// the caller deletes the session on an exchange failure, turning a
	// retryable situation into a lost flow. Say what is wrong instead.
	if clientID != "" {
		return nil, fmt.Errorf("no client registration found for %q; this flow cannot be completed", clientID)
	}

	// No client named at all: a session created before this was recorded.
	// The current registration is what the service used then.
	if c := s.creds.load(); c != nil {
		return c, nil
	}

	return nil, errors.New("OIDC RP has no client credentials")
}

// dynamicRegistrationEnabled reports whether this RP registers itself.
// cfg is immutable after New, so no lock is needed. Nil-safe down the whole
// chain: Registration is a pointer and is only required when Enable is true,
// so a preconfigured or directly-built Service reaches here with nils, and
// nothing about credential renewal applies to it.
func (s *Service) dynamicRegistrationEnabled() bool {
	return s.cfg != nil && s.cfg.Registration != nil &&
		s.cfg.Registration.Dynamic != nil && s.cfg.Registration.Dynamic.Enable
}

// ensureReady makes the service usable: discovered, and holding a client
// secret that has not run out.
//
// This is for paths that START a flow. Renewal replaces the client, so a
// path that has to finish on an existing one - ProcessCallback - calls
// ensureInitialized and resolves the session's own registration instead,
// and a path that uses no client credentials at all - GetUserInfo - calls
// ensureInitialized too.
func (s *Service) ensureReady(ctx context.Context) error {
	if err := s.ensureInitialized(ctx); err != nil {
		return err
	}
	return s.ensureCredentials(ctx)
}

// ensureCredentials re-registers before a dynamically registered client
// secret expires.
//
// Without this the secret was read once at startup and never looked at
// again, so a long-running instance kept presenting an expired secret and
// every OIDC flow failed at the token exchange with an error that said
// nothing about why - until somebody restarted the process (SUNET/vc#295).
//
// Renewal is lazy rather than a background ticker: it happens on the path
// that is about to use the credential, so there is no goroutine to own and
// an idle instance does not register clients nobody asked for.
func (s *Service) ensureCredentials(ctx context.Context) error {
	if !s.dynamicRegistrationEnabled() {
		return nil
	}

	now := time.Now()
	current := s.creds.load()
	if !current.needsRenewal(now) {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Re-check under the lock: concurrent requests all arrive here when the
	// secret ages out, and only the first should register.
	now = time.Now()
	current = s.creds.load()
	if !current.needsRenewal(now) {
		return nil
	}

	if now.Before(s.credentialRetryAfter) {
		// Back off, but do not fail a request the current secret can still
		// serve. Only once it has actually expired is refusing better than
		// trying and getting an opaque error from the OP.
		if now.Before(current.expiresAt) {
			return nil
		}
		return fmt.Errorf("OIDC client secret expired at %s and re-registration is backing off until %s",
			current.expiresAt.Format(time.RFC3339), s.credentialRetryAfter.Format(time.RFC3339))
	}

	// Cluster-wide single-flight. s.mu already collapses concurrent renewals
	// within this process; the lock extends that across HA replicas, so a
	// burst of them all noticing the same secret age out registers one new
	// client at the OP instead of one per replica. The key is the expiring
	// client id - replicas renewing the same registration contend, and the
	// loser adopts the winner's result from the shared store rather than
	// registering again.
	if s.renewalLock != nil {
		acquired, err := s.renewalLock.TryLock(ctx, "oidcrp:renew:"+current.clientID, clientRenewLockTTL)
		switch {
		case err != nil:
			// Lock backend unreachable. Renew anyway rather than refuse a
			// flow for a lock we could not take: a possible extra
			// registration is better than a failed login.
			s.log.Warn("renewal lock unavailable, renewing without cross-replica coordination",
				"error", err.Error(), "client_id", current.clientID)
		case !acquired:
			// Another replica holds the lock and is renewing this client.
			if s.adoptRenewedRegistration(ctx, current) {
				return nil
			}
			// Its result has not reached the store yet. Carry on with the
			// current secret while it is still valid; only once it has run
			// out is saying so better than presenting a dead secret.
			if now.Before(current.expiresAt) {
				return nil
			}
			return fmt.Errorf("OIDC client secret expired at %s and another replica holds the re-registration lock",
				current.expiresAt.Format(time.RFC3339))
		}
	}

	if err := s.renewCredentials(ctx); err != nil {
		s.credentialBackoff = min(max(s.credentialBackoff*2, oidcRPRetryBase), oidcRPRetryMax)
		s.credentialRetryAfter = time.Now().Add(s.credentialBackoff)
		s.log.Error(err, "oidcrp_reregistration_failed",
			"client_id", current.clientID,
			"expires_at", current.expiresAt.Format(time.RFC3339),
			"next_retry_in", s.credentialBackoff.String())

		if time.Now().Before(current.expiresAt) {
			// Still usable. Say so and carry on rather than taking the
			// service down for a secret that has not run out yet.
			return nil
		}
		return err
	}

	s.credentialBackoff = 0
	s.credentialRetryAfter = time.Time{}

	return nil
}

// renewCredentials registers a new client and installs it. Callers hold
// s.mu for writing.
//
// This registers afresh rather than rotating the existing client through
// the RFC 7592 management endpoint. vc stores the registration access token
// and client URI that would allow that, and it would avoid leaving a
// superseded registration at the OP - but RFC 7592 support is optional and
// uneven, while registration is the one thing an OP that got us here is
// known to implement. The superseded local record is deleted below; the
// one at the OP is not ours to clean up.
func (s *Service) renewCredentials(ctx context.Context) error {
	var providerJSON struct {
		RegistrationEndpoint string `json:"registration_endpoint"`
	}
	if err := s.provider.Claims(&providerJSON); err != nil {
		return fmt.Errorf("failed to read provider metadata: %w", err)
	}
	if providerJSON.RegistrationEndpoint == "" {
		return errors.New("OIDC provider does not support dynamic client registration (no registration_endpoint in metadata)")
	}

	regResp, err := s.dynamicClientRegistration(ctx, providerJSON.RegistrationEndpoint,
		s.buildRegistrationRequest(), s.cfg.Registration.Dynamic.InitialAccessToken)
	if err != nil {
		return fmt.Errorf("dynamic client re-registration failed: %w", err)
	}

	previousClientID := ""
	if current := s.creds.load(); current != nil {
		previousClientID = current.clientID
	}

	// Persist before publishing, and fail the renewal if it cannot be
	// persisted. A client this process uses but nobody can look up breaks
	// HA: the shared session records the client id, and a callback landing
	// on another replica cannot resolve credentials for it, so the code
	// cannot be redeemed at all. The caller already tolerates a renewal
	// error while the current secret is still valid, which is the case
	// where carrying on was tempting.
	if err := s.dbService.DynamicRegistrationColl.Save(ctx, &db.DynamicRegistrationCredentials{
		ClientID:                regResp.ClientID,
		ClientSecret:            regResp.ClientSecret,
		RegistrationAccessToken: regResp.RegistrationAccessToken,
		RegistrationClientURI:   regResp.RegistrationClientURI,
		ClientSecretExpiresAt:   regResp.ClientSecretExpiresAt,
	}); err != nil {
		return fmt.Errorf("storing the new client registration: %w", err)
	}

	// Remove registrations whose secret has expired. Expiry rather than
	// age: "registered long ago" says nothing about whether a registration
	// is still in use, and in HA another replica can be running on an
	// hours-old one as its current client. A secret that has expired cannot
	// be redeemed by anyone, so its row is dead to every replica. A failure
	// here is not worth refusing a working renewal over - the rows are
	// inert, and a later renewal clears them.
	if err := s.dbService.DynamicRegistrationColl.PruneExpiredRegistrations(ctx, regResp.ClientID, time.Now()); err != nil {
		s.log.Error(err, "oidcrp_expired_registrations_not_pruned", "client_id", regResp.ClientID)
	}

	s.applyCredentials(regResp.ClientID, regResp.ClientSecret, regResp.ClientSecretExpiresAt)

	s.log.Info("OIDC client re-registered before secret expiry",
		"previous_client_id", previousClientID,
		"client_id", regResp.ClientID,
		"expires_at", s.creds.load().expiresAt.Format(time.RFC3339))

	return nil
}

// adoptRenewedRegistration installs a registration another replica produced,
// when the shared store already holds one newer than current. It returns true
// if it adopted one. Callers hold s.mu for writing.
//
// This is the losing half of the cross-replica renewal lock: the replica that
// did not get to register still has to stop presenting the expiring secret, so
// it reads the newest stored registration - which the winner persists before
// it publishes - and switches to it without contacting the OP at all.
func (s *Service) adoptRenewedRegistration(ctx context.Context, current *credentials) bool {
	if s.dbService == nil || s.dbService.DynamicRegistrationColl == nil {
		return false
	}

	stored, err := s.dbService.DynamicRegistrationColl.Get(ctx)
	if err != nil || stored == nil || stored.ClientID == "" {
		return false
	}
	// The store still names the client we are trying to replace: the winner
	// has not persisted yet, so there is nothing to adopt.
	if current != nil && stored.ClientID == current.clientID {
		return false
	}

	c := s.buildCredentials(stored.ClientID, stored.ClientSecret, stored.ClientSecretExpiresAt)
	// The newest stored registration is itself due for renewal; adopting it
	// would just loop back here, so let the caller fall through instead.
	if c.needsRenewal(time.Now()) {
		return false
	}

	s.creds.store(c)
	s.log.Info("adopted a client registration renewed by another replica",
		"previous_client_id", current.clientID,
		"client_id", stored.ClientID)
	return true
}

// ensureInitialized checks if the service is initialized and retries discovery if not.
func (s *Service) ensureInitialized(ctx context.Context) error {
	s.mu.RLock()
	if s.ready {
		s.mu.RUnlock()
		return nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ready {
		return nil
	}

	if time.Now().Before(s.retryAfter) {
		return fmt.Errorf("OIDC RP not available, next retry at %s", s.retryAfter.Format(time.RFC3339))
	}

	if err := s.initialize(ctx); err != nil {
		s.retryBackoff = min(s.retryBackoff*2, oidcRPRetryMax)
		s.retryAfter = time.Now().Add(s.retryBackoff)
		s.log.Error(err, "oidcrp_retry_failed", "issuer", s.cfg.IssuerURL, "next_retry_in", s.retryBackoff.String())
		return err
	}
	return nil
}

// backgroundDiscovery retries OIDC discovery in the background with exponential
// backoff until the OP becomes reachable, then exits.
func (s *Service) backgroundDiscovery(ctx context.Context) {
	backoff := oidcRPRetryBase
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		s.mu.RLock()
		if s.ready {
			s.mu.RUnlock()
			return
		}
		s.mu.RUnlock()

		s.mu.Lock()
		if s.ready {
			s.mu.Unlock()
			return
		}
		if err := s.initialize(ctx); err != nil {
			backoff = min(backoff*2, oidcRPRetryMax)
			s.retryBackoff = backoff
			s.retryAfter = time.Now().Add(backoff)
			s.mu.Unlock()
			s.log.Info("oidcrp_background_discovery_retry", "issuer", s.cfg.IssuerURL, "next_retry_in", backoff.String())
			continue
		}
		s.mu.Unlock()
		s.log.Info("OIDC OP is now reachable", "issuer", s.cfg.IssuerURL)
		return
	}
}

// AuthRequest represents an OIDC authentication request
type AuthRequest struct {
	AuthorizationURL string
	State            string
}

// InitiateAuth initiates an OIDC authentication flow.
// oidcParams and dynamicParams are optional: when non-nil, they customize the
// authorization request (e.g., acr_values, claims parameter, extra scopes).
func (s *Service) InitiateAuth(ctx context.Context, credentialType string, oidcParams *model.OIDCRequestParams, dynamicParams map[string]string) (*AuthRequest, error) {
	if err := s.ensureReady(ctx); err != nil {
		return nil, fmt.Errorf("OIDC RP not ready: %w", err)
	}

	s.log.Debug("Initiating OIDC auth",
		"credential_type", credentialType)

	// Everything that can be rejected is resolved BEFORE a session exists.
	//
	// resolveOIDCRequestParams reads only its arguments, so an invalid
	// template, malformed claims JSON or reserved custom parameter is a
	// property of the request, not of any session. Creating the session
	// first meant a rejected request still left its state in the cache
	// until the TTL expired, and a caller retrying a misconfigured scope
	// accumulated one dead entry per attempt.
	//
	// Ordering rather than a cleanup path: nothing to forget to delete, and
	// no window in which a state exists for a request that was never sent.
	var extraOpts []oauth2.AuthCodeOption
	if oidcParams != nil {
		resolved, err := resolveOIDCRequestParams(oidcParams, dynamicParams)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve OIDC request params: %w", err)
		}
		extraOpts = resolved
	}

	// Read the registration once. It is immutable, so the authorization URL
	// built below and the client id recorded on the session describe the
	// same client even if a renewal publishes a new one meanwhile.
	creds := s.creds.load()
	if creds == nil {
		return nil, errors.New("OIDC RP has no client credentials")
	}

	// If extra scopes are configured, create a temporary config with merged scopes
	oauthCfg := creds.config
	if oidcParams != nil && len(oidcParams.ExtraScopes) > 0 {
		mergedScopes := make([]string, len(creds.config.Scopes))
		copy(mergedScopes, creds.config.Scopes)
		mergedScopes = append(mergedScopes, oidcParams.ExtraScopes...)
		oauthCfg = &oauth2.Config{
			ClientID:     creds.config.ClientID,
			ClientSecret: creds.config.ClientSecret,
			RedirectURL:  creds.config.RedirectURL,
			Endpoint:     creds.config.Endpoint,
			Scopes:       mergedScopes,
		}
	}

	// Create session with state, nonce, and PKCE verifier
	session, err := s.createSession(ctx, credentialType, creds.clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Generate PKCE code_challenge from code_verifier
	codeChallenge := pkgoauth2.CreateCodeChallenge(pkgoauth2.CodeChallengeMethodS256, session.CodeVerifier)

	// Build authorization URL with PKCE
	authOpts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("nonce", session.Nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	authOpts = append(authOpts, extraOpts...)

	authURL := oauthCfg.AuthCodeURL(session.State, authOpts...)

	s.log.Debug("OIDC authorization URL generated",
		"credential_type", credentialType,
		"state", session.State)

	return &AuthRequest{
		AuthorizationURL: authURL,
		State:            session.State,
	}, nil
}

// InitiateAuthForVCI initiates an OIDC authentication flow that is linked to
// an OpenID4VCI credential issuance session. The VCI session ID is stored in
// the OIDC session so that the callback handler can route the result back into
// the VCI pipeline.
func (s *Service) InitiateAuthForVCI(ctx context.Context, credentialType, vciSessionID string, oidcParams *model.OIDCRequestParams, dynamicParams map[string]string) (*AuthRequest, error) {
	authReq, err := s.InitiateAuth(ctx, credentialType, oidcParams, dynamicParams)
	if err != nil {
		return nil, err
	}

	// Update the OIDC session with VCI linkage
	session, err := s.getSession(ctx, authReq.State)
	if err != nil {
		return nil, fmt.Errorf("failed to update OIDC session with VCI context: %w", err)
	}

	session.VCISessionID = vciSessionID
	s.sessionCache.Set(ctx, session.ID, session)

	s.log.Info("OIDC auth initiated for VCI flow",
		"oidc_state", authReq.State,
		"vci_session_id", vciSessionID,
		"credential_type", credentialType)

	return authReq, nil
}

// reservedOIDCParams are authorization request parameters that CustomParams
// must not be allowed to set, since oauth2.AuthCodeOption values are applied
// by key (last write wins) - letting an operator-configured custom param
// collide with one of these would silently override the state/nonce/PKCE
// guarantees InitiateAuth sets before calling AuthCodeURL.
var reservedOIDCParams = map[string]bool{
	"response_type":         true,
	"client_id":             true,
	"redirect_uri":          true,
	"scope":                 true,
	"state":                 true,
	"nonce":                 true,
	"code_challenge":        true,
	"code_challenge_method": true,

	// These two have dedicated OIDCRequestParams fields, and CustomParams is
	// applied after them, so a custom param of the same name would win
	// silently - the operator would see acr_values configured and a
	// different acr_values sent.
	"acr_values": true,
	"claims":     true,
}

// resolveOIDCRequestParams resolves template variables in OIDC request params
// and returns oauth2.AuthCodeOption values to append to the authorization URL.
func resolveOIDCRequestParams(params *model.OIDCRequestParams, dynamicParams map[string]string) ([]oauth2.AuthCodeOption, error) {
	var opts []oauth2.AuthCodeOption

	if params.ACRValues != "" {
		resolved, err := resolveTemplate(params.ACRValues, dynamicParams)
		if err != nil {
			return nil, fmt.Errorf("acr_values template: %w", err)
		}
		opts = append(opts, oauth2.SetAuthURLParam("acr_values", resolved))
	}

	if params.Claims != "" {
		resolved, err := resolveJSONTemplate(params.Claims, dynamicParams)
		if err != nil {
			return nil, fmt.Errorf("claims template: %w", err)
		}
		opts = append(opts, oauth2.SetAuthURLParam("claims", resolved))
	}

	for key, value := range params.CustomParams {
		if reservedOIDCParams[key] {
			return nil, fmt.Errorf("custom_params key %q is reserved and cannot override a core authorization request parameter", key)
		}
		resolvedValue, err := resolveTemplate(value, dynamicParams)
		if err != nil {
			return nil, fmt.Errorf("custom param %q template: %w", key, err)
		}
		opts = append(opts, oauth2.SetAuthURLParam(key, resolvedValue))
	}

	return opts, nil
}

// resolveJSONTemplate resolves a template whose output must be JSON - the
// OIDC "claims" request parameter (OIDC Core 5.5).
//
// The dynamic values are caller-supplied, arriving in the PAR request body,
// and text/template escapes nothing. The documented way to write this
// parameter puts the variable inside a JSON string:
//
//	{"id_token":{"org_id":{"value":"{{.org_id}}"}}}
//
// so a value containing a quote or a backslash used to end that string and
// let the caller append JSON of their own - asking the OP for claims the
// operator never configured, or simply breaking the request. Each value is
// therefore escaped as JSON string content before templating, which leaves
// it able to affect only the value it sits in and never the structure
// around it.
//
// The result is then checked to be valid JSON. That catches an operator
// template that was malformed to begin with, and means anything this
// function cannot vouch for fails here rather than at the OP.
func resolveJSONTemplate(tmplStr string, data map[string]string) (string, error) {
	escaped := make(map[string]string, len(data))
	for key, value := range data {
		encoded, err := json.Marshal(value)
		if err != nil {
			return "", fmt.Errorf("escaping dynamic param %q: %w", key, err)
		}
		// json.Marshal of a string is quoted; the template inserts into a
		// string that already has its own quotes.
		escaped[key] = string(encoded[1 : len(encoded)-1])
	}

	resolved, err := resolveTemplate(tmplStr, escaped)
	if err != nil {
		return "", err
	}
	if !json.Valid([]byte(resolved)) {
		return "", fmt.Errorf("resolved claims parameter is not valid JSON: %q", resolved)
	}
	return resolved, nil
}

// resolveTemplate resolves Go template syntax in a string using dynamic params as data.
func resolveTemplate(tmplStr string, data map[string]string) (string, error) {
	// No early return for empty data. It used to hand the template back
	// verbatim, so a configured "{{.org_id}}" reached the OP as those literal
	// characters whenever the dynamic parameters were missing - from a cache
	// lookup that failed, a session that carried none, anything. The request
	// was then not bound to the value it was supposed to carry, and nothing
	// said so.
	//
	// Executing with missingkey=error instead makes a template that needs a
	// value and has none an error, while a string containing no actions
	// passes through unchanged as before.
	tmpl, err := template.New("param").Option("missingkey=error").Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("invalid template %q: %w", tmplStr, err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("template execution failed for %q: %w", tmplStr, err)
	}
	return buf.String(), nil
}

// AuthResponse represents the result of OIDC authentication
type AuthResponse struct {
	IDToken      *oidc.IDToken
	AccessToken  string
	RefreshToken string
	Claims       map[string]any
	SessionID    string
}

// ProcessCallback processes the OIDC provider callback
func (s *Service) ProcessCallback(ctx context.Context, code, state string) (*AuthResponse, error) {
	// Discovery only. A callback must NOT renew: renewal registers a brand
	// new client, and this request has to be finished on the client the
	// authorization code was issued to. Credentials come from
	// credentialsForSession below, which reads the session's own client id
	// - including from the store, when the flow started on another replica.
	//
	// Going through ensureReady here also made a callback fail for a reason
	// that had nothing to do with it: if THIS replica's secret had run out
	// and re-registration was backing off, ensureCredentials returned an
	// error before the session was ever loaded - even though the stored
	// registration the flow actually needs was sitting there, valid, and
	// would have worked.
	if err := s.ensureInitialized(ctx); err != nil {
		return nil, fmt.Errorf("OIDC RP not ready: %w", err)
	}

	s.log.Debug("ProcessCallback", "state", state)

	// Retrieve and validate session
	session, err := s.getSession(ctx, state)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired session: %w", err)
	}

	// Finish on the client the flow started on. An authorization code is
	// issued to a specific client, so a renewal that lands between the
	// authorization request and this callback must not change which client
	// redeems it - and the ID token has to be verified against the same
	// one, since the verifier checks `aud`.
	creds, err := s.credentialsForSession(ctx, session.ClientID)
	if err != nil {
		return nil, err
	}

	// Exchange authorization code for tokens with PKCE
	s.log.Debug("ProcessCallback: exchanging authorization code", "state", state, "client_id", session.ClientID)
	oauth2Token, err := creds.config.Exchange(
		ctx,
		code,
		oauth2.SetAuthURLParam("code_verifier", session.CodeVerifier),
	)
	if err != nil {
		s.log.Debug("ProcessCallback: code exchange failed", "state", state, "error", err)
		s.deleteSession(ctx, state)
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}
	s.log.Debug("ProcessCallback: code exchange successful", "state", state)

	// Extract and verify ID token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		s.log.Debug("ProcessCallback: no id_token in token response", "state", state)
		s.deleteSession(ctx, state)
		return nil, fmt.Errorf("no id_token in token response")
	}

	s.log.Debug("ProcessCallback: verifying ID token", "state", state)
	idToken, err := creds.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		s.log.Debug("ProcessCallback: ID token verification failed", "state", state, "error", err)
		s.deleteSession(ctx, state)
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Verify nonce
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		s.deleteSession(ctx, state)
		return nil, fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	if nonce, ok := claims["nonce"].(string); !ok || nonce != session.Nonce {
		s.deleteSession(ctx, state)
		return nil, fmt.Errorf("nonce mismatch")
	}

	s.log.Info("OIDC authentication successful",
		"subject", idToken.Subject,
		"issuer", idToken.Issuer,
	)

	return &AuthResponse{
		IDToken:      idToken,
		AccessToken:  oauth2Token.AccessToken,
		RefreshToken: oauth2Token.RefreshToken,
		Claims:       claims,
		SessionID:    session.ID,
	}, nil
}

// GetSession retrieves a session by state
func (s *Service) GetSession(ctx context.Context, state string) (*Session, error) {
	return s.getSession(ctx, state)
}

// DeleteSession removes a session
func (s *Service) DeleteSession(ctx context.Context, state string) {
	s.deleteSession(ctx, state)
}

// BuildAttributeMapper creates an attribute mapper from the configuration.
// Returns nil if no attribute_mapping is configured (OIDC claims pass through as-is).
func (s *Service) BuildAttributeMapper() *AttributeMapper {
	if s.cfg == nil || len(s.cfg.AttributeMapping) == 0 {
		return nil
	}

	return NewAttributeMapper(s.cfg.AttributeMapping)
}

// createSession creates a new session with generated state, nonce, and PKCE code_verifier.
func (s *Service) createSession(ctx context.Context, credentialType, clientID string) (*Session, error) {
	state, err := crypto.GenerateSecureToken(0, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	nonce, err := crypto.GenerateSecureToken(0, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	codeVerifier, err := pkgoauth2.CreateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to generate code_verifier: %w", err)
	}

	now := time.Now()
	session := &Session{
		ID:             state,
		State:          state,
		Nonce:          nonce,
		CodeVerifier:   codeVerifier,
		CredentialType: credentialType,
		IssuerURL:      s.cfg.IssuerURL,
		ClientID:       clientID,
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Duration(s.cfg.SessionDuration) * time.Second),
	}

	s.sessionCache.Set(ctx, session.ID, session)

	s.log.Debug("session created",
		"session_id", session.ID,
		"credential_type", credentialType,
		"issuer", s.cfg.IssuerURL)

	return session, nil
}

// getSession retrieves a session by state parameter.
func (s *Service) getSession(ctx context.Context, state string) (*Session, error) {
	session, ok := s.sessionCache.Get(ctx, state)
	if !ok || session == nil {
		return nil, fmt.Errorf("session not found or expired")
	}

	return session, nil
}

// deleteSession removes a session.
func (s *Service) deleteSession(ctx context.Context, state string) {
	s.sessionCache.Delete(ctx, state)
	s.log.Debug("session deleted", "state", state)
}

// GetUserInfo fetches additional claims from the UserInfo endpoint
func (s *Service) GetUserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	// Discovery only. The UserInfo request authenticates with the access
	// token it is handed; no client secret takes part in it, so the state
	// of this replica's registration is irrelevant and must not be able to
	// fail the call.
	if err := s.ensureInitialized(ctx); err != nil {
		return nil, fmt.Errorf("OIDC RP not ready: %w", err)
	}

	userInfo, err := s.provider.UserInfo(ctx, oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: accessToken},
	))
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	var claims map[string]any
	if err := userInfo.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse user info claims: %w", err)
	}

	return claims, nil
}
