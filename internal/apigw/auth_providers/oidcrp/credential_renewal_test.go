package oidcrp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeRegistrationStore records what the renewal path writes and removes.
type fakeRegistrationStore struct {
	mu           sync.Mutex
	saved        []*db.DynamicRegistrationCredentials
	keptOnly     []string
	prunedBefore []time.Time
	saveErr      error
}

func (f *fakeRegistrationStore) Save(_ context.Context, creds *db.DynamicRegistrationCredentials) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.saveErr != nil {
		return f.saveErr
	}
	f.saved = append(f.saved, creds)
	return nil
}

func (f *fakeRegistrationStore) Get(context.Context) (*db.DynamicRegistrationCredentials, error) {
	return nil, nil
}

func (f *fakeRegistrationStore) GetByClientID(_ context.Context, clientID string) (*db.DynamicRegistrationCredentials, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.saved {
		if c.ClientID == clientID {
			return c, nil
		}
	}
	return nil, nil
}

func (f *fakeRegistrationStore) PruneExpiredRegistrations(_ context.Context, keepClientID string, now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keptOnly = append(f.keptOnly, keepClientID)
	f.prunedBefore = append(f.prunedBefore, now)
	return nil
}

// opServer is a minimal OP: discovery pointing at itself, and a
// registration endpoint handing out a fresh client each time it is called.
type opServer struct {
	*httptest.Server
	mu            sync.Mutex
	registrations int
	// secretLifetime is written into client_secret_expires_at; zero means
	// the OP says the secret never expires.
	secretLifetime time.Duration
	// refuse makes /register fail, to exercise the backoff path.
	refuse bool
	// omitRegistrationEndpoint drops it from discovery.
	omitRegistrationEndpoint bool
	// registrationBody, when set, replaces /register's response body - for
	// the responses an OP should not be sending.
	registrationBody string
}

func newOPServer(t *testing.T) *opServer {
	t.Helper()
	op := &opServer{secretLifetime: time.Hour}

	mux := http.NewServeMux()
	op.Server = httptest.NewServer(mux)
	t.Cleanup(op.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]any{
			"issuer":                                op.URL,
			"authorization_endpoint":                op.URL + "/authorize",
			"token_endpoint":                        op.URL + "/token",
			"jwks_uri":                              op.URL + "/jwks",
			"userinfo_endpoint":                     op.URL + "/userinfo",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		if !op.omitRegistrationEndpoint {
			doc["registration_endpoint"] = op.URL + "/register"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	// UserInfo authenticates with the access token alone - no client
	// credential takes part in it. It echoes the bearer token back so a
	// test can tell a real response from a cached or fabricated one.
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub":          "user-1",
			"presented_at": r.Header.Get("Authorization"),
		})
	})

	mux.HandleFunc("/register", func(w http.ResponseWriter, _ *http.Request) {
		op.mu.Lock()
		if op.refuse {
			op.mu.Unlock()
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		op.registrations++
		n := op.registrations
		lifetime := op.secretLifetime
		op.mu.Unlock()

		var expiresAt int64
		if lifetime > 0 {
			expiresAt = time.Now().Add(lifetime).Unix()
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if op.registrationBody != "" {
			_, _ = w.Write([]byte(op.registrationBody))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":                 "client-" + string(rune('0'+n)),
			"client_secret":             "secret-" + string(rune('0'+n)),
			"client_secret_expires_at":  expiresAt,
			"registration_access_token": "rat",
			"registration_client_uri":   op.URL + "/register/client",
		})
	})

	return op
}

func (op *opServer) count() int {
	op.mu.Lock()
	defer op.mu.Unlock()
	return op.registrations
}

// renewalService wires a Service against the fake OP, already "ready", with
// a current secret expiring at the given time.
func renewalService(t *testing.T, op *opServer, store db.DynamicRegistrationStore, expiresAt time.Time) *Service {
	t.Helper()

	provider, err := oidc.NewProvider(t.Context(), op.URL)
	require.NoError(t, err)

	enable := true
	s := &Service{
		cfg: &model.OIDCRP{
			IssuerURL:   op.URL,
			RedirectURI: "https://apigw.example.com/callback",
			Scopes:      []string{"openid"},
			Registration: &model.OIDCRPRegistrationConfig{
				Dynamic: &model.OIDCRPDynamicRegistrationConfig{Enable: enable},
			},
		},
		provider:   provider,
		httpClient: op.Client(),
		dbService:  &db.Service{DynamicRegistrationColl: store},
		log:        logger.NewSimple("test"),
		ready:      true,
		creds:      newCredentialSet(5 * time.Minute),
	}

	var expiresAtUnix int64
	if !expiresAt.IsZero() {
		expiresAtUnix = expiresAt.Unix()
	}
	s.applyCredentials("client-0", "secret-0", expiresAtUnix)

	// applyCredentials sets renewNotBefore from the remaining lifetime, so
	// a test that wants a renewal right now has to say so - otherwise the
	// floor that stops a short-lived secret re-registering per request
	// would also stop the test.
	if !expiresAt.IsZero() {
		current := s.creds.load()
		s.creds.store(&credentials{
			clientID:  current.clientID,
			config:    current.config,
			verifier:  current.verifier,
			expiresAt: current.expiresAt,
		})
	}

	return s
}

func (s *Service) currentClientID(t *testing.T) string {
	t.Helper()
	return s.creds.load().config.ClientID
}

// The bug: the secret was read once at startup and never looked at again,
// so a long-running instance kept presenting an expired one and every flow
// failed at the token exchange (SUNET/vc#295).
func TestEnsureCredentialsRenewsBeforeExpiry(t *testing.T) {
	op := newOPServer(t)
	store := &fakeRegistrationStore{}
	// Inside the renewal window, but not yet expired.
	s := renewalService(t, op, store, time.Now().Add(clientSecretRenewBefore/2))

	require.NoError(t, s.ensureCredentials(t.Context()))

	assert.Equal(t, 1, op.count(), "the OP should have been asked for a new client")
	assert.Equal(t, "client-1", s.currentClientID(t), "the new client must be the one in use")

	require.Len(t, store.saved, 1)
	assert.Equal(t, "client-1", store.saved[0].ClientID)

	// Get orders by registered_at, so startup picks the newest whether or
	// not this ran; the prune exists to stop dead rows accumulating, and
	// removes only registrations whose secret has expired.
	assert.Equal(t, []string{"client-1"}, store.keptOnly,
		"the new registration is the one kept")
}

func TestEnsureCredentialsLeavesAFreshSecretAlone(t *testing.T) {
	op := newOPServer(t)
	store := &fakeRegistrationStore{}
	s := renewalService(t, op, store, time.Now().Add(24*time.Hour))

	require.NoError(t, s.ensureCredentials(t.Context()))

	assert.Zero(t, op.count(), "a secret good for a day must not be replaced")
	assert.Equal(t, "client-0", s.currentClientID(t))
	assert.Empty(t, store.saved)
}

// client_secret_expires_at: 0 means the secret never expires (RFC 7591
// §3.2.1), and is also what a preconfigured client looks like here.
func TestEnsureCredentialsIgnoresANonExpiringSecret(t *testing.T) {
	op := newOPServer(t)
	store := &fakeRegistrationStore{}
	s := renewalService(t, op, store, time.Time{})

	require.NoError(t, s.ensureCredentials(t.Context()))

	assert.Zero(t, op.count())
	assert.Empty(t, store.saved)
}

func TestEnsureCredentialsSkipsWhenDynamicRegistrationIsOff(t *testing.T) {
	op := newOPServer(t)
	store := &fakeRegistrationStore{}
	s := renewalService(t, op, store, time.Now().Add(-time.Hour))
	s.cfg.Registration.Dynamic = nil

	require.NoError(t, s.ensureCredentials(t.Context()))

	assert.Zero(t, op.count(), "a preconfigured client is not ours to re-register")
}

// Concurrent requests all arrive here when the secret ages out. Only the
// first should register; the rest must use what it installed.
func TestEnsureCredentialsRenewsOnceUnderConcurrency(t *testing.T) {
	op := newOPServer(t)
	store := &fakeRegistrationStore{}
	s := renewalService(t, op, store, time.Now().Add(clientSecretRenewBefore/2))

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assert.NoError(t, s.ensureCredentials(t.Context()))
		}()
	}
	wg.Wait()

	assert.Equal(t, 1, op.count(), "sixteen callers must not register sixteen clients")
	assert.Len(t, store.saved, 1)
}

// A secret that is inside the renewal window but still valid must not take
// the service down when the OP is unreachable - there is still time.
func TestEnsureCredentialsToleratesAFailureWhileTheSecretIsStillValid(t *testing.T) {
	op := newOPServer(t)
	op.refuse = true
	store := &fakeRegistrationStore{}
	s := renewalService(t, op, store, time.Now().Add(clientSecretRenewBefore/2))

	assert.NoError(t, s.ensureCredentials(t.Context()),
		"the current secret still works; refusing the request would be worse")
	assert.Equal(t, "client-0", s.currentClientID(t))
}

// Once it has actually expired, refusing with a clear message beats letting
// the token exchange fail with whatever the OP says about an unknown client.
func TestEnsureCredentialsFailsOnceTheSecretHasExpired(t *testing.T) {
	op := newOPServer(t)
	op.refuse = true
	store := &fakeRegistrationStore{}
	s := renewalService(t, op, store, time.Now().Add(-time.Hour))

	err := s.ensureCredentials(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "re-registration")
}

// After a failure the OP is not hammered on every request.
func TestEnsureCredentialsBacksOffAfterAFailure(t *testing.T) {
	op := newOPServer(t)
	op.refuse = true
	store := &fakeRegistrationStore{}
	s := renewalService(t, op, store, time.Now().Add(-time.Hour))

	require.Error(t, s.ensureCredentials(t.Context()))
	require.False(t, s.credentialRetryAfter.IsZero(), "a failure must set a retry time")

	// The OP would succeed now, but the backoff has not elapsed.
	op.mu.Lock()
	op.refuse = false
	op.mu.Unlock()

	require.Error(t, s.ensureCredentials(t.Context()))
	assert.Zero(t, op.count(), "the second call must not reach the OP")
}

// An OP that stops advertising dynamic registration cannot be re-registered
// with, and that has to surface rather than loop.
func TestEnsureCredentialsFailsWithoutARegistrationEndpoint(t *testing.T) {
	op := newOPServer(t)
	op.omitRegistrationEndpoint = true
	store := &fakeRegistrationStore{}
	s := renewalService(t, op, store, time.Now().Add(-time.Hour))

	err := s.ensureCredentials(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registration_endpoint")
}

// ensureReady is what a path that STARTS a flow calls - InitiateAuth, and
// InitiateAuthForVCI through it - so renewal has to hang off it. A correct
// ensureCredentials that nothing calls is a renewal that never happens:
// removing the call compiles and leaves every test above passing.
//
// ProcessCallback and GetUserInfo deliberately call ensureInitialized
// instead and must NOT renew - see
// TestProcessCallbackIsNotGatedOnThisReplicasCredentials below for why.
func TestEnsureReadyRenewsExpiringCredentials(t *testing.T) {
	op := newOPServer(t)
	store := &fakeRegistrationStore{}
	s := renewalService(t, op, store, time.Now().Add(clientSecretRenewBefore/2))

	require.NoError(t, s.ensureReady(t.Context()))

	assert.Equal(t, 1, op.count(), "the request path must renew the secret")
	assert.Equal(t, "client-1", s.currentClientID(t))
}

// ... and it must not renew when there is no need, or every ready check
// would register a client.
func TestEnsureReadyLeavesAFreshSecretAlone(t *testing.T) {
	op := newOPServer(t)
	store := &fakeRegistrationStore{}
	s := renewalService(t, op, store, time.Now().Add(24*time.Hour))

	require.NoError(t, s.ensureReady(t.Context()))

	assert.Zero(t, op.count())
}

// An OP that issues secrets shorter than the renewal lead time would
// otherwise never produce one this service calls fresh, so every request
// would register another client.
func TestEnsureCredentialsDoesNotRenewAShortLivedSecretPerRequest(t *testing.T) {
	op := newOPServer(t)
	op.secretLifetime = clientSecretRenewBefore / 2
	store := &fakeRegistrationStore{}
	s := renewalService(t, op, store, time.Now().Add(clientSecretRenewBefore/2))

	for range 10 {
		require.NoError(t, s.ensureCredentials(t.Context()))
	}

	assert.Equal(t, 1, op.count(), "ten requests must not produce ten registrations")
}

// Readers must never see a config from one registration with a verifier
// from another, and must not race the writer.
func TestEnsureCredentialsIsSafeAgainstConcurrentReaders(t *testing.T) {
	op := newOPServer(t)
	op.secretLifetime = 0 // the renewal yields a never-expiring secret
	store := &fakeRegistrationStore{}
	s := renewalService(t, op, store, time.Now().Add(clientSecretRenewBefore/2))

	var wg sync.WaitGroup

	// Bounded rather than "until a channel closes": readers that only stop
	// on a signal sent after wg.Wait() never stop at all.
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 2000 {
				creds := s.creds.load()
				require.NotNil(t, creds)
				// The pair has to belong together: the verifier checks
				// `aud` against the client the config authenticates with.
				assert.Equal(t, creds.clientID, creds.config.ClientID)
				assert.NotNil(t, creds.verifier)
			}
		}()
	}

	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assert.NoError(t, s.ensureCredentials(t.Context()))
		}()
	}

	wg.Wait()

	assert.Equal(t, 1, op.count(), "four writers must produce one registration")
}

// In HA the session store is shared but credentialSet is per process, so a
// callback can land on a replica that never saw the registration its flow
// began on. Falling back to this replica's current client would exchange
// the code with the wrong one, so the stored registration is read instead.
func TestCredentialsForSessionReadsAnotherReplicasRegistration(t *testing.T) {
	op := newOPServer(t)
	store := &fakeRegistrationStore{}
	// The other replica registered this and saved it to the shared store.
	store.saved = append(store.saved, &db.DynamicRegistrationCredentials{
		ClientID:              "client-from-replica-a",
		ClientSecret:          "secret-from-replica-a",
		ClientSecretExpiresAt: time.Now().Add(time.Hour).Unix(),
	})

	// This replica knows nothing about it.
	s := renewalService(t, op, store, time.Now().Add(24*time.Hour))

	creds, err := s.credentialsForSession(t.Context(), "client-from-replica-a")
	require.NoError(t, err)
	assert.Equal(t, "client-from-replica-a", creds.clientID)
	assert.Equal(t, "secret-from-replica-a", creds.config.ClientSecret)
	assert.NotNil(t, creds.verifier)

	// Retained, so a second callback for the same flow does not read it
	// back again.
	assert.Equal(t, "client-from-replica-a", s.creds.forClient("client-from-replica-a").clientID)
}

// A session naming a client nobody can resolve must NOT fall back to the
// current one: the exchange is then guaranteed to fail, and the caller
// deletes the session on an exchange failure, losing a flow that could
// have been retried.
func TestCredentialsForSessionRefusesAnUnresolvableClient(t *testing.T) {
	op := newOPServer(t)
	store := &fakeRegistrationStore{}
	s := renewalService(t, op, store, time.Now().Add(24*time.Hour))

	_, err := s.credentialsForSession(t.Context(), "a-client-nobody-has-heard-of")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "a-client-nobody-has-heard-of")
}

// A session created before the client id was recorded names none, and must
// still work the way it did before.
func TestCredentialsForSessionFallsBackOnlyWhenNoClientIsNamed(t *testing.T) {
	op := newOPServer(t)
	store := &fakeRegistrationStore{}
	s := renewalService(t, op, store, time.Now().Add(24*time.Hour))

	creds, err := s.credentialsForSession(t.Context(), "")
	require.NoError(t, err)
	assert.Equal(t, "client-0", creds.clientID)
}

// Two replicas renewing at once must not each delete the other's brand new
// registration and leave the store empty. The prune is bounded by age, so
// a row saved moments ago is never old enough to remove.
// Pruning is by expiry, not by age. "Registered long ago" says nothing
// about whether a registration is in use - in HA another replica can be
// running on an hours-old one - so the cutoff handed to the store is now,
// and the store deletes only secrets that have already expired.
func TestRenewalPrunesByExpiryNotAge(t *testing.T) {
	op := newOPServer(t)
	store := &fakeRegistrationStore{}
	s := renewalService(t, op, store, time.Now().Add(clientSecretRenewBefore/2))

	require.NoError(t, s.ensureCredentials(t.Context()))

	require.Len(t, store.prunedBefore, 1)
	assert.WithinDuration(t, time.Now(), store.prunedBefore[0], time.Minute,
		"the cutoff is now; the store decides what has expired")
	assert.Equal(t, []string{"client-1"}, store.keptOnly)
}

// A registration that cannot be stored is not published. In HA the shared
// session would record a client id no other replica can resolve, so the
// authorization code could not be redeemed at all.
func TestRenewalDoesNotPublishAnUnstorableRegistration(t *testing.T) {
	op := newOPServer(t)
	store := &fakeRegistrationStore{saveErr: assert.AnError}
	s := renewalService(t, op, store, time.Now().Add(clientSecretRenewBefore/2))

	// The secret is still valid, so ensureCredentials tolerates the failure
	// and the request proceeds - on the old client, which still works.
	require.NoError(t, s.ensureCredentials(t.Context()))

	assert.Equal(t, "client-0", s.currentClientID(t),
		"an unstorable registration must not become the one flows start on")
}

// The same persistence-before-publication rule as renewCredentials, on the
// startup path: a registration nobody can look up cannot redeem its own
// authorization codes in HA, so it must not become the client flows start
// on. Failing initialization is recoverable - the service retries.
func TestInitializeDoesNotPublishAnUnstorableRegistration(t *testing.T) {
	op := newOPServer(t)
	store := &fakeRegistrationStore{saveErr: assert.AnError}

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	s := &Service{
		cfg: &model.OIDCRP{
			IssuerURL:       op.URL,
			RedirectURI:     "https://apigw.example.com/callback",
			Scopes:          []string{"openid"},
			SessionDuration: 300,
			Registration: &model.OIDCRPRegistrationConfig{
				Dynamic: &model.OIDCRPDynamicRegistrationConfig{Enable: true},
			},
		},
		httpClient: op.Client(),
		dbService:  &db.Service{DynamicRegistrationColl: store},
		log:        log.New("oidcrp"),
		creds:      newCredentialSet(5 * time.Minute),
	}

	err = s.initialize(t.Context())
	require.Error(t, err, "an unstorable registration must fail initialization")
	assert.Nil(t, s.creds.load(), "and must not be published")
	assert.False(t, s.ready)
}

// backedOffService is a replica whose own registration has run out and
// whose re-registration is in backoff: the worst state ensureCredentials
// can be in, and the one that used to take the whole RP down with it.
func backedOffService(t *testing.T, op *opServer) *Service {
	t.Helper()
	op.refuse = true
	s := renewalService(t, op, &fakeRegistrationStore{}, time.Now().Add(-time.Hour))
	s.sessionCache = cache.NewMemoryCache[*Session](5 * time.Minute)
	s.credentialBackoff = time.Hour
	s.credentialRetryAfter = time.Now().Add(time.Hour)
	return s
}

// A callback has to be finished on the client the authorization code was
// issued to, which credentialsForSession resolves from the session - from
// the store, when the flow started on another replica. Going through
// ensureReady first meant THIS replica's own expired registration refused
// the callback before the session was even loaded, so one replica losing
// its registration broke flows that had nothing to do with it. Renewing
// would have been worse: it registers a NEW client, and the code cannot be
// redeemed by one.
func TestProcessCallbackIsNotGatedOnThisReplicasCredentials(t *testing.T) {
	op := newOPServer(t)
	s := backedOffService(t, op)

	_, err := s.ProcessCallback(t.Context(), "the-code", "a-state-this-replica-never-saw")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired session",
		"the callback must get as far as looking the session up")
	assert.NotContains(t, err.Error(), "OIDC RP not ready")
	assert.NotContains(t, err.Error(), "re-registration is backing off")
	assert.Equal(t, 0, op.count(), "a callback must never register a new client")
}

// UserInfo presents the access token and nothing else, so the state of this
// replica's client registration cannot make it fail.
func TestGetUserInfoIsNotGatedOnCredentials(t *testing.T) {
	op := newOPServer(t)
	s := backedOffService(t, op)

	claims, err := s.GetUserInfo(t.Context(), "an-access-token")

	require.NoError(t, err)
	assert.Equal(t, "user-1", claims["sub"])
	assert.Equal(t, "Bearer an-access-token", claims["presented_at"])
	assert.Equal(t, 0, op.count(), "UserInfo must never register a client")
}

// The other half: a path that STARTS a flow does renew, so the two tests
// above are not simply the renewal being gone.
func TestInitiateAuthStillRenews(t *testing.T) {
	op := newOPServer(t)
	store := &fakeRegistrationStore{}
	s := renewalService(t, op, store, time.Now().Add(clientSecretRenewBefore/2))
	s.sessionCache = cache.NewMemoryCache[*Session](5 * time.Minute)
	s.cfg.SessionDuration = 300

	_, err := s.InitiateAuth(t.Context(), "pid", nil, nil)

	require.NoError(t, err)
	assert.Equal(t, 1, op.count(), "starting a flow renews an expiring registration")
	assert.Equal(t, "client-1", s.currentClientID(t))
}

// errorStore is a store whose lookups fail, for the case below.
type errorStore struct {
	fakeRegistrationStore
	lookupErr error
}

func (e *errorStore) GetByClientID(context.Context, string) (*db.DynamicRegistrationCredentials, error) {
	return nil, e.lookupErr
}

// A database that cannot be read and a client that was never registered
// are different situations with different fixes, and in HA the first is
// the common one. Collapsing them sent an operator chasing a wave of
// failed callbacks after a registration problem that did not exist.
func TestCredentialsForSessionReportsALookupFailureAsItself(t *testing.T) {
	op := newOPServer(t)
	store := &errorStore{lookupErr: errors.New("connection refused")}
	s := renewalService(t, op, store, time.Now().Add(time.Hour))

	_, err := s.credentialsForSession(t.Context(), "client-from-another-replica")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused",
		"the actionable cause has to survive")
	assert.NotContains(t, err.Error(), "no client registration found",
		"a store outage must not read as a missing registration")
}

// A registration response with no client_id used to be stored and
// published as a client with an empty id. The failure after that is silent
// and permanent: an absent client_secret_expires_at decodes as 0, which
// means "never expires", so needsRenewal never fires and nothing tries
// again - every flow fails at the token exchange until somebody restarts
// the process, which is the exact shape of the bug this PR fixes.
func TestRegistrationResponseMustCarryAClientIDAndSecret(t *testing.T) {
	for name, body := range map[string]string{
		"no client_id":     `{"client_secret":"s","client_secret_expires_at":0}`,
		"no client_secret": `{"client_id":"c","client_secret_expires_at":0}`,
		"neither":          `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			op := newOPServer(t)
			op.registrationBody = body

			store := &fakeRegistrationStore{}
			// Already expired, so the failure surfaces rather than being
			// tolerated - ensureCredentials deliberately carries on when
			// the current secret still has life in it.
			s := renewalService(t, op, store, time.Now().Add(-time.Hour))

			err := s.ensureCredentials(t.Context())
			require.Error(t, err, "an unusable registration response must not be accepted")

			store.mu.Lock()
			saved := len(store.saved)
			store.mu.Unlock()
			assert.Zero(t, saved, "nothing unusable may be persisted")
			assert.Equal(t, "client-0", s.currentClientID(t),
				"the previous registration must stay in place")
		})
	}
}
