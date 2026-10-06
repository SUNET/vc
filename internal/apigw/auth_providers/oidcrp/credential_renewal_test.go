package oidcrp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeRegistrationStore records what the renewal path writes and removes.
type fakeRegistrationStore struct {
	mu      sync.Mutex
	saved   []*db.DynamicRegistrationCredentials
	deleted []string
	saveErr error
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

func (f *fakeRegistrationStore) Delete(_ context.Context, clientID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, clientID)
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
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		if !op.omitRegistrationEndpoint {
			doc["registration_endpoint"] = op.URL + "/register"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
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
		provider:              provider,
		httpClient:            op.Client(),
		dbService:             &db.Service{DynamicRegistrationColl: store},
		log:                   logger.NewSimple("test"),
		ready:                 true,
		clientID:              "client-0",
		clientSecretExpiresAt: expiresAt,
	}
	s.applyCredentials("client-0", "secret-0", expiresAt.Unix())
	return s
}

func (s *Service) currentClientID(t *testing.T) string {
	t.Helper()
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.oauth2Config.ClientID
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

	// Save upserts on client_id and Get reads an arbitrary row, so the
	// superseded record has to go or the next startup finds it expired and
	// registers all over again.
	assert.Equal(t, []string{"client-0"}, store.deleted)
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

// The client exists at the OP whether or not the write succeeded, so it is
// used either way - failing here would leave the expired secret in place.
func TestEnsureCredentialsUsesTheNewClientEvenIfPersistingFails(t *testing.T) {
	op := newOPServer(t)
	store := &fakeRegistrationStore{saveErr: assert.AnError}
	s := renewalService(t, op, store, time.Now().Add(clientSecretRenewBefore/2))

	require.NoError(t, s.ensureCredentials(t.Context()))

	assert.Equal(t, "client-1", s.currentClientID(t))
	assert.Empty(t, store.deleted, "nothing was stored, so there is nothing to supersede")
}

// ensureReady is what every entry point calls - InitiateAuth,
// ProcessCallback and GetUserInfo all start with it - so renewal has to
// hang off it. A correct ensureCredentials that nothing calls is a renewal
// that never happens: removing the call compiles and leaves every test
// above passing.
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
