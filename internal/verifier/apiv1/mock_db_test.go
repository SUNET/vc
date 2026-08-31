package apiv1

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/SUNET/vc/internal/verifier/cache"
	"github.com/SUNET/vc/internal/verifier/db"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"
	"github.com/SUNET/vc/pkg/trace"
	"github.com/SUNET/vc/pkg/trust"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// MockClientCollection is an in-memory implementation of ClientCollection for testing
type MockClientCollection struct {
	mu      sync.RWMutex
	clients map[string]*db.Client
}

// NewMockClientCollection creates a new mock client collection
func NewMockClientCollection() *MockClientCollection {
	return &MockClientCollection{
		clients: make(map[string]*db.Client),
	}
}

// GetByClientID retrieves a client by client ID
func (m *MockClientCollection) GetByClientID(ctx context.Context, clientID string) (*db.Client, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	client, exists := m.clients[clientID]
	if !exists {
		return nil, nil
	}

	return client, nil
}

// Create creates a new client
func (m *MockClientCollection) Create(ctx context.Context, client *db.Client) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.clients[client.ClientID]; exists {
		return errors.New("client already exists")
	}

	m.clients[client.ClientID] = client
	return nil
}

// Update updates a client
func (m *MockClientCollection) Update(ctx context.Context, client *db.Client) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.clients[client.ClientID]; !exists {
		return errors.New("client not found")
	}

	m.clients[client.ClientID] = client
	return nil
}

// Delete deletes a client
func (m *MockClientCollection) Delete(ctx context.Context, clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.clients[clientID]; !exists {
		return errors.New("client not found")
	}

	delete(m.clients, clientID)
	return nil
}

// AddClient is a test helper to add a client to the mock
func (m *MockClientCollection) AddClient(client *db.Client) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients[client.ClientID] = client
}

// Compile-time interface satisfaction checks for mocks
var _ db.ClientStore = (*MockClientCollection)(nil)

// MockDBService creates a mock database service for testing
type MockDBService struct {
	Clients *MockClientCollection
}

// NewMockDBService creates a new mock database service
func NewMockDBService() *MockDBService {
	return &MockDBService{
		Clients: NewMockClientCollection(),
	}
}

// ToDBService creates a db.Service that uses the mock collections
// This allows the mocks to be used with the real Client struct
func (m *MockDBService) ToDBService() *db.Service {
	return db.NewServiceWithMocks(m.Clients)
}

// CreateTestClientWithMock creates a test Client with a mock database for testing handlers
// CreateTestClientWithMock builds a Client wired to mock dependencies.
//
// t is taken so the openid4vp client's ephemeral key cache can be stopped
// when the test finishes; it starts a background expiry goroutine that would
// otherwise outlive every test in the suite.
//
// The cache.NewTestMemory* caches below start goroutines too. MemoryCache
// has a Stop method, but cache.Service types those fields as the Cache
// interface, which does not include it - so they are stopped through a type
// assertion. AuthContext is backed by MemoryStore, which has no Stop at all,
// and is the one goroutine left running.
func CreateTestClientWithMock(t testing.TB, cfg *model.Cfg) (*Client, *MockDBService) {
	ctx := context.TODO()

	if cfg == nil {
		cfg = &model.Cfg{
			Verifier: &model.Verifier{
				PublicURL: "https://verifier.example.com",
				Outbound: model.VerifierOutbound{
					OIDCProvider: &model.OIDCOP{
						Issuer:               "https://verifier.example.com",
						SubjectType:          "public",
						SubjectSalt:          "test-salt",
						SessionDuration:      900,   // 15 minutes
						CodeDuration:         600,   // 10 minutes
						AccessTokenDuration:  3600,  // 1 hour
						IDTokenDuration:      3600,  // 1 hour
						RefreshTokenDuration: 86400, // 24 hours
					},
				},
			},
		}
	}

	log := logger.NewSimple("test-client")
	tracer, _ := trace.NewForTesting(ctx, "test", log)

	mockDB := NewMockDBService()
	dbService := mockDB.ToDBService()

	// Create client directly with mock dependencies
	// Note: We bypass New() to avoid loading real config files
	client := &Client{
		cfg:    cfg,
		db:     dbService,
		log:    log.New("apiv1"),
		tracer: tracer,
		cacheService: &cache.Service{
			AuthContext:            cache.NewTestMemoryStore(15 * time.Minute),
			EphemeralEncryptionKey: cache.NewTestMemoryCache[jwk.Key](10 * time.Minute),
			RequestObject:          cache.NewTestMemoryCache[*openid4vp.RequestObject](5 * time.Minute),
			Credential:             cache.NewTestMemoryCache[[]sdjwtvc.CredentialCache](5 * time.Minute),
		},
		jwksResolver: trust.NewJWKSKeyResolver(trust.JWKSResolverConfig{}),
		// Production wires this in New(); without it any path that needs an
		// ephemeral encryption key - such as an encrypted response_mode -
		// has nothing to generate one from.
		openid4vp: &openid4vp.Client{
			EphemeralKeyCache: openid4vp.NewEphemeralEncryptionKeyCache(10 * time.Minute),
		},
	}

	t.Cleanup(client.openid4vp.Close)

	// Stop the memory caches that can be stopped. The Cache interface omits
	// Stop, so this asserts for it rather than widening the interface for a
	// test-only need.
	for _, c := range []any{
		client.cacheService.Credential,
		client.cacheService.EphemeralEncryptionKey,
		client.cacheService.RequestObject,
	} {
		if stoppable, ok := c.(interface{ Stop() }); ok {
			t.Cleanup(stoppable.Stop)
		}
	}

	return client, mockDB
}
