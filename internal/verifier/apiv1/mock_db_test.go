package apiv1

import (
	"context"
	"errors"
	"sync"
	"time"
	"vc/internal/verifier/db"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/openid4vp"
	"vc/pkg/sdjwtvc"
	"vc/pkg/trace"

	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// MockSessionCollection is an in-memory implementation of SessionCollection for testing
type MockSessionCollection struct {
	mu       sync.RWMutex
	sessions map[string]*db.Session
}

// NewMockSessionCollection creates a new mock session collection
func NewMockSessionCollection() *MockSessionCollection {
	return &MockSessionCollection{
		sessions: make(map[string]*db.Session),
	}
}

// Create creates a new session
func (m *MockSessionCollection) Create(ctx context.Context, session *db.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sessions[session.ID]; exists {
		return errors.New("session already exists")
	}

	m.sessions[session.ID] = session
	return nil
}

// GetByID retrieves a session by ID
func (m *MockSessionCollection) GetByID(ctx context.Context, id string) (*db.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessions[id]
	if !exists {
		return nil, nil
	}

	return session, nil
}

// GetByAuthorizationCode retrieves a session by authorization code
func (m *MockSessionCollection) GetByAuthorizationCode(ctx context.Context, code string) (*db.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, session := range m.sessions {
		if session.Tokens.AuthorizationCode == code {
			return session, nil
		}
	}

	return nil, nil
}

// GetByAccessToken retrieves a session by access token
func (m *MockSessionCollection) GetByAccessToken(ctx context.Context, token string) (*db.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, session := range m.sessions {
		if session.Tokens.AccessToken == token {
			return session, nil
		}
	}

	return nil, nil
}

// Update updates a session
func (m *MockSessionCollection) Update(ctx context.Context, session *db.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sessions[session.ID]; !exists {
		return errors.New("session not found")
	}

	m.sessions[session.ID] = session
	return nil
}

// Delete deletes a session
func (m *MockSessionCollection) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sessions[id]; !exists {
		return errors.New("session not found")
	}

	delete(m.sessions, id)
	return nil
}

// MarkCodeAsUsed marks an authorization code as used
func (m *MockSessionCollection) MarkCodeAsUsed(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.sessions[id]
	if !exists {
		return errors.New("session not found")
	}

	session.Tokens.AuthorizationCodeUsed = true
	return nil
}

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
var _ db.SessionStore = (*MockSessionCollection)(nil)
var _ db.ClientStore = (*MockClientCollection)(nil)

// MockDBService creates a mock database service for testing
type MockDBService struct {
	Sessions *MockSessionCollection
	Clients  *MockClientCollection
}

// NewMockDBService creates a new mock database service
func NewMockDBService() *MockDBService {
	return &MockDBService{
		Sessions: NewMockSessionCollection(),
		Clients:  NewMockClientCollection(),
	}
}

// ToDBService creates a db.Service that uses the mock collections
// This allows the mocks to be used with the real Client struct
func (m *MockDBService) ToDBService() *db.Service {
	return db.NewServiceWithMocks(m.Sessions, m.Clients)
}

// CreateTestClientWithMock creates a test Client with a mock database for testing handlers
func CreateTestClientWithMock(cfg *model.Cfg) (*Client, *MockDBService) {
	ctx := context.TODO()

	if cfg == nil {
		cfg = &model.Cfg{
			Verifier: &model.Verifier{
				ExternalServerURL: "https://verifier.example.com",
				OIDC: model.OIDCConfig{
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
		}
	}

	log := logger.NewSimple("test-client")
	tracer, _ := trace.NewForTesting(ctx, "test", log)

	mockDB := NewMockDBService()
	dbService := mockDB.ToDBService()

	// Create client directly with mock dependencies
	// Note: We bypass New() to avoid loading real config files
	client := &Client{
		cfg:                         cfg,
		db:                          dbService,
		log:                         log.New("apiv1"),
		tracer:                      tracer,
		oidcSigningAlg:              "RS256",
		ephemeralEncryptionKeyCache: ttlcache.New(ttlcache.WithTTL[string, jwk.Key](10 * time.Minute)),
		requestObjectCache:          ttlcache.New(ttlcache.WithTTL[string, *openid4vp.RequestObject](5 * time.Minute)),
		credentialCache:             ttlcache.New(ttlcache.WithTTL[string, []sdjwtvc.CredentialCache](5 * time.Minute)),
	}

	return client, mockDB
}
