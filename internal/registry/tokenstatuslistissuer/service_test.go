package tokenstatuslistissuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"vc/internal/registry/db"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/pki"
	"vc/pkg/tokenstatuslist"
	"vc/pkg/trace"
)

// isDockerAvailable checks if Docker is accessible by running 'docker version'
// This approach is portable across platforms (Linux, macOS, Windows)
func isDockerAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "version")
	if err := cmd.Run(); err != nil {
		return false
	}

	return true
}

// testSuite holds the test infrastructure
type testSuite struct {
	t              *testing.T
	ctx            context.Context
	cancel         context.CancelFunc
	cfg            *model.Cfg
	dbService      *db.Service
	log            *logger.Log
	tracer         *trace.Tracer
	mongoContainer testcontainers.Container
	keyPath        string
}

// newTestSuite creates a new test suite with MongoDB testcontainer
func newTestSuite(t *testing.T) *testSuite {
	// Check if Docker is available
	if !isDockerAvailable() {
		t.Skip("Skipping test: Docker is not available")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)

	suite := &testSuite{
		t:      t,
		ctx:    ctx,
		cancel: cancel,
	}

	suite.generateSigningKey()
	suite.initializeConfiguration()
	suite.startMongoContainer()
	suite.initializeLogging()
	suite.initializeTracing()
	suite.initializeDatabase()

	return suite
}

// generateSigningKey creates a temporary EC256 key file for testing
func (s *testSuite) generateSigningKey() {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		s.t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Create temp directory for the key
	tmpDir := s.t.TempDir()
	s.keyPath = filepath.Join(tmpDir, "signing_key.pem")

	// Write key in PKCS8 PEM format
	keyBytes, err := encodeECPrivateKeyToPKCS8PEM(privateKey)
	if err != nil {
		s.t.Fatalf("Failed to encode private key: %v", err)
	}

	if err := os.WriteFile(s.keyPath, keyBytes, 0600); err != nil {
		s.t.Fatalf("Failed to write key file: %v", err)
	}
}

// encodeECPrivateKeyToPKCS8PEM encodes an ECDSA private key to PKCS8 PEM format
func encodeECPrivateKeyToPKCS8PEM(key *ecdsa.PrivateKey) ([]byte, error) {
	derBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derBytes,
	}

	return pem.EncodeToMemory(block), nil
}

// generateRSAKeyFile creates a temporary RSA key file for testing
func generateRSAKeyFile(t *testing.T) string {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "rsa_key.pem")

	derBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal RSA key: %v", err)
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derBytes,
	}

	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatalf("Failed to write RSA key file: %v", err)
	}

	return keyPath
}

// base64Encode helper for encoding
func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// initializeConfiguration creates test configuration
func (s *testSuite) initializeConfiguration() {
	s.cfg = &model.Cfg{
		Common: &model.Common{
			Production: false,
			Log: model.Log{
				FolderPath: "",
			},
			Mongo: model.Mongo{
				URI: "", // Will be set after MongoDB container starts
			},
		},
		Registry: &model.Registry{
			ExternalServerURL: "https://registry.example.com",
			TokenStatusLists: model.TokenStatusLists{
				KeyConfig: &pki.KeyConfig{
					PrivateKeyPath: s.keyPath,
				},
				TokenRefreshInterval: 600,   // 10 minutes for testing (must be > 5 min buffer)
				SectionSize:          10000, // Use smaller section size for faster tests
			},
		},
	}
}

// startMongoContainer starts a MongoDB container using testcontainers
func (s *testSuite) startMongoContainer() {
	req := testcontainers.ContainerRequest{
		Image:        "mongo:7",
		ExposedPorts: []string{"27017/tcp"},
		WaitingFor:   wait.ForLog("Waiting for connections"),
	}

	var err error
	s.mongoContainer, err = testcontainers.GenericContainer(s.ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		s.t.Fatalf("Failed to start MongoDB container: %v", err)
	}

	// Get the mapped port
	mappedPort, err := s.mongoContainer.MappedPort(s.ctx, "27017")
	if err != nil {
		s.t.Fatalf("Failed to get mapped port: %v", err)
	}

	host, err := s.mongoContainer.Host(s.ctx)
	if err != nil {
		s.t.Fatalf("Failed to get container host: %v", err)
	}

	// Update configuration with MongoDB URI
	s.cfg.Common.Mongo.URI = fmt.Sprintf("mongodb://%s:%s", host, mappedPort.Port())
	s.t.Logf("MongoDB container started at %s", s.cfg.Common.Mongo.URI)
}

// initializeLogging creates test logger
func (s *testSuite) initializeLogging() {
	var err error
	s.log, err = logger.New("tslissuer-test", "", false)
	if err != nil {
		s.t.Fatalf("Failed to create logger: %v", err)
	}
}

// initializeTracing creates test tracer
func (s *testSuite) initializeTracing() {
	var err error
	s.tracer, err = trace.New(s.ctx, s.cfg, "tslissuer-test", s.log)
	if err != nil {
		s.t.Fatalf("Failed to create tracer: %v", err)
	}
}

// initializeDatabase creates database service
func (s *testSuite) initializeDatabase() {
	var err error
	s.dbService, err = db.New(s.ctx, s.cfg, s.tracer, s.log)
	if err != nil {
		s.t.Fatalf("Failed to create database service: %v", err)
	}
}

// cleanup cleans up test resources
func (s *testSuite) cleanup() {
	if s.dbService != nil {
		_ = s.dbService.Close(s.ctx)
	}
	if s.mongoContainer != nil {
		_ = s.mongoContainer.Terminate(s.ctx)
	}
	s.cancel()
}

// newTestSuiteWithSectionSize creates a test suite with a custom section size
func newTestSuiteWithSectionSize(t *testing.T, sectionSize int64) *testSuite {
	// Check if Docker is available
	if !isDockerAvailable() {
		t.Skip("Skipping test: Docker is not available")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)

	suite := &testSuite{
		t:      t,
		ctx:    ctx,
		cancel: cancel,
	}

	suite.generateSigningKey()
	suite.initializeConfiguration()
	suite.cfg.Registry.TokenStatusLists.SectionSize = sectionSize // Override section size
	suite.startMongoContainer()
	suite.initializeLogging()
	suite.initializeTracing()
	suite.initializeDatabase()

	return suite
}

// ============================================================================
// Service Creation Tests
// ============================================================================

func TestNew_Success(t *testing.T) {
	suite := newTestSuite(t)
	defer suite.cleanup()

	service, err := New(suite.ctx, suite.cfg, suite.dbService, suite.log)
	require.NoError(t, err)
	require.NotNil(t, service)

	// Verify service is properly initialized
	assert.NotNil(t, service.jwtCache)
	assert.NotNil(t, service.cwtCache)
	assert.NotNil(t, service.signer)
	assert.Equal(t, suite.cfg, service.cfg)

	// Clean up
	err = service.Close(suite.ctx)
	assert.NoError(t, err)
}

func TestNew_InvalidKeyPath(t *testing.T) {
	suite := newTestSuite(t)
	defer suite.cleanup()

	// Use invalid key path
	suite.cfg.Registry.TokenStatusLists.KeyConfig.PrivateKeyPath = "/nonexistent/path/to/key.pem"

	service, err := New(suite.ctx, suite.cfg, suite.dbService, suite.log)
	assert.Error(t, err)
	assert.Nil(t, service)
	assert.Contains(t, err.Error(), "failed to load Token Status List signing key")
}

func TestNew_RSAKeySupported(t *testing.T) {
	suite := newTestSuite(t)
	defer suite.cleanup()

	// Generate an RSA key (should be accepted - both RSA and ECDSA are supported per OAuth Status List spec)
	rsaKeyPath := generateRSAKeyFile(t)
	suite.cfg.Registry.TokenStatusLists.KeyConfig.PrivateKeyPath = rsaKeyPath

	service, err := New(suite.ctx, suite.cfg, suite.dbService, suite.log)
	require.NoError(t, err)
	require.NotNil(t, service)
	assert.Contains(t, service.signer.Algorithm(), "RS") // RS256, RS384, or RS512
}

func TestNew_DefaultRefreshInterval(t *testing.T) {
	suite := newTestSuite(t)
	defer suite.cleanup()

	// Set refresh interval to 0 to use default
	suite.cfg.Registry.TokenStatusLists.TokenRefreshInterval = 0

	service, err := New(suite.ctx, suite.cfg, suite.dbService, suite.log)
	require.NoError(t, err)
	require.NotNil(t, service)

	// Default should be 43200 seconds (12 hours)
	assert.Equal(t, 43200*time.Second, service.refreshInterval)
	assert.Equal(t, int64(43200), service.ttl)

	err = service.Close(suite.ctx)
	assert.NoError(t, err)
}

func TestNew_CustomRefreshInterval(t *testing.T) {
	suite := newTestSuite(t)
	defer suite.cleanup()

	suite.cfg.Registry.TokenStatusLists.TokenRefreshInterval = 3600 // 1 hour

	service, err := New(suite.ctx, suite.cfg, suite.dbService, suite.log)
	require.NoError(t, err)
	require.NotNil(t, service)

	assert.Equal(t, 3600*time.Second, service.refreshInterval)
	assert.Equal(t, int64(3600), service.ttl)
	// Token validity should be refresh - 5 minutes
	expectedValidity := (3600 * time.Second) - (5 * time.Minute)
	assert.Equal(t, expectedValidity, service.tokenValidity)

	err = service.Close(suite.ctx)
	assert.NoError(t, err)
}

// ============================================================================
// AddStatus Tests
// ============================================================================

func TestAddStatus_Success(t *testing.T) {
	suite := newTestSuite(t)
	defer suite.cleanup()

	service, err := New(suite.ctx, suite.cfg, suite.dbService, suite.log)
	require.NoError(t, err)
	defer service.Close(suite.ctx)

	// Wait for initial cache refresh to complete
	time.Sleep(500 * time.Millisecond)

	// Add a valid status
	section, index, err := service.AddStatus(suite.ctx, tokenstatuslist.StatusValid)
	require.NoError(t, err)
	assert.Equal(t, int64(0), section) // Should be section 0
	assert.GreaterOrEqual(t, index, int64(0))

	t.Logf("Added status at section=%d, index=%d", section, index)
}

func TestAddStatus_MultipleStatuses(t *testing.T) {
	suite := newTestSuite(t)
	defer suite.cleanup()

	service, err := New(suite.ctx, suite.cfg, suite.dbService, suite.log)
	require.NoError(t, err)
	defer service.Close(suite.ctx)

	time.Sleep(500 * time.Millisecond)

	// Add multiple statuses
	statuses := []uint8{tokenstatuslist.StatusValid, tokenstatuslist.StatusInvalid, tokenstatuslist.StatusSuspended}
	results := make([]struct {
		section int64
		index   int64
	}, len(statuses))

	for i, status := range statuses {
		section, index, err := service.AddStatus(suite.ctx, status)
		require.NoError(t, err)
		results[i].section = section
		results[i].index = index
		t.Logf("Status %d: section=%d, index=%d", status, section, index)
	}

	// All should be in section 0
	for _, r := range results {
		assert.Equal(t, int64(0), r.section)
	}
}

// ============================================================================
// GetStatusListForSection Tests
// ============================================================================

func TestGetStatusListForSection_Success(t *testing.T) {
	suite := newTestSuite(t)
	defer suite.cleanup()

	service, err := New(suite.ctx, suite.cfg, suite.dbService, suite.log)
	require.NoError(t, err)
	defer service.Close(suite.ctx)

	time.Sleep(500 * time.Millisecond)

	// Get statuses for section 0 (should have decoys from initialization)
	statuses, err := service.GetStatusListForSection(suite.ctx, 0)
	require.NoError(t, err)
	assert.NotEmpty(t, statuses)

	// Should have 10,000 entries (decoys created during init, using test SectionSize)
	assert.Len(t, statuses, 10000)
}

func TestGetStatusListForSection_NonexistentSection(t *testing.T) {
	suite := newTestSuite(t)
	defer suite.cleanup()

	service, err := New(suite.ctx, suite.cfg, suite.dbService, suite.log)
	require.NoError(t, err)
	defer service.Close(suite.ctx)

	// Get statuses for nonexistent section
	statuses, err := service.GetStatusListForSection(suite.ctx, 999)
	require.NoError(t, err)
	assert.Empty(t, statuses)
}

// ============================================================================
// GetAllSections Tests
// ============================================================================

func TestGetAllSections_Success(t *testing.T) {
	suite := newTestSuite(t)
	defer suite.cleanup()

	service, err := New(suite.ctx, suite.cfg, suite.dbService, suite.log)
	require.NoError(t, err)
	defer service.Close(suite.ctx)

	sections, err := service.GetAllSections(suite.ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, sections)
	assert.Contains(t, sections, int64(0))
}

// ============================================================================
// Cache Tests
// ============================================================================

func TestGetCachedJWT_AfterRefresh(t *testing.T) {
	suite := newTestSuite(t)
	defer suite.cleanup()

	service, err := New(suite.ctx, suite.cfg, suite.dbService, suite.log)
	require.NoError(t, err)
	defer service.Close(suite.ctx)

	// Wait for initial cache refresh to populate the cache
	var jwt string
	require.Eventually(t, func() bool {
		jwt = service.GetCachedJWT(0)
		return jwt != ""
	}, 15*time.Second, 200*time.Millisecond, "JWT should be cached after initial refresh")

	// Verify it's a valid JWT format (header.payload.signature)
	parts := splitJWT(jwt)
	assert.Len(t, parts, 3, "JWT should have 3 parts")
}

func TestGetCachedCWT_AfterRefresh(t *testing.T) {
	suite := newTestSuite(t)
	defer suite.cleanup()

	service, err := New(suite.ctx, suite.cfg, suite.dbService, suite.log)
	require.NoError(t, err)
	defer service.Close(suite.ctx)

	// Wait for initial cache refresh
	var cwt []byte
	require.Eventually(t, func() bool {
		cwt = service.GetCachedCWT(0)
		return len(cwt) > 0
	}, 15*time.Second, 200*time.Millisecond, "CWT should be cached after initial refresh")

	// CWT starts with COSE tag
	assert.True(t, len(cwt) > 10, "CWT should have content")
}

func TestGetCachedJWT_NonexistentSection(t *testing.T) {
	suite := newTestSuite(t)
	defer suite.cleanup()

	service, err := New(suite.ctx, suite.cfg, suite.dbService, suite.log)
	require.NoError(t, err)
	defer service.Close(suite.ctx)

	// Get JWT for nonexistent section
	jwt := service.GetCachedJWT(999)
	assert.Empty(t, jwt)
}

func TestGetCachedCWT_NonexistentSection(t *testing.T) {
	suite := newTestSuite(t)
	defer suite.cleanup()

	service, err := New(suite.ctx, suite.cfg, suite.dbService, suite.log)
	require.NoError(t, err)
	defer service.Close(suite.ctx)

	// Get CWT for nonexistent section
	cwt := service.GetCachedCWT(999)
	assert.Nil(t, cwt)
}

// ============================================================================
// Token Generation Tests
// ============================================================================

func TestGenerateStatusListTokenJWT_Success(t *testing.T) {
	suite := newTestSuite(t)
	defer suite.cleanup()

	service, err := New(suite.ctx, suite.cfg, suite.dbService, suite.log)
	require.NoError(t, err)
	defer service.Close(suite.ctx)

	// Create test statuses
	statuses := []uint8{0, 1, 2, 0, 1}

	cfg := TokenConfig{
		TokenConfig: tokenstatuslist.TokenConfig{
			Subject:   "https://example.com/statuslists/1",
			Issuer:    "https://example.com",
			Statuses:  statuses,
			TTL:       43200,
			ExpiresIn: 12 * time.Hour,
		},
		SigningMethod: jwt.SigningMethodES256,
	}

	jwtToken, err := service.GenerateStatusListTokenJWT(suite.ctx, cfg)
	require.NoError(t, err)
	assert.NotEmpty(t, jwtToken)

	// Verify JWT structure
	parts := splitJWT(jwtToken)
	assert.Len(t, parts, 3)
}

func TestGenerateStatusListTokenCWT_Success(t *testing.T) {
	suite := newTestSuite(t)
	defer suite.cleanup()

	service, err := New(suite.ctx, suite.cfg, suite.dbService, suite.log)
	require.NoError(t, err)
	defer service.Close(suite.ctx)

	statuses := []uint8{0, 1, 2, 0, 1}

	cfg := TokenConfig{
		TokenConfig: tokenstatuslist.TokenConfig{
			Subject:   "https://example.com/statuslists/1",
			Issuer:    "https://example.com",
			Statuses:  statuses,
			TTL:       43200,
			ExpiresIn: 12 * time.Hour,
		},
	}

	cwt, err := service.GenerateStatusListTokenCWT(suite.ctx, cfg)
	require.NoError(t, err)
	assert.NotEmpty(t, cwt)
	assert.True(t, len(cwt) > 10)
}

// ============================================================================
// Close Tests
// ============================================================================

func TestClose_Success(t *testing.T) {
	suite := newTestSuite(t)
	defer suite.cleanup()

	service, err := New(suite.ctx, suite.cfg, suite.dbService, suite.log)
	require.NoError(t, err)

	err = service.Close(suite.ctx)
	assert.NoError(t, err)

	// After close, caches should be stopped (can't easily verify, but no panic)
}

// ============================================================================
// CreateNewSectionIfNeeded Tests
// ============================================================================

func TestCreateNewSectionIfNeeded_KeepsCurrentSection(t *testing.T) {
	suite := newTestSuite(t)
	defer suite.cleanup()

	service, err := New(suite.ctx, suite.cfg, suite.dbService, suite.log)
	require.NoError(t, err)
	defer service.Close(suite.ctx)

	time.Sleep(500 * time.Millisecond)

	// With 1M decoys, should stay on current section
	section, err := service.CreateNewSectionIfNeeded(suite.ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), section)
}

func TestCreateNewSectionIfNeeded_CreatesNewSection(t *testing.T) {
	// Use a small section size (1500) and consume decoys until below threshold (<=1000)
	// This triggers creating a new section
	suite := newTestSuiteWithSectionSize(t, 1500)
	defer suite.cleanup()

	service, err := New(suite.ctx, suite.cfg, suite.dbService, suite.log)
	require.NoError(t, err)
	defer service.Close(suite.ctx)

	// Initially should stay on section 0 (1500 decoys > 1000 threshold)
	section, err := service.CreateNewSectionIfNeeded(suite.ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), section)

	// Add statuses to consume decoys (each AddStatus converts one decoy to a real status)
	// We need to consume more than 500 decoys to get below 1000 threshold
	for i := 0; i < 501; i++ {
		_, _, err := service.AddStatus(suite.ctx, tokenstatuslist.StatusValid)
		require.NoError(t, err)
	}

	// Now we should have ~999 decoys remaining, which triggers new section creation
	section, err = service.CreateNewSectionIfNeeded(suite.ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), section, "Should create new section when decoys <= 1000")

	// Verify we can now add to the new section
	newSection, _, err := service.AddStatus(suite.ctx, tokenstatuslist.StatusInvalid)
	require.NoError(t, err)
	assert.Equal(t, int64(1), newSection, "New statuses should be added to section 1")
}

func TestCreateNewSectionIfNeeded_BoundaryDecoyCount(t *testing.T) {
	// Use exactly 1001 decoys - adding 1 status should trigger new section (1000 <= 1000)
	suite := newTestSuiteWithSectionSize(t, 1001)
	defer suite.cleanup()

	service, err := New(suite.ctx, suite.cfg, suite.dbService, suite.log)
	require.NoError(t, err)
	defer service.Close(suite.ctx)

	// Initially 1001 decoys, should stay on section 0
	section, err := service.CreateNewSectionIfNeeded(suite.ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), section)

	// Add one status to consume one decoy (now 1000 decoys remaining)
	_, _, err = service.AddStatus(suite.ctx, tokenstatuslist.StatusValid)
	require.NoError(t, err)

	// Now exactly 1000 decoys, should create new section (threshold is <=1000)
	section, err = service.CreateNewSectionIfNeeded(suite.ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), section, "Should create new section when decoys == 1000")
}

func TestCreateNewSectionIfNeeded_AboveBoundaryDecoyCount(t *testing.T) {
	// Use 1002 decoys - should NOT create new section until we consume 2
	suite := newTestSuiteWithSectionSize(t, 1002)
	defer suite.cleanup()

	service, err := New(suite.ctx, suite.cfg, suite.dbService, suite.log)
	require.NoError(t, err)
	defer service.Close(suite.ctx)

	// Add one status (now 1001 decoys remaining, still > 1000)
	_, _, err = service.AddStatus(suite.ctx, tokenstatuslist.StatusValid)
	require.NoError(t, err)

	// Should stay on section 0 (1001 > 1000)
	section, err := service.CreateNewSectionIfNeeded(suite.ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), section, "Should stay on current section when decoys > 1000")
}

func TestCreateNewSectionIfNeeded_MultipleSections(t *testing.T) {
	// Test creating multiple sections by depleting decoys repeatedly
	suite := newTestSuiteWithSectionSize(t, 1010) // Small size for quick test
	defer suite.cleanup()

	service, err := New(suite.ctx, suite.cfg, suite.dbService, suite.log)
	require.NoError(t, err)
	defer service.Close(suite.ctx)

	// Consume 10 decoys to trigger first section change
	for i := 0; i < 10; i++ {
		_, _, err := service.AddStatus(suite.ctx, tokenstatuslist.StatusValid)
		require.NoError(t, err)
	}

	// Should now be on section 1
	section, err := service.CreateNewSectionIfNeeded(suite.ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), section)

	// Continue adding to consume decoys in section 1
	for i := 0; i < 10; i++ {
		_, _, err := service.AddStatus(suite.ctx, tokenstatuslist.StatusValid)
		require.NoError(t, err)
	}

	// Should now be on section 2
	section, err = service.CreateNewSectionIfNeeded(suite.ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), section)

	// Verify sections are tracked
	sections, err := service.GetAllSections(suite.ctx)
	require.NoError(t, err)
	assert.Contains(t, sections, int64(0))
	assert.Contains(t, sections, int64(1))
	assert.Contains(t, sections, int64(2))
}

// ============================================================================
// Refresh Loop Tests
// ============================================================================

func TestRefreshLoop_PopulatesCache(t *testing.T) {
	suite := newTestSuite(t)
	defer suite.cleanup()

	service, err := New(suite.ctx, suite.cfg, suite.dbService, suite.log)
	require.NoError(t, err)
	defer service.Close(suite.ctx)

	// The refresh loop runs immediately on start
	// Wait for it to complete
	var jwtToken string
	var cwtToken []byte
	require.Eventually(t, func() bool {
		jwtToken = service.GetCachedJWT(0)
		cwtToken = service.GetCachedCWT(0)
		return jwtToken != "" && len(cwtToken) > 0
	}, 15*time.Second, 200*time.Millisecond, "Cache should be populated by refresh loop")

	assert.NotEmpty(t, jwtToken, "JWT cache should be populated by refresh loop")
	assert.NotEmpty(t, cwtToken, "CWT cache should be populated by refresh loop")
}

func TestRefreshLoop_StopsOnClose(t *testing.T) {
	suite := newTestSuite(t)
	defer suite.cleanup()

	service, err := New(suite.ctx, suite.cfg, suite.dbService, suite.log)
	require.NoError(t, err)

	// Close should stop the refresh loop without hanging
	done := make(chan struct{})
	go func() {
		err := service.Close(suite.ctx)
		assert.NoError(t, err)
		close(done)
	}()

	select {
	case <-done:
		// Success - close completed
	case <-time.After(5 * time.Second):
		t.Fatal("Close took too long - refresh loop may not have stopped")
	}
}

func TestRefreshLoop_StopsOnContextCancel(t *testing.T) {
	suite := newTestSuite(t)
	defer suite.cleanup()

	// Create a cancellable context
	ctx, cancel := context.WithCancel(suite.ctx)

	service, err := New(ctx, suite.cfg, suite.dbService, suite.log)
	require.NoError(t, err)

	// Cancel the context
	cancel()

	// Give time for loop to stop
	time.Sleep(500 * time.Millisecond)

	// Clean up
	err = service.Close(suite.ctx)
	assert.NoError(t, err)
}

// ============================================================================
// Integration Test: Full Flow
// ============================================================================

func TestIntegration_AddStatusAndRetrieve(t *testing.T) {
	suite := newTestSuite(t)
	defer suite.cleanup()

	service, err := New(suite.ctx, suite.cfg, suite.dbService, suite.log)
	require.NoError(t, err)
	defer service.Close(suite.ctx)

	// Wait for initial refresh
	time.Sleep(2 * time.Second)

	// Add a new status
	section, index, err := service.AddStatus(suite.ctx, tokenstatuslist.StatusInvalid)
	require.NoError(t, err)
	t.Logf("Added status at section=%d, index=%d", section, index)

	// Retrieve all statuses for the section
	statuses, err := service.GetStatusListForSection(suite.ctx, section)
	require.NoError(t, err)
	require.Greater(t, len(statuses), int(index))

	// The status at the index should be what we set
	assert.Equal(t, tokenstatuslist.StatusInvalid, statuses[index])
}

func TestIntegration_CacheConsistency(t *testing.T) {
	suite := newTestSuite(t)
	defer suite.cleanup()

	service, err := New(suite.ctx, suite.cfg, suite.dbService, suite.log)
	require.NoError(t, err)
	defer service.Close(suite.ctx)

	// Wait for initial cache population (may take a few seconds due to 1M decoys)
	var jwt1 string
	var cwt1 []byte
	require.Eventually(t, func() bool {
		jwt1 = service.GetCachedJWT(0)
		cwt1 = service.GetCachedCWT(0)
		return jwt1 != "" && len(cwt1) > 0
	}, 15*time.Second, 200*time.Millisecond, "JWT and CWT cache should be populated")

	// Get them again - should be the same (cached)
	jwt2 := service.GetCachedJWT(0)
	assert.Equal(t, jwt1, jwt2, "JWT should be consistent")

	cwt2 := service.GetCachedCWT(0)
	assert.Equal(t, cwt1, cwt2, "CWT should be consistent")
}

// ============================================================================
// Helper Functions
// ============================================================================

func splitJWT(jwt string) []string {
	return strings.Split(jwt, ".")
}
