package apiv1

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/tokenstatuslist"
)

// int64Ptr is a helper to create a pointer to an int64
func int64Ptr(v int64) *int64 {
	return &v
}

// mockTokenStatusListIssuer is a mock implementation of the TokenStatusListIssuer interface for testing
type mockTokenStatusListIssuer struct {
	jwtCache *ttlcache.Cache[string, string]
	cwtCache *ttlcache.Cache[string, []byte]
	sections []int64
	err      error
}

func newMockTokenStatusListIssuer() *mockTokenStatusListIssuer {
	return &mockTokenStatusListIssuer{
		jwtCache: ttlcache.New(ttlcache.WithTTL[string, string](time.Hour)),
		cwtCache: ttlcache.New(ttlcache.WithTTL[string, []byte](time.Hour)),
		sections: []int64{},
	}
}

func (m *mockTokenStatusListIssuer) GetCachedJWT(section int64) string {
	key := strconv.FormatInt(section, 10)
	item := m.jwtCache.Get(key)
	if item == nil {
		return ""
	}
	return item.Value()
}

func (m *mockTokenStatusListIssuer) GetCachedCWT(section int64) []byte {
	key := strconv.FormatInt(section, 10)
	item := m.cwtCache.Get(key)
	if item == nil {
		return nil
	}
	return item.Value()
}

func (m *mockTokenStatusListIssuer) GetAllSections(ctx context.Context) ([]int64, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.sections, nil
}

func (m *mockTokenStatusListIssuer) SetJWT(section int64, jwt string) {
	key := strconv.FormatInt(section, 10)
	m.jwtCache.Set(key, jwt, ttlcache.DefaultTTL)
}

func (m *mockTokenStatusListIssuer) SetCWT(section int64, cwt []byte) {
	key := strconv.FormatInt(section, 10)
	m.cwtCache.Set(key, cwt, ttlcache.DefaultTTL)
}

func (m *mockTokenStatusListIssuer) SetSections(sections []int64) {
	m.sections = sections
}

func (m *mockTokenStatusListIssuer) SetError(err error) {
	m.err = err
}

// newTestClient creates a Client with mock dependencies for testing
func newTestClient() (*Client, *mockTokenStatusListIssuer) {
	mock := newMockTokenStatusListIssuer()
	client := &Client{
		cfg: &model.Cfg{
			Registry: &model.Registry{
				ExternalServerURL: "https://example.com",
			},
		},
		log:                   logger.NewSimple("test"),
		tokenStatusListIssuer: mock,
	}
	return client, mock
}

// ============================================================================
// StatusLists Handler Tests
// ============================================================================

func TestTokenStatusLists_Success_JWT(t *testing.T) {
	client, mock := newTestClient()
	ctx := t.Context()

	// Setup: add a JWT to the cache
	expectedJWT := "eyJhbGciOiJFUzI1NiIsInR5cCI6InN0YXR1c2xpc3Qrand0In0.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9zdGF0dXNsaXN0cy8xIiwiZXhwIjoyMjkxNzIwMTcwLCJpYXQiOjE2ODY5MjAxNzAsInN0YXR1c19saXN0Ijp7ImJpdHMiOjgsImxzdCI6ImVOcmJ1UmdBQWhjQlhRIn0sInR0bCI6NDMyMDB9.signature"
	mock.SetJWT(1, expectedJWT)

	req := &TokenStatusListsRequest{
		ID:     1,
		Accept: "", // Default to JWT
	}

	resp, err := client.TokenStatusLists(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, tokenstatuslist.MediaTypeJWT, resp.ContentType)
	assert.Equal(t, expectedJWT, string(resp.Token))
}

func TestTokenStatusLists_Success_JWT_ExplicitAcceptHeader(t *testing.T) {
	client, mock := newTestClient()
	ctx := t.Context()

	expectedJWT := "eyJhbGciOiJFUzI1NiJ9.payload.signature"
	mock.SetJWT(42, expectedJWT)

	req := &TokenStatusListsRequest{
		ID:     42,
		Accept: tokenstatuslist.MediaTypeJWT,
	}

	resp, err := client.TokenStatusLists(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, tokenstatuslist.MediaTypeJWT, resp.ContentType)
	assert.Equal(t, expectedJWT, string(resp.Token))
}

func TestTokenStatusLists_Success_CWT(t *testing.T) {
	client, mock := newTestClient()
	ctx := t.Context()

	// CWT is binary data
	expectedCWT := []byte{0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA0, 0x58, 0x24}
	mock.SetCWT(1, expectedCWT)

	req := &TokenStatusListsRequest{
		ID:     1,
		Accept: tokenstatuslist.MediaTypeCWT,
	}

	resp, err := client.TokenStatusLists(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, tokenstatuslist.MediaTypeCWT, resp.ContentType)
	assert.Equal(t, expectedCWT, resp.Token)
}

func TestTokenStatusLists_SectionNotFound_JWT(t *testing.T) {
	client, _ := newTestClient()
	ctx := t.Context()

	req := &TokenStatusListsRequest{
		ID:     999, // Non-existent section
		Accept: "",  // Default JWT
	}

	resp, err := client.TokenStatusLists(ctx, req)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, tokenstatuslist.ErrSectionNotFound)
}

func TestTokenStatusLists_SectionNotFound_CWT(t *testing.T) {
	client, _ := newTestClient()
	ctx := t.Context()

	req := &TokenStatusListsRequest{
		ID:     999, // Non-existent section
		Accept: tokenstatuslist.MediaTypeCWT,
	}

	resp, err := client.TokenStatusLists(ctx, req)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, tokenstatuslist.ErrSectionNotFound)
}

func TestTokenStatusLists_HistoricalResolution_NotSupported(t *testing.T) {
	client, mock := newTestClient()
	ctx := t.Context()

	// Add data to cache so we know it's not a "not found" error
	mock.SetJWT(1, "some.jwt.token")

	req := &TokenStatusListsRequest{
		ID:   1,
		Time: int64Ptr(1686920170), // Valid Unix timestamp
	}

	resp, err := client.TokenStatusLists(ctx, req)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, tokenstatuslist.ErrHistoricalResolutionNotSupported)
}

// TestTokenStatusLists_NegativeTimeParameter tests that negative timestamps are valid
// (they represent dates before Unix epoch 1970-01-01) but still return historical
// resolution not supported
func TestTokenStatusLists_NegativeTimeParameter(t *testing.T) {
	client, mock := newTestClient()
	ctx := t.Context()

	mock.SetJWT(1, "some.jwt.token")

	req := &TokenStatusListsRequest{
		ID:   1,
		Time: int64Ptr(-1234567890), // Valid negative timestamp (before 1970)
	}

	resp, err := client.TokenStatusLists(ctx, req)
	assert.Nil(t, resp)
	// Negative timestamps are valid int64, so we get historical not supported
	assert.ErrorIs(t, err, tokenstatuslist.ErrHistoricalResolutionNotSupported)
}

func TestTokenStatusLists_UnrecognizedAcceptHeader_DefaultsToJWT(t *testing.T) {
	client, mock := newTestClient()
	ctx := t.Context()

	expectedJWT := "default.jwt.token"
	mock.SetJWT(1, expectedJWT)

	testCases := []string{
		"application/json",
		"text/html",
		"*/*",
		"application/xml",
		"invalid-media-type",
	}

	for _, accept := range testCases {
		t.Run(accept, func(t *testing.T) {
			req := &TokenStatusListsRequest{
				ID:     1,
				Accept: accept,
			}

			resp, err := client.TokenStatusLists(ctx, req)
			require.NoError(t, err)
			require.NotNil(t, resp)

			assert.Equal(t, tokenstatuslist.MediaTypeJWT, resp.ContentType)
			assert.Equal(t, expectedJWT, string(resp.Token))
		})
	}
}

func TestTokenStatusLists_MultipleSections(t *testing.T) {
	client, mock := newTestClient()
	ctx := t.Context()

	// Setup multiple sections
	mock.SetJWT(0, "jwt.section.0")
	mock.SetJWT(1, "jwt.section.1")
	mock.SetJWT(100, "jwt.section.100")
	mock.SetCWT(0, []byte{0x00})
	mock.SetCWT(1, []byte{0x01})
	mock.SetCWT(100, []byte{0x64})

	// Test each section
	sections := []int64{0, 1, 100}
	for _, section := range sections {
		t.Run("JWT_section_"+strconv.FormatInt(section, 10), func(t *testing.T) {
			req := &TokenStatusListsRequest{
				ID:     section,
				Accept: tokenstatuslist.MediaTypeJWT,
			}
			resp, err := client.TokenStatusLists(ctx, req)
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, tokenstatuslist.MediaTypeJWT, resp.ContentType)
		})

		t.Run("CWT_section_"+strconv.FormatInt(section, 10), func(t *testing.T) {
			req := &TokenStatusListsRequest{
				ID:     section,
				Accept: tokenstatuslist.MediaTypeCWT,
			}
			resp, err := client.TokenStatusLists(ctx, req)
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, tokenstatuslist.MediaTypeCWT, resp.ContentType)
		})
	}
}

func TestTokenStatusLists_LargeSectionID(t *testing.T) {
	client, mock := newTestClient()
	ctx := t.Context()

	// Test with a large section ID
	largeSectionID := int64(9223372036854775807) // Max int64
	expectedJWT := "jwt.for.large.section"
	mock.SetJWT(largeSectionID, expectedJWT)

	req := &TokenStatusListsRequest{
		ID: largeSectionID,
	}

	resp, err := client.TokenStatusLists(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, expectedJWT, string(resp.Token))
}

func TestTokenStatusLists_ZeroSectionID(t *testing.T) {
	client, mock := newTestClient()
	ctx := t.Context()

	expectedJWT := "jwt.for.section.zero"
	mock.SetJWT(0, expectedJWT)

	req := &TokenStatusListsRequest{
		ID: 0,
	}

	resp, err := client.TokenStatusLists(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, expectedJWT, string(resp.Token))
}

// ============================================================================
// TokenStatusListAggregation Handler Tests
// ============================================================================

func TestTokenStatusListAggregation_Success_Empty(t *testing.T) {
	client, mock := newTestClient()
	ctx := t.Context()

	mock.SetSections([]int64{})

	resp, err := client.TokenStatusListAggregation(ctx)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Empty(t, resp.StatusLists)
}

func TestTokenStatusListAggregation_Success_SingleSection(t *testing.T) {
	client, mock := newTestClient()
	ctx := t.Context()

	mock.SetSections([]int64{1})

	resp, err := client.TokenStatusListAggregation(ctx)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Len(t, resp.StatusLists, 1)
	assert.Equal(t, "https://example.com/statuslists/1", resp.StatusLists[0])
}

func TestTokenStatusListAggregation_Success_MultipleSections(t *testing.T) {
	client, mock := newTestClient()
	ctx := t.Context()

	mock.SetSections([]int64{0, 1, 2, 10, 100})

	resp, err := client.TokenStatusListAggregation(ctx)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Len(t, resp.StatusLists, 5)

	expected := []string{
		"https://example.com/statuslists/0",
		"https://example.com/statuslists/1",
		"https://example.com/statuslists/2",
		"https://example.com/statuslists/10",
		"https://example.com/statuslists/100",
	}
	assert.Equal(t, expected, resp.StatusLists)
}

func TestTokenStatusListAggregation_Error_DatabaseFailure(t *testing.T) {
	client, mock := newTestClient()
	ctx := t.Context()

	dbError := errors.New("database connection failed")
	mock.SetError(dbError)

	resp, err := client.TokenStatusListAggregation(ctx)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, dbError)
}

func TestTokenStatusListAggregation_DifferentBaseURLs(t *testing.T) {
	testCases := []struct {
		name        string
		baseURL     string
		expectedURI string
	}{
		{
			name:        "https_url",
			baseURL:     "https://registry.example.com",
			expectedURI: "https://registry.example.com/statuslists/1",
		},
		{
			name:        "http_url",
			baseURL:     "http://localhost:8080",
			expectedURI: "http://localhost:8080/statuslists/1",
		},
		{
			name:        "with_path",
			baseURL:     "https://api.example.com/v1",
			expectedURI: "https://api.example.com/v1/statuslists/1",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			client, mock := newTestClient()
			client.cfg.Registry.ExternalServerURL = tt.baseURL
			mock.SetSections([]int64{1})

			ctx := t.Context()
			resp, err := client.TokenStatusListAggregation(ctx)
			require.NoError(t, err)
			require.NotNil(t, resp)

			assert.Len(t, resp.StatusLists, 1)
			assert.Equal(t, tt.expectedURI, resp.StatusLists[0])
		})
	}
}

func TestTokenStatusListAggregation_LargeSectionNumbers(t *testing.T) {
	client, mock := newTestClient()
	ctx := t.Context()

	// Test with large section numbers
	mock.SetSections([]int64{0, 999999, 1000000})

	resp, err := client.TokenStatusListAggregation(ctx)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Len(t, resp.StatusLists, 3)
	assert.Contains(t, resp.StatusLists[0], "/statuslists/0")
	assert.Contains(t, resp.StatusLists[1], "/statuslists/999999")
	assert.Contains(t, resp.StatusLists[2], "/statuslists/1000000")
}

// ============================================================================
// Request/Response Type Tests
// ============================================================================

func TestTokenStatusListsRequest_Fields(t *testing.T) {
	timeVal := int64(1686920170)
	req := &TokenStatusListsRequest{
		ID:     42,
		Time:   &timeVal,
		Accept: tokenstatuslist.MediaTypeCWT,
	}

	assert.Equal(t, int64(42), req.ID)
	assert.Equal(t, int64(1686920170), *req.Time)
	assert.Equal(t, tokenstatuslist.MediaTypeCWT, req.Accept)
}

func TestTokenStatusListsRequest_NilTime(t *testing.T) {
	req := &TokenStatusListsRequest{
		ID:     42,
		Accept: tokenstatuslist.MediaTypeCWT,
	}

	assert.Equal(t, int64(42), req.ID)
	assert.Nil(t, req.Time)
	assert.Equal(t, tokenstatuslist.MediaTypeCWT, req.Accept)
}

func TestTokenStatusListsResponse_Fields(t *testing.T) {
	resp := &TokenStatusListsResponse{
		Token:       []byte("test-token"),
		ContentType: tokenstatuslist.MediaTypeJWT,
	}

	assert.Equal(t, []byte("test-token"), resp.Token)
	assert.Equal(t, tokenstatuslist.MediaTypeJWT, resp.ContentType)
}

func TestTokenStatusListAggregationResponse_Fields(t *testing.T) {
	resp := &TokenStatusListAggregationResponse{
		StatusLists: []string{
			"https://example.com/statuslists/1",
			"https://example.com/statuslists/2",
		},
	}

	assert.Len(t, resp.StatusLists, 2)
	assert.Equal(t, "https://example.com/statuslists/1", resp.StatusLists[0])
}

// ============================================================================
// Edge Cases and Boundary Tests
// ============================================================================

func TestTokenStatusLists_EmptyJWTInCache(t *testing.T) {
	client, _ := newTestClient()
	ctx := t.Context()

	// Empty cache - section not found
	req := &TokenStatusListsRequest{
		ID: 1,
	}

	resp, err := client.TokenStatusLists(ctx, req)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, tokenstatuslist.ErrSectionNotFound)
}

func TestTokenStatusLists_EmptyCWTInCache(t *testing.T) {
	client, _ := newTestClient()
	ctx := t.Context()

	// Similar to JWT, nil/empty CWT should be not found
	req := &TokenStatusListsRequest{
		ID:     1,
		Accept: tokenstatuslist.MediaTypeCWT,
	}

	resp, err := client.TokenStatusLists(ctx, req)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, tokenstatuslist.ErrSectionNotFound)
}

func TestTokenStatusLists_CWTWithBinaryData(t *testing.T) {
	client, mock := newTestClient()
	ctx := t.Context()

	// Test with various binary patterns
	binaryData := []byte{
		0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD,
		0x80, 0x7F, 0x00, 0x00, 0x00, 0x00,
	}
	mock.SetCWT(1, binaryData)

	req := &TokenStatusListsRequest{
		ID:     1,
		Accept: tokenstatuslist.MediaTypeCWT,
	}

	resp, err := client.TokenStatusLists(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, binaryData, resp.Token)
}

func TestTokenStatusLists_JWTWithSpecialCharacters(t *testing.T) {
	client, mock := newTestClient()
	ctx := t.Context()

	// JWT with base64url characters
	jwtToken := "eyJhbGciOiJFUzI1NiIsInR5cCI6InN0YXR1c2xpc3Qrand0In0.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9zdGF0dXNsaXN0cy8xIn0.MEUCIQDnGL_-gEP-3Z0xBLJJKz6x_d1WBHdPFX0H8oNTn8A4ngIgYbw7E6ydR0WC5sF8xGCNW7EzNqVZ8EH3qJNs0MxVH-A"
	mock.SetJWT(1, jwtToken)

	req := &TokenStatusListsRequest{
		ID: 1,
	}

	resp, err := client.TokenStatusLists(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, jwtToken, string(resp.Token))
}

func TestTokenStatusLists_TimeParameter_ValidTimestamps(t *testing.T) {
	client, mock := newTestClient()
	ctx := t.Context()

	// Even valid timestamps should return "not supported" error
	validTimestamps := []int64{
		0,
		1,
		1686920170,
		2147483647,       // Max 32-bit timestamp
		9999999999999999, // Far future
	}

	mock.SetJWT(1, "some.jwt.token")

	for _, ts := range validTimestamps {
		t.Run("timestamp_"+strconv.FormatInt(ts, 10), func(t *testing.T) {
			req := &TokenStatusListsRequest{
				ID:   1,
				Time: int64Ptr(ts),
			}

			resp, err := client.TokenStatusLists(ctx, req)
			assert.Nil(t, resp)
			assert.ErrorIs(t, err, tokenstatuslist.ErrHistoricalResolutionNotSupported)
		})
	}
}

// ============================================================================
// Concurrency Tests
// ============================================================================

func TestTokenStatusLists_ConcurrentAccess(t *testing.T) {
	client, mock := newTestClient()
	ctx := t.Context()

	// Setup cache
	mock.SetJWT(1, "jwt.token.1")
	mock.SetCWT(1, []byte{0x01, 0x02, 0x03})

	// Run concurrent requests
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func(i int) {
			var req *TokenStatusListsRequest
			if i%2 == 0 {
				req = &TokenStatusListsRequest{ID: 1, Accept: tokenstatuslist.MediaTypeJWT}
			} else {
				req = &TokenStatusListsRequest{ID: 1, Accept: tokenstatuslist.MediaTypeCWT}
			}

			resp, err := client.TokenStatusLists(ctx, req)
			assert.NoError(t, err)
			assert.NotNil(t, resp)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}
}

func TestTokenStatusListAggregation_ConcurrentAccess(t *testing.T) {
	client, mock := newTestClient()
	ctx := t.Context()

	mock.SetSections([]int64{1, 2, 3, 4, 5})

	done := make(chan bool)
	for i := 0; i < 50; i++ {
		go func() {
			resp, err := client.TokenStatusListAggregation(ctx)
			assert.NoError(t, err)
			assert.NotNil(t, resp)
			assert.Len(t, resp.StatusLists, 5)
			done <- true
		}()
	}

	for i := 0; i < 50; i++ {
		<-done
	}
}

// ============================================================================
// Media Type Constants Tests
// ============================================================================

func TestMediaTypeConstants(t *testing.T) {
	// Verify the media type constants match the spec
	assert.Equal(t, "application/statuslist+jwt", tokenstatuslist.MediaTypeJWT)
	assert.Equal(t, "application/statuslist+cwt", tokenstatuslist.MediaTypeCWT)
}

// ============================================================================
// Error Type Tests
// ============================================================================

func TestErrorTypes(t *testing.T) {
	// Verify error types are properly defined
	assert.NotNil(t, tokenstatuslist.ErrSectionNotFound)
	assert.NotNil(t, tokenstatuslist.ErrInvalidTimeParameter)
	assert.NotNil(t, tokenstatuslist.ErrHistoricalResolutionNotSupported)

	// Verify error messages are meaningful
	assert.Contains(t, tokenstatuslist.ErrSectionNotFound.Error(), "not found")
	assert.Contains(t, tokenstatuslist.ErrInvalidTimeParameter.Error(), "time")
	assert.Contains(t, tokenstatuslist.ErrHistoricalResolutionNotSupported.Error(), "historical")
}

// ============================================================================
// Client Constructor Test
// ============================================================================

func TestNew(t *testing.T) {
	ctx := t.Context()
	cfg := &model.Cfg{
		Registry: &model.Registry{
			ExternalServerURL: "https://example.com",
		},
	}
	log := logger.NewSimple("test")
	mock := newMockTokenStatusListIssuer()

	client, err := New(ctx, cfg, mock, nil, log)
	require.NoError(t, err)
	require.NotNil(t, client)

	assert.Equal(t, cfg, client.cfg)
	assert.NotNil(t, client.log)
	assert.Equal(t, mock, client.tokenStatusListIssuer)
}

// ============================================================================
// Interface Compliance Test
// ============================================================================

func TestMockTokenStatusListIssuer_ImplementsInterface(t *testing.T) {
	// Verify that mockTokenStatusListIssuer implements TokenStatusListIssuer interface
	var _ TokenStatusListIssuer = (*mockTokenStatusListIssuer)(nil)
}
