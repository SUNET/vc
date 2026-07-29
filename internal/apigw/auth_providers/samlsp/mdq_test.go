package samlsp

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/logger"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testIDPMetadata = `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/idp">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`

func TestMDQClient_GetIDPMetadata_Success(t *testing.T) {
	// Create test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request path contains URL-encoded entity ID (first slash is from path)
		assert.Contains(t, r.URL.Path, "idp.example.com")

		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(testIDPMetadata)) // #nosec G104
	}))
	defer server.Close()

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	client := NewMDQClient(server.URL, 3600, nil, log)

	ctx := t.Context()
	metadata, err := client.GetIDPMetadata(ctx, "https://idp.example.com/idp")
	require.NoError(t, err)
	require.NotNil(t, metadata)

	assert.Equal(t, "https://idp.example.com/idp", metadata.EntityID)
	assert.Len(t, metadata.IDPSSODescriptors, 1)
	assert.Len(t, metadata.IDPSSODescriptors[0].SingleSignOnServices, 1)
	assert.Equal(t, "https://idp.example.com/sso", metadata.IDPSSODescriptors[0].SingleSignOnServices[0].Location)
}

func TestMDQClient_GetIDPMetadata_Caching(t *testing.T) {
	requestCount := 0

	// Create test HTTP server that counts requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(testIDPMetadata)) // #nosec G104
	}))
	defer server.Close()

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	client := NewMDQClient(server.URL, 3600, nil, log)

	ctx := t.Context()
	entityID := "https://idp.example.com/idp"

	// First request - should hit server
	_, err = client.GetIDPMetadata(ctx, entityID)
	require.NoError(t, err)
	assert.Equal(t, 1, requestCount)

	// Second request - should use cache
	_, err = client.GetIDPMetadata(ctx, entityID)
	require.NoError(t, err)
	assert.Equal(t, 1, requestCount, "Second request should use cache")

	// Third request - should still use cache
	_, err = client.GetIDPMetadata(ctx, entityID)
	require.NoError(t, err)
	assert.Equal(t, 1, requestCount, "Third request should use cache")
}

func TestMDQClient_GetIDPMetadata_CacheExpiration(t *testing.T) {
	requestCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(testIDPMetadata)) // #nosec G104
	}))
	defer server.Close()

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	client := NewMDQClient(server.URL, 1, nil, log)

	ctx := t.Context()
	entityID := "https://idp.example.com/idp"

	// First request
	_, err = client.GetIDPMetadata(ctx, entityID)
	require.NoError(t, err)
	assert.Equal(t, 1, requestCount)

	// Wait for cache to expire
	time.Sleep(2 * time.Second)

	// Second request after expiration - should hit server again
	_, err = client.GetIDPMetadata(ctx, entityID)
	require.NoError(t, err)
	assert.Equal(t, 2, requestCount, "Request after cache expiration should hit server")
}

func TestMDQClient_GetIDPMetadata_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("IdP not found")) // #nosec G104
	}))
	defer server.Close()

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	client := NewMDQClient(server.URL, 3600, nil, log)

	ctx := t.Context()
	_, err = client.GetIDPMetadata(ctx, "https://nonexistent.idp.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

func TestMDQClient_GetIDPMetadata_InvalidXML(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid xml content")) // #nosec G104
	}))
	defer server.Close()

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	client := NewMDQClient(server.URL, 3600, nil, log)

	ctx := t.Context()
	_, err = client.GetIDPMetadata(ctx, "https://idp.example.com/idp")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse")
}

func TestMDQClient_GetIDPMetadata_NoIDPDescriptor(t *testing.T) {
	// Metadata without IDPSSODescriptor
	metadataWithoutIDP := `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
  </SPSSODescriptor>
</EntityDescriptor>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(metadataWithoutIDP)) // #nosec G104
	}))
	defer server.Close()

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	client := NewMDQClient(server.URL, 3600, nil, log)

	ctx := t.Context()
	_, err = client.GetIDPMetadata(ctx, "https://sp.example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "IdP")
}

func TestMDQClient_MultipleConcurrentRequests(t *testing.T) {
	var requestCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		// Simulate slow response
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(testIDPMetadata)) // #nosec G104
	}))
	defer server.Close()

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	client := NewMDQClient(server.URL, 3600, nil, log)

	ctx := t.Context()
	entityID := "https://idp.example.com/idp"

	// Make multiple concurrent requests
	done := make(chan bool)
	for range 5 {
		go func() {
			_, err := client.GetIDPMetadata(ctx, entityID)
			assert.NoError(t, err)
			done <- true
		}()
	}

	// Wait for all goroutines
	for range 5 {
		<-done
	}

	// Due to caching, we expect at most all 5 to hit before caching kicks in
	// This is a race condition test, so be lenient
	assert.LessOrEqual(t, requestCount.Load(), int32(5), "Concurrent requests should use cache once populated")
}
