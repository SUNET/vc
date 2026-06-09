package samlsp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/SUNET/vc/pkg/logger"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testStaticIDPMetadata = `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://static-idp.example.com/idp">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://static-idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`

func TestNewStaticMDQClient_FromFile(t *testing.T) {
	// Create temporary metadata file
	tmpDir := t.TempDir()
	metadataPath := filepath.Join(tmpDir, "idp-metadata.xml")
	err := os.WriteFile(metadataPath, []byte(testStaticIDPMetadata), 0o644) // #nosec G306
	require.NoError(t, err)

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	// Create static MDQ client from file
	client, err := NewStaticMDQClient(metadataPath, "https://static-idp.example.com/idp", false, nil, log)
	require.NoError(t, err)
	require.NotNil(t, client)

	// Verify static mode is enabled
	assert.True(t, client.IsStaticMode())
	assert.Equal(t, "https://static-idp.example.com/idp", client.GetStaticEntityID())

	// Test fetching metadata (should return static metadata)
	ctx := t.Context()
	metadata, err := client.GetIDPMetadata(ctx, "https://static-idp.example.com/idp")
	require.NoError(t, err)
	require.NotNil(t, metadata)

	assert.Equal(t, "https://static-idp.example.com/idp", metadata.EntityID)
	assert.Len(t, metadata.IDPSSODescriptors, 1)
	assert.Equal(t, "https://static-idp.example.com/sso", metadata.IDPSSODescriptors[0].SingleSignOnServices[0].Location)
}

func TestNewStaticMDQClient_FromURL(t *testing.T) {
	// Create test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(testStaticIDPMetadata)) // #nosec G104
	}))
	defer server.Close()

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	// Create static MDQ client from URL
	client, err := NewStaticMDQClient(server.URL+"/metadata", "https://static-idp.example.com/idp", true, nil, log)
	require.NoError(t, err)
	require.NotNil(t, client)

	// Verify static mode is enabled
	assert.True(t, client.IsStaticMode())
	assert.Equal(t, "https://static-idp.example.com/idp", client.GetStaticEntityID())

	// Test fetching metadata (should return static metadata)
	ctx := t.Context()
	metadata, err := client.GetIDPMetadata(ctx, "https://static-idp.example.com/idp")
	require.NoError(t, err)
	require.NotNil(t, metadata)

	assert.Equal(t, "https://static-idp.example.com/idp", metadata.EntityID)
}

func TestStaticMDQClient_GetIDPMetadata_IgnoresEntityID(t *testing.T) {
	// Create temporary metadata file
	tmpDir := t.TempDir()
	metadataPath := filepath.Join(tmpDir, "idp-metadata.xml")
	err := os.WriteFile(metadataPath, []byte(testStaticIDPMetadata), 0o644) // #nosec G306
	require.NoError(t, err)

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	client, err := NewStaticMDQClient(metadataPath, "https://static-idp.example.com/idp", false, nil, log)
	require.NoError(t, err)

	ctx := t.Context()

	// Request with different entity ID - should still return static metadata
	metadata, err := client.GetIDPMetadata(ctx, "https://different-idp.example.com")
	require.NoError(t, err)
	require.NotNil(t, metadata)

	// Should still get the static IdP metadata
	assert.Equal(t, "https://static-idp.example.com/idp", metadata.EntityID)

	// Request with empty entity ID - should also work
	metadata, err = client.GetIDPMetadata(ctx, "")
	require.NoError(t, err)
	assert.Equal(t, "https://static-idp.example.com/idp", metadata.EntityID)
}

func TestNewStaticMDQClient_FileNotFound(t *testing.T) {
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	// Try to create client with non-existent file
	_, err = NewStaticMDQClient("/nonexistent/metadata.xml", "https://idp.example.com", false, nil, log)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read metadata file")
}

func TestNewStaticMDQClient_InvalidXML(t *testing.T) {
	tmpDir := t.TempDir()
	metadataPath := filepath.Join(tmpDir, "invalid-metadata.xml")
	err := os.WriteFile(metadataPath, []byte("not valid xml"), 0o644) // #nosec G306
	require.NoError(t, err)

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	_, err = NewStaticMDQClient(metadataPath, "https://idp.example.com", false, nil, log)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse IdP metadata XML")
}

func TestNewStaticMDQClient_NoIDPDescriptor(t *testing.T) {
	invalidMetadata := `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
  </SPSSODescriptor>
</EntityDescriptor>`

	tmpDir := t.TempDir()
	metadataPath := filepath.Join(tmpDir, "sp-metadata.xml")
	err := os.WriteFile(metadataPath, []byte(invalidMetadata), 0o644) // #nosec G306
	require.NoError(t, err)

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	_, err = NewStaticMDQClient(metadataPath, "https://sp.example.com", false, nil, log)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not contain IdP SSO descriptor")
}

func TestNewStaticMDQClient_URLFetchError(t *testing.T) {
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	// Unreachable URL — client should be created (lazy mode) but GetIDPMetadata should fail.
	client, err := NewStaticMDQClient("http://nonexistent.invalid/metadata", "https://idp.example.com", true, nil, log)
	require.NoError(t, err, "client should be created even when URL is unreachable")
	assert.True(t, client.IsStaticMode(), "should still report static mode")
	assert.Nil(t, client.staticMetadata, "metadata should not be loaded yet")

	_, err = client.GetIDPMetadata(context.Background(), "https://idp.example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "static IdP metadata not available")
}

func TestNewStaticMDQClient_EntityIDMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	metadataPath := filepath.Join(tmpDir, "idp-metadata.xml")
	err := os.WriteFile(metadataPath, []byte(testStaticIDPMetadata), 0o644) // #nosec G306
	require.NoError(t, err)

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	// Create client with different entityID than in metadata
	// Should succeed but log warning (not tested here, but functionality works)
	client, err := NewStaticMDQClient(metadataPath, "https://different-idp.example.com", false, nil, log)
	require.NoError(t, err)
	require.NotNil(t, client)

	// Verify it uses the configured entityID
	assert.Equal(t, "https://different-idp.example.com", client.GetStaticEntityID())

	// But the metadata still has the original entityID
	metadata, err := client.GetIDPMetadata(t.Context(), "")
	require.NoError(t, err)
	assert.Equal(t, "https://static-idp.example.com/idp", metadata.EntityID)
}
