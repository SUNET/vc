//go:build saml

package samlsp

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"vc/pkg/logger"

	"github.com/crewjam/saml"
	"github.com/patrickmn/go-cache"
)

// MDQClient handles Metadata Query Protocol (MDQ) requests or static metadata
type MDQClient struct {
	serverURL      string
	cache          *cache.Cache
	client         *http.Client
	log            *logger.Log
	staticMetadata *saml.EntityDescriptor // For single static IdP mode
	staticEntityID string                 // EntityID of static IdP
}

// NewMDQClient creates a new MDQ client
func NewMDQClient(serverURL string, cacheTTL int, log *logger.Log) *MDQClient {
	if cacheTTL == 0 {
		cacheTTL = 3600
	}

	if serverURL != "" && !strings.HasSuffix(serverURL, "/") {
		serverURL += "/"
	}

	return &MDQClient{
		serverURL: serverURL,
		cache:     cache.New(time.Duration(cacheTTL)*time.Second, time.Duration(cacheTTL*2)*time.Second),
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		log: log.New("mdq"),
	}
}

// NewStaticMDQClient creates a new MDQ client with static IdP metadata
func NewStaticMDQClient(metadataSource, entityID string, isURL bool, log *logger.Log) (*MDQClient, error) {
	client := &MDQClient{
		staticEntityID: entityID,
		log:            log.New("mdq"),
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}

	var metadataXML []byte
	var err error

	if isURL {
		// Fetch metadata from URL
		log.Debug("fetching static IdP metadata from URL", "url", metadataSource)
		metadataXML, err = client.fetchMetadataFromURL(metadataSource)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch metadata from URL: %w", err)
		}
	} else {
		// Read metadata from file
		log.Debug("loading static IdP metadata from file", "path", metadataSource)
		metadataXML, err = os.ReadFile(metadataSource)
		if err != nil {
			return nil, fmt.Errorf("failed to read metadata file: %w", err)
		}
	}

	// Parse metadata XML
	var metadata saml.EntityDescriptor
	if err := xml.Unmarshal(metadataXML, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse IdP metadata XML: %w", err)
	}

	// Validate metadata structure
	if len(metadata.IDPSSODescriptors) == 0 {
		return nil, fmt.Errorf("metadata does not contain IdP SSO descriptor")
	}

	if len(metadata.IDPSSODescriptors[0].SingleSignOnServices) == 0 {
		return nil, fmt.Errorf("IdP metadata does not contain SSO service endpoint")
	}

	// Verify entityID matches if specified in metadata
	if metadata.EntityID != "" && metadata.EntityID != entityID {
		log.Info("configured entityID differs from metadata entityID",
			"configured", entityID,
			"metadata", metadata.EntityID)
	}

	client.staticMetadata = &metadata

	log.Info("static IdP metadata loaded",
		"entity_id", entityID,
		"sso_location", metadata.IDPSSODescriptors[0].SingleSignOnServices[0].Location)

	return client, nil
}

// fetchMetadataFromURL fetches metadata from an HTTP(S) URL
func (m *MDQClient) fetchMetadataFromURL(metadataURL string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/samlmetadata+xml")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

// GetIDPMetadata retrieves IdP metadata from MDQ server or returns static metadata
func (m *MDQClient) GetIDPMetadata(ctx context.Context, entityID string) (*saml.EntityDescriptor, error) {
	// If we have static metadata, return it (ignoring entityID parameter)
	if m.staticMetadata != nil {
		if entityID != "" && entityID != m.staticEntityID {
			m.log.Info("requested entityID differs from static IdP",
				"requested", entityID,
				"static", m.staticEntityID)
		}
		m.log.Debug("returning static IdP metadata", "entity_id", m.staticEntityID)
		return m.staticMetadata, nil
	}

	// Otherwise use MDQ
	m.log.Debug("fetching IdP metadata", "entity_id", entityID)

	if cached, found := m.cache.Get(entityID); found {
		m.log.Debug("IdP metadata found in cache", "entity_id", entityID)
		return cached.(*saml.EntityDescriptor), nil
	}

	encodedEntityID := url.QueryEscape(entityID)
	mdqURL := m.serverURL + encodedEntityID

	m.log.Debug("querying MDQ server", "url", mdqURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mdqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create MDQ request: %w", err)
	}

	req.Header.Set("Accept", "application/samlmetadata+xml")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("MDQ request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("MDQ server returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read MDQ response: %w", err)
	}

	var metadata saml.EntityDescriptor
	if err := xml.Unmarshal(body, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse IdP metadata XML: %w", err)
	}

	if len(metadata.IDPSSODescriptors) == 0 {
		return nil, fmt.Errorf("metadata does not contain IdP SSO descriptor")
	}

	if len(metadata.IDPSSODescriptors[0].SingleSignOnServices) == 0 {
		return nil, fmt.Errorf("IdP metadata does not contain SSO service endpoint")
	}

	m.cache.Set(entityID, &metadata, cache.DefaultExpiration)

	m.log.Info("IdP metadata fetched and cached",
		"entity_id", entityID,
		"sso_location", metadata.IDPSSODescriptors[0].SingleSignOnServices[0].Location)

	return &metadata, nil
}

// ClearCache clears all cached metadata
func (m *MDQClient) ClearCache() {
	m.cache.Flush()
	m.log.Debug("MDQ cache cleared")
}

// CacheStats returns cache statistics
func (m *MDQClient) CacheStats() (itemCount int) {
	return m.cache.ItemCount()
}

// GetStaticEntityID returns the static IdP entityID if configured, empty string otherwise
func (m *MDQClient) GetStaticEntityID() string {
	return m.staticEntityID
}

// IsStaticMode returns true if client is configured for static IdP mode
func (m *MDQClient) IsStaticMode() bool {
	return m.staticMetadata != nil
}
