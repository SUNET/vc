package samlsp

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/SUNET/vc/pkg/logger"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/patrickmn/go-cache"
	dsig "github.com/russellhaering/goxmldsig"
)

// MDQClient handles Metadata Query Protocol (MDQ) requests or static metadata
type MDQClient struct {
	serverURL      string
	cache          *cache.Cache
	client         *http.Client
	log            *logger.Log
	staticMetadata *saml.EntityDescriptor // For single static IdP mode
	staticEntityID string                 // EntityID of static IdP
	signingCert    *x509.Certificate      // Optional: federation metadata signing cert

	// Lazy-init state for URL-based static metadata
	mu                sync.RWMutex
	staticMetadataURL string        // Non-empty when metadata should be fetched from URL
	retryAfter        time.Time     // Earliest time to retry after a failure
	retryBackoff      time.Duration // Current backoff duration
}

// NewMDQClient creates a new MDQ client
func NewMDQClient(serverURL string, cacheTTL int, signingCert *x509.Certificate, log *logger.Log) *MDQClient {
	if cacheTTL == 0 {
		cacheTTL = 3600
	}

	if serverURL != "" && !strings.HasSuffix(serverURL, "/") {
		serverURL += "/"
	}

	return &MDQClient{
		serverURL:   serverURL,
		cache:       cache.New(time.Duration(cacheTTL)*time.Second, time.Duration(cacheTTL*2)*time.Second),
		signingCert: signingCert,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		log: log.New("mdq"),
	}
}

const (
	mdqRetryBase = 5 * time.Second
	mdqRetryMax  = 2 * time.Minute
)

// NewStaticMDQClient creates a new MDQ client with static IdP metadata.
// For URL-based metadata, if the initial fetch fails (e.g. IdP unreachable),
// the client is still returned and will retry lazily on GetIDPMetadata calls.
func NewStaticMDQClient(metadataSource, entityID string, isURL bool, signingCert *x509.Certificate, log *logger.Log) (*MDQClient, error) {
	client := &MDQClient{
		staticEntityID: entityID,
		signingCert:    signingCert,
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
			// Defer to lazy init — store URL and retry on first GetIDPMetadata call.
			log.Error(err, "static_idp_metadata_fetch_failed_will_retry", "url", metadataSource)
			client.staticMetadataURL = metadataSource
			client.retryBackoff = mdqRetryBase
			client.retryAfter = time.Now().Add(client.retryBackoff)
			return client, nil
		}
	} else {
		// Read metadata from file — files must exist at startup.
		log.Debug("loading static IdP metadata from file", "path", metadataSource)
		metadataXML, err = os.ReadFile(filepath.Clean(metadataSource))
		if err != nil {
			return nil, fmt.Errorf("failed to read metadata file: %w", err)
		}
	}

	metadata, err := client.parseAndVerifyMetadata(metadataXML)
	if err != nil {
		return nil, err
	}

	if err := client.validateAndSetMetadata(metadata, log); err != nil {
		return nil, err
	}

	return client, nil
}

// validateAndSetMetadata checks that the metadata has required fields and stores it.
func (m *MDQClient) validateAndSetMetadata(metadata *saml.EntityDescriptor, log *logger.Log) error {
	if len(metadata.IDPSSODescriptors) == 0 {
		return fmt.Errorf("metadata does not contain IdP SSO descriptor")
	}

	if len(metadata.IDPSSODescriptors[0].SingleSignOnServices) == 0 {
		return fmt.Errorf("IdP metadata does not contain SSO service endpoint")
	}

	if metadata.EntityID != "" && metadata.EntityID != m.staticEntityID {
		log.Info("configured entityID differs from metadata entityID",
			"configured", m.staticEntityID,
			"metadata", metadata.EntityID)
	}

	m.staticMetadata = metadata

	log.Info("static IdP metadata loaded",
		"entity_id", m.staticEntityID,
		"sso_location", metadata.IDPSSODescriptors[0].SingleSignOnServices[0].Location)

	return nil
}

// retryStaticMetadataFetch retries fetching URL-based static metadata with exponential backoff.
func (m *MDQClient) retryStaticMetadataFetch() error {
	m.mu.RLock()
	if m.staticMetadata != nil {
		m.mu.RUnlock()
		return nil
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after lock.
	if m.staticMetadata != nil {
		return nil
	}

	if time.Now().Before(m.retryAfter) {
		return fmt.Errorf("next retry at %s", m.retryAfter.Format(time.RFC3339))
	}

	metadataXML, err := m.fetchMetadataFromURL(m.staticMetadataURL)
	if err != nil {
		m.retryBackoff = min(m.retryBackoff*2, mdqRetryMax)
		m.retryAfter = time.Now().Add(m.retryBackoff)
		m.log.Error(err, "static_idp_metadata_retry_failed", "url", m.staticMetadataURL, "next_retry_in", m.retryBackoff.String())
		return fmt.Errorf("fetch failed: %w", err)
	}

	metadata, err := m.parseAndVerifyMetadata(metadataXML)
	if err != nil {
		m.retryBackoff = min(m.retryBackoff*2, mdqRetryMax)
		m.retryAfter = time.Now().Add(m.retryBackoff)
		return fmt.Errorf("parse failed: %w", err)
	}

	if err := m.validateAndSetMetadata(metadata, m.log); err != nil {
		return err
	}

	m.retryBackoff = 0
	m.staticMetadataURL = "" // Clear to stop retrying
	return nil
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

	// Lazy retry for URL-based static metadata that failed at startup.
	if m.staticMetadataURL != "" {
		if err := m.retryStaticMetadataFetch(); err != nil {
			return nil, fmt.Errorf("static IdP metadata not available: %w", err)
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

	metadata, err := m.parseAndVerifyMetadata(body)
	if err != nil {
		return nil, err
	}

	if len(metadata.IDPSSODescriptors) == 0 {
		return nil, fmt.Errorf("metadata does not contain IdP SSO descriptor")
	}

	if len(metadata.IDPSSODescriptors[0].SingleSignOnServices) == 0 {
		return nil, fmt.Errorf("IdP metadata does not contain SSO service endpoint")
	}

	m.cache.Set(entityID, metadata, cache.DefaultExpiration)

	m.log.Info("IdP metadata fetched and cached",
		"entity_id", entityID,
		"sso_location", metadata.IDPSSODescriptors[0].SingleSignOnServices[0].Location)

	return metadata, nil
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
	return m.staticMetadata != nil || m.staticMetadataURL != ""
}

// parseAndVerifyMetadata parses metadata XML and, when a signing certificate is
// configured, validates the enveloped XML signature. Returns the parsed descriptor.
func (m *MDQClient) parseAndVerifyMetadata(metadataXML []byte) (*saml.EntityDescriptor, error) {
	if m.signingCert != nil {
		if err := m.verifyMetadataSignature(metadataXML); err != nil {
			return nil, fmt.Errorf("metadata signature verification failed: %w", err)
		}
		m.log.Debug("metadata signature verified successfully")
	}

	var metadata saml.EntityDescriptor
	if err := xml.Unmarshal(metadataXML, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse IdP metadata XML: %w", err)
	}

	return &metadata, nil
}

// verifyMetadataSignature validates the XML signature on a metadata document
// using the configured federation signing certificate.
func (m *MDQClient) verifyMetadataSignature(metadataXML []byte) error {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(metadataXML); err != nil {
		return fmt.Errorf("failed to parse metadata XML for signature verification: %w", err)
	}

	certStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{m.signingCert},
	}

	validationCtx := dsig.NewDefaultValidationContext(&certStore)
	validationCtx.IdAttribute = "ID"

	_, err := validationCtx.Validate(doc.Root())
	if err != nil {
		return fmt.Errorf("invalid metadata signature: %w", err)
	}

	return nil
}

// LoadMetadataSigningCert loads an X.509 certificate from a PEM file for
// metadata signature verification.
func LoadMetadataSigningCert(certPath string) (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(filepath.Clean(certPath))
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata signing certificate: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from %s", certPath)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse metadata signing certificate: %w", err)
	}

	return cert, nil
}
