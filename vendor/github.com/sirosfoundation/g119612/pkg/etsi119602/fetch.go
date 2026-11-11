package etsi119602

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirosfoundation/g119612/pkg/resilience"
)

// FetchOptions configures how LoTEs are fetched.
type FetchOptions struct {
	// UserAgent is sent in the User-Agent header.
	UserAgent string

	// Timeout is the HTTP request timeout.
	Timeout time.Duration

	// HTTPClient allows injecting a custom client (e.g., for testing).
	HTTPClient *http.Client

	// MaxAttempts is the maximum number of fetch attempts per URL (1 = no retry).
	// Transient failures (transport errors, 5xx) are retried with exponential
	// backoff; 4xx and parse errors fail immediately. Default: 3.
	MaxAttempts int

	// RetryBaseDelay is the initial backoff duration; doubled after each retry.
	// Default: 500ms.
	RetryBaseDelay time.Duration

	// MaxBodyBytes limits the response body size. Returns an error if the
	// response exceeds this limit. Default: 10MB.
	MaxBodyBytes int64
}

// JWSVerifier verifies JWS compact serializations and returns the payload.
type JWSVerifier interface {
	Verify(compact string) ([]byte, error)
}

// FetchLoTE fetches and parses a LoTE from a URL or file path.
// Automatically detects JSON vs XML format based on file extension
// and content. File paths are detected by the "file://" prefix or
// absence of "://".
func FetchLoTE(location string, opts *FetchOptions) (*ListOfTrustedEntities, error) {
	if strings.HasPrefix(location, "file://") {
		path := strings.TrimPrefix(location, "file://")
		return parseLoTEFileAutoDetect(path)
	}
	if !strings.Contains(location, "://") {
		return parseLoTEFileAutoDetect(location)
	}
	return fetchLoTEFromURL(location, opts)
}

// FetchLoTEXML fetches and parses a LoTE from an XML URL or file path.
func FetchLoTEXML(location string, opts *FetchOptions) (*ListOfTrustedEntities, error) {
	if strings.HasPrefix(location, "file://") {
		path := strings.TrimPrefix(location, "file://")
		return ParseLoTEXMLFromFile(path)
	}
	if !strings.Contains(location, "://") {
		return ParseLoTEXMLFromFile(location)
	}
	data, err := fetchRawFromURL(location, opts, "application/xml")
	if err != nil {
		return nil, err
	}
	return ParseLoTEXML(data)
}

// FetchLoTL fetches and parses a LoTL from a URL or file path.
// Automatically detects JSON vs XML format.
func FetchLoTL(location string, opts *FetchOptions) (*ListOfTrustedLists, error) {
	if strings.HasPrefix(location, "file://") {
		path := strings.TrimPrefix(location, "file://")
		return parseLoTLFileAutoDetect(path)
	}
	if !strings.Contains(location, "://") {
		return parseLoTLFileAutoDetect(location)
	}
	return fetchLoTLFromURL(location, opts)
}

// FetchLoTLXML fetches and parses a LoTL from an XML URL or file path.
func FetchLoTLXML(location string, opts *FetchOptions) (*ListOfTrustedLists, error) {
	if strings.HasPrefix(location, "file://") {
		path := strings.TrimPrefix(location, "file://")
		return ParseLoTLXMLFromFile(path)
	}
	if !strings.Contains(location, "://") {
		return ParseLoTLXMLFromFile(location)
	}
	data, err := fetchRawFromURL(location, opts, "application/xml")
	if err != nil {
		return nil, err
	}
	return ParseLoTLXML(data)
}

// FetchAndVerifyLoTE fetches a JWS-signed LoTE, verifies the signature, and returns the payload.
func FetchAndVerifyLoTE(location string, opts *FetchOptions, verifier JWSVerifier) (*ListOfTrustedEntities, error) {
	data, err := fetchRawFromURL(location, opts, "application/jose, application/json")
	if err != nil {
		return nil, err
	}
	payload, err := verifier.Verify(string(data))
	if err != nil {
		return nil, fmt.Errorf("JWS verification failed for %s: %w", location, err)
	}
	return ParseLoTE(payload)
}

// FetchRaw fetches raw bytes from a URL or file path without parsing.
// For file paths, reads the file directly. For URLs, fetches with Accept: */*.
func FetchRaw(location string, opts *FetchOptions) ([]byte, error) {
	if strings.HasPrefix(location, "file://") {
		return os.ReadFile(strings.TrimPrefix(location, "file://"))
	}
	if !strings.Contains(location, "://") {
		return os.ReadFile(location)
	}
	return fetchRawFromURL(location, opts, "*/*")
}

// isXMLLocation returns true if the location (URL or file path) looks like XML.
func isXMLLocation(location string) bool {
	// Strip query/fragment for URL analysis
	loc := location
	if idx := strings.IndexAny(loc, "?#"); idx >= 0 {
		loc = loc[:idx]
	}
	ext := strings.ToLower(filepath.Ext(loc))
	return ext == ".xml"
}

// IsXMLContent detects XML content by checking for the XML declaration or
// a root element starting with '<'.
func IsXMLContent(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	return bytes.HasPrefix(trimmed, []byte("<?xml")) || bytes.HasPrefix(trimmed, []byte("<"))
}

// parseLoTEFileAutoDetect loads a LoTE from a file, auto-detecting JSON vs XML
// based on file extension first, then falling back to content sniffing.
func parseLoTEFileAutoDetect(path string) (*ListOfTrustedEntities, error) {
	if isXMLLocation(path) {
		return ParseLoTEXMLFromFile(path)
	}
	// Read content and sniff for XML
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}
	if IsXMLContent(data) {
		return ParseLoTEXML(data)
	}
	return ParseLoTE(data)
}

// parseLoTLFileAutoDetect loads a LoTL from a file, auto-detecting JSON vs XML
// based on file extension first, then falling back to content sniffing.
func parseLoTLFileAutoDetect(path string) (*ListOfTrustedLists, error) {
	if isXMLLocation(path) {
		return ParseLoTLXMLFromFile(path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}
	if IsXMLContent(data) {
		return ParseLoTLXML(data)
	}
	return ParseLoTL(data)
}

func fetchLoTEFromURL(url string, opts *FetchOptions) (*ListOfTrustedEntities, error) {
	accept := "application/json"
	if isXMLLocation(url) {
		accept = "application/xml"
	}
	body, contentType, err := fetchRawWithContentType(url, opts, accept)
	if err != nil {
		return nil, err
	}
	if isXMLContentType(contentType) || (contentType == "" && IsXMLContent(body)) {
		return ParseLoTEXML(body)
	}
	return ParseLoTE(body)
}

func fetchLoTLFromURL(url string, opts *FetchOptions) (*ListOfTrustedLists, error) {
	accept := "application/json"
	if isXMLLocation(url) {
		accept = "application/xml"
	}
	body, contentType, err := fetchRawWithContentType(url, opts, accept)
	if err != nil {
		return nil, err
	}
	if isXMLContentType(contentType) || (contentType == "" && IsXMLContent(body)) {
		return ParseLoTLXML(body)
	}
	return ParseLoTL(body)
}

func isXMLContentType(ct string) bool {
	// Strip parameters (e.g. "application/xml; charset=utf-8")
	if idx := strings.IndexByte(ct, ';'); idx >= 0 {
		ct = strings.TrimSpace(ct[:idx])
	}
	ct = strings.ToLower(ct)
	return ct == "application/xml" || ct == "text/xml" || strings.HasSuffix(ct, "+xml")
}

func fetchRawFromURL(url string, opts *FetchOptions, accept string) ([]byte, error) {
	body, _, err := fetchRawWithContentType(url, opts, accept)
	return body, err
}

func fetchRawWithContentType(url string, opts *FetchOptions, accept string) ([]byte, string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	timeout := 30 * time.Second
	var maxAttempts int
	var retryBaseDelay time.Duration
	var maxBody int64 = 10 * 1024 * 1024 // 10MB default

	if opts != nil {
		if opts.HTTPClient != nil {
			client = opts.HTTPClient
		} else if opts.Timeout > 0 {
			client.Timeout = opts.Timeout
		}
		if opts.Timeout > 0 {
			timeout = opts.Timeout
		}
		maxAttempts = opts.MaxAttempts
		retryBaseDelay = opts.RetryBaseDelay
		if opts.MaxBodyBytes > 0 {
			maxBody = opts.MaxBodyBytes
		}
	}

	retryCfg := resilience.Config{
		MaxAttempts:    maxAttempts,
		RetryBaseDelay: retryBaseDelay,
		MaxBodyBytes:   maxBody,
	}.WithDefaults()

	// Overall context accounts for all attempts + backoff.
	overallTimeout := timeout * time.Duration(retryCfg.MaxAttempts) * 2
	ctx, cancel := context.WithTimeout(context.Background(), overallTimeout)
	defer cancel()

	var body []byte
	var ct string

	err := resilience.DoWithRetry(ctx, retryCfg, func() error {
		// Per-attempt context so a single timeout doesn't exhaust the overall deadline.
		attemptCtx, attemptCancel := context.WithTimeout(ctx, timeout)
		defer attemptCancel()

		req, reqErr := http.NewRequestWithContext(attemptCtx, "GET", url, nil)
		if reqErr != nil {
			return fmt.Errorf("failed to create request for %s: %w", url, reqErr)
		}
		req.Header.Set("Accept", accept)
		if opts != nil && opts.UserAgent != "" {
			req.Header.Set("User-Agent", opts.UserAgent)
		}

		resp, doErr := client.Do(req)
		if doErr != nil {
			return &resilience.TransportError{Err: fmt.Errorf("failed to fetch from %s: %w", url, doErr)}
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return &resilience.HTTPStatusError{StatusCode: resp.StatusCode, URL: url}
		}

		ct = ""
		if raw := resp.Header.Get("Content-Type"); raw != "" {
			ct = strings.ToLower(strings.TrimSpace(strings.SplitN(raw, ";", 2)[0]))
		}

		// Reject clearly wrong content types
		allowedTypes := map[string]bool{
			"application/json":         true,
			"application/jose":         true,
			"application/xml":          true,
			"text/xml":                 true,
			"text/plain":               true,
			"application/octet-stream": true,
			"":                         true,
		}
		if !allowedTypes[ct] {
			return fmt.Errorf("unexpected Content-Type %q fetching %s", ct, url)
		}

		body, doErr = io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
		if doErr != nil {
			return &resilience.TransportError{Err: fmt.Errorf("failed to read response from %s: %w", url, doErr)}
		}
		if int64(len(body)) > maxBody {
			return fmt.Errorf("response body from %s exceeds maximum size of %d bytes", url, maxBody)
		}

		return nil
	})

	if err != nil {
		return nil, "", err
	}

	return body, ct, nil
}
