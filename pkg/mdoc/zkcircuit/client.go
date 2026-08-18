// Package zkcircuit is a Go client for the go-zk-circuits catalog REST API -
// the real, deployed read-only service for discovering/downloading ZK-proof
// circuit artifacts for the Longfellow-ZKP-pseudonym feature
// (https://zk-circuits.fly.dev today). It is a port of
// siros-sdk-kotlin's ZkCircuitClient.kt (same org, same wire protocol -
// mirror that file if the wire protocol ever changes.
//
// Wire protocol:
//
//	GET /v1/manifest.json         -> Manifest{circuits: []CircuitDescriptor}
//	GET /v1/circuits/{id}.json    -> CircuitDescriptor (id may be an alias;
//	                                 the server 301-redirects to the
//	                                 canonical id)
//	GET <artifact.url>            -> the circuit's raw (zstd-compressed)
//	                                 bytes
//
// Callers MUST verify a downloaded artifact's SHA-256 digest against
// Artifact.Hash themselves - the API's own docs are explicit that this is
// the client's responsibility, never guaranteed by a successful HTTP fetch
// alone. DownloadArtifact does this; see its doc comment.
package zkcircuit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
)

// DefaultZkCircuitURL is the default (pre-DNS) base URL of the deployed
// zk-circuits catalog service.
const DefaultZkCircuitURL = "https://zk-circuits.fly.dev"

// VerificationRecord is one format-specific interop verification recorded
// against a circuit's Source, mirroring catalog.VerificationRecord in
// go-zk-circuits' pkg/catalog/types.go field-for-field. Descriptive
// metadata only - not itself a trust decision.
type VerificationRecord struct {
	Tool             string `json:"tool,omitempty"`
	ToolVersion      string `json:"toolVersion,omitempty"`
	VerifierIdentity string `json:"verifierIdentity,omitempty"`
	Date             string `json:"date,omitempty"`
	Result           string `json:"result,omitempty"`
	Notes            string `json:"notes,omitempty"`
}

// Source is a CircuitDescriptor's provenance, mirroring catalog.Source.
type Source struct {
	Origin     string               `json:"origin,omitempty"`
	OriginRef  string               `json:"originRef,omitempty"`
	OriginPath string               `json:"originPath,omitempty"`
	Toolchain  string               `json:"toolchain,omitempty"`
	License    string               `json:"license,omitempty"`
	OpenSource bool                 `json:"openSource,omitempty"`
	AddedBy    string               `json:"addedBy,omitempty"`
	VerifiedBy []VerificationRecord `json:"verifiedBy,omitempty"`
}

// Uncompressed is the decompressed-form hash/size of an Artifact, present
// when Artifact.Compression is not "none". Mirrors catalog.Uncompressed.
type Uncompressed struct {
	Hash string `json:"hash,omitempty"`
	Size int64  `json:"size,omitempty"`
}

// Artifact describes the downloadable bytes for a circuit, mirroring
// catalog.Artifact.
//
// URL, in the real deployed service, is usually a *relative* path (e.g.
// "/v1/artifacts/sha256/<hex>"), not an absolute URL - DownloadArtifact
// resolves it against each configured source mirror accordingly.
//
// Hash is over the bytes AS SERVED (compressed, if Compression != "none");
// Uncompressed.Hash is over the decompressed bytes.
type Artifact struct {
	URL          string        `json:"url,omitempty"`
	Hash         string        `json:"hash,omitempty"`
	Size         int64         `json:"size,omitempty"`
	Compression  string        `json:"compression,omitempty"`
	MediaType    string        `json:"mediaType,omitempty"`
	Uncompressed *Uncompressed `json:"uncompressed,omitempty"`
}

// CircuitDescriptor is one catalog entry - the body of
// GET /v1/circuits/{id}.json and one element of Manifest.Circuits -
// mirroring catalog.CircuitDescriptor field-for-field.
//
// Params is deliberately loosely typed (map[string]any, mirroring the
// Kotlin client's JsonObject): format-specific "meta" properties like
// "version", "num_attributes", "circuit_hash" vary in JSON type (numbers
// decode as float64) - use ParamInt/ParamString to read them.
type CircuitDescriptor struct {
	ID            string         `json:"id"`
	Aliases       []string       `json:"aliases,omitempty"`
	System        string         `json:"system,omitempty"`
	SystemVersion string         `json:"systemVersion,omitempty"`
	DocTypes      []string       `json:"docTypes,omitempty"`
	Published     bool           `json:"published,omitempty"`
	Status        string         `json:"status,omitempty"`
	Params        map[string]any `json:"params,omitempty"`
	Artifact      *Artifact      `json:"artifact,omitempty"`
	Source        *Source        `json:"source,omitempty"`
	PublishedAt   string         `json:"publishedAt,omitempty"`
	DeprecatedAt  string         `json:"deprecatedAt,omitempty"`
	Notes         string         `json:"notes,omitempty"`
}

// ParamInt reads a numeric Params entry (decoded from JSON, so stored as
// float64) as an int. Returns (0, false) if the key is absent or not
// numeric.
func (d *CircuitDescriptor) ParamInt(key string) (int, bool) {
	v, ok := d.Params[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	default:
		return 0, false
	}
}

// ParamString reads a string Params entry. Returns ("", false) if the key
// is absent or not a string.
func (d *CircuitDescriptor) ParamString(key string) (string, bool) {
	v, ok := d.Params[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// Manifest is the top-level document served at GET /v1/manifest.json,
// mirroring catalog.Manifest.
type Manifest struct {
	ManifestVersion int                 `json:"manifestVersion,omitempty"`
	GeneratedAt     string              `json:"generatedAt,omitempty"`
	Catalog         string              `json:"catalog,omitempty"`
	Circuits        []CircuitDescriptor `json:"circuits,omitempty"`
	Next            string              `json:"next,omitempty"`
}

// ArtifactError is returned by DownloadArtifact when no configured source
// (or URL candidate) produced hash-verified artifact bytes - either every
// fetch attempt failed outright, or the downloaded bytes' SHA-256 digest
// never matched the expected hash. Per the service's own API contract, hash
// verification is the client's responsibility, not something the server
// guarantees.
type ArtifactError struct {
	Message string
}

func (e *ArtifactError) Error() string { return e.Message }

// Client is a client for the go-zk-circuits catalog REST API.
//
// DELIBERATELY DIFFERENT fallback semantics than a typical multi-registry
// client: Sources here are *mirrors of the same catalog* (the literal same
// service, reachable at a different hostname), not distinct registries
// whose entries get merged - every method tries each source **in list
// order** and returns the first one that succeeds, without ever merging
// results across sources. This mirrors siros-sdk-kotlin's ZkCircuitClient
// exactly.
type Client struct {
	// Sources are mirror base URLs, tried in order until one succeeds.
	Sources []string

	// HTTPClient backs the default (non-injected) fetch implementations.
	// Defaults to a client with a 30s timeout if nil when first used.
	HTTPClient *http.Client

	// FetchText is an optional injectable text-fetch function (used for
	// manifest.json/circuit descriptor JSON), for tests. When nil, a real
	// HTTPClient-backed implementation is used.
	FetchText func(ctx context.Context, url string) (string, error)

	// FetchBytes is an optional injectable byte-fetch function (used for
	// artifact downloads), for tests. When nil, a real HTTPClient-backed
	// implementation is used.
	FetchBytes func(ctx context.Context, url string) ([]byte, error)
}

// NewClient creates a Client for the given mirror source URLs. If no
// sources are given, DefaultZkCircuitURL is used.
func NewClient(sources ...string) *Client {
	if len(sources) == 0 {
		sources = []string{DefaultZkCircuitURL}
	}
	return &Client{
		Sources:    sources,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// FetchManifest performs GET /v1/manifest.json, returning the first
// Sources entry that serves a parseable manifest (see the Client doc
// comment for the ordered-fallback, non-merging semantics). Returns an
// error only if every source failed.
func (c *Client) FetchManifest(ctx context.Context) (*Manifest, error) {
	var lastErr error
	for _, source := range c.Sources {
		url := manifestURL(source)
		body, err := c.fetchText(ctx, url)
		if err != nil {
			lastErr = fmt.Errorf("fetch %s: %w", url, err)
			continue
		}
		var manifest Manifest
		if err := json.Unmarshal([]byte(body), &manifest); err != nil {
			lastErr = fmt.Errorf("parse manifest from %s: %w", url, err)
			continue
		}
		return &manifest, nil
	}
	return nil, fmt.Errorf("all %d zk-circuit source(s) failed to yield a manifest: %w", len(c.Sources), lastErr)
}

// FetchCircuit performs GET /v1/circuits/{id}.json, returning the first
// Sources entry that serves a descriptor for id (a canonical id or alias -
// the server redirects an alias to its canonical id; the default
// HTTPClient-backed fetch follows redirects automatically via
// net/http's default behavior). Returns an error only if every source
// failed.
func (c *Client) FetchCircuit(ctx context.Context, id string) (*CircuitDescriptor, error) {
	var lastErr error
	for _, source := range c.Sources {
		url := circuitURL(source, id)
		body, err := c.fetchText(ctx, url)
		if err != nil {
			lastErr = fmt.Errorf("fetch %s: %w", url, err)
			continue
		}
		var descriptor CircuitDescriptor
		if err := json.Unmarshal([]byte(body), &descriptor); err != nil {
			lastErr = fmt.Errorf("parse circuit descriptor %q from %s: %w", id, url, err)
			continue
		}
		return &descriptor, nil
	}
	return nil, fmt.Errorf("all %d zk-circuit source(s) failed to yield circuit %q: %w", len(c.Sources), id, lastErr)
}

// DownloadArtifact downloads a circuit's artifact bytes (AS SERVED - still
// compressed, if descriptor.Artifact.Compression != "none") and verifies
// their SHA-256 digest against descriptor.Artifact.Hash before returning
// them. See DownloadAndDecompress to also decompress and verify the
// decompressed digest.
//
// Builds an ordered list of URL candidates and tries each in turn (first
// hash-verified success wins):
//   - if Artifact.URL is already an absolute URL, it is the only candidate
//     (it already pins its own host - nothing to mirror-fallback across);
//   - otherwise (the real service's current behavior) it is a relative
//     path, resolved against every configured Sources mirror in order;
//   - if Artifact.URL is blank, the path is instead constructed from
//     Artifact.Hash as "v1/artifacts/{alg}/{hex}" ("sha256" is the only
//     algorithm the service supports today), again resolved against every
//     mirror.
//
// Returns an *ArtifactError if descriptor has no Artifact, or if every URL
// candidate either failed to fetch or failed hash verification.
func (c *Client) DownloadArtifact(ctx context.Context, descriptor *CircuitDescriptor) ([]byte, error) {
	artifact := descriptor.Artifact
	if artifact == nil {
		return nil, &ArtifactError{Message: fmt.Sprintf("circuit %q has no artifact", descriptor.ID)}
	}

	var lastFailure string
	for _, url := range c.candidateArtifactURLs(artifact) {
		data, err := c.fetchBytes(ctx, url)
		if err != nil {
			lastFailure = fmt.Sprintf("fetch failed from %s: %v", url, err)
			continue
		}
		actual := sha256Hex(data)
		expected := bareHex(artifact.Hash)
		if !strings.EqualFold(actual, expected) {
			lastFailure = fmt.Sprintf("hash mismatch from %s: expected %s, got %s", url, expected, actual)
			continue
		}
		return data, nil
	}
	return nil, &ArtifactError{
		Message: fmt.Sprintf(
			"failed to download a hash-verified artifact for circuit %q from any of %d source(s) (last: %s)",
			descriptor.ID, len(c.Sources), lastFailure,
		),
	}
}

// DownloadAndDecompress downloads a circuit's artifact (see
// DownloadArtifact), then decompresses it if Artifact.Compression is
// "zstd" (the only compression the live service uses today; "none" is
// passed through unchanged). If Artifact.Uncompressed.Hash is present, the
// decompressed bytes' SHA-256 digest is additionally verified against it -
// belt-and-braces on top of the compressed-bytes check DownloadArtifact
// already performed, since a native ZK verifier is handed these
// decompressed bytes directly and a corrupt circuit file would fail far
// less legibly there than here.
func (c *Client) DownloadAndDecompress(ctx context.Context, descriptor *CircuitDescriptor) ([]byte, error) {
	compressed, err := c.DownloadArtifact(ctx, descriptor)
	if err != nil {
		return nil, err
	}

	artifact := descriptor.Artifact
	var decompressed []byte
	switch artifact.Compression {
	case "", "none":
		decompressed = compressed
	case "zstd":
		decoder, err := zstd.NewReader(bytes.NewReader(compressed))
		if err != nil {
			return nil, fmt.Errorf("failed to initialize zstd decoder for circuit %q: %w", descriptor.ID, err)
		}
		defer decoder.Close()
		decompressed, err = io.ReadAll(decoder)
		if err != nil {
			return nil, fmt.Errorf("failed to zstd-decompress circuit %q: %w", descriptor.ID, err)
		}
	default:
		return nil, fmt.Errorf("circuit %q uses unsupported compression %q", descriptor.ID, artifact.Compression)
	}

	if artifact.Uncompressed != nil && artifact.Uncompressed.Hash != "" {
		actual := sha256Hex(decompressed)
		expected := bareHex(artifact.Uncompressed.Hash)
		if !strings.EqualFold(actual, expected) {
			return nil, &ArtifactError{Message: fmt.Sprintf(
				"decompressed circuit %q hash mismatch: expected %s, got %s",
				descriptor.ID, expected, actual,
			)}
		}
	}

	return decompressed, nil
}

func manifestURL(source string) string {
	return strings.TrimRight(source, "/") + "/v1/manifest.json"
}

func circuitURL(source, id string) string {
	return strings.TrimRight(source, "/") + "/v1/circuits/" + id + ".json"
}

// candidateArtifactURLs implements the resolution rules documented on
// DownloadArtifact.
func (c *Client) candidateArtifactURLs(artifact *Artifact) []string {
	url := artifact.URL
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		return []string{url}
	}
	path := strings.TrimPrefix(url, "/")
	if path == "" {
		path = "v1/artifacts/sha256/" + bareHex(artifact.Hash)
	}
	candidates := make([]string, 0, len(c.Sources))
	for _, source := range c.Sources {
		candidates = append(candidates, strings.TrimRight(source, "/")+"/"+path)
	}
	return candidates
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// bareHex strips a "sha256:" prefix if present (the wire format's
// convention for Artifact.Hash/Uncompressed.Hash), leaving the string
// as-is otherwise so a legacy unprefixed hash would still compare
// correctly too.
func bareHex(hash string) string {
	return strings.TrimPrefix(hash, "sha256:")
}

func (c *Client) fetchText(ctx context.Context, url string) (string, error) {
	if c.FetchText != nil {
		return c.FetchText(ctx, url)
	}
	data, err := c.fetchBytesHTTP(ctx, url)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (c *Client) fetchBytes(ctx context.Context, url string) ([]byte, error) {
	if c.FetchBytes != nil {
		return c.FetchBytes(ctx, url)
	}
	return c.fetchBytesHTTP(ctx, url)
}

func (c *Client) fetchBytesHTTP(ctx context.Context, url string) ([]byte, error) {
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}
	return io.ReadAll(resp.Body)
}
