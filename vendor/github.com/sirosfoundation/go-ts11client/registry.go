package ts11client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirosfoundation/go-ts11client/schemameta"
)

const (
	// defaultTimeout bounds a single HTTP request to a registry, used
	// when a RegistryConfig doesn't set its own Timeout.
	defaultTimeout = 10 * time.Second
	// wellKnownPath is where every TS11-compatible registry publishes its
	// discovery index (confirmed against registry.siros.org's own output,
	// and called out in registry-cli's source as the format
	// "expected by go-wallet-backend's registry fetcher").
	wellKnownPath = "/.well-known/vctm-registry.json"
)

// RegistryConfig identifies one registry to query.
type RegistryConfig struct {
	// BaseURL is the registry's origin, e.g. "https://registry.siros.org"
	// (no trailing slash required either way).
	BaseURL string
	// Timeout bounds each HTTP request to this registry. Defaults to
	// defaultTimeout if zero.
	Timeout time.Duration
}

// doctypeEntry is a resolved mdoc document plus the registry entry it
// belongs to, cached together so resolveDoctype doesn't need to re-fetch
// the same document it already read to extract Doctype from.
type doctypeEntry struct {
	entry schemameta.Entry
	data  []byte
}

// registryHandle holds one registry's cached discovery index and lazily
// built doctype index. Safe for concurrent use.
type registryHandle struct {
	baseURL         string
	httpClient      *http.Client
	timeout         time.Duration
	refreshInterval time.Duration

	// fetchMu serializes actual network fetches for this registry, so N
	// concurrent callers hitting a cold/expired cache trigger one fetch,
	// not N.
	fetchMu sync.Mutex

	mu         sync.RWMutex
	byVCT      map[string]schemameta.Entry
	fetchedAt  time.Time
	generation uint64

	doctypeMu         sync.Mutex
	doctypeIndex      map[string]doctypeEntry
	doctypeGeneration uint64
}

func newRegistryHandle(cfg RegistryConfig, httpClient *http.Client, refreshInterval time.Duration) *registryHandle {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &registryHandle{
		baseURL:         strings.TrimRight(cfg.BaseURL, "/"),
		httpClient:      httpClient,
		timeout:         timeout,
		refreshInterval: refreshInterval,
	}
}

// ensureIndex returns this registry's current vct->Entry index, fetching
// (or re-fetching, if refreshInterval has elapsed) as needed. Returns the
// generation number the returned index belongs to, so callers building a
// derived index (the doctype index) can tell when to rebuild.
func (h *registryHandle) ensureIndex(ctx context.Context) (map[string]schemameta.Entry, uint64, error) {
	if idx, gen, ok := h.cachedIndex(); ok {
		return idx, gen, nil
	}

	h.fetchMu.Lock()
	defer h.fetchMu.Unlock()
	// Another goroutine may have refreshed it while we waited for fetchMu.
	if idx, gen, ok := h.cachedIndex(); ok {
		return idx, gen, nil
	}

	idx, err := h.fetchIndex(ctx)
	if err != nil {
		return nil, 0, err
	}

	h.mu.Lock()
	h.byVCT = idx
	h.fetchedAt = time.Now()
	h.generation++
	gen := h.generation
	h.mu.Unlock()
	return idx, gen, nil
}

func (h *registryHandle) cachedIndex() (map[string]schemameta.Entry, uint64, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.byVCT == nil {
		return nil, 0, false
	}
	if h.refreshInterval > 0 && time.Since(h.fetchedAt) >= h.refreshInterval {
		return nil, 0, false
	}
	return h.byVCT, h.generation, true
}

func (h *registryHandle) fetchIndex(ctx context.Context) (map[string]schemameta.Entry, error) {
	data, err := h.fetchDocument(ctx, h.baseURL+wellKnownPath)
	if err != nil {
		return nil, err
	}
	var index schemameta.Index
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, fmt.Errorf("ts11client: decode discovery index from %s: %w", h.baseURL, err)
	}
	byVCT := make(map[string]schemameta.Entry, len(index.Credentials))
	for _, e := range index.Credentials {
		byVCT[e.VCT] = e
	}
	return byVCT, nil
}

// fetchDocument fetches an arbitrary document URL with this registry's
// timeout, returning its raw bytes.
func (h *registryHandle) fetchDocument(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("ts11client: build request for %s: %w", url, err)
	}
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ts11client: fetch %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ts11client: fetch %s: unexpected status %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ts11client: read response from %s: %w", url, err)
	}
	return data, nil
}

// resolveVCT looks up vct in this registry's index and fetches its VCTM document.
func (h *registryHandle) resolveVCT(ctx context.Context, vct string) (*Resolved, error) {
	byVCT, _, err := h.ensureIndex(ctx)
	if err != nil {
		return nil, err
	}
	entry, ok := byVCT[vct]
	if !ok {
		return nil, fmt.Errorf("%w: vct=%q (registry=%s)", ErrNotFound, vct, h.baseURL)
	}
	ref, ok := entry.Formats[schemameta.FormatVCTM]
	if !ok {
		return nil, fmt.Errorf("%w: vct=%q has no vctm format (registry=%s)", ErrNotFound, vct, h.baseURL)
	}
	data, err := h.fetchDocument(ctx, ref.URL)
	if err != nil {
		return nil, err
	}
	return &Resolved{Entry: entry, Format: schemameta.FormatVCTM, Data: data, Source: h.baseURL}, nil
}

// resolveDoctype looks up doctype in this registry. Unlike vct, doctype
// isn't present in the discovery index itself (confirmed against real
// registry.siros.org data - every credential there carries a "vct" index
// key regardless of format, but "doctype" only appears inside each mdoc
// document's own content), so this maintains a lazily-built doctype index
// by fetching every mdoc-format entry's document once per index
// generation and reading its internal "doctype" field.
func (h *registryHandle) resolveDoctype(ctx context.Context, doctype string) (*Resolved, error) {
	byVCT, gen, err := h.ensureIndex(ctx)
	if err != nil {
		return nil, err
	}
	idx, err := h.ensureDoctypeIndex(ctx, byVCT, gen)
	if err != nil {
		return nil, err
	}
	de, ok := idx[doctype]
	if !ok {
		return nil, fmt.Errorf("%w: doctype=%q (registry=%s)", ErrNotFound, doctype, h.baseURL)
	}
	return &Resolved{Entry: de.entry, Format: schemameta.FormatMDOC, Data: de.data, Source: h.baseURL}, nil
}

func (h *registryHandle) ensureDoctypeIndex(ctx context.Context, byVCT map[string]schemameta.Entry, gen uint64) (map[string]doctypeEntry, error) {
	h.doctypeMu.Lock()
	defer h.doctypeMu.Unlock()

	if h.doctypeIndex != nil && h.doctypeGeneration == gen {
		return h.doctypeIndex, nil
	}

	idx := make(map[string]doctypeEntry)
	for _, entry := range byVCT {
		ref, ok := entry.Formats[schemameta.FormatMDOC]
		if !ok {
			continue
		}
		data, err := h.fetchDocument(ctx, ref.URL)
		if err != nil {
			// Best-effort: one unreachable mdoc document shouldn't fail
			// resolution of every other doctype in this registry.
			continue
		}
		doctype, err := schemameta.ExtractDoctype(data)
		if err != nil || doctype == "" {
			continue
		}
		idx[doctype] = doctypeEntry{entry: entry, data: data}
	}
	h.doctypeIndex = idx
	h.doctypeGeneration = gen
	return idx, nil
}
