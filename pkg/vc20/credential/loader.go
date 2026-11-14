package credential

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/vc20/contextstore"

	"github.com/jellydator/ttlcache/v3"
	"github.com/piprate/json-gold/ld"
)

// maxContextBytes caps a context document, so a hostile or broken endpoint
// cannot stream indefinitely into memory.
const maxContextBytes = 4 << 20

var (
	globalLoader *CachingDocumentLoader
	loaderOnce   sync.Once
)

// GetGlobalLoader returns the singleton caching document loader
func GetGlobalLoader() *CachingDocumentLoader {
	loaderOnce.Do(func() {
		globalLoader = NewCachingDocumentLoader()
	})
	return globalLoader
}

// CachingDocumentLoader is a document loader that caches contexts in memory
// and preloads common contexts to avoid network requests
type CachingDocumentLoader struct {
	client *http.Client
	cache  *ttlcache.Cache[string, *ld.RemoteDocument]
	log    *logger.Log

	// sourcesMu guards sources, which an operator's configuration sets
	// once at startup and every LoadDocument then reads.
	sourcesMu sync.RWMutex
	sources   map[string]ContextSource
}

// ContextSource is where one context document's bytes come from, when the
// operator has provided a copy rather than letting the URL be dereferenced.
//
// Exactly one field is set. File reads from disk and makes no request at
// all; URL fetches a mirror through the ordinary path, so the scheme and
// address policy apply to it unchanged.
type ContextSource struct {
	File string
	URL  string
}

// SetContextSources installs the operator's copies of context documents.
//
// Consulted by LoadDocument as well as by pinning, so a source applies
// however the context is reached: pinned at startup, re-fetched by a
// refresh, or loaded on first use under the lazy policy. A source that only
// covered pinning would silently stop applying in the one mode that never
// pins.
func (l *CachingDocumentLoader) SetContextSources(sources map[string]ContextSource) {
	l.sourcesMu.Lock()
	l.sources = maps.Clone(sources)
	l.sourcesMu.Unlock()

	// Anything already cached for these URLs has to go, because
	// LoadDocument answers from the cache BEFORE it consults a source. The
	// W3C base contexts are preloaded at construction with no expiry, so
	// an operator who configured a copy of one would have been served the
	// embedded document instead - for the life of the process, with
	// nothing to say the setting had been ignored.
	for url := range sources {
		l.cache.Delete(url)
	}
}

// contextSource returns the configured source for a URL, if there is one.
func (l *CachingDocumentLoader) contextSource(url string) (ContextSource, bool) {
	l.sourcesMu.RLock()
	defer l.sourcesMu.RUnlock()
	source, ok := l.sources[url]
	return source, ok
}

// loadFromSource loads a context from the operator's copy of it, reporting
// whether a copy was configured at all.
//
// The document is returned under the CANONICAL url - the one the credential
// names and the one the processor will ask for again - whichever source it
// came from. A mirror that answered under its own URL would be cached under
// that URL and fetched again under the canonical one.
func (l *CachingDocumentLoader) loadFromSource(url string) (*ld.RemoteDocument, bool, error) {
	source, ok := l.contextSource(url)
	if !ok {
		return nil, false, nil
	}
	switch {
	case source.File != "":
		doc, err := l.readContextFile(url, source.File)
		return doc, true, err
	case source.URL != "":
		doc, err := l.fetchContext(source.URL)
		if err != nil {
			return nil, true, fmt.Errorf("JSON-LD context %q from its configured mirror: %w", url, err)
		}
		// Re-homed onto the canonical URL. DocumentURL is also what
		// relative references inside the document resolve against, and
		// resolving them against the mirror would point the closure at
		// the mirror's layout rather than the publisher's.
		doc.DocumentURL = url
		return doc, true, nil
	default:
		return nil, true, fmt.Errorf("JSON-LD context %q has a source with neither file nor url", url)
	}
}

// readContextFile reads a context document from a path the operator
// configured.
//
// Capped at the same size as a fetched document: the cap is there so one
// context cannot exhaust memory, and that is as true of a file as of a
// response body.
func (l *CachingDocumentLoader) readContextFile(url, path string) (*ld.RemoteDocument, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("JSON-LD context %q from %q: %w", url, path, err)
	}
	defer file.Close()

	body, err := io.ReadAll(io.LimitReader(file, maxContextBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading JSON-LD context %q from %q: %w", url, path, err)
	}
	if len(body) > maxContextBytes {
		return nil, fmt.Errorf("JSON-LD context %q at %q is larger than the %d byte limit", url, path, maxContextBytes)
	}

	var document any
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, fmt.Errorf("JSON-LD context %q at %q is not valid JSON: %w", url, path, err)
	}

	return &ld.RemoteDocument{DocumentURL: url, Document: document}, nil
}

// schemeOf returns the scheme of a context URL, or "" if it has none.
func schemeOf(raw string) string {
	u, err := neturl.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Scheme
}

// nonPublicRanges are address blocks the public internet does not route to,
// beyond what net.IP's own predicates cover. IsPrivate knows only RFC 1918 and
// RFC 4193, so the shared-address and reserved blocks have to be listed.
var nonPublicRanges = func() []*net.IPNet {
	blocks := []string{
		"100.64.0.0/10",   // RFC 6598 carrier-grade NAT
		"192.0.0.0/24",    // RFC 6890 IETF protocol assignments
		"192.0.2.0/24",    // TEST-NET-1
		"198.18.0.0/15",   // RFC 2544 benchmarking
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"240.0.0.0/4",     // reserved
		"2001:db8::/32",   // IPv6 documentation
		"64:ff9b::/96",    // IPv4/IPv6 translation
	}
	out := make([]*net.IPNet, 0, len(blocks))
	for _, b := range blocks {
		if _, n, err := net.ParseCIDR(b); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

// isInternalAddr reports whether an address is one the public internet cannot
// reach, and which a context fetch therefore has no business connecting to.
//
// Deliberately broader than net.IP's predicates: those cover loopback, RFC
// 1918 private space and link-local, but not carrier-grade NAT, the reserved
// and benchmarking blocks, or multicast generally. An unparsable address
// counts as internal, so the failure direction is refusal.
func isInternalAddr(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	// An IPv4-mapped IPv6 address must be judged as the IPv4 address it is.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, block := range nonPublicRanges {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// contextHTTPClient fetches remote JSON-LD contexts, refusing to CONNECT to
// anything the public internet cannot reach.
//
// The check is at dial time on purpose. Checking the URL before the request
// covers only the paths this package controls, and json-gold takes others:
// it follows redirects, and a Link header with rel=alternate makes it call its
// OWN loader recursively, which never re-enters CachingDocumentLoader. A dial
// hook sees every one of those, including the recursive fetch, because they
// all end up opening a socket through this client.
//
// It is also the only layer that survives DNS rebinding: the address checked
// is the address connected to, not one resolved a moment earlier.
//
// Redirects themselves stay allowed - w3id.org exists to redirect and the Data
// Integrity contexts resolve through it - they just cannot land anywhere
// internal.
func contextHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	dialer.Control = func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("refusing a JSON-LD context connection to an unparsable address %q: %w", address, err)
		}
		if ip := net.ParseIP(host); isInternalAddr(ip) {
			return fmt.Errorf("refusing to connect to internal address %s while loading a JSON-LD context", host)
		}
		return nil
	}

	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{DialContext: dialer.DialContext},
	}
}

// NewCachingDocumentLoader creates a new caching document loader
func NewCachingDocumentLoader() *CachingDocumentLoader {
	cache := ttlcache.New[string, *ld.RemoteDocument](
		ttlcache.WithTTL[string, *ld.RemoteDocument](1 * time.Hour),
	)
	go cache.Start()

	l := &CachingDocumentLoader{
		client: contextHTTPClient(),
		cache:  cache,
		log:    logger.NewSimple("loader"),
	}
	l.preloadContexts()
	return l
}

// fetchContext retrieves a JSON-LD context over HTTP and nothing else.
//
// Link: rel=alternate is deliberately not followed. json-gold's loader
// implements it by recursing into itself, which is how a file:// target became
// reachable; a context this stack fetches is either served as JSON at its own
// URL or it is not used. The W3C base contexts are preloaded and never come
// through here.
func (l *CachingDocumentLoader) fetchContext(rawURL string) (*ld.RemoteDocument, error) {
	u, err := neturl.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("JSON-LD context %q is not a URL: %w", rawURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		l.log.Warn("refused a non-HTTP JSON-LD context", "url", rawURL, "scheme", u.Scheme)
		return nil, fmt.Errorf("refusing to load JSON-LD context %q: only http and https are fetched, got scheme %q", rawURL, u.Scheme)
	}

	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building request for JSON-LD context %q: %w", rawURL, err)
	}
	req.Header.Set("Accept", "application/ld+json, application/json;q=0.9")

	resp, err := l.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("loading JSON-LD context %q: %w", rawURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("loading JSON-LD context %q: HTTP %d", rawURL, resp.StatusCode)
	}

	// Read the bytes first, capped, instead of decoding through a
	// LimitReader. json.Decoder.Decode stops at the end of the first JSON
	// value and never looks at what follows, so a response that opens with a
	// small valid value and then continues was accepted however long it ran -
	// the cap constrained what Decode consumed, not what the body could be.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxContextBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading JSON-LD context %q: %w", rawURL, err)
	}
	if len(body) > maxContextBytes {
		return nil, fmt.Errorf("JSON-LD context %q is larger than the %d byte limit", rawURL, maxContextBytes)
	}

	var document any
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, fmt.Errorf("JSON-LD context %q is not valid JSON: %w", rawURL, err)
	}

	doc := &ld.RemoteDocument{DocumentURL: resp.Request.URL.String(), Document: document}

	// A context served as application/json may name the real context in a
	// Link header (JSON-LD 1.1 section 6.1). Honour that: json-gold resolves
	// ContextURL through the DocumentLoader it was given - this one - so the
	// fetch re-enters the scheme and dial checks.
	//
	// rel=alternate is NOT honoured, and that difference is the point. The
	// processor resolves ContextURL through us; json-gold resolved alternate
	// by calling its own loader, which is how file:// became reachable.
	ctxURL, err := contextLinkTarget(resp)
	if err != nil {
		return nil, fmt.Errorf("loading JSON-LD context %q: %w", rawURL, err)
	}
	if ctxURL != "" {
		// Resolved against the response URL, so a relative target works and a
		// scheme-relative or query-bearing one is not mangled. Parsing first
		// and resolving the result is the only form that handles all three.
		ref, err := neturl.Parse(ctxURL)
		if err != nil {
			return nil, fmt.Errorf("loading JSON-LD context %q: its context link target %q is not a URL: %w", rawURL, ctxURL, err)
		}
		doc.ContextURL = resp.Request.URL.ResolveReference(ref).String()
	}

	return doc, nil
}

// contextLinkTarget returns the target of a Link header naming the document's
// JSON-LD context, if the response is plain JSON. A response already served as
// application/ld+json IS the context and needs no indirection.
func contextLinkTarget(resp *http.Response) (string, error) {
	// PARSED, not prefix-matched. A media type is case-insensitive (RFC 9110
	// 8.3.1), so Application/LD+JSON names this very type - and a prefix test
	// accepts application/ld+jsonx, which names a different one. Both
	// mistakes decide whether the response IS the context or merely points at
	// one, and which context applies decides what RDF a signature covers: a
	// server could serve the context under a differently-cased type and send
	// a Link header to have a DIFFERENT document used in its place.
	//
	// mime.ParseMediaType lowercases the type and strips parameters and
	// surrounding whitespace, so each of those spellings compares equal here.
	// A Content-Type that is absent or unparseable is not this type, and the
	// link is honoured as it is for any other JSON response.
	if mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err == nil &&
		mediaType == "application/ld+json" {
		return "", nil
	}
	// Values, not Get: a response may send several Link headers, and Get
	// returns only the first - so a second one would be invisible, including
	// a second context link, which is the case this function has to detect.
	links := ld.ParseLinkHeader(strings.Join(resp.Header.Values("Link"), ", "))["http://www.w3.org/ns/json-ld#context"]
	switch len(links) {
	case 0:
		return "", nil
	case 1:
		return links[0]["target"], nil
	default:
		// JSON-LD 1.1 6.1 makes this an error rather than a choice, and
		// json-gold raises MultipleContextLinkHeaders for it. Dropping the
		// header instead would parse an ambiguous document as though it named
		// no context at all.
		return "", errors.New("the response carries multiple JSON-LD context links, which is ambiguous")
	}
}

// cloneRemoteDocument returns a deep copy of a loaded document.
//
// The cache hands the same object to every caller, and json-gold MUTATES
// what it is given: handling "@import" it merges the importing context's
// members into the imported document's own map - including the "@import"
// key itself (see vendor/github.com/piprate/json-gold/ld/context.go, "merge
// import context into the outer context"). The cached document is then a
// context that declares a nested @import, which the very next expansion
// refuses with "must not include @import entry".
//
// So a context using @import worked exactly once per process and failed
// every time after. Nothing here expanded twice before this file's startup
// policy began re-checking scopes, which is how it stayed hidden; the
// defect is in handing a shared mutable map to a processor that writes to
// it, so it is fixed here rather than at the callers that now notice.
func cloneRemoteDocument(doc *ld.RemoteDocument) *ld.RemoteDocument {
	if doc == nil {
		return nil
	}
	return &ld.RemoteDocument{
		DocumentURL: doc.DocumentURL,
		Document:    cloneJSONValue(doc.Document),
		ContextURL:  doc.ContextURL,
	}
}

// cloneJSONValue deep-copies a decoded JSON value. json.Unmarshal into an
// `any` produces only these shapes, so the default case is every scalar.
func cloneJSONValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[key] = cloneJSONValue(item)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = cloneJSONValue(item)
		}
		return out
	default:
		return value
	}
}

// LoadDocument implements ld.DocumentLoader
//
// Every successful path returns a COPY: see cloneRemoteDocument.
func (l *CachingDocumentLoader) LoadDocument(url string) (*ld.RemoteDocument, error) {
	if item := l.cache.Get(url); item != nil {
		return cloneRemoteDocument(item.Value()), nil
	}

	// An operator's own copy wins over dereferencing the URL. Checked here
	// rather than only while pinning so it also applies under the lazy
	// startup policy, where nothing is pinned and this is the only path a
	// context is ever loaded by.
	if doc, configured, err := l.loadFromSource(url); configured {
		if err != nil {
			return nil, err
		}
		l.cache.Set(url, doc, ttlcache.DefaultTTL)
		return cloneRemoteDocument(doc), nil
	}

	// Fetched here rather than by json-gold's loader, which calls os.Open for
	// any non-HTTP URL - and resolves a Link: rel=alternate header by calling
	// ITSELF, so an http context could name a file:// alternate and have it
	// read. At verification the context list comes from the wallet, so that is
	// a remote-triggered local file read. Nothing in this path can open a
	// file: it makes an HTTP request or it fails.
	//
	// Preloaded contexts are served from the cache above and never reach this.
	doc, err := l.fetchContext(url)
	if err != nil {
		return nil, err
	}

	l.cache.Set(url, doc, ttlcache.DefaultTTL)

	return cloneRemoteDocument(doc), nil
}

func (l *CachingDocumentLoader) preloadContexts() {
	// Load all embedded contexts
	for url, content := range contextstore.GetAllContexts() {
		l.AddContext(url, string(content))
	}
}

// IsPinned reports whether this URL is held with no expiry, which is what
// pinning means: the document that was validated is the one that will be
// used, rather than one re-fetched when a TTL lapses.
func (l *CachingDocumentLoader) IsPinned(url string) bool {
	item := l.cache.Get(url)
	return item != nil && item.ExpiresAt().IsZero()
}

// AddContext adds a context to the cache manually
func (l *CachingDocumentLoader) AddContext(url string, content string) {
	var doc any
	if err := json.Unmarshal([]byte(content), &doc); err != nil {
		l.log.Info("Failed to parse preloaded context", "url", url, "error", err)
		return
	}

	l.cache.Set(url, &ld.RemoteDocument{
		DocumentURL: url,
		Document:    doc,
		ContextURL:  "", // Not needed for context documents usually
	}, ttlcache.NoTTL)
}
