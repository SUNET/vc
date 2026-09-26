package credential

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
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
	contentType := resp.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "application/ld+json") {
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

// LoadDocument implements ld.DocumentLoader
func (l *CachingDocumentLoader) LoadDocument(url string) (*ld.RemoteDocument, error) {
	if item := l.cache.Get(url); item != nil {
		return item.Value(), nil
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

	return doc, nil
}

func (l *CachingDocumentLoader) preloadContexts() {
	// Load all embedded contexts
	for url, content := range contextstore.GetAllContexts() {
		l.AddContext(url, string(content))
	}
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
