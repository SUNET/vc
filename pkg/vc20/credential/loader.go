package credential

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	neturl "net/url"
	"sync"
	"syscall"
	"time"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/vc20/contextstore"

	"github.com/jellydator/ttlcache/v3"
	"github.com/piprate/json-gold/ld"
)

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
	fallback ld.DocumentLoader
	cache    *ttlcache.Cache[string, *ld.RemoteDocument]
	log      *logger.Log
}

// schemeOf returns the scheme of a context URL, or "" if it has none.
func schemeOf(raw string) string {
	u, err := neturl.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Scheme
}

// isInternalAddr reports whether an address is one the public internet cannot
// reach, and which a context fetch therefore has no business connecting to.
func isInternalAddr(ip net.IP) bool {
	return ip == nil || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
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
		fallback: ld.NewDefaultDocumentLoader(contextHTTPClient()),
		cache:    cache,
		log:      logger.NewSimple("loader"),
	}
	l.preloadContexts()
	return l
}

// LoadDocument implements ld.DocumentLoader
func (l *CachingDocumentLoader) LoadDocument(url string) (*ld.RemoteDocument, error) {
	if item := l.cache.Get(url); item != nil {
		return item.Value(), nil
	}

	// http(s) only. json-gold's loader opens any other URL as a LOCAL FILE
	// (os.Open), and at verification the context list comes from the wallet -
	// so file:///etc/passwd would be read and parsed as a context. Where the
	// connection may go is enforced at dial time by contextHTTPClient; what
	// may be opened at all is enforced here.
	//
	// Preloaded contexts are served from the cache above and never reach this.
	if scheme := schemeOf(url); scheme != "http" && scheme != "https" {
		l.log.Warn("refused a non-HTTP JSON-LD context", "url", url, "scheme", scheme)
		return nil, fmt.Errorf("refusing to load JSON-LD context %q: only http and https are fetched, got scheme %q", url, scheme)
	}

	// Fallback to network
	doc, err := l.fallback.LoadDocument(url)
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
