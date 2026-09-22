package credential

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
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

// contextHTTPClient fetches remote JSON-LD contexts, refusing redirects that
// leave the public internet, and without waiting indefinitely.
//
// Redirects cannot simply be refused: w3id.org exists to redirect, and the
// Data Integrity contexts resolve through it to w3.org. But a redirect also
// defeats any decision made about the URL before the fetch - the issuer
// allowlists which context URLs it may dereference
// (issuer.jsonld_context_allowlist), and an allowlisted endpoint answering 302
// would otherwise send that fetch anywhere the issuer can reach.
//
// So redirects are followed, but never to a private, loopback or link-local
// address, which is where an allowlist bypass would be aiming.
func contextHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many redirects while loading a JSON-LD context")
			}
			if internal, addr := resolvesToInternalAddress(req.URL.Hostname()); internal {
				return fmt.Errorf("refusing to follow a JSON-LD context redirect to an internal address (%s -> %s)", req.URL, addr)
			}
			return nil
		},
	}
}

// resolvesToInternalAddress reports whether a host resolves to any address the
// public internet cannot reach, and which one.
func resolvesToInternalAddress(host string) (bool, string) {
	if host == "" {
		return true, "empty host"
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		// Unresolvable is not reachable; let the request fail on its own terms.
		return false, ""
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return true, ip.String()
		}
	}
	return false, ""
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
