package credential

import (
	"encoding/json"
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

// NewCachingDocumentLoader creates a new caching document loader
func NewCachingDocumentLoader() *CachingDocumentLoader {
	cache := ttlcache.New[string, *ld.RemoteDocument](
		ttlcache.WithTTL[string, *ld.RemoteDocument](1 * time.Hour),
	)
	go cache.Start()

	l := &CachingDocumentLoader{
		fallback: ld.NewDefaultDocumentLoader(nil),
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
