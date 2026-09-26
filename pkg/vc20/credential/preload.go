package credential

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jellydator/ttlcache/v3"
	"github.com/piprate/json-gold/ld"
)

// PinRemoteContext fetches a JSON-LD context once and keeps it for the life of
// the process.
//
// Two reasons to do this at startup rather than lazily at signing time.
//
// It makes a broken context a STARTUP failure instead of an issuance failure:
// signing canonicalizes the credential to RDF, which dereferences every
// context in it, so an unreachable one otherwise breaks issuance at request
// time - after the user has been sent to their wallet.
//
// And it means the signing path never fetches. Whatever a context endpoint
// does later - redirect somewhere new, serve different content, disappear -
// cannot affect an issued credential, because the document used is the one
// pinned here. The fetch still goes through LoadDocument, so scheme and
// address policy apply to it.
func (l *CachingDocumentLoader) PinRemoteContext(url string) error {
	return l.pinContext(url, make(map[string]bool), 0)
}

// maxPinDepth bounds how far pinning follows references. Contexts nest a
// couple of levels in practice; the bound is there so a hostile or looping
// document cannot turn startup into an unbounded crawl. Cycles are caught by
// the seen set, this catches depth.
const maxPinDepth = 8

// pinContext pins url and everything reaching it: the document itself, the
// URL a Link header redirected the processor to, and any context the
// document references by URL.
//
// Pinning only the requested URL would make the process-lifetime contract a
// half-truth. json-gold resolves a Link-header ContextURL, a nested
// "@context": "https://..." and an "@import" through this same loader, and
// those lookups would land on the normal TTL - so after expiry a signature
// or verification could fetch a context that has since changed, or fail
// because it has gone, despite the configuration having been "pinned" at
// startup. The point of pinning is that what was validated at boot is what
// gets used, and that only holds if it covers the whole closure.
func (l *CachingDocumentLoader) pinContext(url string, seen map[string]bool, depth int) error {
	if url == "" || seen[url] {
		return nil
	}
	if depth > maxPinDepth {
		return fmt.Errorf("context %q nests deeper than %d levels", url, maxPinDepth)
	}
	seen[url] = true

	doc, err := l.LoadDocument(url)
	if err != nil {
		return err
	}
	l.cache.Set(url, doc, ttlcache.NoTTL)

	// The processor will ask for this one by name during expansion.
	if doc.ContextURL != "" && doc.ContextURL != url {
		if err := l.pinContext(doc.ContextURL, seen, depth+1); err != nil {
			return fmt.Errorf("context %q links to %q: %w", url, doc.ContextURL, err)
		}
	}

	for _, ref := range referencedContexts(doc.Document) {
		if err := l.pinContext(ref, seen, depth+1); err != nil {
			return fmt.Errorf("context %q references %q: %w", url, ref, err)
		}
	}
	return nil
}

// referencedContexts collects the context URLs a loaded document refers to by
// string - the values of "@context" and "@import" anywhere within it.
//
// Only absolute http(s) URLs are returned. A relative reference is left to
// the processor and the loader's own address policy; the point here is to
// find the documents that would otherwise be fetched later on a normal TTL.
func referencedContexts(document any) []string {
	var out []string
	var walk func(any)
	walk = func(node any) {
		switch v := node.(type) {
		case map[string]any:
			for key, val := range v {
				if key == "@context" || key == "@import" {
					collectContextStrings(val, &out)
				}
				walk(val)
			}
		case []any:
			for _, item := range v {
				walk(item)
			}
		}
	}
	walk(document)
	return out
}

func collectContextStrings(node any, out *[]string) {
	switch v := node.(type) {
	case string:
		if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
			*out = append(*out, v)
		}
	case []any:
		for _, item := range v {
			collectContextStrings(item, out)
		}
	}
}

// ExpandTypes returns the fully expanded type IRIs a credential carrying these
// compact types would have, given these contexts.
//
// This is the operation that connects credential_types to
// credential_type_values: a term no context defines survives expansion as a
// relative IRI, which identifies nothing, so it is dropped here. What comes
// back is what a verifier would actually match against.
func ExpandTypes(contexts []string, types []string) ([]string, error) {
	doc := map[string]any{
		"@context": append([]string{ContextV2}, contexts...),
		"type":     types,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("encoding types for expansion: %w", err)
	}
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("decoding types for expansion: %w", err)
	}

	opts := ld.NewJsonLdOptions("")
	opts.DocumentLoader = GetGlobalLoader()

	expanded, err := ld.NewJsonLdProcessor().Expand(parsed, opts)
	if err != nil {
		return nil, fmt.Errorf("expanding types: %w", err)
	}

	var iris []string
	for _, node := range expanded {
		nodeMap, ok := node.(map[string]any)
		if !ok {
			continue
		}
		nodeTypes, _ := nodeMap["@type"].([]any)
		for _, t := range nodeTypes {
			// Absolute only: a term the contexts do not define stays relative
			// and cannot equal any configured IRI.
			if iri, ok := t.(string); ok && isAbsoluteIRI(iri) {
				iris = append(iris, iri)
			}
		}
	}
	return iris, nil
}

// isAbsoluteIRI reports whether expansion produced a real identifier rather
// than leaving a term as-is.
func isAbsoluteIRI(s string) bool {
	for i := range len(s) {
		if s[i] == ':' {
			return i > 0
		}
		if s[i] == '/' || s[i] == '#' || s[i] == '?' {
			return false
		}
	}
	return false
}
