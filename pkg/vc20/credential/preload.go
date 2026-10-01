package credential

import (
	"encoding/json"
	"fmt"
	neturl "net/url"
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

// maxPinDepth bounds how far pinning follows references, and
// maxPinnedContexts bounds how MANY it reaches.
//
// Depth alone does not bound the crawl, which the comment here used to claim.
// A single document can list an unbounded number of distinct @context or
// @import URLs, and every one of them sits at depth 1 - so a hostile or
// compromised allowlisted document could turn startup into a crawl of
// thousands of fetches without ever nesting. The seen set stops a URL being
// fetched twice; it does not stop there being very many of them.
//
// Each document is already capped at maxContextBytes, so a count bound caps
// the bytes too. Contexts reach a handful of documents in practice.
const (
	maxPinDepth       = 8
	maxPinnedContexts = 64
)

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
	// Counted across the WHOLE closure, not per level: seen holds every
	// distinct URL this pin has reached, so its size is the crawl so far.
	if len(seen) >= maxPinnedContexts {
		return fmt.Errorf("pinning reaches more than %d contexts, refusing to fetch %q", maxPinnedContexts, url)
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

	// Relative references resolve against the document's own URL, the way
	// json-gold does before calling LoadDocument.
	base := doc.DocumentURL
	if base == "" {
		base = url
	}
	for _, ref := range referencedContexts(doc.Document, base) {
		if err := l.pinContext(ref, seen, depth+1); err != nil {
			return fmt.Errorf("context %q references %q: %w", url, ref, err)
		}
	}
	return nil
}

// referencedContexts collects the context URLs a loaded document refers to by
// string - the values of "@context" and "@import" anywhere within it -
// resolving relative references against base.
//
// Relative references are resolved rather than skipped because json-gold
// resolves them against RemoteDocument.DocumentURL before calling
// LoadDocument (see ld/context.go). Leaving them out meant a document
// containing "nested.jsonld" was fetched later on the normal TTL, so after
// expiry it could change or fail while startup had reported the whole
// closure pinned. Skipping them made the pinning contract a half-truth in
// exactly the way pinning exists to prevent.
func referencedContexts(document any, base string) []string {
	var out []string
	// An unparsable base leaves relative references unresolvable; they are
	// then skipped rather than guessed at.
	baseURL, err := neturl.Parse(base)
	if err != nil {
		baseURL = nil
	}
	var walk func(any)
	walk = func(node any) {
		switch v := node.(type) {
		case map[string]any:
			for key, val := range v {
				if key == "@context" || key == "@import" {
					collectContextStrings(val, baseURL, &out)
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

func collectContextStrings(node any, base *neturl.URL, out *[]string) {
	switch v := node.(type) {
	case string:
		if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
			*out = append(*out, v)
			return
		}
		// Relative: resolve against the document that referenced it, which
		// is what the processor will do when it fetches this later.
		if base == nil || v == "" {
			return
		}
		ref, err := neturl.Parse(v)
		if err != nil {
			return
		}
		resolved := base.ResolveReference(ref)
		if resolved.Scheme == "http" || resolved.Scheme == "https" {
			*out = append(*out, resolved.String())
		}
	case []any:
		for _, item := range v {
			collectContextStrings(item, base, out)
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

// IsAbsoluteIRI reports whether expansion produced a real identifier rather
// than leaving a term as-is.
//
// Exported because three other packages were deciding the same question
// with `strings.Contains(s, ":")`, which is not the same test: a relative
// reference such as "/relative:Type" or "path/to:thing" contains a colon
// and is still relative. A term a document's context does not define
// survives expansion unchanged, so admitting one of those lets a constraint
// be satisfied by string coincidence.
//
// The rule: everything before the first colon must be a SCHEME, and the
// colon must come before any '/', '#' or '?'.
//
// "Nonempty" is not enough for the first half. RFC 3986 section 3.1 spells a
// scheme ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ), so "1:Type" and
// "foo_bar:Type" are relative references that merely contain a colon - and
// admitting them is the exact defect this helper replaced, one character
// narrower: a type no context defines survives expansion unchanged, and then
// satisfies a meta.type_values constraint by string coincidence.
func IsAbsoluteIRI(s string) bool {
	return isAbsoluteIRI(s)
}

func isAbsoluteIRI(s string) bool {
	for i := range len(s) {
		if s[i] == ':' {
			return i > 0 && isSchemeStart(s[0]) && isSchemeTail(s[1:i])
		}
		if s[i] == '/' || s[i] == '#' || s[i] == '?' {
			return false
		}
	}
	return false
}

// isSchemeStart reports whether c may begin a scheme: ALPHA only, so a
// leading digit disqualifies.
func isSchemeStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// isSchemeTail reports whether every byte may continue a scheme:
// ALPHA / DIGIT / "+" / "-" / "." - notably NOT "_".
func isSchemeTail(s string) bool {
	for i := range len(s) {
		c := s[i]
		switch {
		case isSchemeStart(c), c >= '0' && c <= '9', c == '+', c == '-', c == '.':
		default:
			return false
		}
	}
	return true
}
