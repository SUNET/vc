package credential

import (
	"encoding/json"
	"fmt"

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
	doc, err := l.LoadDocument(url)
	if err != nil {
		return err
	}
	l.cache.Set(url, doc, ttlcache.NoTTL)
	return nil
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
