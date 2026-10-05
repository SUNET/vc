package credential

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/jellydator/ttlcache/v3"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
)

// seedWithTTL puts a context in the cache the way a normal fetch would -
// with an expiry - so a test can tell pinning apart from merely being
// present. AddContext cannot be used for this: it already pins.
func seedWithTTL(t *testing.T, l *CachingDocumentLoader, url, content string) {
	t.Helper()
	var doc any
	if err := json.Unmarshal([]byte(content), &doc); err != nil {
		t.Fatalf("seed %s: %v", url, err)
	}
	l.cache.Set(url, &ld.RemoteDocument{DocumentURL: url, Document: doc}, ttlcache.DefaultTTL)
}

func pinned(t *testing.T, l *CachingDocumentLoader, url string) bool {
	t.Helper()
	item := l.cache.Get(url)
	if item == nil {
		t.Fatalf("%s is not cached at all", url)
	}
	return item.ExpiresAt().IsZero()
}

// Pinning only the requested URL would make the process-lifetime contract a
// half-truth: json-gold resolves a nested "@context": "https://..." through
// this same loader during expansion, and that lookup would land on the
// normal TTL. After expiry, signing or verification could then fetch a
// context that has changed - or fail because it has gone - despite the
// configuration having been pinned at startup.
func TestPinRemoteContext_PinsReferencedContexts(t *testing.T) {
	l := NewCachingDocumentLoader()

	const root = "https://ctx.example.org/root.jsonld"
	const leaf = "https://ctx.example.org/leaf.jsonld"
	const nested = "https://ctx.example.org/nested.jsonld"

	seedWithTTL(t, l, root, `{"@context":["`+leaf+`",{"Root":"https://example.org/Root"}]}`)
	seedWithTTL(t, l, leaf, `{"@context":{"@import":"`+nested+`","Leaf":"https://example.org/Leaf"}}`)
	seedWithTTL(t, l, nested, `{"@context":{"Nested":"https://example.org/Nested"}}`)

	if pinned(t, l, leaf) {
		t.Fatal("precondition: the seeded leaf must start unpinned, or this test proves nothing")
	}

	if err := l.PinRemoteContext(root); err != nil {
		t.Fatalf("PinRemoteContext: %v", err)
	}

	for _, u := range []string{root, leaf, nested} {
		if !pinned(t, l, u) {
			t.Errorf("%s still has a TTL, so the pin does not cover the whole closure", u)
		}
	}
}

// A context that references itself, directly or through a cycle, must not
// send pinning round forever.
func TestPinRemoteContext_SurvivesACycle(t *testing.T) {
	l := NewCachingDocumentLoader()

	const a = "https://ctx.example.org/a.jsonld"
	const b = "https://ctx.example.org/b.jsonld"
	seedWithTTL(t, l, a, `{"@context":["`+b+`"]}`)
	seedWithTTL(t, l, b, `{"@context":["`+a+`"]}`)

	if err := l.PinRemoteContext(a); err != nil {
		t.Fatalf("PinRemoteContext: %v", err)
	}
	if !pinned(t, l, a) || !pinned(t, l, b) {
		t.Fatal("both sides of the cycle should be pinned")
	}
}

func TestReferencedContexts(t *testing.T) {
	doc := map[string]any{
		"@context": []any{
			"https://example.org/one.jsonld",
			map[string]any{
				"@import": "https://example.org/two.jsonld",
				"Term":    "https://example.org/Term",
				"nested":  map[string]any{"@context": "https://example.org/three.jsonld"},
			},
			// Relative: json-gold resolves this against the document's own
			// URL and fetches it later, so it belongs in the pinned closure
			// too - skipping it made the contract a half-truth.
			"relative.jsonld",
			"../up/one.jsonld",
			// Non-http after resolution is REPORTED, not excluded: a
			// reference this cannot pin must fail the pin rather than
			// vanish from the closure startup claims to have pinned.
			"mailto:someone@example.org",
		},
	}

	got, unsupported := referencedContexts(doc, "https://example.org/deep/base.jsonld")
	if len(unsupported) != 1 || unsupported[0] != "mailto:someone@example.org" {
		t.Fatalf("unsupported = %v, want the mailto reference reported rather than dropped", unsupported)
	}
	want := map[string]bool{
		"https://example.org/one.jsonld":           true,
		"https://example.org/two.jsonld":           true,
		"https://example.org/three.jsonld":         true,
		"https://example.org/deep/relative.jsonld": true,
		"https://example.org/up/one.jsonld":        true,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %d entries including the resolved relative ones", got, len(want))
	}
	for _, u := range got {
		if !want[u] {
			t.Errorf("unexpected %q - only http(s) context URLs, absolute or resolved, belong here", u)
		}
	}
}

// TestReferencedContexts_NoBaseReportsRelatives: with no usable base there
// is nothing to resolve against, and guessing would pin a URL the processor
// will never ask for. It is still REPORTED rather than dropped - "I cannot
// pin this" is the honest answer, and the caller refuses on it.
func TestReferencedContexts_NoBaseReportsRelatives(t *testing.T) {
	doc := map[string]any{"@context": []any{"relative.jsonld", "https://example.org/abs.jsonld"}}

	got, unsupported := referencedContexts(doc, "")
	if len(got) != 1 || got[0] != "https://example.org/abs.jsonld" {
		t.Fatalf("got %v, want only the absolute URL", got)
	}
	// Reported in its RESOLVED form ("/relative.jsonld" against an empty
	// base), which is what the processor would have asked for - the error
	// should name what could not be pinned, not what was written.
	if len(unsupported) != 1 || unsupported[0] != "/relative.jsonld" {
		t.Fatalf("unsupported = %v, want the unresolvable relative reference reported", unsupported)
	}
}

// TestPinRemoteContext_BoundsFanOutNotJustDepth: maxPinDepth bounds how far
// pinning follows references and says nothing about how MANY it reaches. A
// single document can list an unbounded number of distinct @context URLs, all
// of them at depth 1 - so a hostile or compromised allowlisted document could
// turn startup into a crawl of thousands of fetches without ever nesting.
//
// The seen set stops a URL being fetched twice. It does not stop there being
// very many of them.
func TestPinRemoteContext_BoundsFanOutNotJustDepth(t *testing.T) {
	t.Run("a wide document is refused", func(t *testing.T) {
		l := NewCachingDocumentLoader()

		const root = "https://ctx.example.org/wide.jsonld"
		refs := make([]string, 0, maxPinnedContexts+10)
		for i := range cap(refs) {
			leaf := fmt.Sprintf("https://ctx.example.org/leaf-%d.jsonld", i)
			seedWithTTL(t, l, leaf, `{"@context":{"Leaf":"https://example.org/Leaf"}}`)
			refs = append(refs, `"`+leaf+`"`)
		}
		seedWithTTL(t, l, root, `{"@context":[`+strings.Join(refs, ",")+`]}`)

		err := l.PinRemoteContext(root)
		require.Error(t, err, "fan-out at depth 1 must be bounded, not only nesting")
		require.Contains(t, err.Error(), "reaches more than")

		// And it stopped: the documents past the budget were never pinned.
		last := fmt.Sprintf("https://ctx.example.org/leaf-%d.jsonld", cap(refs)-1)
		require.False(t, pinned(t, l, last),
			"the crawl stopped at the budget rather than finishing and then complaining")
	})

	t.Run("an ordinary closure still pins", func(t *testing.T) {
		l := NewCachingDocumentLoader()

		const root = "https://ctx.example.org/narrow.jsonld"
		refs := make([]string, 0, 5)
		for i := range cap(refs) {
			leaf := fmt.Sprintf("https://ctx.example.org/narrow-leaf-%d.jsonld", i)
			seedWithTTL(t, l, leaf, `{"@context":{"Leaf":"https://example.org/Leaf"}}`)
			refs = append(refs, `"`+leaf+`"`)
		}
		seedWithTTL(t, l, root, `{"@context":[`+strings.Join(refs, ",")+`]}`)

		require.NoError(t, l.PinRemoteContext(root),
			"the budget must not refuse the closures real contexts have")
		require.True(t, pinned(t, l, root))
	})
}

// TestPinRemoteContext_RefusesAnUnpinnableReference: the whole promise of
// pinning the closure at startup is that nothing in it is fetched again
// later. A nested reference this cannot pin used to be dropped silently, so
// an allowlisted root passed the pin with a hole in its closure - and the
// reference was met for the first time during issuance, where LoadDocument
// refuses it and a credential fails to sign.
//
// Refused at pin time, naming the reference, so the configuration fails
// where it can still be fixed.
func TestPinRemoteContext_RefusesAnUnpinnableReference(t *testing.T) {
	for name, ref := range map[string]string{
		"file":  "file:///etc/ssl/context.jsonld",
		"data":  "data:application/ld+json,%7B%7D",
		"other": "mailto:someone@example.org",
	} {
		t.Run(name+" is refused", func(t *testing.T) {
			l := NewCachingDocumentLoader()
			const root = "https://ctx.example.org/root.jsonld"
			seedWithTTL(t, l, root, `{"@context":["`+ref+`"]}`)

			err := l.PinRemoteContext(root)
			require.Error(t, err, "a reference that cannot be pinned must fail the pin")
			require.Contains(t, err.Error(), "cannot be pinned")
			require.Contains(t, err.Error(), ref,
				"the error must name the reference, or an operator cannot find it")
		})
	}

	// The control: an ordinary http reference still pins, so the test above
	// is not passing against a function that refuses every nested reference.
	t.Run("an http reference still pins", func(t *testing.T) {
		l := NewCachingDocumentLoader()
		const root = "https://ctx.example.org/ok-root.jsonld"
		const leaf = "https://ctx.example.org/ok-leaf.jsonld"
		seedWithTTL(t, l, leaf, `{"@context":{"Leaf":"https://example.org/Leaf"}}`)
		seedWithTTL(t, l, root, `{"@context":["`+leaf+`"]}`)

		require.NoError(t, l.PinRemoteContext(root))
		require.True(t, pinned(t, l, leaf))
	})
}
