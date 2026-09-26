package credential

import (
	"encoding/json"
	"testing"

	"github.com/jellydator/ttlcache/v3"
	"github.com/piprate/json-gold/ld"
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
			// Relative references are the processor's business, not ours.
			"relative.jsonld",
		},
	}

	got := referencedContexts(doc)
	want := map[string]bool{
		"https://example.org/one.jsonld":   true,
		"https://example.org/two.jsonld":   true,
		"https://example.org/three.jsonld": true,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want the three absolute URLs", got)
	}
	for _, u := range got {
		if !want[u] {
			t.Errorf("unexpected %q - only absolute http(s) context URLs belong here", u)
		}
	}
}
