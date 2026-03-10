package credential

import (
	"testing"

	"github.com/piprate/json-gold/ld"
)

func TestNewJSONLDOptions(t *testing.T) {
	opts := NewJSONLDOptions("https://example.com")
	if opts == nil {
		t.Error("Expected options, got nil")
	}
	if opts.DocumentLoader == nil {
		t.Error("Expected document loader to be set")
	}

	// Test that the loader is our caching loader
	loader := opts.DocumentLoader
	if _, ok := loader.(*CachingDocumentLoader); !ok {
		t.Errorf("Expected CachingDocumentLoader, got %T", loader)
	}
}

func TestNewJSONLDOptionsEmptyBase(t *testing.T) {
	opts := NewJSONLDOptions("")
	if opts == nil {
		t.Error("Expected options, got nil")
	}
}

func TestConstants(t *testing.T) {
	if ContextV2 != "https://www.w3.org/ns/credentials/v2" {
		t.Errorf("Expected ContextV2 to be https://www.w3.org/ns/credentials/v2, got %s", ContextV2)
	}
	if ProofTypeDataIntegrity != "DataIntegrityProof" {
		t.Errorf("Expected ProofTypeDataIntegrity to be DataIntegrityProof, got %s", ProofTypeDataIntegrity)
	}
}

func TestGetGlobalLoader(t *testing.T) {
	loader1 := GetGlobalLoader()
	if loader1 == nil {
		t.Error("Expected loader, got nil")
	}

	// Call again to test singleton
	loader2 := GetGlobalLoader()
	if loader1 != loader2 {
		t.Error("Expected GetGlobalLoader to return same instance")
	}
}

func TestCachingDocumentLoaderLoadDocument(t *testing.T) {
	loader := GetGlobalLoader()

	// Load a preloaded context
	doc, err := loader.LoadDocument("https://www.w3.org/ns/credentials/v2")
	if err != nil {
		t.Fatalf("Failed to load document: %v", err)
	}

	if doc == nil {
		t.Error("Expected document, got nil")
	}

	if doc.DocumentURL != "https://www.w3.org/ns/credentials/v2" {
		t.Errorf("Expected DocumentURL to be https://www.w3.org/ns/credentials/v2, got %s", doc.DocumentURL)
	}

	if doc.Document == nil {
		t.Error("Expected Document to be set")
	}
}

func TestCachingDocumentLoaderCacheHit(t *testing.T) {
	loader := GetGlobalLoader()

	// First load
	doc1, err := loader.LoadDocument("https://www.w3.org/ns/credentials/v2")
	if err != nil {
		t.Fatalf("Failed to load document: %v", err)
	}

	// Second load should hit cache
	doc2, err := loader.LoadDocument("https://www.w3.org/ns/credentials/v2")
	if err != nil {
		t.Fatalf("Failed to load document on second call: %v", err)
	}

	if doc1 != doc2 {
		t.Error("Expected same document from cache")
	}
}

func TestCachingDocumentLoaderAddContext(t *testing.T) {
	loader := NewCachingDocumentLoader()

	// Add a custom context
	customContext := `{"@context": {"test": "https://example.com/test"}}`
	loader.AddContext("https://example.com/test/context", customContext)

	// Load it back
	doc, err := loader.LoadDocument("https://example.com/test/context")
	if err != nil {
		t.Fatalf("Failed to load custom context: %v", err)
	}

	if doc == nil {
		t.Error("Expected document, got nil")
	}

	if doc.DocumentURL != "https://example.com/test/context" {
		t.Errorf("Expected DocumentURL to be https://example.com/test/context, got %s", doc.DocumentURL)
	}
}

func TestCachingDocumentLoaderAddInvalidContext(t *testing.T) {
	loader := NewCachingDocumentLoader()

	// Add invalid JSON - should not crash, just log an error
	loader.AddContext("https://example.com/invalid", "not valid json")

	// Loading should fail or return nil - but AddContext doesn't cache it
	doc, err := loader.LoadDocument("https://example.com/invalid")
	// This will try to fetch from network, which should fail
	_ = doc
	_ = err
}

func TestNewRDFCredentialFromJSONWithCustomOptions(t *testing.T) {
	credentialJSON := []byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": "VerifiableCredential",
		"issuer": "https://example.com/issuer",
		"credentialSubject": {"id": "did:example:123"}
	}`)

	// Test with custom options
	opts := ld.NewJsonLdOptions("")
	opts.DocumentLoader = GetGlobalLoader()

	rdfCred, err := NewRDFCredentialFromJSON(credentialJSON, opts)
	if err != nil {
		t.Fatalf("Failed to create RDFCredential with custom options: %v", err)
	}

	if rdfCred == nil {
		t.Error("Expected RDFCredential, got nil")
	}
}

func TestNewRDFCredentialFromJSONWithDefaultLoader(t *testing.T) {
	credentialJSON := []byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": "VerifiableCredential",
		"issuer": "https://example.com/issuer",
		"credentialSubject": {"id": "did:example:123"}
	}`)

	// Test with options that have default document loader (should be replaced)
	opts := ld.NewJsonLdOptions("")
	opts.DocumentLoader = ld.NewDefaultDocumentLoader(nil)

	rdfCred, err := NewRDFCredentialFromJSON(credentialJSON, opts)
	if err != nil {
		t.Fatalf("Failed to create RDFCredential: %v", err)
	}

	if rdfCred == nil {
		t.Error("Expected RDFCredential, got nil")
	}
}
