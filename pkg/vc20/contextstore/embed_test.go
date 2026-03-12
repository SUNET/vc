package contextstore

import (
	"encoding/json"
	"testing"
)

func TestGetContext_V2(t *testing.T) {
	data, err := GetContext("https://www.w3.org/ns/credentials/v2")
	if err != nil {
		t.Fatalf("failed to get V2 context: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("V2 context is empty")
	}

	// Verify it's valid JSON-LD
	var jsonld map[string]any
	if err := json.Unmarshal(data, &jsonld); err != nil {
		t.Fatalf("V2 context is not valid JSON: %v", err)
	}

	// Verify it has @context
	if _, ok := jsonld["@context"]; !ok {
		t.Fatal("V2 context missing @context key")
	}
}

func TestGetContext_V1(t *testing.T) {
	data, err := GetContext("https://www.w3.org/2018/credentials/v1")
	if err != nil {
		t.Fatalf("failed to get V1 context: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("V1 context is empty")
	}

	// Verify it's valid JSON-LD
	var jsonld map[string]any
	if err := json.Unmarshal(data, &jsonld); err != nil {
		t.Fatalf("V1 context is not valid JSON: %v", err)
	}

	// Verify it has @context
	if _, ok := jsonld["@context"]; !ok {
		t.Fatal("V1 context missing @context key")
	}
}

func TestGetContext_Unknown(t *testing.T) {
	_, err := GetContext("https://example.com/unknown-context")
	if err == nil {
		t.Fatal("expected error for unknown context")
	}
}

func TestGetAllContexts(t *testing.T) {
	contexts := GetAllContexts()

	if len(contexts) == 0 {
		t.Fatal("GetAllContexts returned no contexts")
	}

	// Should contain V1 and V2
	expectedURLs := []string{
		"https://www.w3.org/ns/credentials/v2",
		"https://www.w3.org/2018/credentials/v1",
	}

	for _, url := range expectedURLs {
		data, ok := contexts[url]
		if !ok {
			t.Errorf("missing expected context: %s", url)
			continue
		}
		if len(data) == 0 {
			t.Errorf("context %s is empty", url)
		}
	}
}
