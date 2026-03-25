package discoverfeatures

import (
	"testing"

	"github.com/SUNET/vc/pkg/didcomm/message"
)

func TestNewQuery(t *testing.T) {
	query, err := NewQuery(
		"did:example:alice",
		"did:example:bob",
		QueryProtocols("https://didcomm.org/*"),
	)
	if err != nil {
		t.Fatalf("NewQuery() error = %v", err)
	}

	if query.Type != TypeQueries {
		t.Errorf("Type = %v, want %v", query.Type, TypeQueries)
	}

	body, err := GetQueryBody(query)
	if err != nil {
		t.Fatalf("GetQueryBody() error = %v", err)
	}

	if len(body.Queries) != 1 {
		t.Fatalf("Queries count = %d, want 1", len(body.Queries))
	}

	if body.Queries[0].FeatureType != FeatureTypeProtocol {
		t.Errorf("FeatureType = %v, want %v", body.Queries[0].FeatureType, FeatureTypeProtocol)
	}

	if body.Queries[0].Match != "https://didcomm.org/*" {
		t.Errorf("Match = %v, want https://didcomm.org/*", body.Queries[0].Match)
	}
}

func TestNewQuery_MultipleQueries(t *testing.T) {
	query, err := NewQuery(
		"did:example:alice",
		"did:example:bob",
		QueryProtocols("*"),
		QueryGoalCodes("issue-*"),
		AddQuery(FeatureTypeHeader, "custom-header"),
	)
	if err != nil {
		t.Fatalf("NewQuery() error = %v", err)
	}

	body, _ := GetQueryBody(query)
	if len(body.Queries) != 3 {
		t.Errorf("Queries count = %d, want 3", len(body.Queries))
	}
}

func TestNewQuery_Empty(t *testing.T) {
	_, err := NewQuery("did:example:alice", "did:example:bob")
	if err == nil {
		t.Error("expected error for empty queries")
	}
}

func TestNewDisclose(t *testing.T) {
	query, _ := NewQuery(
		"did:example:alice",
		"did:example:bob",
		QueryProtocols("*"),
	)

	features := []Feature{
		{FeatureType: FeatureTypeProtocol, ID: "https://didcomm.org/trust-ping/2.0"},
		{FeatureType: FeatureTypeProtocol, ID: "https://didcomm.org/discover-features/2.0"},
	}

	disclose, err := NewDisclose(query, features)
	if err != nil {
		t.Fatalf("NewDisclose() error = %v", err)
	}

	if disclose.Type != TypeDisclose {
		t.Errorf("Type = %v, want %v", disclose.Type, TypeDisclose)
	}

	// Should be from bob to alice
	if disclose.From != "did:example:bob" {
		t.Errorf("From = %v, want did:example:bob", disclose.From)
	}

	body, _ := GetDiscloseBody(disclose)
	if len(body.Disclosures) != 2 {
		t.Errorf("Disclosures count = %d, want 2", len(body.Disclosures))
	}
}

func TestProtocolRegistry(t *testing.T) {
	registry := NewProtocolRegistry()
	registry.RegisterProtocol("https://didcomm.org/trust-ping/2.0", "sender", "receiver")
	registry.RegisterProtocol("https://didcomm.org/discover-features/2.0", "requester", "responder")
	registry.RegisterProtocol("https://didcomm.org/out-of-band/2.0")
	registry.RegisterGoalCode("issue-credential")
	registry.RegisterGoalCode("verify-credential")

	// Query all protocols
	query, _ := NewQuery("did:example:alice", "did:example:bob", QueryProtocols("*"))
	disclose, err := registry.HandleQuery(query)
	if err != nil {
		t.Fatalf("HandleQuery() error = %v", err)
	}

	body, _ := GetDiscloseBody(disclose)
	if len(body.Disclosures) != 3 {
		t.Errorf("Disclosures count = %d, want 3", len(body.Disclosures))
	}
}

func TestProtocolRegistry_PrefixMatch(t *testing.T) {
	registry := NewProtocolRegistry()
	registry.RegisterProtocol("https://didcomm.org/trust-ping/2.0")
	registry.RegisterProtocol("https://didcomm.org/discover-features/2.0")
	registry.RegisterProtocol("https://example.com/custom/1.0")

	// Query only didcomm.org protocols
	query, _ := NewQuery("did:example:alice", "did:example:bob", QueryProtocols("https://didcomm.org/*"))
	disclose, _ := registry.HandleQuery(query)

	body, _ := GetDiscloseBody(disclose)
	if len(body.Disclosures) != 2 {
		t.Errorf("Disclosures count = %d, want 2", len(body.Disclosures))
	}
}

func TestProtocolRegistry_GoalCodes(t *testing.T) {
	registry := NewProtocolRegistry()
	registry.RegisterGoalCode("issue-credential")
	registry.RegisterGoalCode("issue-license")
	registry.RegisterGoalCode("verify-credential")

	// Query issue-* goal codes
	query, _ := NewQuery("did:example:alice", "did:example:bob", QueryGoalCodes("issue-*"))
	disclose, _ := registry.HandleQuery(query)

	body, _ := GetDiscloseBody(disclose)
	if len(body.Disclosures) != 2 {
		t.Errorf("Disclosures count = %d, want 2 (issue-credential, issue-license)", len(body.Disclosures))
	}
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"*", "anything", true},
		{"", "anything", true},
		{"exact", "exact", true},
		{"exact", "different", false},
		{"prefix*", "prefixsuffix", true},
		{"prefix*", "other", false},
		{"https://didcomm.org/*", "https://didcomm.org/trust-ping/2.0", true},
		{"https://didcomm.org/*", "https://example.com/other", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.value, func(t *testing.T) {
			got := matchPattern(tt.pattern, tt.value)
			if got != tt.want {
				t.Errorf("matchPattern(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

func TestIsQuery(t *testing.T) {
	query, _ := NewQuery("did:example:alice", "did:example:bob", QueryProtocols("*"))
	if !IsQuery(query) {
		t.Error("IsQuery() = false for query message")
	}

	other := message.New(message.WithType("https://example.com/other"))
	if IsQuery(other) {
		t.Error("IsQuery() = true for non-query message")
	}
}

func TestIsDisclose(t *testing.T) {
	query, _ := NewQuery("did:example:alice", "did:example:bob", QueryProtocols("*"))
	disclose, _ := NewDisclose(query, nil)

	if !IsDisclose(disclose) {
		t.Error("IsDisclose() = false for disclose message")
	}

	if IsDisclose(query) {
		t.Error("IsDisclose() = true for query message")
	}
}
