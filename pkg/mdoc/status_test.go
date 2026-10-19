package mdoc

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// testCache returns a WithStatusCache option with an in-memory cache for testing.
func TestCredentialStatus_String(t *testing.T) {
	tests := []struct {
		status CredentialStatus
		want   string
	}{
		{CredentialStatusValid, "valid"},
		{CredentialStatusInvalid, "invalid"},
		{CredentialStatusSuspended, "suspended"},
		{CredentialStatusUnknown, "unknown"},
		{CredentialStatus(99), "unknown"},
	}

	for _, tt := range tests {
		got := tt.status.String()
		if got != tt.want {
			t.Errorf("CredentialStatus(%d).String() = %s, want %s", tt.status, got, tt.want)
		}
	}
}

func TestNewStatusManager(t *testing.T) {
	sm := NewStatusManager("https://example.com/status", 100)

	if sm == nil {
		t.Fatal("NewStatusManager() returned nil")
	}

	if sm.statusList.Len() != 100 {
		t.Errorf("status list size = %d, want 100", sm.statusList.Len())
	}

	if sm.uri != "https://example.com/status" {
		t.Errorf("uri = %s, want https://example.com/status", sm.uri)
	}
}

func TestStatusManager_AllocateIndex(t *testing.T) {
	sm := NewStatusManager("https://example.com/status", 10)

	for i := range int64(10) {
		idx, err := sm.AllocateIndex()
		if err != nil {
			t.Fatalf("AllocateIndex() error = %v", err)
		}
		if idx != i {
			t.Errorf("AllocateIndex() = %d, want %d", idx, i)
		}
	}

	// Should fail when full
	_, err := sm.AllocateIndex()
	if err == nil {
		t.Error("AllocateIndex() should fail when list is full")
	}
}

func TestStatusManager_GetStatusReference(t *testing.T) {
	sm := NewStatusManager("https://example.com/status", 100)

	ref := sm.GetStatusReference(42)

	if ref.URI != "https://example.com/status" {
		t.Errorf("URI = %s, want https://example.com/status", ref.URI)
	}
	if ref.Index != 42 {
		t.Errorf("Index = %d, want 42", ref.Index)
	}
}

func TestStatusManager_Revoke(t *testing.T) {
	sm := NewStatusManager("https://example.com/status", 100)

	err := sm.Revoke(5)
	if err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	status, _ := sm.GetStatus(5)
	if status != CredentialStatusInvalid {
		t.Errorf("Status after revoke = %v, want invalid", status)
	}
}

func TestStatusManager_Revoke_OutOfRange(t *testing.T) {
	sm := NewStatusManager("https://example.com/status", 10)

	err := sm.Revoke(100)
	if err == nil {
		t.Error("Revoke() with out-of-range index should fail")
	}
}

func TestStatusManager_Suspend(t *testing.T) {
	sm := NewStatusManager("https://example.com/status", 100)

	err := sm.Suspend(5)
	if err != nil {
		t.Fatalf("Suspend() error = %v", err)
	}

	status, _ := sm.GetStatus(5)
	if status != CredentialStatusSuspended {
		t.Errorf("Status after suspend = %v, want suspended", status)
	}
}

func TestStatusManager_Reinstate(t *testing.T) {
	sm := NewStatusManager("https://example.com/status", 100)

	// Suspend first
	sm.Suspend(5) // #nosec G104

	// Then reinstate
	err := sm.Reinstate(5)
	if err != nil {
		t.Fatalf("Reinstate() error = %v", err)
	}

	status, _ := sm.GetStatus(5)
	if status != CredentialStatusValid {
		t.Errorf("Status after reinstate = %v, want valid", status)
	}
}

func TestStatusManager_GetStatus(t *testing.T) {
	sm := NewStatusManager("https://example.com/status", 100)

	// Initial status should be valid
	status, err := sm.GetStatus(0)
	if err != nil {
		t.Fatalf("GetStatus() error = %v", err)
	}
	if status != CredentialStatusValid {
		t.Errorf("Initial status = %v, want valid", status)
	}
}

func TestStatusManager_GetStatus_OutOfRange(t *testing.T) {
	sm := NewStatusManager("https://example.com/status", 10)

	_, err := sm.GetStatus(100)
	if err == nil {
		t.Error("GetStatus() with out-of-range index should fail")
	}
}

func TestStatusManager_StatusList(t *testing.T) {
	sm := NewStatusManager("https://example.com/status", 100)

	sl := sm.StatusList()
	if sl == nil {
		t.Error("StatusList() returned nil")
	}
}

func TestExtractStatusReference_NilDoc(t *testing.T) {
	_, err := ExtractStatusReference(nil)
	if err == nil {
		t.Error("ExtractStatusReference(nil) should fail")
	}
}

func TestExtractStatusReference_NoStatus(t *testing.T) {
	issuerSignedNS := make(map[string][]any)
	for ns, items := range map[string][]IssuerSignedItem{
		Namespace: {{DigestID: 0, Random: make([]byte, 16), ElementIdentifier: "family_name", ElementValue: "Test"}},
	} {
		anyItems := make([]any, len(items))
		for i, item := range items {
			// Here, item is an IssuerSignedItem, being stored as 'any'
			anyItems[i] = item
		}
		issuerSignedNS[ns] = anyItems
	}

	emptyMapBytes, _ := cbor.Marshal(map[string]any{})
	doc := &DocumentMdoc{
		DocType: DocType,
		IssuerSigned: IssuerSignedMdoc{
			NameSpaces: issuerSignedNS,
			IssuerAuth: []any{0xD2},
		},
		DeviceSigned: DeviceSignedMdoc{
			// Wrap in Tag 24 as required by the latest review comments
			NameSpaces: cbor.Tag{Number: 24, Content: emptyMapBytes},
			DeviceAuth: DeviceAuthMdoc{
				DeviceSignature: []byte{0xD2},
			},
		},
	}

	_, err := ExtractStatusReference(doc)
	if err == nil {
		t.Error("ExtractStatusReference() should fail when no status element")
	}
}

func TestExtractStatusReference_WithStatus(t *testing.T) {
	statusValue := map[string]any{
		"status_list": map[string]any{
			"uri": "https://example.com/status",
			"idx": int64(42),
		},
	}

	doc := &DocumentMdoc{
		DocType: DocType,
		IssuerSigned: IssuerSignedMdoc{
			// Change the slice type in the map literal to []any
			NameSpaces: map[string][]any{
				Namespace: {
					IssuerSignedItem{
						ElementIdentifier: "status",
						ElementValue:      statusValue,
					},
				},
			},
		},
	}

	ref, err := ExtractStatusReference(doc)
	if err != nil {
		t.Fatalf("ExtractStatusReference() error = %v", err)
	}

	if ref.URI != "https://example.com/status" {
		t.Errorf("URI = %s, want https://example.com/status", ref.URI)
	}
	if ref.Index != 42 {
		t.Errorf("Index = %d, want 42", ref.Index)
	}
}

func TestParseStatusElement_MapStringAny(t *testing.T) {
	value := map[string]any{
		"status_list": map[string]any{
			"uri": "https://example.com/status",
			"idx": int64(10),
		},
	}

	ref, ok := parseStatusElement(value)
	if !ok {
		t.Fatal("parseStatusElement() returned false")
	}

	if ref.URI != "https://example.com/status" {
		t.Errorf("URI = %s", ref.URI)
	}
	if ref.Index != 10 {
		t.Errorf("Index = %d", ref.Index)
	}
}

func TestParseStatusElement_MapAnyAny(t *testing.T) {
	value := map[any]any{
		"status_list": map[any]any{
			"uri": "https://example.com/status",
			"idx": float64(20),
		},
	}

	ref, ok := parseStatusElement(value)
	if !ok {
		t.Fatal("parseStatusElement() returned false")
	}

	if ref.Index != 20 {
		t.Errorf("Index = %d, want 20", ref.Index)
	}
}

func TestParseStatusElement_InvalidType(t *testing.T) {
	_, ok := parseStatusElement("invalid")
	if ok {
		t.Error("parseStatusElement() should return false for invalid type")
	}
}
