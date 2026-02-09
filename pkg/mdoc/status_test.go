package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"vc/pkg/tokenstatuslist"

	"github.com/golang-jwt/jwt/v5"
)

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

func TestNewStatusChecker(t *testing.T) {
	sc := NewStatusChecker()

	if sc == nil {
		t.Fatal("NewStatusChecker() returned nil")
	}

	if sc.httpClient == nil {
		t.Error("httpClient is nil")
	}

	if sc.cache == nil {
		t.Error("cache is nil")
	}
}

func TestNewStatusChecker_WithOptions(t *testing.T) {
	customClient := &http.Client{Timeout: 10 * time.Second}

	sc := NewStatusChecker(
		WithHTTPClient(customClient),
		WithCacheExpiry(10*time.Minute),
	)

	if sc.httpClient != customClient {
		t.Error("custom HTTP client not set")
	}

	if sc.cacheExpiry != 10*time.Minute {
		t.Errorf("cache expiry = %v, want %v", sc.cacheExpiry, 10*time.Minute)
	}
}

func TestStatusChecker_CheckStatus_NilRef(t *testing.T) {
	sc := NewStatusChecker()

	_, err := sc.CheckStatus(t.Context(), nil)
	if err == nil {
		t.Error("CheckStatus(nil) should fail")
	}
}

func TestStatusChecker_CheckStatus_EmptyURI(t *testing.T) {
	sc := NewStatusChecker()

	_, err := sc.CheckStatus(t.Context(), &StatusReference{URI: "", Index: 0})
	if err == nil {
		t.Error("CheckStatus with empty URI should fail")
	}
}

func TestStatusChecker_CheckStatus_NegativeIndex(t *testing.T) {
	sc := NewStatusChecker()

	_, err := sc.CheckStatus(t.Context(), &StatusReference{URI: "https://example.com/status", Index: -1})
	if err == nil {
		t.Error("CheckStatus with negative index should fail")
	}
}

func TestStatusChecker_CheckStatus_WithServer(t *testing.T) {
	// Generate a test key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create a test status list
	statuses := make([]uint8, 100)
	statuses[0] = tokenstatuslist.StatusValid
	statuses[1] = tokenstatuslist.StatusInvalid
	statuses[2] = tokenstatuslist.StatusSuspended

	sl := tokenstatuslist.NewWithConfig(statuses, "test-issuer", "https://example.com/status")
	sl.ExpiresIn = time.Hour
	sl.TTL = 3600

	// Generate a JWT token
	jwtToken, err := sl.GenerateJWT(tokenstatuslist.JWTSigningConfig{
		SigningKey:    privateKey,
		SigningMethod: jwt.SigningMethodES256,
	})
	if err != nil {
		t.Fatalf("Failed to generate JWT: %v", err)
	}

	publicKey := &privateKey.PublicKey

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", tokenstatuslist.MediaTypeJWT)
		w.Write([]byte(jwtToken))
	}))
	defer server.Close()

	sc := NewStatusChecker(WithKeyFunc(func(token *jwt.Token) (any, error) {
		return publicKey, nil
	}))

	// Test valid status
	result, err := sc.CheckStatus(t.Context(), &StatusReference{URI: server.URL, Index: 0})
	if err != nil {
		t.Fatalf("CheckStatus() error = %v", err)
	}

	if result.Status != CredentialStatusValid {
		t.Errorf("Status = %v, want %v", result.Status, CredentialStatusValid)
	}

	// Test invalid status
	result, err = sc.CheckStatus(t.Context(), &StatusReference{URI: server.URL, Index: 1})
	if err != nil {
		t.Fatalf("CheckStatus() error = %v", err)
	}

	if result.Status != CredentialStatusInvalid {
		t.Errorf("Status = %v, want %v", result.Status, CredentialStatusInvalid)
	}

	// Test suspended status
	result, err = sc.CheckStatus(t.Context(), &StatusReference{URI: server.URL, Index: 2})
	if err != nil {
		t.Fatalf("CheckStatus() error = %v", err)
	}

	if result.Status != CredentialStatusSuspended {
		t.Errorf("Status = %v, want %v", result.Status, CredentialStatusSuspended)
	}
}

func TestStatusChecker_CheckStatus_IndexOutOfRange(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	statuses := make([]uint8, 10)
	sl := tokenstatuslist.NewWithConfig(statuses, "test-issuer", "https://example.com/status")
	sl.ExpiresIn = time.Hour

	jwtToken, _ := sl.GenerateJWT(tokenstatuslist.JWTSigningConfig{
		SigningKey:    privateKey,
		SigningMethod: jwt.SigningMethodES256,
	})

	publicKey := &privateKey.PublicKey

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", tokenstatuslist.MediaTypeJWT)
		w.Write([]byte(jwtToken))
	}))
	defer server.Close()

	sc := NewStatusChecker(WithKeyFunc(func(token *jwt.Token) (any, error) {
		return publicKey, nil
	}))

	_, err := sc.CheckStatus(t.Context(), &StatusReference{URI: server.URL, Index: 100})
	if err == nil {
		t.Error("CheckStatus with out-of-range index should fail")
	}
}

func TestStatusChecker_ClearCache(t *testing.T) {
	sc := NewStatusChecker()

	// Add something to cache
	sc.cache.entries["test"] = &statusCacheEntry{
		statuses:  []uint8{0, 1, 2},
		expiresAt: time.Now().Add(time.Hour),
	}

	if len(sc.cache.entries) != 1 {
		t.Fatal("cache should have 1 entry")
	}

	sc.ClearCache()

	if len(sc.cache.entries) != 0 {
		t.Error("cache should be empty after ClearCache()")
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

	for i := int64(0); i < 10; i++ {
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
	sm.Suspend(5)

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

func TestNewVerifierStatusCheck(t *testing.T) {
	sc := NewStatusChecker()
	vsc := NewVerifierStatusCheck(sc)

	if vsc == nil {
		t.Fatal("NewVerifierStatusCheck() returned nil")
	}

	if !vsc.enabled {
		t.Error("enabled should be true by default")
	}
}

func TestVerifierStatusCheck_SetEnabled(t *testing.T) {
	sc := NewStatusChecker()
	vsc := NewVerifierStatusCheck(sc)

	vsc.SetEnabled(false)
	if vsc.enabled {
		t.Error("enabled should be false")
	}

	vsc.SetEnabled(true)
	if !vsc.enabled {
		t.Error("enabled should be true")
	}
}

func TestExtractStatusReference_NilDoc(t *testing.T) {
	_, err := ExtractStatusReference(nil)
	if err == nil {
		t.Error("ExtractStatusReference(nil) should fail")
	}
}

func TestExtractStatusReference_NoStatus(t *testing.T) {
	doc := &Document{
		DocType: DocType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]IssuerSignedItem{
				Namespace: {
					{ElementIdentifier: "family_name", ElementValue: "Test"},
				},
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

	doc := &Document{
		DocType: DocType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]IssuerSignedItem{
				Namespace: {
					{ElementIdentifier: "status", ElementValue: statusValue},
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

func TestMapStatusCode(t *testing.T) {
	tests := []struct {
		code   uint8
		status CredentialStatus
	}{
		{tokenstatuslist.StatusValid, CredentialStatusValid},
		{tokenstatuslist.StatusInvalid, CredentialStatusInvalid},
		{tokenstatuslist.StatusSuspended, CredentialStatusSuspended},
		{99, CredentialStatusUnknown},
	}

	for _, tt := range tests {
		got := mapStatusCode(tt.code)
		if got != tt.status {
			t.Errorf("mapStatusCode(%d) = %v, want %v", tt.code, got, tt.status)
		}
	}
}

func TestStatusChecker_CacheExpiry(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	statuses := make([]uint8, 10)
	sl := tokenstatuslist.NewWithConfig(statuses, "test-issuer", "https://example.com/status")
	sl.ExpiresIn = time.Hour

	jwtToken, _ := sl.GenerateJWT(tokenstatuslist.JWTSigningConfig{
		SigningKey:    privateKey,
		SigningMethod: jwt.SigningMethodES256,
	})

	publicKey := &privateKey.PublicKey

	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", tokenstatuslist.MediaTypeJWT)
		w.Write([]byte(jwtToken))
	}))
	defer server.Close()

	sc := NewStatusChecker(
		WithCacheExpiry(time.Hour),
		WithKeyFunc(func(token *jwt.Token) (any, error) {
			return publicKey, nil
		}),
	)

	// First call should hit the server
	_, err := sc.CheckStatus(t.Context(), &StatusReference{URI: server.URL, Index: 0})
	if err != nil {
		t.Fatalf("CheckStatus() error = %v", err)
	}
	if callCount != 1 {
		t.Errorf("Expected 1 server call, got %d", callCount)
	}

	// Second call should use cache
	_, err = sc.CheckStatus(t.Context(), &StatusReference{URI: server.URL, Index: 1})
	if err != nil {
		t.Fatalf("CheckStatus() error = %v", err)
	}
	if callCount != 1 {
		t.Errorf("Expected 1 server call (cached), got %d", callCount)
	}
}

func TestVerifierStatusCheck_CheckDocumentStatus_Disabled(t *testing.T) {
	sc := NewStatusChecker()
	vsc := NewVerifierStatusCheck(sc)
	vsc.SetEnabled(false)

	// Create a document (status doesn't matter when disabled)
	doc := &Document{
		DocType: DocType,
	}

	result, err := vsc.CheckDocumentStatus(t.Context(), doc)
	if err != nil {
		t.Fatalf("CheckDocumentStatus() error = %v", err)
	}

	if result == nil {
		t.Fatal("CheckDocumentStatus() returned nil result when disabled")
	}

	if result.Status != CredentialStatusValid {
		t.Errorf("Status = %v, want valid (disabled always returns valid)", result.Status)
	}
}

func TestVerifierStatusCheck_CheckDocumentStatus_NoStatusReference(t *testing.T) {
	sc := NewStatusChecker()
	vsc := NewVerifierStatusCheck(sc)

	// Document without status element
	doc := &Document{
		DocType: DocType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]IssuerSignedItem{
				Namespace: {
					{ElementIdentifier: "family_name", ElementValue: "Test"},
				},
			},
		},
	}

	result, err := vsc.CheckDocumentStatus(t.Context(), doc)
	// No status reference means no revocation support - should return nil, nil
	if err != nil {
		t.Fatalf("CheckDocumentStatus() error = %v", err)
	}
	if result != nil {
		t.Error("CheckDocumentStatus() should return nil for doc without status reference")
	}
}

func TestVerifierStatusCheck_CheckDocumentStatus_Valid(t *testing.T) {
	// Create test server with status list
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	statuses := make([]uint8, 100)
	statuses[42] = tokenstatuslist.StatusValid // Index 42 is valid

	sl := tokenstatuslist.NewWithConfig(statuses, "test-issuer", "https://example.com/status")
	sl.ExpiresIn = time.Hour

	jwtToken, _ := sl.GenerateJWT(tokenstatuslist.JWTSigningConfig{
		SigningKey:    privateKey,
		SigningMethod: jwt.SigningMethodES256,
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", tokenstatuslist.MediaTypeJWT)
		w.Write([]byte(jwtToken))
	}))
	defer server.Close()

	sc := NewStatusChecker(WithKeyFunc(func(token *jwt.Token) (any, error) {
		return &privateKey.PublicKey, nil
	}))
	vsc := NewVerifierStatusCheck(sc)

	// Document with status reference pointing to our server
	statusValue := map[string]any{
		"status_list": map[string]any{
			"uri": server.URL,
			"idx": int64(42),
		},
	}

	doc := &Document{
		DocType: DocType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]IssuerSignedItem{
				Namespace: {
					{ElementIdentifier: "status", ElementValue: statusValue},
				},
			},
		},
	}

	result, err := vsc.CheckDocumentStatus(t.Context(), doc)
	if err != nil {
		t.Fatalf("CheckDocumentStatus() error = %v", err)
	}

	if result == nil {
		t.Fatal("CheckDocumentStatus() returned nil result")
	}

	if result.Status != CredentialStatusValid {
		t.Errorf("Status = %v, want valid", result.Status)
	}
}

func TestVerifierStatusCheck_CheckDocumentStatus_Revoked(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	statuses := make([]uint8, 100)
	statuses[10] = tokenstatuslist.StatusInvalid // Index 10 is revoked

	sl := tokenstatuslist.NewWithConfig(statuses, "test-issuer", "https://example.com/status")
	sl.ExpiresIn = time.Hour

	jwtToken, _ := sl.GenerateJWT(tokenstatuslist.JWTSigningConfig{
		SigningKey:    privateKey,
		SigningMethod: jwt.SigningMethodES256,
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", tokenstatuslist.MediaTypeJWT)
		w.Write([]byte(jwtToken))
	}))
	defer server.Close()

	sc := NewStatusChecker(WithKeyFunc(func(token *jwt.Token) (any, error) {
		return &privateKey.PublicKey, nil
	}))
	vsc := NewVerifierStatusCheck(sc)

	statusValue := map[string]any{
		"status_list": map[string]any{
			"uri": server.URL,
			"idx": int64(10),
		},
	}

	doc := &Document{
		DocType: DocType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]IssuerSignedItem{
				Namespace: {
					{ElementIdentifier: "status", ElementValue: statusValue},
				},
			},
		},
	}

	result, err := vsc.CheckDocumentStatus(t.Context(), doc)
	if err != nil {
		t.Fatalf("CheckDocumentStatus() error = %v", err)
	}

	if result.Status != CredentialStatusInvalid {
		t.Errorf("Status = %v, want invalid (revoked)", result.Status)
	}
}

func TestVerifierStatusCheck_CheckDocumentStatus_Suspended(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	statuses := make([]uint8, 100)
	statuses[5] = tokenstatuslist.StatusSuspended // Index 5 is suspended

	sl := tokenstatuslist.NewWithConfig(statuses, "test-issuer", "https://example.com/status")
	sl.ExpiresIn = time.Hour

	jwtToken, _ := sl.GenerateJWT(tokenstatuslist.JWTSigningConfig{
		SigningKey:    privateKey,
		SigningMethod: jwt.SigningMethodES256,
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", tokenstatuslist.MediaTypeJWT)
		w.Write([]byte(jwtToken))
	}))
	defer server.Close()

	sc := NewStatusChecker(WithKeyFunc(func(token *jwt.Token) (any, error) {
		return &privateKey.PublicKey, nil
	}))
	vsc := NewVerifierStatusCheck(sc)

	statusValue := map[string]any{
		"status_list": map[string]any{
			"uri": server.URL,
			"idx": int64(5),
		},
	}

	doc := &Document{
		DocType: DocType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]IssuerSignedItem{
				Namespace: {
					{ElementIdentifier: "status", ElementValue: statusValue},
				},
			},
		},
	}

	result, err := vsc.CheckDocumentStatus(t.Context(), doc)
	if err != nil {
		t.Fatalf("CheckDocumentStatus() error = %v", err)
	}

	if result.Status != CredentialStatusSuspended {
		t.Errorf("Status = %v, want suspended", result.Status)
	}
}

func TestVerifierStatusCheck_CheckDocumentStatus_IntegrationWithIssuer(t *testing.T) {
	// Test the full flow: issuer creates credential with status, later revokes it,
	// verifier checks status

	// 1. Issuer creates status manager
	sm := NewStatusManager("https://example.com/status", 100)

	// 2. Issuer allocates index for new credential
	credIndex, err := sm.AllocateIndex()
	if err != nil {
		t.Fatalf("AllocateIndex() error = %v", err)
	}

	// 3. Get status reference for embedding in credential
	statusRef := sm.GetStatusReference(credIndex)

	// 4. Create a document with the status reference
	statusValue := map[string]any{
		"status_list": map[string]any{
			"uri": statusRef.URI,
			"idx": statusRef.Index,
		},
	}

	doc := &Document{
		DocType: DocType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]IssuerSignedItem{
				Namespace: {
					{ElementIdentifier: "family_name", ElementValue: "Test"},
					{ElementIdentifier: "status", ElementValue: statusValue},
				},
			},
		},
	}

	// 5. Issuer revokes the credential
	err = sm.Revoke(credIndex)
	if err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	// 6. Generate JWT status list for publishing
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	sl := sm.StatusList()
	jwtToken, err := sl.GenerateJWT(tokenstatuslist.JWTSigningConfig{
		SigningKey:    privateKey,
		SigningMethod: jwt.SigningMethodES256,
	})
	if err != nil {
		t.Fatalf("GenerateJWT() error = %v", err)
	}

	// 7. Verifier fetches status list from server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", tokenstatuslist.MediaTypeJWT)
		w.Write([]byte(jwtToken))
	}))
	defer server.Close()

	// Update the document's status URI to point to test server
	doc.IssuerSigned.NameSpaces[Namespace][1].ElementValue = map[string]any{
		"status_list": map[string]any{
			"uri": server.URL,
			"idx": statusRef.Index,
		},
	}

	// 8. Verifier checks document status
	sc := NewStatusChecker(WithKeyFunc(func(token *jwt.Token) (any, error) {
		return &privateKey.PublicKey, nil
	}))
	vsc := NewVerifierStatusCheck(sc)

	result, err := vsc.CheckDocumentStatus(t.Context(), doc)
	if err != nil {
		t.Fatalf("CheckDocumentStatus() error = %v", err)
	}

	if result.Status != CredentialStatusInvalid {
		t.Errorf("Status = %v, want invalid (credential was revoked)", result.Status)
	}
}

func TestStatusChecker_CheckStatus_CWTFormat(t *testing.T) {
	// Generate a test key for signing
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create a test status list
	statuses := make([]uint8, 100)
	statuses[0] = tokenstatuslist.StatusValid
	statuses[1] = tokenstatuslist.StatusInvalid
	statuses[2] = tokenstatuslist.StatusSuspended

	sl := tokenstatuslist.NewWithConfig(statuses, "test-issuer", "https://example.com/status")
	sl.ExpiresIn = time.Hour
	sl.TTL = 3600

	// Generate a CWT token
	cwtToken, err := sl.GenerateCWT(tokenstatuslist.CWTSigningConfig{
		SigningKey: privateKey,
		Algorithm:  tokenstatuslist.CoseAlgES256,
	})
	if err != nil {
		t.Fatalf("Failed to generate CWT: %v", err)
	}

	// Create test server that returns CWT
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", tokenstatuslist.MediaTypeCWT)
		w.Write(cwtToken)
	}))
	defer server.Close()

	sc := NewStatusChecker()

	// Test valid status (index 0)
	result, err := sc.CheckStatus(t.Context(), &StatusReference{URI: server.URL, Index: 0})
	if err != nil {
		t.Fatalf("CheckStatus() CWT error = %v", err)
	}
	if result.Status != CredentialStatusValid {
		t.Errorf("CWT Status[0] = %v, want valid", result.Status)
	}

	// Test invalid status (index 1)
	result, err = sc.CheckStatus(t.Context(), &StatusReference{URI: server.URL, Index: 1})
	if err != nil {
		t.Fatalf("CheckStatus() CWT error = %v", err)
	}
	if result.Status != CredentialStatusInvalid {
		t.Errorf("CWT Status[1] = %v, want invalid", result.Status)
	}

	// Test suspended status (index 2)
	result, err = sc.CheckStatus(t.Context(), &StatusReference{URI: server.URL, Index: 2})
	if err != nil {
		t.Fatalf("CheckStatus() CWT error = %v", err)
	}
	if result.Status != CredentialStatusSuspended {
		t.Errorf("CWT Status[2] = %v, want suspended", result.Status)
	}
}

func TestStatusChecker_CheckStatus_CWTAutoDetect(t *testing.T) {
	// Generate a test key
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	statuses := make([]uint8, 50)
	statuses[10] = tokenstatuslist.StatusInvalid

	sl := tokenstatuslist.NewWithConfig(statuses, "test-issuer", "https://example.com/status")
	sl.ExpiresIn = time.Hour

	cwtToken, err := sl.GenerateCWT(tokenstatuslist.CWTSigningConfig{
		SigningKey: privateKey,
		Algorithm:  tokenstatuslist.CoseAlgES256,
	})
	if err != nil {
		t.Fatalf("Failed to generate CWT: %v", err)
	}

	// Server returns CWT without proper content-type (auto-detect via 0xD2 tag)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(cwtToken)
	}))
	defer server.Close()

	sc := NewStatusChecker()

	// Should auto-detect CWT format from CBOR tag 18 (0xD2)
	result, err := sc.CheckStatus(t.Context(), &StatusReference{URI: server.URL, Index: 10})
	if err != nil {
		t.Fatalf("CheckStatus() auto-detect CWT error = %v", err)
	}
	if result.Status != CredentialStatusInvalid {
		t.Errorf("CWT auto-detect Status[10] = %v, want invalid", result.Status)
	}
}

func TestStatusChecker_parseCWTStatusList_InvalidCBOR(t *testing.T) {
	sc := NewStatusChecker()

	// Invalid CBOR data
	_, err := sc.parseCWTStatusList([]byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Error("parseCWTStatusList() should fail with invalid CBOR")
	}
}

func TestStatusChecker_parseCWTStatusList_MissingStatusListClaim(t *testing.T) {
	sc := NewStatusChecker()

	// Create a valid COSE_Sign1 but without status_list claim
	// This is a manually crafted minimal COSE_Sign1 with empty payload
	// Tag 18 + array[protected, unprotected, payload, signature]
	// For simplicity, we'll use the tokenstatuslist to make a CWT then modify it

	// Actually, it's easier to just test with empty payload that parses but has no claim
	// We can't easily create a valid CWT without status_list, so let's test the error path
	// by providing data that parses but has wrong structure

	// This test verifies the error handling for malformed CWT
	_, err := sc.parseCWTStatusList([]byte{
		0xD2, // CBOR tag 18
		0x84, // Array of 4 items
		0x40, // Empty bytes (protected)
		0xA0, // Empty map (unprotected)
		0x40, // Empty bytes (payload - no claims)
		0x40, // Empty bytes (signature)
	})
	if err == nil {
		t.Error("parseCWTStatusList() should fail with empty payload")
	}
}

func TestStatusChecker_parseCWTStatusList_ValidToken(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create status list with known values
	statuses := make([]uint8, 20)
	statuses[0] = tokenstatuslist.StatusValid
	statuses[5] = tokenstatuslist.StatusInvalid
	statuses[10] = tokenstatuslist.StatusSuspended

	sl := tokenstatuslist.NewWithConfig(statuses, "test-issuer", "https://example.com/status")
	sl.ExpiresIn = time.Hour

	cwtToken, err := sl.GenerateCWT(tokenstatuslist.CWTSigningConfig{
		SigningKey: privateKey,
		Algorithm:  tokenstatuslist.CoseAlgES256,
	})
	if err != nil {
		t.Fatalf("Failed to generate CWT: %v", err)
	}

	sc := NewStatusChecker()

	// Parse the CWT directly
	statuses, err = sc.parseCWTStatusList(cwtToken)
	if err != nil {
		t.Fatalf("parseCWTStatusList() error = %v", err)
	}

	if len(statuses) < 20 {
		t.Fatalf("parseCWTStatusList() returned %d statuses, want at least 20", len(statuses))
	}

	// Verify status values
	if statuses[0] != tokenstatuslist.StatusValid {
		t.Errorf("Status[0] = %d, want %d (valid)", statuses[0], tokenstatuslist.StatusValid)
	}
	if statuses[5] != tokenstatuslist.StatusInvalid {
		t.Errorf("Status[5] = %d, want %d (invalid)", statuses[5], tokenstatuslist.StatusInvalid)
	}
	if statuses[10] != tokenstatuslist.StatusSuspended {
		t.Errorf("Status[10] = %d, want %d (suspended)", statuses[10], tokenstatuslist.StatusSuspended)
	}
}

func TestVerifierStatusCheck_CheckDocumentStatus_CWT(t *testing.T) {
	// Test full flow with CWT format status list
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	statuses := make([]uint8, 100)
	statuses[25] = tokenstatuslist.StatusSuspended

	sl := tokenstatuslist.NewWithConfig(statuses, "test-issuer", "https://example.com/status")
	sl.ExpiresIn = time.Hour

	cwtToken, _ := sl.GenerateCWT(tokenstatuslist.CWTSigningConfig{
		SigningKey: privateKey,
		Algorithm:  tokenstatuslist.CoseAlgES256,
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", tokenstatuslist.MediaTypeCWT)
		w.Write(cwtToken)
	}))
	defer server.Close()

	sc := NewStatusChecker()
	vsc := NewVerifierStatusCheck(sc)

	statusValue := map[string]any{
		"status_list": map[string]any{
			"uri": server.URL,
			"idx": int64(25),
		},
	}

	doc := &Document{
		DocType: DocType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]IssuerSignedItem{
				Namespace: {
					{ElementIdentifier: "status", ElementValue: statusValue},
				},
			},
		},
	}

	result, err := vsc.CheckDocumentStatus(t.Context(), doc)
	if err != nil {
		t.Fatalf("CheckDocumentStatus() CWT error = %v", err)
	}

	if result.Status != CredentialStatusSuspended {
		t.Errorf("CWT CheckDocumentStatus() = %v, want suspended", result.Status)
	}
}
