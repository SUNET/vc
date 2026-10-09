package statusserviceclient

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// fakeStatusService is a minimal, but real (not mocked-out) stand-in for
// siros-status-service's AS + ingestion API, for tests to run this
// package's client against over real HTTP. "Real" specifically means it
// performs actual RFC 7523 client-assertion verification - parsing the
// JWT, pulling the signing key out of its own embedded `jwk` header (there
// is no pre-registered key to check against, by design - see
// siros-status-service's internal/clientassertion package, which this
// mirrors at test scope since it lives in a different Go module and an
// internal package, so it cannot be imported directly here) and verifying
// the signature against that key - rather than a stub that accepts any
// bearer token unconditionally. A client bug that sends a malformed or
// wrongly-audienced assertion is caught by this test double exactly as it
// would be by the real service.
type fakeStatusService struct {
	t *testing.T

	mu          sync.Mutex
	tokens      map[string]string // access token -> issuer ID
	nextIndex   uint64
	owners      map[string]string // "listID/idx" -> issuer ID
	statusCalls []statusCall

	// allocateFailures, when > 0, makes that many consecutive /allocate
	// calls fail with allocateFailureStatus before succeeding - for
	// exercising retry behaviour. Decremented atomically.
	allocateFailures      atomic.Int32
	allocateFailureStatus int

	// statusFailures does the same for PATCH /status.
	statusFailures      atomic.Int32
	statusFailureStatus int

	allocateCalls   atomic.Int32
	tokenCalls      atomic.Int32
	statusCallCount atomic.Int32

	server              *httptest.Server
	asURL, ingestionURL string
}

type statusCall struct {
	listID, idx, status, issuerID string
}

func newFakeStatusService(t *testing.T) *fakeStatusService {
	t.Helper()
	f := &fakeStatusService{
		t:                     t,
		tokens:                map[string]string{},
		owners:                map[string]string{},
		allocateFailureStatus: http.StatusInternalServerError,
		statusFailureStatus:   http.StatusInternalServerError,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/token", f.handleToken)
	mux.HandleFunc("/allocate", f.handleAllocate)
	mux.HandleFunc("/status/", f.handleSetStatus)

	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	f.asURL = f.server.URL
	f.ingestionURL = f.server.URL
	return f
}

func (f *fakeStatusService) handleToken(w http.ResponseWriter, r *http.Request) {
	f.tokenCalls.Add(1)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	assertion := r.PostFormValue("client_assertion")
	issuerID, err := verifyClientAssertion(assertion, f.asURL+"/token")
	if err != nil {
		http.Error(w, "invalid client assertion: "+err.Error(), http.StatusUnauthorized)
		return
	}

	token := fmt.Sprintf("tok-%s-%d", issuerID, time.Now().UnixNano())
	f.mu.Lock()
	f.tokens[token] = issuerID
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(tokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	})
}

// verifyClientAssertion is a from-scratch (but spec-faithful) reimplementation
// of the RFC 7523 embedded-jwk verification this package's identity.go
// builds assertions for, used only so the fake server in tests performs
// genuine cryptographic verification instead of trusting any bearer blindly.
func verifyClientAssertion(assertion, audience string) (string, error) {
	if assertion == "" {
		return "", fmt.Errorf("no client_assertion")
	}

	var issuerID string
	token, err := jwt.ParseWithClaims(assertion, &jwt.RegisteredClaims{}, func(tok *jwt.Token) (any, error) {
		if _, ok := tok.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", tok.Header["alg"])
		}
		rawJWK, ok := tok.Header["jwk"]
		if !ok {
			return nil, fmt.Errorf("missing jwk header")
		}
		jwkBytes, err := json.Marshal(rawJWK)
		if err != nil {
			return nil, err
		}
		var jwk jose.JSONWebKey
		if err := jwk.UnmarshalJSON(jwkBytes); err != nil {
			return nil, err
		}
		pub, ok := jwk.Key.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("embedded jwk is not an EC public key")
		}
		return pub, nil
	}, jwt.WithValidMethods([]string{"ES256"}), jwt.WithAudience(audience), jwt.WithExpirationRequired())
	if err != nil {
		return "", err
	}
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		return "", fmt.Errorf("invalid claims")
	}
	if claims.Issuer == "" || claims.Issuer != claims.Subject {
		return "", fmt.Errorf("iss and sub must match and be non-empty")
	}
	issuerID = claims.Issuer
	if time.Until(claims.ExpiresAt.Time) > 5*time.Minute {
		return "", fmt.Errorf("assertion lifetime too long")
	}
	return issuerID, nil
}

func (f *fakeStatusService) authenticate(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", false
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	f.mu.Lock()
	defer f.mu.Unlock()
	issuerID, ok := f.tokens[token]
	return issuerID, ok
}

func (f *fakeStatusService) handleAllocate(w http.ResponseWriter, r *http.Request) {
	f.allocateCalls.Add(1)
	issuerID, ok := f.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if n := f.allocateFailures.Load(); n > 0 {
		f.allocateFailures.Add(-1)
		http.Error(w, "injected failure", f.allocateFailureStatus)
		return
	}

	f.mu.Lock()
	idx := f.nextIndex
	f.nextIndex++
	f.owners[fmt.Sprintf("list-a/%d", idx)] = issuerID
	f.mu.Unlock()

	resp := allocateResponse{
		ListURL: f.server.URL + "/lists/list-a",
		Index:   idx,
		Exp:     time.Now().Add(24 * time.Hour),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

func (f *fakeStatusService) handleSetStatus(w http.ResponseWriter, r *http.Request) {
	f.statusCallCount.Add(1)
	issuerID, ok := f.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Path: /status/{listID}/{idx}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/status/"), "/")
	if len(parts) != 2 {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	listID, idxStr := parts[0], parts[1]
	if _, err := strconv.ParseUint(idxStr, 10, 64); err != nil {
		http.Error(w, "bad index", http.StatusBadRequest)
		return
	}

	if n := f.statusFailures.Load(); n > 0 {
		f.statusFailures.Add(-1)
		http.Error(w, "injected failure", f.statusFailureStatus)
		return
	}

	f.mu.Lock()
	owner, known := f.owners[listID+"/"+idxStr]
	f.mu.Unlock()
	if !known {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if owner != issuerID {
		http.Error(w, "not owner", http.StatusForbidden)
		return
	}

	var body setStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}

	f.mu.Lock()
	f.statusCalls = append(f.statusCalls, statusCall{listID: listID, idx: idxStr, status: body.Status, issuerID: issuerID})
	f.mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

// url is a small convenience so tests don't need to import net/url just to
// join a path onto the fake server's base URL.
func (f *fakeStatusService) url(path string) string {
	u, err := url.Parse(f.server.URL)
	if err != nil {
		f.t.Fatalf("parse fake server URL: %v", err)
	}
	u.Path = path
	return u.String()
}
