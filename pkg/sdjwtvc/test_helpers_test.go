package sdjwtvc

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"vc/pkg/jose"
)

// testSigner implements the Signer interface for unit tests.
type testSigner struct {
	key    any
	algo   string
	kid    string
	pubKey any
	method jwt.SigningMethod
}

func newTestSigner(key any, kid string) *testSigner {
	method, algo := jose.GetSigningMethodFromKey(key)
	var pubKey any
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	}
	return &testSigner{key: key, algo: algo, kid: kid, pubKey: pubKey, method: method}
}

func (s *testSigner) Sign(_ context.Context, data []byte) ([]byte, error) {
	return s.method.Sign(string(data), s.key)
}
func (s *testSigner) Algorithm() string { return s.algo }
func (s *testSigner) KeyID() string     { return s.kid }
func (s *testSigner) PublicKey() any    { return s.pubKey }

// failingSigner implements Signer but always returns an error on Sign.
type failingSigner struct{}

func (s *failingSigner) Sign(_ context.Context, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("mock signing failure")
}
func (s *failingSigner) Algorithm() string { return "ES256" }
func (s *failingSigner) KeyID() string     { return "fail-key" }
func (s *failingSigner) PublicKey() any    { return nil }

// serveVCTM starts an httptest server that serves the given VCTM as JSON.
// It computes the SRI integrity hash and registers cleanup via t.Cleanup.
// Returns the server URL (to use as vct) and the integrity string.
func serveVCTM(t *testing.T, vctm *VCTM) (vctURL string, integrity string) {
	t.Helper()
	raw, err := json.Marshal(vctm)
	require.NoError(t, err)
	integrity, err = vctm.SRIIntegrity(raw)
	require.NoError(t, err)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(raw)
	}))
	t.Cleanup(ts.Close)
	return ts.URL, integrity
}

// marshalVCTM marshals a VCTM to JSON bytes and computes the SRI integrity hash.
// Unlike serveVCTM, this does not start an HTTP server — the raw bytes are
// intended for the inline VCTM parameter of BuildCredentialWithSigner.
func marshalVCTM(t *testing.T, vctm *VCTM) (raw []byte, integrity string) {
	t.Helper()
	raw, err := json.Marshal(vctm)
	require.NoError(t, err)
	integrity, err = vctm.SRIIntegrity(raw)
	require.NoError(t, err)
	return raw, integrity
}
