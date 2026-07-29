package httpserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/pki"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeTestSigningKey generates a fresh EC private key and writes it as a PEM
// file under t.TempDir(), returning the file path. Mirrors the pattern used
// in pkg/pki/signer_config_test.go.
func writeTestSigningKey(t *testing.T) string {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	require.NoError(t, err)

	keyPath := filepath.Join(t.TempDir(), "test-key.pem")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	return keyPath
}

// testSetupDID builds a minimal gin engine that registers only the DID
// document endpoint, matching how it's wired in service.go.
func testSetupDID(t *testing.T, verifierCfg *model.Verifier) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	ctx := context.Background()
	tracer, err := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, err)

	cfg := &model.Cfg{
		Common:   &model.Common{},
		Verifier: verifierCfg,
	}

	helpers, err := httphelpers.New(ctx, tracer, cfg, log)
	require.NoError(t, err)

	s := &Service{
		cfg:         cfg,
		log:         log.New("httpserver"),
		tracer:      tracer,
		httpHelpers: helpers,
	}

	engine := gin.New()
	rg := engine.Group("/")
	helpers.Server.RegEndpoint(ctx, rg, http.MethodGet, ".well-known/did.json", http.StatusOK, s.endpointDIDDocument)

	return engine
}

// TestEndpointDIDDocument_Disabled verifies that when DID mode is not enabled
// (ClientIDScheme != "did" or DID unset), the endpoint responds with a real
// 404 that is not overwritten by RegEndpoint's default-status fallback.
func TestEndpointDIDDocument_Disabled(t *testing.T) {
	tests := []struct {
		name string
		cfg  *model.Verifier
	}{
		{
			name: "client_id_scheme not did",
			cfg: &model.Verifier{
				ClientIDScheme: "x509_san_dns",
				DID:            "",
			},
		},
		{
			name: "did scheme but empty DID",
			cfg: &model.Verifier{
				ClientIDScheme: "did",
				DID:            "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := testSetupDID(t, tt.cfg)

			req := httptest.NewRequest(http.MethodGet, "/.well-known/did.json", nil)
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)

			assert.Equal(t, http.StatusNotFound, w.Code)
			assert.Empty(t, w.Body.Bytes())
		})
	}
}

// TestEndpointDIDDocument_Enabled verifies that when DID mode is enabled the
// endpoint renders the DID Document via RegEndpoint (i.e. the handler returns
// the document instead of writing the response itself), with the expected
// status code and JSON content-type.
func TestEndpointDIDDocument_Enabled(t *testing.T) {
	keyPath := writeTestSigningKey(t)

	verifierCfg := &model.Verifier{
		ClientIDScheme: "did",
		DID:            "did:web:verifier.example.com",
		PublicURL:      "https://verifier.example.com",
		KeyConfig: &pki.KeyConfig{
			PrivateKeyPath: keyPath,
		},
	}

	engine := testSetupDID(t, verifierCfg)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/did.json", nil)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	assert.Contains(t, w.Body.String(), `"id":"did:web:verifier.example.com"`)
	assert.Contains(t, w.Body.String(), "verificationMethod")
	assert.Contains(t, w.Body.String(), "alsoKnownAs")
}
