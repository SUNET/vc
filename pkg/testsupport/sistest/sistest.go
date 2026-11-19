// Package sistest starts SIS, the Edu-API provider, in a container for tests
// that need a real Edu-API server, together with the token issuer SIS trusts.
//
// The image is docker.sunet.se/iam_vc/sis:local unless SIS_TEST_IMAGE names
// another. Build it from the SIS repository (docker compose build sis).
//
// SIS verifies tokens against a key set fetched over HTTP, so a small
// container on a shared network serves it. The token endpoint itself runs in
// the test process: only the client under test calls it, never SIS.
package sistest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/testsupport"
	"github.com/SUNET/vc/pkg/testsupport/jwktest"

	"github.com/golang-jwt/jwt/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

//go:embed testdata/students.json
var studentsJSON []byte

const (
	defaultImage = "docker.sunet.se/iam_vc/sis:local"

	// Audience is the aud SIS requires in every access token.
	Audience = "sis"
	// ReadScope is the scope SIS accepts for reads.
	ReadScope = "sis.read"

	// BasePath is where SIS serves Edu-API v1.0 Final.
	BasePath = "/1edtech/eduapi/base/v1p0"

	// ClientID and ClientSecret are what the token endpoint accepts.
	ClientID     = "sunet-vc"
	ClientSecret = "sunet-vc-secret"

	// issuer is the iss SIS trusts. It is only a name: SIS is given the key
	// set's address directly and never fetches this.
	issuer = "https://token-issuer.sistest.invalid"
	keyID  = "sistest-1"

	jwksHost = "token-issuer"
)

// Stack is a running SIS and the token endpoint in front of it.
type Stack struct {
	// BaseURL is SIS's Edu-API base URL as the test process reaches it.
	BaseURL string
	// TokenURL is the token endpoint, for a client credentials grant.
	TokenURL string

	key *ecdsa.PrivateKey
}

// Start runs SIS with the fixture in testdata/students.json and returns once
// it answers. It skips the test when Docker or the SIS image is missing, and
// fails it when SIS does not start.
func Start(t *testing.T) *Stack {
	t.Helper()
	if !testsupport.IsDockerAvailable() {
		t.Skip("Docker is not available")
	}
	image := os.Getenv("SIS_TEST_IMAGE")
	if image == "" {
		image = defaultImage
	}
	if err := exec.Command("docker", "image", "inspect", image).Run(); err != nil { // #nosec G204 -- image name comes from the test environment
		t.Skipf("SIS image %s is not available; build it from the SIS repository", image)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	s := &Stack{key: key}

	tokens := httptest.NewServer(http.HandlerFunc(s.serveToken))
	t.Cleanup(tokens.Close)
	s.TokenURL = tokens.URL

	ctx := t.Context()
	nw, err := network.New(ctx)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	t.Cleanup(func() { _ = nw.Remove(context.Background()) })

	onNetwork := func(alias string) testcontainers.CustomizeRequestOption {
		return network.WithNetwork([]string{alias}, nw)
	}

	jwks, err := json.Marshal(map[string]any{"keys": []any{s.publicJWK()}})
	if err != nil {
		t.Fatalf("encode key set: %v", err)
	}
	keys, err := testcontainers.Run(ctx, "busybox:latest",
		onNetwork(jwksHost),
		testcontainers.WithCmd("httpd", "-f", "-p", "8080", "-h", "/www"),
		testcontainers.WithFiles(testcontainers.ContainerFile{Reader: strings.NewReader(string(jwks)), ContainerFilePath: "/www/jwks.json", FileMode: 0o644}),
		testcontainers.WithExposedPorts("8080/tcp"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("8080/tcp").WithStartupTimeout(time.Minute)),
	)
	terminateOnCleanup(t, keys, "key set server")
	if err != nil {
		t.Fatalf("start key set server: %v", err)
	}

	sis, err := testcontainers.Run(ctx, image,
		onNetwork("sis"),
		testcontainers.WithEnv(map[string]string{"SIS_CONFIG_YAML": "/home/nonroot/config.yaml"}),
		testcontainers.WithFiles(
			testcontainers.ContainerFile{Reader: strings.NewReader(sisConfig()), ContainerFilePath: "/home/nonroot/config.yaml", FileMode: 0o644},
			testcontainers.ContainerFile{Reader: strings.NewReader(string(studentsJSON)), ContainerFilePath: "/home/nonroot/students.json", FileMode: 0o644},
		),
		testcontainers.WithExposedPorts("8080/tcp"),
		testcontainers.WithWaitStrategy(wait.ForHTTP("/healthz").WithPort("8080/tcp").WithStartupTimeout(2*time.Minute)),
	)
	terminateOnCleanup(t, sis, "SIS")
	if err != nil {
		t.Fatalf("start SIS: %v", err)
	}

	endpoint, err := sis.PortEndpoint(ctx, "8080/tcp", "http")
	if err != nil {
		t.Fatalf("SIS endpoint: %v", err)
	}
	s.BaseURL = endpoint + BasePath
	return s
}

// terminateOnCleanup stops c when the test ends and prints its log first when
// the test failed. c may be non-nil even when starting it failed.
func terminateOnCleanup(t *testing.T, c *testcontainers.DockerContainer, name string) {
	t.Helper()
	if c == nil {
		return
	}
	t.Cleanup(func() {
		if t.Failed() {
			if logs, err := c.Logs(context.Background()); err == nil {
				out, _ := io.ReadAll(logs)
				t.Logf("%s log:\n%s", name, out)
			}
		}
		_ = c.Terminate(context.Background())
	})
}

// Token returns an access token for scope, as the token endpoint mints it.
func (s *Stack) Token(t *testing.T, scope string) string {
	t.Helper()
	signed, err := s.signToken(scope, Audience)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func (s *Stack) signToken(scope, audience string) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss":   issuer,
		"sub":   ClientID,
		"aud":   audience,
		"scope": scope,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
	})
	tok.Header["kid"] = keyID
	return tok.SignedString(s.key)
}

func (s *Stack) publicJWK() map[string]any {
	jwk := jwktest.PublicKeyJWK(&s.key.PublicKey)
	jwk["kid"] = keyID
	jwk["alg"] = "ES256"
	jwk["use"] = "sig"
	return jwk
}

func sisConfig() string {
	return fmt.Sprintf(`common:
  production: false
  log:
    level: info
    json: false
sis:
  httpserver:
    addr: ":8080"
  auth:
    issuers:
      - issuer: %q
        audience: %q
        jwks_url: "http://%s:8080/jwks.json"
  adapter:
    outbound:
      postgres:
        connection_string: ""
  file_import:
    files:
      - students.json
`, issuer, Audience, jwksHost)
}

// serveToken is the client credentials grant.
func (s *Stack) serveToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "client_credentials" ||
		r.PostForm.Get("client_id") != ClientID || r.PostForm.Get("client_secret") != ClientSecret {
		http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
		return
	}
	signed, err := s.signToken(r.PostForm.Get("scope"), Audience)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": signed, "token_type": "Bearer", "expires_in": 300})
}
