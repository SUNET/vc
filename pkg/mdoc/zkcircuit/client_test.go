package zkcircuit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/klauspost/compress/zstd"
)

const sampleManifestJSON = `{
  "manifestVersion": 1,
  "generatedAt": "2026-08-16T20:56:15Z",
  "catalog": "siros-zk-circuits",
  "circuits": [
    {
      "id": "longfellow-libzk-v1_8_2_4307_2945",
      "system": "longfellow",
      "systemVersion": "8",
      "published": true,
      "status": "active",
      "params": {"version": 8, "num_attributes": 2, "circuit_hash": "bb8e6a26"},
      "artifact": {
        "url": "/v1/artifacts/sha256/deadbeef",
        "hash": "sha256:deadbeef",
        "size": 100,
        "compression": "zstd"
      }
    }
  ]
}`

func mustSha256Hex(t *testing.T, data []byte) string {
	t.Helper()
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// TestFetchManifest_InjectedFetch mirrors the Kotlin ZkCircuitClient test's
// injectable-fetch-function pattern: a fake FetchText function stands in
// for a real HTTP call.
func TestFetchManifest_InjectedFetch(t *testing.T) {
	client := NewClient("https://example.invalid")
	var gotURL string
	client.FetchText = func(ctx context.Context, url string) (string, error) {
		gotURL = url
		return sampleManifestJSON, nil
	}

	manifest, err := client.FetchManifest(context.Background())
	if err != nil {
		t.Fatalf("FetchManifest: %v", err)
	}
	if gotURL != "https://example.invalid/v1/manifest.json" {
		t.Errorf("unexpected manifest URL: %s", gotURL)
	}
	if len(manifest.Circuits) != 1 {
		t.Fatalf("expected 1 circuit, got %d", len(manifest.Circuits))
	}
	c := manifest.Circuits[0]
	if c.ID != "longfellow-libzk-v1_8_2_4307_2945" {
		t.Errorf("unexpected id: %s", c.ID)
	}
	if v, ok := c.ParamInt("version"); !ok || v != 8 {
		t.Errorf("expected version=8, got %d (ok=%v)", v, ok)
	}
	if n, ok := c.ParamInt("num_attributes"); !ok || n != 2 {
		t.Errorf("expected num_attributes=2, got %d (ok=%v)", n, ok)
	}
	if h, ok := c.ParamString("circuit_hash"); !ok || h != "bb8e6a26" {
		t.Errorf("expected circuit_hash=bb8e6a26, got %q (ok=%v)", h, ok)
	}
}

// TestFetchManifest_MirrorFallback confirms sources are tried in order and
// results are NOT merged - the first source that succeeds wins outright,
// matching ZkCircuitClient.kt's documented semantics.
func TestFetchManifest_MirrorFallback(t *testing.T) {
	client := NewClient("https://mirror-a.invalid", "https://mirror-b.invalid")
	var calledURLs []string
	client.FetchText = func(ctx context.Context, url string) (string, error) {
		calledURLs = append(calledURLs, url)
		if url == "https://mirror-a.invalid/v1/manifest.json" {
			return "", errors.New("connection refused")
		}
		return sampleManifestJSON, nil
	}

	manifest, err := client.FetchManifest(context.Background())
	if err != nil {
		t.Fatalf("FetchManifest: %v", err)
	}
	if len(calledURLs) != 2 {
		t.Fatalf("expected both mirrors to be tried, got %v", calledURLs)
	}
	if len(manifest.Circuits) != 1 {
		t.Fatalf("expected manifest from mirror-b, got %+v", manifest)
	}
}

// TestFetchManifest_AllSourcesFail confirms a clear error when every mirror
// fails.
func TestFetchManifest_AllSourcesFail(t *testing.T) {
	client := NewClient("https://mirror-a.invalid", "https://mirror-b.invalid")
	client.FetchText = func(ctx context.Context, url string) (string, error) {
		return "", errors.New("boom")
	}

	_, err := client.FetchManifest(context.Background())
	if err == nil {
		t.Fatal("expected an error when all sources fail")
	}
}

// TestFetchCircuit_ByID confirms GET /v1/circuits/{id}.json URL
// construction and parsing.
func TestFetchCircuit_ByID(t *testing.T) {
	client := NewClient("https://example.invalid")
	descriptorJSON := `{"id": "longfellow-libzk-v1_8_1_4259_2945", "system": "longfellow", "params": {"num_attributes": 1}}`
	var gotURL string
	client.FetchText = func(ctx context.Context, url string) (string, error) {
		gotURL = url
		return descriptorJSON, nil
	}

	d, err := client.FetchCircuit(context.Background(), "longfellow-libzk-v1_8_1_4259_2945")
	if err != nil {
		t.Fatalf("FetchCircuit: %v", err)
	}
	if gotURL != "https://example.invalid/v1/circuits/longfellow-libzk-v1_8_1_4259_2945.json" {
		t.Errorf("unexpected circuit URL: %s", gotURL)
	}
	if d.ID != "longfellow-libzk-v1_8_1_4259_2945" {
		t.Errorf("unexpected id: %s", d.ID)
	}
}

// TestDownloadArtifact_HashVerified confirms a successful download whose
// bytes match the declared hash.
func TestDownloadArtifact_HashVerified(t *testing.T) {
	client := NewClient("https://example.invalid")
	payload := []byte("fake circuit bytes")
	hash := mustSha256Hex(t, payload)

	descriptor := &CircuitDescriptor{
		ID: "test-circuit",
		Artifact: &Artifact{
			URL:  "/v1/artifacts/sha256/" + hash,
			Hash: "sha256:" + hash,
		},
	}

	var gotURL string
	client.FetchBytes = func(ctx context.Context, url string) ([]byte, error) {
		gotURL = url
		return payload, nil
	}

	data, err := client.DownloadArtifact(context.Background(), descriptor)
	if err != nil {
		t.Fatalf("DownloadArtifact: %v", err)
	}
	if string(data) != string(payload) {
		t.Errorf("unexpected data: %q", data)
	}
	if gotURL != "https://example.invalid/v1/artifacts/sha256/"+hash {
		t.Errorf("unexpected artifact URL: %s", gotURL)
	}
}

// TestDownloadArtifact_HashMismatch confirms that bytes not matching the
// declared hash are rejected, not silently trusted.
func TestDownloadArtifact_HashMismatch(t *testing.T) {
	client := NewClient("https://example.invalid")
	descriptor := &CircuitDescriptor{
		ID: "test-circuit",
		Artifact: &Artifact{
			URL:  "/v1/artifacts/sha256/deadbeef",
			Hash: "sha256:deadbeef",
		},
	}
	client.FetchBytes = func(ctx context.Context, url string) ([]byte, error) {
		return []byte("wrong bytes"), nil
	}

	_, err := client.DownloadArtifact(context.Background(), descriptor)
	if err == nil {
		t.Fatal("expected a hash-mismatch error")
	}
	var artifactErr *ArtifactError
	if !errors.As(err, &artifactErr) {
		t.Fatalf("expected *ArtifactError, got %T: %v", err, err)
	}
}

// TestDownloadArtifact_AbsoluteURLNotMirrored confirms an absolute
// Artifact.URL is used as-is and is not resolved against every source
// mirror (it already pins its own host).
func TestDownloadArtifact_AbsoluteURLNotMirrored(t *testing.T) {
	client := NewClient("https://mirror-a.invalid", "https://mirror-b.invalid")
	payload := []byte("bytes")
	hash := mustSha256Hex(t, payload)
	descriptor := &CircuitDescriptor{
		ID: "test-circuit",
		Artifact: &Artifact{
			// Same host as the first configured source (allowed per the
			// SSRF-prevention host allowlist - see
			// TestDownloadArtifact_AbsoluteURLDisallowedHostRejected for the
			// mismatched-host rejection case), different path, proving this
			// absolute URL is used as-is rather than being resolved as a
			// relative path against every mirror.
			URL:  "https://mirror-a.invalid/circuit.zst",
			Hash: "sha256:" + hash,
		},
	}
	var calledURLs []string
	client.FetchBytes = func(ctx context.Context, url string) ([]byte, error) {
		calledURLs = append(calledURLs, url)
		return payload, nil
	}
	if _, err := client.DownloadArtifact(context.Background(), descriptor); err != nil {
		t.Fatalf("DownloadArtifact: %v", err)
	}
	if len(calledURLs) != 1 || calledURLs[0] != "https://mirror-a.invalid/circuit.zst" {
		t.Errorf("expected exactly one call to the absolute URL, got %v", calledURLs)
	}
}

// TestDownloadArtifact_AbsoluteURLDisallowedHostRejected guards against the
// SSRF finding on PR #576: an absolute Artifact.URL from the remote,
// configurable catalog whose host doesn't match any configured Source must
// be rejected before any fetch is attempted - otherwise a
// compromised/malicious mirror could redirect this client to an arbitrary
// host (SHA-256 verification alone doesn't help, since it only runs after
// the fetch already completed).
func TestDownloadArtifact_AbsoluteURLDisallowedHostRejected(t *testing.T) {
	client := NewClient("https://mirror-a.invalid", "https://mirror-b.invalid")
	payload := []byte("bytes")
	hash := mustSha256Hex(t, payload)
	descriptor := &CircuitDescriptor{
		ID: "test-circuit",
		Artifact: &Artifact{
			URL:  "https://cdn.example.com/circuit.zst",
			Hash: "sha256:" + hash,
		},
	}
	fetchCalled := false
	client.FetchBytes = func(ctx context.Context, url string) ([]byte, error) {
		fetchCalled = true
		return payload, nil
	}
	_, err := client.DownloadArtifact(context.Background(), descriptor)
	if err == nil {
		t.Fatal("expected an error for an absolute URL whose host isn't a configured source, got nil")
	}
	if !strings.Contains(err.Error(), "cdn.example.com") {
		t.Errorf("expected error to name the rejected host, got: %v", err)
	}
	if fetchCalled {
		t.Error("expected the disallowed host to be rejected before any fetch was attempted")
	}
}

// TestDownloadArtifact_PlaintextHTTPRejected guards against a real gap
// flagged in Copilot review on PR #576: a remote/untrusted catalog's
// absolute Artifact.URL could specify plaintext "http://" transport.
// SHA-256 verification still catches tampered bytes, but this should be
// refused up front rather than silently fetched - unnecessary exposure to
// on-path inspection/tampering-in-transit for no benefit.
func TestDownloadArtifact_PlaintextHTTPRejected(t *testing.T) {
	client := NewClient("https://mirror-a.invalid")
	payload := []byte("bytes")
	hash := mustSha256Hex(t, payload)
	descriptor := &CircuitDescriptor{
		ID: "test-circuit",
		Artifact: &Artifact{
			URL:  "http://cdn.example.com/circuit.zst",
			Hash: "sha256:" + hash,
		},
	}
	called := false
	client.FetchBytes = func(ctx context.Context, url string) ([]byte, error) {
		called = true
		return payload, nil
	}
	_, err := client.DownloadArtifact(context.Background(), descriptor)
	if err == nil {
		t.Fatal("expected an error for a plaintext http:// artifact URL, got nil")
	}
	if called {
		t.Error("expected DownloadArtifact to refuse http:// before ever fetching, but FetchBytes was called")
	}
}

// TestDownloadArtifact_BlankURLFallsBackToHashPath confirms the
// hash-derived path construction rule when Artifact.URL is blank.
func TestDownloadArtifact_BlankURLFallsBackToHashPath(t *testing.T) {
	client := NewClient("https://example.invalid")
	payload := []byte("bytes")
	hash := mustSha256Hex(t, payload)
	descriptor := &CircuitDescriptor{
		ID:       "test-circuit",
		Artifact: &Artifact{URL: "", Hash: "sha256:" + hash},
	}
	var gotURL string
	client.FetchBytes = func(ctx context.Context, url string) ([]byte, error) {
		gotURL = url
		return payload, nil
	}
	if _, err := client.DownloadArtifact(context.Background(), descriptor); err != nil {
		t.Fatalf("DownloadArtifact: %v", err)
	}
	expected := "https://example.invalid/v1/artifacts/sha256/" + hash
	if gotURL != expected {
		t.Errorf("expected %s, got %s", expected, gotURL)
	}
}

// TestDownloadAndDecompress_Zstd confirms zstd decompression plus
// verification of the decompressed bytes' hash.
func TestDownloadAndDecompress_Zstd(t *testing.T) {
	client := NewClient("https://example.invalid")
	original := []byte("decompressed circuit contents, repeated. decompressed circuit contents, repeated.")

	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatalf("zstd.NewWriter: %v", err)
	}
	compressed := encoder.EncodeAll(original, nil)
	encoder.Close()

	compressedHash := mustSha256Hex(t, compressed)
	uncompressedHash := mustSha256Hex(t, original)

	descriptor := &CircuitDescriptor{
		ID: "test-circuit",
		Artifact: &Artifact{
			URL:          "/v1/artifacts/sha256/" + compressedHash,
			Hash:         "sha256:" + compressedHash,
			Compression:  "zstd",
			Uncompressed: &Uncompressed{Hash: "sha256:" + uncompressedHash, Size: int64(len(original))},
		},
	}
	client.FetchBytes = func(ctx context.Context, url string) ([]byte, error) {
		return compressed, nil
	}

	data, err := client.DownloadAndDecompress(context.Background(), descriptor)
	if err != nil {
		t.Fatalf("DownloadAndDecompress: %v", err)
	}
	if string(data) != string(original) {
		t.Errorf("decompressed data mismatch")
	}
}

// TestDownloadAndDecompress_UncompressedHashMismatch confirms a corrupt
// decompressed circuit is rejected even though the compressed bytes
// matched their own hash (e.g. a bug in the server's declared uncompressed
// hash, or bit-rot surviving decompression).
func TestDownloadAndDecompress_UncompressedHashMismatch(t *testing.T) {
	client := NewClient("https://example.invalid")
	original := []byte("real contents")
	encoder, _ := zstd.NewWriter(nil)
	compressed := encoder.EncodeAll(original, nil)
	encoder.Close()
	compressedHash := mustSha256Hex(t, compressed)

	descriptor := &CircuitDescriptor{
		ID: "test-circuit",
		Artifact: &Artifact{
			URL:          "/v1/artifacts/sha256/" + compressedHash,
			Hash:         "sha256:" + compressedHash,
			Compression:  "zstd",
			Uncompressed: &Uncompressed{Hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
		},
	}
	client.FetchBytes = func(ctx context.Context, url string) ([]byte, error) {
		return compressed, nil
	}

	_, err := client.DownloadAndDecompress(context.Background(), descriptor)
	if err == nil {
		t.Fatal("expected an uncompressed-hash-mismatch error")
	}
}

// TestDownloadArtifact_NoArtifact confirms a descriptor with no artifact is
// rejected with a clear ArtifactError rather than a nil-pointer panic.
func TestDownloadArtifact_NoArtifact(t *testing.T) {
	client := NewClient("https://example.invalid")
	_, err := client.DownloadArtifact(context.Background(), &CircuitDescriptor{ID: "no-artifact"})
	var artifactErr *ArtifactError
	if !errors.As(err, &artifactErr) {
		t.Fatalf("expected *ArtifactError, got %T: %v", err, err)
	}
}

// TestRealHTTPRoundTrip exercises the default (non-injected) HTTPClient
// path against a real local httptest server - confirms the manifest/
// circuit/artifact URL construction and default fetch implementation work
// with actual net/http, not just the injected-function fast path.
func TestRealHTTPRoundTrip(t *testing.T) {
	payload := []byte("real http round trip payload")
	hash := mustSha256Hex(t, payload)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		manifest := Manifest{
			Circuits: []CircuitDescriptor{{
				ID: "circuit-1",
				Artifact: &Artifact{
					URL:  "/v1/artifacts/sha256/" + hash,
					Hash: "sha256:" + hash,
				},
			}},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(manifest)
	})
	mux.HandleFunc("/v1/circuits/circuit-1.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(CircuitDescriptor{
			ID: "circuit-1",
			Artifact: &Artifact{
				URL:  "/v1/artifacts/sha256/" + hash,
				Hash: "sha256:" + hash,
			},
		})
	})
	mux.HandleFunc("/v1/artifacts/sha256/"+hash, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewClient(server.URL)

	manifest, err := client.FetchManifest(context.Background())
	if err != nil {
		t.Fatalf("FetchManifest: %v", err)
	}
	if len(manifest.Circuits) != 1 || manifest.Circuits[0].ID != "circuit-1" {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}

	descriptor, err := client.FetchCircuit(context.Background(), "circuit-1")
	if err != nil {
		t.Fatalf("FetchCircuit: %v", err)
	}

	data, err := client.DownloadArtifact(context.Background(), descriptor)
	if err != nil {
		t.Fatalf("DownloadArtifact: %v", err)
	}
	if string(data) != string(payload) {
		t.Errorf("unexpected artifact bytes: %q", data)
	}
}

// TestRealHTTPRoundTrip_NonSuccessStatus confirms a non-2xx response is
// treated as a fetch failure, not silently returning an empty/error-page
// body as if it were valid content.
func TestRealHTTPRoundTrip_NonSuccessStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	_, err := client.FetchManifest(context.Background())
	if err == nil {
		t.Fatal("expected an error for a 500 response")
	}
}

// TestDownloadArtifact_RedirectToDisallowedHostRejected confirms a
// compromised/malicious configured source can't use an HTTP redirect to
// smuggle the actual fetch to an arbitrary host. DownloadArtifact's own
// host-allowlist check only validates the URL it's about to request -
// without CheckRedirect enforcement inside fetchBytesHTTP, a 3xx response
// from an otherwise-trusted source would let net/http's default client
// silently follow the request anywhere (a blind SSRF primitive).
func TestDownloadArtifact_RedirectToDisallowedHostRejected(t *testing.T) {
	var attackerHit atomic.Bool
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attackerHit.Store(true)
		_, _ = w.Write([]byte("should never be reached"))
	}))
	defer attacker.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/artifacts/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+"/payload", http.StatusFound)
	})
	source := httptest.NewServer(mux)
	defer source.Close()

	client := NewClient(source.URL)
	descriptor := &CircuitDescriptor{
		ID: "circuit-redirect",
		Artifact: &Artifact{
			URL:  "/v1/artifacts/redirect",
			Hash: "sha256:" + mustSha256Hex(t, []byte("irrelevant")),
		},
	}

	_, err := client.DownloadArtifact(context.Background(), descriptor)
	if err == nil {
		t.Fatal("expected the redirect to a disallowed host to be rejected")
	}
	if attackerHit.Load() {
		t.Fatal("attacker server was reached - a redirect to a disallowed host was followed")
	}
}

// TestDownloadArtifact_RedirectDowngradeToHTTPRejected confirms a same-host
// https->http redirect is rejected even though the host-allowlist check
// alone would pass it (same host, still within Sources): validating only
// the host silently permits a scheme downgrade, defeating DownloadArtifact's
// explicit rejection of plaintext absolute artifact URLs. Uses a real TLS
// test server (matching production, where Sources are genuinely https) so
// the host check alone would succeed here - only the scheme check catches it.
func TestDownloadArtifact_RedirectDowngradeToHTTPRejected(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	// Built from server.URL (known at test setup, not the incoming
	// request) so the redirect target isn't derived from request data -
	// avoids tripping static-analysis open-redirect rules that flag any
	// http.Redirect() target built from an *http.Request field, even
	// though this is a fixed test URL, not attacker input.
	downgradedURL := "http://" + strings.TrimPrefix(server.URL, "https://") + "/v1/artifacts/plain"
	mux.HandleFunc("/v1/artifacts/downgrade", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, downgradedURL, http.StatusFound)
	})

	client := NewClient(server.URL)
	client.HTTPClient = server.Client() // trusts the test server's self-signed cert

	descriptor := &CircuitDescriptor{
		ID: "circuit-downgrade",
		Artifact: &Artifact{
			URL:  "/v1/artifacts/downgrade",
			Hash: "sha256:" + mustSha256Hex(t, []byte("irrelevant")),
		},
	}

	_, err := client.DownloadArtifact(context.Background(), descriptor)
	if err == nil {
		t.Fatal("expected the https->http downgrade redirect to be rejected")
	}
	if !strings.Contains(err.Error(), "non-https") {
		t.Errorf("expected a non-https scheme rejection, got: %v", err)
	}
}

// TestBareHex confirms the "sha256:" prefix strip is case-insensitive (an
// uppercase/mixed-case prefix from the catalog must not survive into the
// hash comparison), and that an unprefixed or non-matching-prefix hash
// passes through unchanged.
func TestBareHex(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"lowercase prefix", "sha256:deadbeef", "deadbeef"},
		{"uppercase prefix", "SHA256:DEADBEEF", "DEADBEEF"},
		{"mixed-case prefix", "Sha256:deadBEEF", "deadBEEF"},
		{"no prefix", "deadbeef", "deadbeef"},
		{"too short for a prefix", "sha2", "sha2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bareHex(tc.in); got != tc.want {
				t.Errorf("bareHex(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestDownloadArtifact_OversizedResponseRejected confirms a response body
// larger than the descriptor's declared Artifact.Size (+ margin) is
// rejected rather than read into memory unbounded - Sources are remote and
// configurable, so an oversized/malicious response must not be able to
// exhaust memory.
func TestDownloadArtifact_OversizedResponseRejected(t *testing.T) {
	oversized := bytes.Repeat([]byte("x"), 10_000)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(oversized)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	descriptor := &CircuitDescriptor{
		ID: "test-circuit",
		Artifact: &Artifact{
			URL:  "/v1/artifacts/sha256/deadbeef",
			Hash: "sha256:deadbeef",
			// Declared far smaller than what the server actually serves -
			// the +10% margin cap should still reject long before 10,000
			// bytes are read.
			Size: 50,
		},
	}

	_, err := client.DownloadArtifact(context.Background(), descriptor)
	if err == nil {
		t.Fatal("expected an error for a response exceeding the declared size cap")
	}
	var artifactErr *ArtifactError
	if !errors.As(err, &artifactErr) {
		t.Fatalf("expected *ArtifactError, got %T: %v", err, err)
	}
}

// TestDownloadAndDecompress_BombRejected confirms a zstd payload that
// decompresses to far more than the descriptor's declared
// Uncompressed.Size is rejected rather than fully materialized in memory -
// this is the decompression-bomb case: a small compressed artifact that
// expands to a huge amount of data.
func TestDownloadAndDecompress_BombRejected(t *testing.T) {
	// Highly compressible payload - real zstd ratios on real circuits are
	// already ~300x (see hardCeilingDecompressedBytes' doc comment); an
	// all-zero buffer compresses far more aggressively than that, so this
	// keeps the test's actual compressed/decompressed sizes small while
	// still exercising a genuine, large compression-ratio bomb shape.
	bomb := make([]byte, 8*1024*1024) // 8 MiB of zeros

	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatalf("zstd.NewWriter: %v", err)
	}
	compressed := encoder.EncodeAll(bomb, nil)
	encoder.Close()

	compressedHash := mustSha256Hex(t, compressed)

	descriptor := &CircuitDescriptor{
		ID: "test-circuit",
		Artifact: &Artifact{
			URL:         "/v1/artifacts/sha256/" + compressedHash,
			Hash:        "sha256:" + compressedHash,
			Size:        int64(len(compressed)),
			Compression: "zstd",
			// Declared decompressed size is tiny/wrong compared to the
			// actual ~8MiB the payload expands to - the cap must catch
			// this using the streamed LimitReader, not by decompressing
			// everything first and checking length afterward.
			Uncompressed: &Uncompressed{Size: 100},
		},
	}
	client := NewClient("https://example.invalid")
	client.FetchBytes = func(ctx context.Context, url string) ([]byte, error) {
		return compressed, nil
	}

	_, err = client.DownloadAndDecompress(context.Background(), descriptor)
	if err == nil {
		t.Fatal("expected an error for a decompressed payload exceeding the declared size cap")
	}
	var artifactErr *ArtifactError
	if !errors.As(err, &artifactErr) {
		t.Fatalf("expected *ArtifactError, got %T: %v", err, err)
	}
}

// TestDownloadAndDecompress_NoDeclaredSizeUsesHardCeiling confirms that
// when a descriptor omits Uncompressed.Size entirely, decompression still
// succeeds for a legitimately-sized payload (falls back to the generous
// hard ceiling, not a tiny default that would reject real circuits).
func TestDownloadAndDecompress_NoDeclaredSizeUsesHardCeiling(t *testing.T) {
	original := []byte("legitimate circuit content with no declared uncompressed size")
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatalf("zstd.NewWriter: %v", err)
	}
	compressed := encoder.EncodeAll(original, nil)
	encoder.Close()
	compressedHash := mustSha256Hex(t, compressed)

	descriptor := &CircuitDescriptor{
		ID: "test-circuit",
		Artifact: &Artifact{
			URL:         "/v1/artifacts/sha256/" + compressedHash,
			Hash:        "sha256:" + compressedHash,
			Compression: "zstd",
			// No Uncompressed field at all.
		},
	}
	client := NewClient("https://example.invalid")
	client.FetchBytes = func(ctx context.Context, url string) ([]byte, error) {
		return compressed, nil
	}

	data, err := client.DownloadAndDecompress(context.Background(), descriptor)
	if err != nil {
		t.Fatalf("DownloadAndDecompress: %v", err)
	}
	if string(data) != string(original) {
		t.Errorf("decompressed data mismatch")
	}
}

// TestParamInt_RejectsNonIntegralAndOutOfRange guards against a real
// concern (raised in Copilot review on PR #576): Params is decoded from
// JSON, so a numeric entry is always a float64 on the way in. Without
// validation, a remote/untrusted catalog response with a fractional value
// (e.g. "num_attributes": 2.5) or one outside the platform int range
// would silently truncate/misbehave via a bare int(float64) conversion.
func TestParamInt_RejectsNonIntegralAndOutOfRange(t *testing.T) {
	cases := []struct {
		name    string
		value   any
		wantOK  bool
		wantInt int
	}{
		{"integral float64", float64(2), true, 2},
		{"native int", 3, true, 3},
		{"fractional float64", 2.5, false, 0},
		{"too large for int64-range float64", math.MaxFloat64, false, 0},
		{"negative infinity", math.Inf(-1), false, 0},
		{"NaN", math.NaN(), false, 0},
		{"non-numeric", "not-a-number", false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &CircuitDescriptor{Params: map[string]any{"k": tc.value}}
			got, ok := d.ParamInt("k")
			if ok != tc.wantOK {
				t.Fatalf("ParamInt(%v) ok = %v, want %v", tc.value, ok, tc.wantOK)
			}
			if ok && got != tc.wantInt {
				t.Errorf("ParamInt(%v) = %d, want %d", tc.value, got, tc.wantInt)
			}
		})
	}
}
