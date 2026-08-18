package zkcircuit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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
			URL:  "https://cdn.example.com/circuit.zst",
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
	if len(calledURLs) != 1 || calledURLs[0] != "https://cdn.example.com/circuit.zst" {
		t.Errorf("expected exactly one call to the absolute URL, got %v", calledURLs)
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
