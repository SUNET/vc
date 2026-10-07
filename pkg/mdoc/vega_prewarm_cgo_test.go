//go:build zknative

package mdoc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// warmMirror writes a vendored file:// catalog mirror holding, for each
// named circuit, a descriptor and a small artifact. Returns the source URL.
//
// Small artifacts rather than real ~100MB keys: warming downloads and
// stores bytes, and nothing on this path parses them - the native library
// only ever sees them inside the worker. What the test is about is WHICH
// circuits get warmed, not what is in them.
func warmMirror(t *testing.T, circuits []map[string]any) string {
	t.Helper()
	dir := t.TempDir()

	for _, c := range circuits {
		id := c["id"].(string)
		artifact := []byte("artifact for " + id)
		sum := sha256.Sum256(artifact)
		hash := hex.EncodeToString(sum[:])
		path := "v1/artifacts/sha256/" + hash

		c["artifact"] = map[string]any{
			"url": path, "hash": "sha256:" + hash,
			"compression": "none", "size": len(artifact),
		}

		writeMirrorFile(t, filepath.Join(dir, filepath.FromSlash(path)), artifact)
		writeMirrorFile(t, filepath.Join(dir, "v1", "circuits", id+".json"), mustJSON(t, c))
	}

	writeMirrorFile(t, filepath.Join(dir, "v1", "manifest.json"),
		mustJSON(t, map[string]any{"manifestVersion": 1, "circuits": circuits}))

	// Served over HTTP rather than read off disk: that is what a real
	// source is, and it keeps the artifact-hash and host-allowlist checks
	// in the path the way a live warm-up has them.
	server := httptest.NewServer(http.FileServer(http.Dir(dir)))
	t.Cleanup(server.Close)
	mirrorDirs[server.URL] = dir
	return server.URL
}

// mirrorDirs maps a mirror's URL back to the directory behind it, so a test
// can break the mirror and show that a cached key needs no second fetch.
var mirrorDirs = map[string]string{}

func writeMirrorFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func vegaCircuit(id, version, role, status string) map[string]any {
	return map[string]any{
		"id": id, "system": "vega-mc", "systemVersion": version,
		"status": status, "published": true,
		"docTypes": []string{"org.iso.18013.5.1.mDL"},
		"params":   map[string]any{"role": role, "saltBytes": "32"},
	}
}

// resetVegaKeyState gives a test its own store and in-flight map, since
// both are process-wide (see vegaVerifierKeys' doc comment for why).
func resetVegaKeyState(t *testing.T) {
	t.Helper()
	previous := vegaVerifierKeys
	vegaVerifierKeys = newVegaKeyStore(t.TempDir(), defaultVegaVerifierKeyCacheBytes)

	vegaVerifierKeyCacheState.mu.Lock()
	vegaVerifierKeyCacheState.inFly = make(map[string]*inFlightLoad)
	vegaVerifierKeyCacheState.mu.Unlock()

	t.Cleanup(func() {
		_ = vegaVerifierKeys.removeAll()
		vegaVerifierKeys = previous
	})
}

// The point of pre-warming: after it, a presentation naming an active
// circuit finds its verifier key already on disk instead of paying for a
// ~100MB download while the holder waits (SUNET/vc#656).
func TestWarmVegaVerifierKeysFillsTheStore(t *testing.T) {
	resetVegaKeyState(t)

	source := warmMirror(t, []map[string]any{
		vegaCircuit("vega-prover-r12", "12", "prover", "active"),
		vegaCircuit("vega-verifier-r12", "12", "verifier", "active"),
	})

	result, err := WarmVegaVerifierKeys(t.Context(), []string{source})
	if err != nil {
		t.Fatalf("WarmVegaVerifierKeys() error = %v", err)
	}
	if len(result.Failed) != 0 {
		t.Fatalf("Failed = %v, want none", result.Failed)
	}
	if len(result.Warmed) != 1 || result.Warmed[0] != "vega-prover-r12" {
		t.Fatalf("Warmed = %v, want [vega-prover-r12]", result.Warmed)
	}

	// Keyed by the PROVER id, because that is what a wallet names in its
	// proof - warming under the verifier id would leave every request a
	// miss while looking like a working cache.
	path, ok := vegaVerifierKeys.get("vega-prover-r12")
	if !ok {
		t.Fatal("the warmed key is not in the store under the prover id")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the warmed key: %v", err)
	}
	// The VERIFIER sibling's bytes, not the prover's: a verifier has no use
	// for a prover key, and storing the wrong one would only fail much
	// later, inside the worker.
	if string(data) != "artifact for vega-verifier-r12" {
		t.Errorf("stored bytes = %q, want the verifier sibling's artifact", data)
	}
}

func TestWarmVegaVerifierKeysSkipsWhatItShould(t *testing.T) {
	resetVegaKeyState(t)

	source := warmMirror(t, []map[string]any{
		vegaCircuit("vega-prover-r12", "12", "prover", "active"),
		vegaCircuit("vega-verifier-r12", "12", "verifier", "active"),
		// Deprecated: wallets still present it and it still loads lazily,
		// but warming every revision ever published grows without bound.
		vegaCircuit("vega-prover-r11", "11", "prover", "deprecated"),
		vegaCircuit("vega-verifier-r11", "11", "verifier", "deprecated"),
		// Unpublished, even though active.
		{
			"id": "vega-prover-r13", "system": "vega-mc", "systemVersion": "13",
			"status": "active", "published": false,
			"docTypes": []string{"org.iso.18013.5.1.mDL"},
			"params":   map[string]any{"role": "prover"},
		},
		// Longfellow declares no role at all, and is verified in-process
		// rather than through this store.
		{
			"id": "longfellow-libzk-v1_8_2", "system": "longfellow", "systemVersion": "8",
			"status": "active", "published": true,
			"docTypes": []string{"org.iso.18013.5.1.mDL"},
			"params":   map[string]any{"num_attributes": 2},
		},
	})

	result, err := WarmVegaVerifierKeys(t.Context(), []string{source})
	if err != nil {
		t.Fatalf("WarmVegaVerifierKeys() error = %v", err)
	}
	if len(result.Warmed) != 1 || result.Warmed[0] != "vega-prover-r12" {
		t.Fatalf("Warmed = %v, want only the active, published, prover-role entry", result.Warmed)
	}
	for _, id := range []string{"vega-prover-r11", "vega-prover-r13", "longfellow-libzk-v1_8_2"} {
		if _, ok := vegaVerifierKeys.get(id); ok {
			t.Errorf("%s should not have been warmed", id)
		}
	}
}

// One circuit the catalog cannot serve must not deny the others the
// warm-up they were going to get, and must be reported rather than
// swallowed.
func TestWarmVegaVerifierKeysReportsPerCircuitFailures(t *testing.T) {
	resetVegaKeyState(t)

	source := warmMirror(t, []map[string]any{
		vegaCircuit("vega-prover-r12", "12", "prover", "active"),
		vegaCircuit("vega-verifier-r12", "12", "verifier", "active"),
		// No verifier sibling for r14, so resolving it fails.
		vegaCircuit("vega-prover-r14", "14", "prover", "active"),
	})

	result, err := WarmVegaVerifierKeys(t.Context(), []string{source})
	if err != nil {
		t.Fatalf("a per-circuit failure must not fail the whole warm-up: %v", err)
	}
	if len(result.Warmed) != 1 || result.Warmed[0] != "vega-prover-r12" {
		t.Errorf("Warmed = %v, want [vega-prover-r12]", result.Warmed)
	}
	if _, ok := result.Failed["vega-prover-r14"]; !ok {
		t.Errorf("Failed = %v, want it to name vega-prover-r14", result.Failed)
	}
}

func TestWarmVegaVerifierKeysReportsAnUnreachableCatalog(t *testing.T) {
	resetVegaKeyState(t)

	_, err := WarmVegaVerifierKeys(t.Context(), []string{"http://127.0.0.1:1"})
	if err == nil {
		t.Fatal("expected an error when the catalog cannot be consulted at all")
	}
}

// getOrLoadVegaVerifierKey hands the worker a PATH now, not bytes. A second
// call must not refetch, and the path must still be readable.
func TestGetOrLoadVegaVerifierKeyCachesThePath(t *testing.T) {
	resetVegaKeyState(t)

	source := warmMirror(t, []map[string]any{
		vegaCircuit("vega-prover-r12", "12", "prover", "active"),
		vegaCircuit("vega-verifier-r12", "12", "verifier", "active"),
	})

	first, err := getOrLoadVegaVerifierKey(t.Context(), "vega-prover-r12", []string{source})
	if err != nil {
		t.Fatalf("getOrLoadVegaVerifierKey() error = %v", err)
	}

	// Breaking the mirror proves the second call did not go back to it.
	if err := os.RemoveAll(filepath.Join(mirrorDirs[source], "v1")); err != nil {
		t.Fatal(err)
	}

	second, err := getOrLoadVegaVerifierKey(t.Context(), "vega-prover-r12", []string{source})
	if err != nil {
		t.Fatalf("a cached key must not need the catalog: %v", err)
	}
	if second != first {
		t.Errorf("path = %q, want the cached %q", second, first)
	}
	if _, err := os.Stat(second); err != nil {
		t.Errorf("the cached path must be readable: %v", err)
	}
}

// A key whose file has gone must read as a miss and refetch, not hand the
// worker a path it cannot open.
func TestGetOrLoadVegaVerifierKeyRefetchesAfterTheFileGoes(t *testing.T) {
	resetVegaKeyState(t)

	source := warmMirror(t, []map[string]any{
		vegaCircuit("vega-prover-r12", "12", "prover", "active"),
		vegaCircuit("vega-verifier-r12", "12", "verifier", "active"),
	})

	path, err := getOrLoadVegaVerifierKey(t.Context(), "vega-prover-r12", []string{source})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	again, err := getOrLoadVegaVerifierKey(t.Context(), "vega-prover-r12", []string{source})
	if err != nil {
		t.Fatalf("a key whose file is gone must be refetched: %v", err)
	}
	if _, err := os.Stat(again); err != nil {
		t.Errorf("the refetched path must be readable: %v", err)
	}
}
