//go:build zknative

package mdoc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// mirrorCounts records how often a mirror served an artifact, so a test
// can tell one shared load from several.
type mirrorCounts struct {
	mu sync.Mutex
	n  int
}

func (m *mirrorCounts) artifactFetches() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.n
}

// countingWarmMirror is warmMirror with a request counter over the
// artifact paths.
func countingWarmMirror(t *testing.T, circuits []map[string]any) (string, *mirrorCounts) {
	t.Helper()
	source := warmMirror(t, circuits)
	dir := mirrorDirs[source]

	counts := &mirrorCounts{}
	files := http.FileServer(http.Dir(dir))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/artifacts/") {
			counts.mu.Lock()
			counts.n++
			counts.mu.Unlock()
		}
		files.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	mirrorDirs[server.URL] = dir
	return server.URL, counts
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
		_ = vegaVerifierKeys.removeAll(context.Background())
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
		// "role" is a GENERIC params key. A future or custom system
		// adopting it would otherwise have its artifacts downloaded into
		// a store sized for Vega keys, evicting the real ones - a cache
		// that quietly stops holding what it is for.
		//
		// Given a verifier SIBLING on purpose: without one, resolution
		// fails and the entry stays out of the store for the wrong
		// reason, and the test would pass with no system filter at all.
		{
			"id": "someother-prover-v1", "system": "someother-zk", "systemVersion": "1",
			"status": "active", "published": true,
			"docTypes": []string{"org.iso.18013.5.1.mDL"},
			"params":   map[string]any{"role": "prover"},
		},
		{
			"id": "someother-verifier-v1", "system": "someother-zk", "systemVersion": "1",
			"status": "active", "published": true,
			"docTypes": []string{"org.iso.18013.5.1.mDL"},
			"params":   map[string]any{"role": "verifier"},
		},
	})

	result, err := WarmVegaVerifierKeys(t.Context(), []string{source})
	if err != nil {
		t.Fatalf("WarmVegaVerifierKeys() error = %v", err)
	}
	if len(result.Warmed) != 1 || result.Warmed[0] != "vega-prover-r12" {
		t.Fatalf("Warmed = %v, want only the active, published, Vega prover-role entry", result.Warmed)
	}
	if len(result.Failed) != 0 {
		t.Fatalf("Failed = %v, want none - a skipped entry is skipped, not attempted and failed", result.Failed)
	}
	for _, id := range []string{"vega-prover-r11", "vega-prover-r13", "longfellow-libzk-v1_8_2", "someother-prover-v1"} {
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

	first, releaseFirst, err := getOrLoadVegaVerifierKey(t.Context(), "vega-prover-r12", []string{source})
	if err != nil {
		t.Fatalf("getOrLoadVegaVerifierKey() error = %v", err)
	}
	defer releaseFirst()

	// Breaking the mirror proves the second call did not go back to it.
	if err := os.RemoveAll(filepath.Join(mirrorDirs[source], "v1")); err != nil {
		t.Fatal(err)
	}

	second, releaseSecond, err := getOrLoadVegaVerifierKey(t.Context(), "vega-prover-r12", []string{source})
	if err != nil {
		t.Fatalf("a cached key must not need the catalog: %v", err)
	}
	defer releaseSecond()
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

	path, releasePath, err := getOrLoadVegaVerifierKey(t.Context(), "vega-prover-r12", []string{source})
	if err != nil {
		t.Fatal(err)
	}
	releasePath()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	again, releaseAgain, err := getOrLoadVegaVerifierKey(t.Context(), "vega-prover-r12", []string{source})
	if err != nil {
		t.Fatalf("a key whose file is gone must be refetched: %v", err)
	}
	defer releaseAgain()
	if _, err := os.Stat(again); err != nil {
		t.Errorf("the refetched path must be readable: %v", err)
	}
}

// Every caller that misses the cache during a cold start must join one
// load, not start its own ~100MB download. The in-flight map does that,
// but the store check ahead of it is unlocked relative to the map, so a
// loader finishing in that gap used to leave the next caller believing no
// load was running.
//
// A general dedup assertion: it pins "one fetch for N concurrent callers"
// and does not deterministically reproduce that particular interleaving,
// which needs a seam this code does not have.
func TestGetOrLoadVegaVerifierKeyLoadsOncePerID(t *testing.T) {
	resetVegaKeyState(t)

	source, counts := countingWarmMirror(t, []map[string]any{
		vegaCircuit("vega-prover-r12", "12", "prover", "active"),
		vegaCircuit("vega-verifier-r12", "12", "verifier", "active"),
	})

	const callers = 16
	var wg sync.WaitGroup
	paths := make([]string, callers)
	errs := make([]error, callers)

	wg.Add(callers)
	for i := range callers {
		go func() {
			defer wg.Done()
			path, release, err := getOrLoadVegaVerifierKey(t.Context(), "vega-prover-r12", []string{source})
			paths[i], errs[i] = path, err
			if err == nil {
				release()
			}
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
		if paths[i] != paths[0] {
			t.Errorf("caller %d got %q, want the single shared %q", i, paths[i], paths[0])
		}
	}

	if got := counts.artifactFetches(); got != 1 {
		t.Errorf("artifact fetched %d times for %d callers, want 1", got, callers)
	}
}

// Warmed must mean "on disk now", not "loaded successfully at some point".
// The store is bounded, so a working set larger than max_bytes has later
// circuits evicting earlier ones - and a result claiming every key is
// ready, with a startup log to match, is worse than no claim at all when
// the first presentation has to refetch.
func TestWarmVegaVerifierKeysReportsResidencyNotAttempts(t *testing.T) {
	resetVegaKeyState(t)

	// Room for one key only: "artifact for vega-verifier-rNN" is ~30 bytes.
	vegaVerifierKeys.setMax(40)

	source := warmMirror(t, []map[string]any{
		vegaCircuit("vega-prover-r11", "11", "prover", "active"),
		vegaCircuit("vega-verifier-r11", "11", "verifier", "active"),
		vegaCircuit("vega-prover-r12", "12", "prover", "active"),
		vegaCircuit("vega-verifier-r12", "12", "verifier", "active"),
	})

	result, err := WarmVegaVerifierKeys(t.Context(), []string{source})
	if err != nil {
		t.Fatalf("WarmVegaVerifierKeys() error = %v", err)
	}
	if len(result.Failed) != 0 {
		t.Fatalf("Failed = %v, want none - both loaded fine, one just did not survive", result.Failed)
	}

	if len(result.Warmed) != 1 {
		t.Fatalf("Warmed = %v, want exactly the one key the bound has room for", result.Warmed)
	}
	if len(result.Evicted) != 1 {
		t.Fatalf("Evicted = %v, want the one that did not survive", result.Evicted)
	}
	if result.Warmed[0] == result.Evicted[0] {
		t.Fatal("the same id is reported both resident and evicted")
	}

	// And the claim is true: what Warmed names really is on disk.
	if _, ok := vegaVerifierKeys.get(result.Warmed[0]); !ok {
		t.Errorf("%s is reported warmed but is not in the store", result.Warmed[0])
	}
	if _, ok := vegaVerifierKeys.get(result.Evicted[0]); ok {
		t.Errorf("%s is reported evicted but is still in the store", result.Evicted[0])
	}
}

// The residency snapshot is taken under ONE lock. Asking id by id while
// the server is serving can see a key evicted between two questions and
// report a set that was never true at any instant.
func TestWarmResidencySnapshotIsTakenAtOnce(t *testing.T) {
	resetVegaKeyState(t)

	for _, id := range []string{"a", "b", "c"} {
		if _, release, err := vegaVerifierKeys.put(id, []byte("key "+id)); err != nil {
			t.Fatal(err)
		} else {
			release()
		}
	}

	resident, missing := vegaVerifierKeys.partition([]string{"a", "b", "c", "never-loaded"})
	if len(resident) != 3 {
		t.Errorf("resident = %v, want all three", resident)
	}
	if len(missing) != 1 || missing[0] != "never-loaded" {
		t.Errorf("missing = %v, want [never-loaded]", missing)
	}

	// A file that has gone counts as missing, not resident - the same rule
	// acquire applies, so the report matches what a request would find.
	path, ok := vegaVerifierKeys.get("b")
	if !ok {
		t.Fatal("b should be resident")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	resident, missing = vegaVerifierKeys.partition([]string{"a", "b", "c"})
	if len(resident) != 2 {
		t.Errorf("resident = %v, want a and c", resident)
	}
	if len(missing) != 1 || missing[0] != "b" {
		t.Errorf("missing = %v, want [b]", missing)
	}
}

// A pre-warm is best effort: when it fails, the key is supposed to be
// loaded at first use instead. That promise was broken for the one caller
// most likely to be affected - a live verification that arrived while the
// warm was still running, and so was parked on the warm's in-flight entry
// when it failed. It woke up and returned the warm's error as its own, even
// with plenty of time left on its own deadline, because the pre-warm's
// 15-minute context had nothing to do with the request's.
//
// Asserted on the one pass rather than on two racing goroutines: what has
// to hold is that a shared load's failure is reported as "go round again",
// and the loop in getOrLoadVegaVerifierKey then retries under the context
// it was given. Driving it with real goroutines needs the waiter to be
// provably parked before the other load fails, which nothing here can
// observe - a sleep would make the test probable rather than certain, and
// a miss would pass for the wrong reason.
func TestSharedLoadFailureIsRetriedNotInherited(t *testing.T) {
	resetVegaKeyState(t)

	// The pre-warm, finished and failed: its 15-minute context expired
	// while this caller was parked on it. Removed from the map before the
	// channel closes, the way the real loader's defer does it, so the
	// waiter holds a pointer to an entry that is already gone.
	prewarm := &inFlightLoad{done: make(chan struct{})}
	prewarm.err = fmt.Errorf("downloading verifier-key artifact: %w", context.DeadlineExceeded)
	close(prewarm.done)

	vegaVerifierKeyCacheState.mu.Lock()
	vegaVerifierKeyCacheState.inFly["vega-prover-r12"] = prewarm
	vegaVerifierKeyCacheState.mu.Unlock()
	defer func() {
		vegaVerifierKeyCacheState.mu.Lock()
		delete(vegaVerifierKeyCacheState.inFly, "vega-prover-r12")
		vegaVerifierKeyCacheState.mu.Unlock()
	}()

	_, _, retry, err := tryLoadVegaVerifierKey(t.Context(), "vega-prover-r12", []string{"https://example.invalid"})
	if !retry {
		t.Errorf("retry = false, want the caller to load the key itself rather than inherit the pre-warm's failure (err = %v)", err)
	}
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want the reason kept so an exhausted retry can report it", err)
	}
}

// ...but the retry is bounded, and when it runs out the error has to say
// what actually kept failing. Reporting an undersized max_bytes for a
// download that never worked sends the operator after the wrong thing.
func TestExhaustedRetriesReportTheUnderlyingLoadFailure(t *testing.T) {
	resetVegaKeyState(t)

	// Never removed, so every attempt finds the same failed load: the
	// shape of a source that is down rather than a cache that is too
	// small.
	stuck := &inFlightLoad{done: make(chan struct{})}
	stuck.err = fmt.Errorf("fetching prover-key circuit descriptor: %w", errors.New("connection refused"))
	close(stuck.done)

	vegaVerifierKeyCacheState.mu.Lock()
	vegaVerifierKeyCacheState.inFly["vega-prover-r12"] = stuck
	vegaVerifierKeyCacheState.mu.Unlock()

	_, _, err := getOrLoadVegaVerifierKey(t.Context(), "vega-prover-r12", []string{"https://example.invalid"})
	if err == nil {
		t.Fatal("expected a repeatedly failing load to be reported as an error")
	}
	if !strings.Contains(err.Error(), "could not be loaded on 3 consecutive attempts") {
		t.Errorf("error = %v, want it to report the exhausted retry", err)
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error = %v, want the underlying load failure preserved", err)
	}
	if strings.Contains(err.Error(), "max_bytes") {
		t.Errorf("error = %v, want it not to blame the cache size for a download failure", err)
	}
}
