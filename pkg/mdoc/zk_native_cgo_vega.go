//go:build zknative

package mdoc

// This file provides the real implementation of nativeVerifyZkProofVega -
// the Vega counterpart of zk_native_cgo.go's nativeVerifyZkProofWithPPID.
//
// Unlike the Longfellow path, this does NOT link zk-cred-vega's cgo
// binding directly into this process. The reason is the cgo risk this
// package cannot mitigate any other way (see pkg/mdoc/zknative_vega's own
// package doc, and docs/ZK_PPID_VERIFICATION_PLAN.md): the actual cgo call
// touching attacker-controlled proof bytes runs in the isolated
// cmd/zkvegaverifyworker subprocess instead: this file only resolves the
// wallet-declared zkSystemId to a verifier-key artifact (caching the raw
// bytes, same shape as getOrLoadVerifier below) and execs the worker once
// per verify call, so a memory-safety fault in the native library only
// takes down one worker process, not this one.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"github.com/SUNET/vc/pkg/mdoc/zkcircuit"
	"github.com/SUNET/vc/pkg/mdoc/zkvegaworker"
)

// DefaultZkVegaWorkerPath is used when ZkVerifierConfig.VegaWorkerPath is
// empty - resolved via the OS's normal PATH lookup at exec time (see
// exec.Command's own doc on bare-name resolution), so a deployment only
// needs cmd/zkvegaverifyworker's build output somewhere on PATH rather
// than wiring an absolute path through config.
const DefaultZkVegaWorkerPath = "zkvegaverifyworker"

// nativeVerifyZkProofVega resolves zkSystemID (the wallet-declared
// PROVER-key catalog id, e.g. "vega-mc-p256-v1-prover-key-r7" - see
// getOrLoadVegaVerifierKey's doc comment for why the corresponding
// VERIFIER-key entry has to be separately resolved) to a verifier-key
// artifact, then execs the isolated worker subprocess to verify proof
// against it.
//
// This does NOT perform the caller's own comparison checks (issuer pubkey
// vs. trust-evaluated cert, disclosed plaintext vs. wire-declared
// elementValue, validity window vs. now) - see zk_verifier.go's Vega
// dispatch branch for those; this function only reports what the proof
// itself proved.
func nativeVerifyZkProofVega(
	ctx context.Context,
	zkSystemID string,
	proof []byte,
	disclosedBytes [][]byte,
	zkCircuitSources []string,
	workerPath string,
) (zkvegaworker.VerifyResult, error) {
	// The release is what keeps the key file on disk for as long as the
	// worker needs it: the worker is a separate process and opens the path
	// itself, so an eviction between here and that open would fail a
	// perfectly valid presentation.
	verifierKeyPath, release, err := getOrLoadVegaVerifierKey(ctx, zkSystemID, zkCircuitSources)
	if err != nil {
		return zkvegaworker.VerifyResult{}, fmt.Errorf("failed to resolve/load Vega verifier key for %q: %w", zkSystemID, err)
	}
	defer release()

	if workerPath == "" {
		workerPath = DefaultZkVegaWorkerPath
	}
	result, err := runZkVegaVerifyWorker(ctx, workerPath, verifierKeyPath, proof, disclosedBytes)
	if err != nil {
		return zkvegaworker.VerifyResult{}, fmt.Errorf("Vega ZK proof verification failed: %w", err)
	}
	return result, nil
}

// runZkVegaVerifyWorker execs workerPath, writes a zkvegaworker.Request as
// JSON to its stdin, and reads a zkvegaworker.Response as JSON from its
// stdout - see pkg/mdoc/zkvegaworker's package doc for the full protocol
// and subprocess-isolation rationale. One process per call (see that
// package's doc on why this isn't pooled yet).
func runZkVegaVerifyWorker(ctx context.Context, workerPath, verifierKeyPath string, proof []byte, disclosedBytes [][]byte) (zkvegaworker.VerifyResult, error) {
	reqBytes, err := json.Marshal(zkvegaworker.Request{
		VerifierKeyPath: verifierKeyPath,
		ProofBytes:      proof,
		DisclosedBytes:  disclosedBytes,
	})
	if err != nil {
		return zkvegaworker.VerifyResult{}, fmt.Errorf("encoding worker request: %w", err)
	}

	cmd := exec.CommandContext(ctx, workerPath)
	cmd.Stdin = bytes.NewReader(reqBytes)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	var resp zkvegaworker.Response
	if decodeErr := json.Unmarshal(stdout.Bytes(), &resp); decodeErr != nil {
		// The worker may have crashed (e.g. a memory-safety fault in the
		// native library) before writing any valid JSON at all - report
		// the raw exit error/stderr rather than a confusing JSON decode
		// error, since that's the actually useful signal here.
		if runErr != nil {
			return zkvegaworker.VerifyResult{}, fmt.Errorf("worker exited without a valid response (%w); stderr: %s", runErr, strings.TrimSpace(stderr.String()))
		}
		return zkvegaworker.VerifyResult{}, fmt.Errorf("failed to decode worker response: %w; stderr: %s", decodeErr, strings.TrimSpace(stderr.String()))
	}
	if resp.Error != "" {
		// stderr comes along: a native fault can print a diagnostic there and
		// still let the worker serialize an error, and dropping it leaves the
		// most useful half of the failure on the floor.
		if diag := strings.TrimSpace(stderr.String()); diag != "" {
			return zkvegaworker.VerifyResult{}, fmt.Errorf("%s; stderr: %s", resp.Error, diag)
		}
		return zkvegaworker.VerifyResult{}, fmt.Errorf("%s", resp.Error)
	}
	if resp.Result == nil {
		return zkvegaworker.VerifyResult{}, fmt.Errorf("worker reported neither a result nor an error")
	}
	// A parseable success response is not on its own proof the worker
	// finished cleanly: it could have written a result and then died (a
	// fault in the native library after the answer was serialized, or a
	// context kill). The protocol says a successful worker exits zero, so a
	// non-zero exit here contradicts the response and the response is not
	// trustworthy.
	if runErr != nil {
		return zkvegaworker.VerifyResult{}, fmt.Errorf("worker returned a result but exited non-zero (%w); stderr: %s", runErr, strings.TrimSpace(stderr.String()))
	}
	return *resp.Result, nil
}

// vegaVerifierKeyCacheState caches raw (decompressed) verifier-key
// artifacts ON DISK, keyed by the wallet-declared PROVER-key zkSystemID -
// mirrors verifierCacheState's shape/in-flight-dedup pattern below, but
// caches bytes rather than a loaded native handle: deserialization into a
// native handle happens once PER WORKER INVOCATION (see
// zknative_vega.NewVerifierKey), not once per process, since the handle
// only ever exists inside a short-lived worker subprocess.
//
// The blobs themselves live in a byte-bounded LRU - see vegaKeyCache, which
// is in its own untagged file so its eviction rule can be tested without the
// crate staged, and whose doc comment explains why this cache sits outside
// pkg/cache and Common.HA. The mutex here covers both that and the in-flight
// map.
//
// inFly dedups concurrent loads within one process only. Under HA that means
// each instance fetches a given artifact once rather than one fetching it for
// the whole deployment - N cold-start fetches from the circuit catalog, not
// one. Acceptable (they are cache misses on immutable public artifacts, and
// the catalog is a CDN-shaped mirror list), but worth knowing before reading
// a burst of identical fetches as a bug.
var vegaVerifierKeyCacheState = struct {
	mu    sync.Mutex
	inFly map[string]*inFlightLoad
}{
	inFly: make(map[string]*inFlightLoad),
}

// getOrLoadVegaVerifierKey returns the path to a local file holding the raw
// (decompressed) verifier key for the wallet-declared zkSystemID, fetching
// it on a miss, together with a release the caller MUST call when it is
// finished with the path.
//
// The file belongs to vegaKeyStore and may be evicted once released. Until
// then it is pinned: the worker is a separate process that opens the path
// itself, so an eviction in that window would fail a valid presentation.
//
// zkSystemID (from ZkDocumentDataMdoc.ZkSystemID, i.e. ZkSystemSpec.id on
// the wallet side - see SirosWallet.buildZkPresentationToken) is the
// PROVER-key catalog entry id the wallet actually used to build the proof
// (e.g. "vega-mc-p256-v1-prover-key-r7") - unlike Longfellow, where one
// circuit artifact serves both roles, zk-cred-vega publishes SEPARATE
// prover-key/verifier-key catalog entries (see go-zk-circuits' vega-mc
// catalog: params.role "prover" vs "verifier", same system+systemVersion).
// A verifier never needs the prover key at all, so this resolves the
// CORRESPONDING verifier-key entry instead: fetch the prover descriptor
// first (to read its System/SystemVersion), then search the full manifest
// for the sibling entry with the same System+SystemVersion and
// params.role == "verifier" - robust against the exact id-suffix
// convention (e.g. "-prover-key-r7" -> "-verifier-key-r7") ever changing,
// unlike a plain string substitution would be.
func getOrLoadVegaVerifierKey(ctx context.Context, zkSystemID string, zkCircuitSources []string) (string, func(), error) {
	// A loop, because a waiter can find the key gone again: a concurrent
	// load for another circuit may evict it between the loading goroutine
	// installing it and this one pinning it, which a small or churning
	// cache makes ordinary rather than exceptional. That used to be
	// reported as an internal error and failed a perfectly valid request;
	// now it just goes round and loads the key itself.
	//
	// Bounded so a pathologically small max_bytes cannot spin here
	// forever - at that point the deployment has a configuration problem
	// and should be told so rather than hang.
	for range vegaKeyLoadAttempts {
		path, release, retry, err := tryLoadVegaVerifierKey(ctx, zkSystemID, zkCircuitSources)
		if err != nil {
			return "", nil, err
		}
		if !retry {
			return path, release, nil
		}
	}
	return "", nil, fmt.Errorf(
		"Vega verifier key %q was evicted before it could be used on %d consecutive attempts; verifier.zk_key_cache.max_bytes is too small to hold the circuits in use",
		zkSystemID, vegaKeyLoadAttempts)
}

// vegaKeyLoadAttempts bounds the retry above.
const vegaKeyLoadAttempts = 3

// tryLoadVegaVerifierKey is one pass of getOrLoadVegaVerifierKey. retry is
// true when the key was loaded by somebody else and evicted again before
// this caller could pin it.
func tryLoadVegaVerifierKey(ctx context.Context, zkSystemID string, zkCircuitSources []string) (_ string, _ func(), retry bool, err error) {
	if cached, releaseCached, ok := vegaVerifierKeys.acquire(zkSystemID); ok {
		return cached, releaseCached, false, nil
	}

	vegaVerifierKeyCacheState.mu.Lock()

	// Re-check the store under the in-flight lock. The acquire above is
	// unlocked relative to this one, so between the two another goroutine
	// can finish its load, install the key and drop its inFly entry -
	// leaving this one to see no load in progress and start a second
	// ~100MB download of a key that is already on disk. Exactly the
	// overlap a cold start with traffic produces, which is when it costs
	// the most.
	//
	// Lock order is cacheState.mu then keys.mu, and never the reverse:
	// put() below runs with cacheState.mu released.
	if cached, releaseCached, ok := vegaVerifierKeys.acquire(zkSystemID); ok {
		vegaVerifierKeyCacheState.mu.Unlock()
		return cached, releaseCached, false, nil
	}

	if load, loading := vegaVerifierKeyCacheState.inFly[zkSystemID]; loading {
		vegaVerifierKeyCacheState.mu.Unlock()
		select {
		case <-ctx.Done():
			return "", nil, false, fmt.Errorf("waiting for Vega verifier key %q to finish loading on another goroutine: %w", zkSystemID, ctx.Err())
		case <-load.done:
		}
		if load.err != nil {
			return "", nil, false, fmt.Errorf("Vega verifier key %q failed to load on another goroutine: %w", zkSystemID, load.err)
		}
		if cached, releaseCached, ok := vegaVerifierKeys.acquire(zkSystemID); ok {
			return cached, releaseCached, false, nil
		}
		return "", nil, true, nil
	}

	load := &inFlightLoad{done: make(chan struct{})}
	vegaVerifierKeyCacheState.inFly[zkSystemID] = load
	vegaVerifierKeyCacheState.mu.Unlock()

	defer func() {
		if r := recover(); r != nil {
			vegaVerifierKeyCacheState.mu.Lock()
			load.err = fmt.Errorf("panic while loading Vega verifier key %q: %v", zkSystemID, r)
			delete(vegaVerifierKeyCacheState.inFly, zkSystemID)
			close(load.done)
			vegaVerifierKeyCacheState.mu.Unlock()
			panic(r)
		}

		vegaVerifierKeyCacheState.mu.Lock()
		load.err = err
		delete(vegaVerifierKeyCacheState.inFly, zkSystemID)
		close(load.done)
		vegaVerifierKeyCacheState.mu.Unlock()
	}()

	client := zkcircuit.NewClient(zkCircuitSources...)
	proverDescriptor, fetchErr := client.FetchCircuit(ctx, zkSystemID)
	if fetchErr != nil {
		err = fmt.Errorf("fetching prover-key circuit descriptor: %w", fetchErr)
		return "", nil, false, err
	}

	manifest, manifestErr := client.FetchManifest(ctx)
	if manifestErr != nil {
		err = fmt.Errorf("fetching circuit manifest to resolve verifier-key sibling: %w", manifestErr)
		return "", nil, false, err
	}

	verifierDescriptor, findErr := findVegaVerifierKeyEntry(manifest, proverDescriptor)
	if findErr != nil {
		err = findErr
		return "", nil, false, err
	}

	circuitBytes, dlErr := client.DownloadAndDecompress(ctx, verifierDescriptor)
	if dlErr != nil {
		err = fmt.Errorf("downloading verifier-key artifact %q: %w", verifierDescriptor.ID, dlErr)
		return "", nil, false, err
	}
	if len(circuitBytes) == 0 {
		err = fmt.Errorf("verifier-key artifact %q decompressed to nothing", verifierDescriptor.ID)
		return "", nil, false, err
	}

	// Stored before returning rather than in the defer, so a store that
	// cannot be written is the caller's error rather than a silent fall
	// through to a path that is not there. The bytes are dropped here: from
	// this point on the key only exists as a file, which is the whole point
	// (SUNET/vc#656).
	path, releaseNew, storeErr := vegaVerifierKeys.put(zkSystemID, circuitBytes)
	if storeErr != nil {
		err = storeErr
		return "", nil, false, err
	}
	return path, releaseNew, false, nil
}

// findVegaVerifierKeyEntry searches manifest for the single entry sharing
// proverDescriptor's System/SystemVersion with params.role == "verifier" -
// see getOrLoadVegaVerifierKey's doc comment for why this lookup (rather
// than a naming-convention string substitution) is used.
func findVegaVerifierKeyEntry(manifest *zkcircuit.Manifest, proverDescriptor *zkcircuit.CircuitDescriptor) (*zkcircuit.CircuitDescriptor, error) {
	var match *zkcircuit.CircuitDescriptor
	for i := range manifest.Circuits {
		c := &manifest.Circuits[i]
		if c.System != proverDescriptor.System || c.SystemVersion != proverDescriptor.SystemVersion {
			continue
		}
		role, _ := c.ParamString("role")
		if role != "verifier" {
			continue
		}
		if match != nil {
			return nil, fmt.Errorf(
				"more than one verifier-key entry found for system %q version %q (%q and %q) - ambiguous, refusing to guess which one was intended",
				proverDescriptor.System, proverDescriptor.SystemVersion, match.ID, c.ID,
			)
		}
		match = c
	}
	if match == nil {
		return nil, fmt.Errorf("no verifier-key entry found for system %q version %q (prover-key id %q)", proverDescriptor.System, proverDescriptor.SystemVersion, proverDescriptor.ID)
	}
	return match, nil
}
