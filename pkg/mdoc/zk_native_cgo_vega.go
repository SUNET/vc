//go:build zknative

package mdoc

// This file provides the real implementation of nativeVerifyZkProofVega -
// the Vega counterpart of zk_native_cgo.go's nativeVerifyZkProofWithPPID.
//
// Unlike the Longfellow path, this does NOT link zk-cred-vega's cgo
// binding directly into this process. Per the agreed cgo-risk mitigation
// (see ~/.claude/plans/dreamy-frolicking-chipmunk.md's "cgo risk decision"
// and pkg/mdoc/zknative_vega's own package doc), the actual cgo call
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
	verifierKeyBytes, err := getOrLoadVegaVerifierKey(ctx, zkSystemID, zkCircuitSources)
	if err != nil {
		return zkvegaworker.VerifyResult{}, fmt.Errorf("failed to resolve/load Vega verifier key for %q: %w", zkSystemID, err)
	}

	if workerPath == "" {
		workerPath = DefaultZkVegaWorkerPath
	}
	result, err := runZkVegaVerifyWorker(ctx, workerPath, verifierKeyBytes, proof, disclosedBytes)
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
func runZkVegaVerifyWorker(ctx context.Context, workerPath string, verifierKeyBytes, proof []byte, disclosedBytes [][]byte) (zkvegaworker.VerifyResult, error) {
	reqBytes, err := json.Marshal(zkvegaworker.Request{
		VerifierKeyBytes: verifierKeyBytes,
		ProofBytes:       proof,
		DisclosedBytes:   disclosedBytes,
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
		return zkvegaworker.VerifyResult{}, fmt.Errorf("%s", resp.Error)
	}
	if resp.Result == nil {
		return zkvegaworker.VerifyResult{}, fmt.Errorf("worker reported neither a result nor an error")
	}
	return *resp.Result, nil
}

// vegaVerifierKeyCacheState caches raw (decompressed) verifier-key
// artifact bytes, keyed by the wallet-declared PROVER-key zkSystemID -
// mirrors verifierCacheState's shape/in-flight-dedup pattern below, but
// caches bytes rather than a loaded native handle: deserialization into a
// native handle happens once PER WORKER INVOCATION (see
// zknative_vega.NewVerifierKey), not once per process, since the handle
// only ever exists inside a short-lived worker subprocess.
var vegaVerifierKeyCacheState = struct {
	mu    sync.Mutex
	byID  map[string][]byte
	inFly map[string]*inFlightLoad
}{
	byID:  make(map[string][]byte),
	inFly: make(map[string]*inFlightLoad),
}

// getOrLoadVegaVerifierKey returns cached, raw (decompressed) verifier-key
// bytes for the wallet-declared zkSystemID, loading them on a cache miss.
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
func getOrLoadVegaVerifierKey(ctx context.Context, zkSystemID string, zkCircuitSources []string) (verifierKeyBytes []byte, err error) {
	vegaVerifierKeyCacheState.mu.Lock()
	if cached, ok := vegaVerifierKeyCacheState.byID[zkSystemID]; ok {
		vegaVerifierKeyCacheState.mu.Unlock()
		return cached, nil
	}
	if load, loading := vegaVerifierKeyCacheState.inFly[zkSystemID]; loading {
		vegaVerifierKeyCacheState.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("waiting for Vega verifier key %q to finish loading on another goroutine: %w", zkSystemID, ctx.Err())
		case <-load.done:
		}
		if load.err != nil {
			return nil, fmt.Errorf("Vega verifier key %q failed to load on another goroutine: %w", zkSystemID, load.err)
		}
		vegaVerifierKeyCacheState.mu.Lock()
		cached, ok := vegaVerifierKeyCacheState.byID[zkSystemID]
		vegaVerifierKeyCacheState.mu.Unlock()
		if !ok {
			return nil, fmt.Errorf("Vega verifier key %q finished loading on another goroutine but is unexpectedly missing from the cache", zkSystemID)
		}
		return cached, nil
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
		if err == nil && len(verifierKeyBytes) > 0 {
			vegaVerifierKeyCacheState.byID[zkSystemID] = verifierKeyBytes
		}
		load.err = err
		delete(vegaVerifierKeyCacheState.inFly, zkSystemID)
		close(load.done)
		vegaVerifierKeyCacheState.mu.Unlock()
	}()

	client := zkcircuit.NewClient(zkCircuitSources...)
	proverDescriptor, fetchErr := client.FetchCircuit(ctx, zkSystemID)
	if fetchErr != nil {
		err = fmt.Errorf("fetching prover-key circuit descriptor: %w", fetchErr)
		return nil, err
	}

	manifest, manifestErr := client.FetchManifest(ctx)
	if manifestErr != nil {
		err = fmt.Errorf("fetching circuit manifest to resolve verifier-key sibling: %w", manifestErr)
		return nil, err
	}

	verifierDescriptor, findErr := findVegaVerifierKeyEntry(manifest, proverDescriptor)
	if findErr != nil {
		err = findErr
		return nil, err
	}

	circuitBytes, dlErr := client.DownloadAndDecompress(ctx, verifierDescriptor)
	if dlErr != nil {
		err = fmt.Errorf("downloading verifier-key artifact %q: %w", verifierDescriptor.ID, dlErr)
		return nil, err
	}

	verifierKeyBytes = circuitBytes
	return verifierKeyBytes, nil
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
