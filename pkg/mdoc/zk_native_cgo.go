//go:build zknative

package mdoc

// This file provides the real, cgo-backed implementations of
// nativeVerifyZkProofWithPPID (and, in the "no PPID" direction, a stub
// with a specific documented reason - see below) - see zk_native_stub.go
// for the default (no "zknative" tag) stand-in, and this package's
// zk_verifier.go doc comment for why this is build-tag-gated at all
// (mirrors pkg/pki's PKCS#11 support).
//
// Setup: `make zk-native-lib` at the repo root, then build/test with
// `-tags zknative` - see README.md's "Native ZK/PPID proof verification"
// section and the Makefile's `build-verifier-zknative` target.

import (
	"context"
	"fmt"
	"sync"

	"github.com/SUNET/vc/pkg/mdoc/zkcircuit"
	"github.com/SUNET/vc/pkg/mdoc/zknative"
)

// nativeVerifyZkProof is the non-PPID native ZK verify call site. It
// remains unimplemented EVEN with the "zknative" build tag: unlike
// verify_with_ppid, zk-cred-longfellow's Go-facing C ABI
// (src/go_ffi.rs/include/zk_cred_longfellow_go.h) does not export a plain
// non-PPID verify function today - only rust_verify_with_ppid exists.
// Adding one is zk-cred-longfellow (Rust crate) work, not something this
// Go binding can conjure. Wiring nativeVerifyZkProofWithPPID for real (the
// path every real presentation from this org's wallets actually uses,
// since the deployed circuits are 2-attribute given_name+pairwise_pseudonym
// - see docs/ZK_PPID_VERIFICATION_PLAN.md) was this change's explicit
// scope; a non-PPID native verify is a smaller, separate follow-up once
// zk-cred-longfellow exposes one.
func nativeVerifyZkProof(
	ctx context.Context,
	zkSystemID string,
	issuerPublicKeySEC1 []byte,
	attributes []ZkAttribute,
	docType string,
	deviceNameSpacesBytes []byte,
	sessionTranscript []byte,
	timeStr string,
	proof []byte,
	zkCircuitSources []string,
) error {
	return fmt.Errorf(
		"%w: zk-cred-longfellow's Go C ABI does not export a non-PPID verify function yet (only rust_verify_with_ppid) - see nativeVerifyZkProofWithPPID",
		ErrNativeZkVerifyNotImplemented,
	)
}

// nativeVerifyZkProofWithPPID resolves zkSystemID to a circuit (via
// pkg/mdoc/zkcircuit, caching the loaded native verifier - see
// verifierCache below), then calls zk-cred-longfellow's real
// rust_verify_with_ppid via pkg/mdoc/zknative.
func nativeVerifyZkProofWithPPID(
	ctx context.Context,
	zkSystemID string,
	issuerPublicKeySEC1 []byte,
	attributes []ZkAttribute,
	docType string,
	deviceNameSpacesBytes []byte,
	sessionTranscript []byte,
	timeStr string,
	verifierContext []byte,
	proof []byte,
	zkCircuitSources []string,
) error {
	verifier, numAttributes, err := getOrLoadVerifier(ctx, zkSystemID, zkCircuitSources)
	if err != nil {
		return fmt.Errorf("failed to resolve/load ZK circuit %q: %w", zkSystemID, err)
	}

	if len(attributes) != numAttributes {
		return fmt.Errorf(
			"zkSystemId %q circuit expects %d attribute(s), presented document has %d",
			zkSystemID, numAttributes, len(attributes),
		)
	}

	nativeAttrs := make([]zknative.Attribute, len(attributes))
	for i, a := range attributes {
		nativeAttrs[i] = zknative.Attribute{Identifier: a.Identifier, ValueCBOR: a.ValueCBOR}
	}

	err = verifier.VerifyWithPPID(zknative.VerifyWithPPIDArgs{
		IssuerPublicKeySEC1:   issuerPublicKeySEC1,
		Attributes:            nativeAttrs,
		DocType:               docType,
		DeviceNameSpacesBytes: deviceNameSpacesBytes,
		SessionTranscript:     sessionTranscript,
		Time:                  timeStr,
		VerifierContext:       verifierContext,
		Proof:                 proof,
	})
	if err != nil {
		return fmt.Errorf("ZK proof verification failed: %w", err)
	}
	return nil
}

// cachedVerifier pairs a loaded native verifier with the attribute count it
// was initialized for (needed to validate a presented document's attribute
// count before calling VerifyWithPPID, since a mismatch is a Rust-side
// panic-turned-error rather than a clean early rejection otherwise).
type cachedVerifier struct {
	verifier      *zknative.Verifier
	numAttributes int
}

// verifierCacheState holds every circuit this process has loaded so far,
// keyed by circuit id (zkSystemID, which IS the zk-circuits catalog's own
// circuit id on the wire - see ZKSystemTypeSpec's doc comment in
// pkg/openid4vp/dcql_zk.go). Circuit loading (rust_initialize_verifier) is
// expensive - see zknative.NewVerifier's doc comment - so every distinct
// circuit is loaded at most once per process and reused across requests
// and goroutines (MdocZkVerifier holds no interior mutability; concurrent
// reads through the same handle are sound per zk-cred-longfellow's own
// docs).
var verifierCacheState = struct {
	mu    sync.Mutex
	byID  map[string]*cachedVerifier
	inFly map[string]*sync.WaitGroup
}{
	byID:  make(map[string]*cachedVerifier),
	inFly: make(map[string]*sync.WaitGroup),
}

// getOrLoadVerifier returns a cached native verifier for zkSystemID,
// loading it (fetching the circuit descriptor + artifact from
// zkCircuitSources, or zkcircuit.DefaultZkCircuitURL if empty) on a cache
// miss.
func getOrLoadVerifier(ctx context.Context, zkSystemID string, zkCircuitSources []string) (*zknative.Verifier, int, error) {
	verifierCacheState.mu.Lock()
	if cached, ok := verifierCacheState.byID[zkSystemID]; ok {
		verifierCacheState.mu.Unlock()
		return cached.verifier, cached.numAttributes, nil
	}
	// Only one goroutine loads a given circuit at a time; others wait for
	// it rather than redundantly re-downloading/re-compiling the same
	// (expensive) circuit concurrently.
	if wg, loading := verifierCacheState.inFly[zkSystemID]; loading {
		verifierCacheState.mu.Unlock()
		wg.Wait()
		verifierCacheState.mu.Lock()
		cached, ok := verifierCacheState.byID[zkSystemID]
		verifierCacheState.mu.Unlock()
		if !ok {
			return nil, 0, fmt.Errorf("circuit %q failed to load on another goroutine", zkSystemID)
		}
		return cached.verifier, cached.numAttributes, nil
	}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	verifierCacheState.inFly[zkSystemID] = wg
	verifierCacheState.mu.Unlock()

	defer func() {
		verifierCacheState.mu.Lock()
		delete(verifierCacheState.inFly, zkSystemID)
		verifierCacheState.mu.Unlock()
		wg.Done()
	}()

	client := zkcircuit.NewClient(zkCircuitSources...)
	descriptor, err := client.FetchCircuit(ctx, zkSystemID)
	if err != nil {
		return nil, 0, fmt.Errorf("fetching circuit descriptor: %w", err)
	}
	version, ok := descriptor.ParamInt("version")
	if !ok {
		return nil, 0, fmt.Errorf("circuit %q descriptor has no numeric params.version", zkSystemID)
	}
	numAttributes, ok := descriptor.ParamInt("num_attributes")
	if !ok {
		return nil, 0, fmt.Errorf("circuit %q descriptor has no numeric params.num_attributes", zkSystemID)
	}

	circuitBytes, err := client.DownloadAndDecompress(ctx, descriptor)
	if err != nil {
		return nil, 0, fmt.Errorf("downloading circuit artifact: %w", err)
	}

	nativeVerifier, err := zknative.NewVerifier(circuitBytes, uint8(version), uint8(numAttributes))
	if err != nil {
		return nil, 0, fmt.Errorf("initializing native verifier: %w", err)
	}

	verifierCacheState.mu.Lock()
	verifierCacheState.byID[zkSystemID] = &cachedVerifier{verifier: nativeVerifier, numAttributes: numAttributes}
	verifierCacheState.mu.Unlock()

	return nativeVerifier, numAttributes, nil
}
