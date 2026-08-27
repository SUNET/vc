// Package zkvegaworker defines the stdin/stdout JSON wire protocol between
// the main vc-verifier process and the standalone cmd/zkvegaverifyworker
// subprocess.
//
// This package is intentionally NOT cgo-tagged (no "zknative" build
// constraint, no import of pkg/mdoc/zknative_vega): it's imported by both
// sides of the pipe - the main process (which must keep building with
// CGO_ENABLED=0) and the worker binary (which links zk-cred-vega via cgo) -
// so the wire types themselves can't carry a cgo dependency either.
//
// Protocol: the main process writes one Request as a single JSON object to
// the worker's stdin, then closes stdin (or the worker reads until EOF -
// either way, exactly one request per process invocation - see this
// package's own doc on why the worker isn't a long-lived pooled process
// yet). The worker writes exactly one Response as a single JSON object to
// stdout, then exits 0 (a struct Response.Result was produced, possibly
// nil for a rejected-but-not-erroring... no: Result is always set on
// success) or non-zero (Response.Error is set; process also exits
// non-zero so a caller that fails to parse stdout at all still sees
// something went wrong via the exit code).
//
// See docs/ZK_PPID_VERIFICATION_PLAN.md and
// ~/.claude/plans/dreamy-frolicking-chipmunk.md's Phase 2/3 for the
// subprocess-isolation rationale: the cgo call touching attacker-supplied
// proof bytes runs in this isolated worker, not the main verifier process,
// so a memory-safety fault in the native library only takes down one
// worker, not the process serving other in-flight requests.
package zkvegaworker

// Request is the single JSON object the main process writes to the
// worker's stdin.
type Request struct {
	// VerifierKeyBytes is the raw (decompressed) verifier-key artifact
	// bytes - the same bytes zkcircuit.Client.DownloadAndDecompress
	// returns for a vega-mc-p256-v1-*-verifier-key-* catalog entry. The
	// main process is expected to cache these across calls (see
	// getOrLoadVegaVerifierKey in zk_native_cgo.go); the worker
	// re-deserializes them on every invocation since it holds no state
	// across calls itself.
	VerifierKeyBytes []byte `json:"verifier_key_bytes"`

	// ProofBytes is the presented ZK proof to verify.
	ProofBytes []byte `json:"proof_bytes"`

	// DisclosedBytes is the r12 circuit revision's required verify()
	// input: exactly MAX_CLAIMS_V1 entries, one per circuit claim slot, in
	// slot order - a disclosed slot's real IssuerSignedItemBytes, or an
	// empty slice for an undisclosed one. zk_cred_vega no longer returns a
	// disclosed claim's plaintext from the proof itself; the caller
	// supplies it here and verify() re-derives + checks its blinded
	// digest against the proof's own binding (a hard failure of the WHOLE
	// call if any slot's bytes don't match). See
	// BuildVegaDisclosedBytes's doc comment (in zk_verifier.go) for how
	// the main process builds this slice from the wire's
	// claimSlotDigestIds + per-item issuerSignedItemBytes fields.
	DisclosedBytes [][]byte `json:"disclosed_bytes"`
}

// DisclosedClaim mirrors zknative_vega.DisclosedClaim over the wire.
type DisclosedClaim struct {
	Disclosed bool   `json:"disclosed"`
	Digest    []byte `json:"digest"`
	RealLen   uint32 `json:"real_len"`
	Plaintext []byte `json:"plaintext"`
	DigestID  uint32 `json:"digest_id"`
}

// VerifyResult mirrors zknative_vega.VerifyResult over the wire - the
// verified, bound public output of a presentation. See that type's own doc
// comment: this is everything the proof itself proved, NOT a pass/fail
// against caller-supplied expected values.
type VerifyResult struct {
	Qx, Qy                              []byte
	Claims                              []DisclosedClaim
	DeviceX, DeviceY                    []byte
	SignedTs, ValidFromTs, ValidUntilTs []byte
}

// Response is the single JSON object the worker writes to stdout before
// exiting. Exactly one of Result/Error is set.
type Response struct {
	Result *VerifyResult `json:"result,omitempty"`
	Error  string        `json:"error,omitempty"`
}
