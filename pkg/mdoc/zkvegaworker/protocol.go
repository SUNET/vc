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
// stdout, then exits. Two invariants, and a caller may rely on both:
//
//   - exit 0 means Response.Result is set and Response.Error is empty.
//   - a non-zero exit means Response.Error is set and Response.Result is
//     nil. The exit code carries the failure as well as the body, so a
//     caller that cannot parse stdout at all still learns something went
//     wrong.
//
// There is no third case: the worker never exits 0 with a nil Result to
// mean "rejected but not errored". A proof that fails verification is an
// error.
//
// See docs/ZK_PPID_VERIFICATION_PLAN.md for the subprocess-isolation
// rationale: the cgo call touching attacker-supplied
// proof bytes runs in this isolated worker, not the main verifier process,
// so a memory-safety fault in the native library only takes down one
// worker, not the process serving other in-flight requests.
package zkvegaworker

// MaxClaims is zk-cred-vega's MAX_CLAIMS_V1: the fixed number of claim
// slots a v1 circuit has, and so the exact length of Request.DisclosedBytes.
//
// It lives here because this package is the one both sides can import - the
// authoritative value is C.ZK_CRED_VEGA_MAX_CLAIMS in the crate's header,
// but that is only reachable under the cgo build tag, and the verifier-side
// builder has to know the slot count without it. zknative_vega asserts at
// compile time that this matches the header, so a circuit revision that
// changes the count fails the tagged build instead of producing wire data
// the worker then rejects at runtime.
const MaxClaims = 4

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
// Tagged explicitly, like every other type here: these names are a wire
// protocol between two separately-built binaries, so leaving them to
// default Go field names would let a rename in one silently stop matching
// the other.
type VerifyResult struct {
	Qx           []byte           `json:"qx"`
	Qy           []byte           `json:"qy"`
	Claims       []DisclosedClaim `json:"claims"`
	DeviceX      []byte           `json:"device_x"`
	DeviceY      []byte           `json:"device_y"`
	SignedTs     []byte           `json:"signed_ts"`
	ValidFromTs  []byte           `json:"valid_from_ts"`
	ValidUntilTs []byte           `json:"valid_until_ts"`
}

// Response is the single JSON object the worker writes to stdout before
// exiting. Exactly one of Result/Error is set.
type Response struct {
	Result *VerifyResult `json:"result,omitempty"`
	Error  string        `json:"error,omitempty"`
}
