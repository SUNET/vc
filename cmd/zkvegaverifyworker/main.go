//go:build zknative

// Command zkvegaverifyworker is a small, standalone subprocess that links
// pkg/mdoc/zknative_vega (zk-cred-vega's cgo Go C-ABI binding) so the main
// vc-verifier process never has to. See pkg/mdoc/zkvegaworker's package
// doc for the full rationale (an isolated-subprocess mitigation for the
// cgo marshaling shim processing attacker-controlled proof bytes) and wire
// protocol.
//
// Reads exactly one zkvegaworker.Request as JSON from stdin, verifies it,
// writes exactly one zkvegaworker.Response as JSON to stdout, and exits:
// 0 on a successful verify (Response.Result set), 1 on any failure
// (Response.Error set - malformed request, bad verifier key, or a
// rejected/tampered proof are all reported the same way over stdout; only
// the exit code distinguishes "something went wrong" for a caller that
// doesn't parse stdout).
//
// Built only with the "zknative" tag (same convention as
// pkg/mdoc/zknative_vega itself) - see the Makefile's
// `build-zkvegaverifyworker` target.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/SUNET/vc/pkg/mdoc/zknative_vega"
	"github.com/SUNET/vc/pkg/mdoc/zkvegaworker"
)

func main() {
	os.Exit(run())
}

// run does the real work and returns a process exit code, rather than
// calling os.Exit directly at every failure point - keeps every deferred
// Close() actually running (os.Exit skips deferred calls) and keeps this
// testable as an ordinary function.
func run() int {
	reqBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fail(fmt.Errorf("reading request from stdin: %w", err))
	}

	var req zkvegaworker.Request
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		return fail(fmt.Errorf("parsing request JSON: %w", err))
	}

	result, err := verify(req)
	if err != nil {
		return fail(err)
	}

	return succeed(result)
}

func verify(req zkvegaworker.Request) (*zkvegaworker.VerifyResult, error) {
	vk, err := zknative_vega.NewVerifierKey(req.VerifierKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("loading verifier key: %w", err)
	}
	defer vk.Close()

	result, err := vk.Verify(req.ProofBytes)
	if err != nil {
		return nil, fmt.Errorf("verifying proof: %w", err)
	}

	claims := make([]zkvegaworker.DisclosedClaim, len(result.Claims))
	for i, c := range result.Claims {
		claims[i] = zkvegaworker.DisclosedClaim{
			Disclosed: c.Disclosed,
			Digest:    c.Digest[:],
			RealLen:   c.RealLen,
			Plaintext: c.Plaintext,
			DigestID:  c.DigestID,
		}
	}

	return &zkvegaworker.VerifyResult{
		Qx:           result.Qx[:],
		Qy:           result.Qy[:],
		Claims:       claims,
		DeviceX:      result.DeviceX[:],
		DeviceY:      result.DeviceY[:],
		SignedTs:     result.SignedTs[:],
		ValidFromTs:  result.ValidFromTs[:],
		ValidUntilTs: result.ValidUntilTs[:],
	}, nil
}

func succeed(result *zkvegaworker.VerifyResult) int {
	resp := zkvegaworker.Response{Result: result}
	if err := writeResponse(resp); err != nil {
		fmt.Fprintln(os.Stderr, "zkvegaverifyworker: failed to write response:", err)
		return 1
	}
	return 0
}

func fail(err error) int {
	resp := zkvegaworker.Response{Error: err.Error()}
	if writeErr := writeResponse(resp); writeErr != nil {
		fmt.Fprintln(os.Stderr, "zkvegaverifyworker: failed to write error response:", writeErr)
	}
	return 1
}

func writeResponse(resp zkvegaworker.Response) error {
	enc := json.NewEncoder(os.Stdout)
	return enc.Encode(resp)
}
