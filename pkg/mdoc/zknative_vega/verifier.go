//go:build zknative

// Package zknative_vega is a cgo wrapper around zk-cred-vega's plain
// C-ABI Go verifier binding (src/go_ffi.rs / include/zk_cred_vega_go.h in
// that crate) - the Vega counterpart of pkg/mdoc/zknative (which wraps
// zk-cred-longfellow instead). The two are separate packages, not one,
// because they wrap genuinely different C headers/shared libraries with
// different verify shapes (see VerifierKey.Verify's own doc comment).
//
// This package is linked ONLY into the standalone cmd/zkvegaverifyworker
// binary, never into the main vc-verifier process - see that command's
// package doc for why (an isolated-subprocess mitigation for the cgo
// marshaling shim processing attacker-controlled proof bytes). It is built
// only when the "zknative" Go build tag is set, same convention as
// pkg/mdoc/zknative.
//
// Setup: run `make zk-native-lib-vega` at the repo root (fetches/builds
// zk-cred-vega's `go-cabi` target and stages the shared library + header
// under third_party/zk-cred-vega/), then build/test with `-tags zknative`
// and CGO_CFLAGS/CGO_LDFLAGS pointing at that directory - see the
// Makefile's `build-zkvegaverifyworker` target and README.md's "Native
// ZK/PPID proof verification" section.
package zknative_vega

/*
#cgo CFLAGS: -I${SRCDIR}/../../../third_party/zk-cred-vega/include
#cgo LDFLAGS: -L${SRCDIR}/../../../third_party/zk-cred-vega/lib -lzk_cred_vega
#include <stdlib.h>
#include "zk_cred_vega_go.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

// MaxClaims/MaxClaimBytes/TimestampLen mirror the crate's own
// MAX_CLAIMS_V1/MAX_CLAIM_BYTES_V1/mso::TIMESTAMP_LEN constants (see
// zk_cred_vega_go.h's ZK_CRED_VEGA_MAX_CLAIMS/_MAX_CLAIM_BYTES/_TIMESTAMP_LEN
// macros, and go_ffi.rs's own compile-time assertions tying those to the
// real crate constants) - fixed at compile time on the Rust side, so fixed
// here too rather than read from anywhere at runtime.
const (
	MaxClaims      = int(C.ZK_CRED_VEGA_MAX_CLAIMS)
	MaxClaimBytes  = int(C.ZK_CRED_VEGA_MAX_CLAIM_BYTES)
	TimestampLen   = int(C.ZK_CRED_VEGA_TIMESTAMP_LEN)
	P256CoordBytes = 32
)

// VerifierKey wraps an opaque, deserialized zk-cred-vega verifier-key
// handle (C.GoVegaVerifierKey). Deserializing a key is comparatively cheap
// (no circuit compilation happens here, unlike zknative.NewVerifier), but a
// long-lived process should still construct one VerifierKey per distinct
// circuit (via NewVerifierKey) and reuse it across many Verify calls,
// mirroring zknative.Verifier's own caching guidance.
type VerifierKey struct {
	handle *C.GoVegaVerifierKey
	// closeOnce guards zk_cred_vega_free_verifier_key against a
	// check-then-act double-free race - see zknative.Verifier.closeOnce's
	// identical rationale.
	closeOnce sync.Once
}

// NewVerifierKey deserializes a published verifier-key artifact (the same
// bytes go-zk-circuits serves for a vega-mc-p256-v1-*-verifier-key-* entry)
// into a reusable VerifierKey.
func NewVerifierKey(bytes []byte) (*VerifierKey, error) {
	if len(bytes) == 0 {
		return nil, errors.New("zknative_vega: verifier key bytes must not be empty")
	}

	ptr, length := bytesPtr(bytes)
	var errOut *C.char
	handle := C.zk_cred_vega_deserialize_verifier_key(ptr, length, &errOut)
	// ptr points into bytes' backing array - KeepAlive guarantees bytes (and
	// so its backing array) can't be GC'd before the (synchronous) C call
	// above returns. See zknative.NewVerifier's identical rationale.
	runtime.KeepAlive(bytes)
	if handle == nil {
		return nil, fmt.Errorf("zknative_vega: zk_cred_vega_deserialize_verifier_key: %s", takeErrorString(errOut))
	}
	if errOut != nil {
		_ = takeErrorString(errOut)
	}
	return &VerifierKey{handle: handle}, nil
}

// Close releases the underlying verifier-key handle. Safe to call more than
// once (and concurrently) - only the first call frees the handle. Not safe
// to call concurrently with an in-flight Verify call using the same
// VerifierKey.
func (k *VerifierKey) Close() error {
	if k == nil {
		return nil
	}
	k.closeOnce.Do(func() {
		if k.handle != nil {
			C.zk_cred_vega_free_verifier_key(k.handle)
			k.handle = nil
		}
	})
	return nil
}

// DisclosedClaim is one claim slot's verified disclosure outcome, mirroring
// zk-cred-vega's CDisclosedClaim (and, one level up, its Rust
// DisclosedClaim). Plaintext is exactly RealLen bytes (already trimmed of
// the C ABI's fixed MaxClaimBytes padding) - meaningful only when Disclosed
// is true (all-zero otherwise, per the crate's own masking).
type DisclosedClaim struct {
	Disclosed bool
	Digest    [32]byte
	RealLen   uint32
	Plaintext []byte
	DigestID  uint32
}

// VerifyResult is the verified, bound public output of a presentation,
// mirroring zk-cred-vega's CVerifyResult.
//
// IMPORTANT (see Verify's own doc comment): this is everything the proof
// itself proved, NOT a pass/fail against caller-supplied expected values -
// the caller must independently compare these fields against whatever it
// already knows before treating the presentation as accepted.
type VerifyResult struct {
	Qx, Qy                              [P256CoordBytes]byte
	Claims                              [MaxClaims]DisclosedClaim
	DeviceX, DeviceY                    [32]byte
	SignedTs, ValidFromTs, ValidUntilTs [TimestampLen]byte
}

// Verify verifies proofBytes and checks the step<->core binding in one
// call via zk-cred-vega's real zk_cred_vega_verify - a thin cgo marshaling
// wrapper, not a separate/weaker check.
//
// A REAL SHAPE DIFFERENCE from zknative.Verifier.VerifyWithPPID: that
// function takes the *expected* attribute values as input and returns only
// an error (pass/fail) - the caller already knows what should be true and
// just asks Rust to confirm it. This function takes ONLY the proof and
// *returns* the recomputed public values (issuer pubkey, disclosed claims,
// MSO-body fields) - the caller must independently check them against
// whatever it already knows. See pkg/mdoc/zk_verifier.go's Vega dispatch
// branch for exactly that comparison logic.
func (k *VerifierKey) Verify(proof []byte) (VerifyResult, error) {
	if k == nil || k.handle == nil {
		return VerifyResult{}, errors.New("zknative_vega: verifier key is closed or nil")
	}
	if len(proof) == 0 {
		return VerifyResult{}, errors.New("zknative_vega: proof must not be empty")
	}

	proofPtr, proofLen := bytesPtr(proof)
	var cResult C.CVerifyResult
	var errOut *C.char
	status := C.zk_cred_vega_verify(k.handle, proofPtr, proofLen, &cResult, &errOut)
	// proofPtr points into proof's backing array - KeepAlive guarantees proof
	// can't be GC'd before the (synchronous) C call above returns.
	runtime.KeepAlive(proof)
	if status != 0 {
		return VerifyResult{}, fmt.Errorf("zknative_vega: zk_cred_vega_verify failed (status=%d): %s", int32(status), takeErrorString(errOut))
	}
	if errOut != nil {
		_ = takeErrorString(errOut)
	}
	return fromCResult(&cResult), nil
}

// fromCResult copies a C.CVerifyResult (backed by C memory that becomes
// invalid the instant the calling function returns) into a plain Go
// VerifyResult - no pointers into C memory escape this function.
func fromCResult(r *C.CVerifyResult) VerifyResult {
	var out VerifyResult
	copyBytes(out.Qx[:], unsafe.Pointer(&r.qx[0]), len(out.Qx))
	copyBytes(out.Qy[:], unsafe.Pointer(&r.qy[0]), len(out.Qy))
	copyBytes(out.DeviceX[:], unsafe.Pointer(&r.device_x[0]), len(out.DeviceX))
	copyBytes(out.DeviceY[:], unsafe.Pointer(&r.device_y[0]), len(out.DeviceY))
	copyBytes(out.SignedTs[:], unsafe.Pointer(&r.signed_ts[0]), len(out.SignedTs))
	copyBytes(out.ValidFromTs[:], unsafe.Pointer(&r.valid_from_ts[0]), len(out.ValidFromTs))
	copyBytes(out.ValidUntilTs[:], unsafe.Pointer(&r.valid_until_ts[0]), len(out.ValidUntilTs))

	for i := 0; i < MaxClaims; i++ {
		c := r.claims[i]
		var claim DisclosedClaim
		claim.Disclosed = c.disclosed != 0
		copyBytes(claim.Digest[:], unsafe.Pointer(&c.digest[0]), len(claim.Digest))
		claim.RealLen = uint32(c.real_len)
		claim.DigestID = uint32(c.digest_id)
		realLen := int(claim.RealLen)
		if realLen > MaxClaimBytes {
			// Defensive: a value this large from the native library would
			// indicate a real bug in the crate's own verify_and_check_binding
			// (see go_ffi.rs's identical validation), not caller-controlled
			// input - clamp rather than read out of the fixed C array.
			realLen = MaxClaimBytes
		}
		if claim.Disclosed && realLen > 0 {
			claim.Plaintext = make([]byte, realLen)
			copyBytes(claim.Plaintext, unsafe.Pointer(&c.plaintext[0]), realLen)
		}
		out.Claims[i] = claim
	}
	return out
}

// copyBytes copies n bytes from a C-owned array (src) into dst, which must
// have length >= n. Used only for fixed-size fields read out of a
// C.CVerifyResult passed by value into fromCResult (i.e. src always points
// into memory owned by the calling Go stack frame's C struct copy, not
// separately heap-allocated C memory needing a free).
func copyBytes(dst []byte, src unsafe.Pointer, n int) {
	srcSlice := unsafe.Slice((*byte)(src), n)
	copy(dst, srcSlice)
}

// bytesPtr returns a pointer to the first byte of b and its length, or
// (nil, 0) for an empty slice. Only safe for pointers passed directly as
// top-level cgo call arguments - see pkg/mdoc/zknative's identical
// bytesPtr for the same rule (this package never needs cBytesCopy's
// struct-field variant, since it never builds an array of C structs to
// pass by pointer the way zknative.VerifyWithPPID's CAttribute array does).
func bytesPtr(b []byte) (*C.uint8_t, C.size_t) {
	if len(b) == 0 {
		return nil, 0
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b))
}

// takeErrorString converts and frees an owned error string written into an
// error_out out-parameter by zk-cred-vega's C ABI, returning "(no message)"
// if ptr is nil. Mirrors pkg/mdoc/zknative's identical helper - MUST use
// zk_cred_vega_free_error_string (not the generic C.free) since the string
// was allocated Rust-side via CString::into_raw, not malloc; freeing it any
// other way is undefined behavior even if it happens to work today.
func takeErrorString(ptr *C.char) string {
	if ptr == nil {
		return "(no message)"
	}
	msg := C.GoString(ptr)
	C.zk_cred_vega_free_error_string(ptr)
	return msg
}
