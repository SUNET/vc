//go:build zknative

// Package zknative is a cgo wrapper around zk-cred-longfellow's plain
// C-ABI nym_auth verifier (src/nymauth/c_abi.rs /
// include/zk_cred_longfellow_nymauth.h in that crate). It is built only
// when the "zknative" Go build tag is set - see
// pkg/nymauth/verifier/native_cgo.go, the sole consumer within this
// repo, and this repo's Makefile targets `zk-native-lib` and
// `test-zknative`.
//
// Same tag-gating, and the same reason, as pkg/mdoc/zknative: cgo needs
// CGO_ENABLED=1 and a linker able to find the staged shared library,
// and the default vc-verifier build (CGO_ENABLED=0, fully static) must
// keep working without either.
//
// This package deliberately does NOT import pkg/nymauth/verifier: that
// package imports this one under the build tag, and the dependency has
// to run one way. Its arguments are therefore flat bytes and strings,
// and the mapping from a verifier.Request lives in
// pkg/nymauth/verifier/native.go, where it is testable without the
// native library.
//
// Setup: `make zk-native-lib` at the repo root stages the shared
// library and both headers under third_party/zk-cred-longfellow/; then
// build or test with `-tags zknative` and LD_LIBRARY_PATH pointing at
// that lib directory (see the Makefile's `test-zknative`).
package zknative

/*
#cgo CFLAGS: -I${SRCDIR}/../../../../third_party/zk-cred-longfellow/include
#cgo LDFLAGS: -L${SRCDIR}/../../../../third_party/zk-cred-longfellow/lib -lzk_cred_longfellow
#include <stdlib.h>
#include "zk_cred_longfellow_nymauth.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

// PseudonymBytes is the width of a nym_auth pseudonym and of every
// digest this ABI takes or returns.
const PseudonymBytes = 32

// Params are the catalog descriptor's circuit parameters
// (NymAuthCParams). The loader checks the artifact against its
// allowlist entry - length, SHA-256 and these - and refuses anything
// else before parsing it.
type Params struct {
	BlockEncHash  uint32
	BlockEncSig   uint32
	HashCircuitID string
	SigCircuitID  string
}

// Request is NymAuthCRequest: the values both sides know. Every one of
// them is the verifier's own; see pkg/nymauth/verifier's Request for
// why that matters and where each comes from.
type Request struct {
	IssuerKeyX, IssuerKeyY []byte
	Time                   string
	Earliest, Cutoff       string
	ChallengeDigest        []byte
	VerifierInput          []byte
	TranscriptSeed         []byte
}

// Verifier wraps a loaded NymAuthVerifier handle. Loading is the
// expensive step (about 0.15 s), so construct one per circuit build and
// reuse it; the underlying Rust type holds no interior mutability, so
// concurrent Verify calls through one handle are fine.
type Verifier struct {
	handle *C.NymAuthVerifier
	// closeOnce makes "freed exactly once" a guarantee rather than a
	// doc comment: two concurrent Close calls on a nil-check/assign
	// pattern can both pass the check and both free the handle, which
	// is a cgo double free. Same reasoning as pkg/mdoc/zknative.
	closeOnce sync.Once
}

// NewVerifier loads a decompressed nym_auth circuit artifact
// (signature circuit then hash circuit, LFC2 - zstd-decompress first if
// it came from the circuit catalog).
func NewVerifier(circuit []byte, params Params) (*Verifier, error) {
	if len(circuit) == 0 {
		return nil, errors.New("zknative: circuit must not be empty")
	}

	var a arena
	defer a.free()

	// params is passed BY POINTER, so its NymAuthBytes fields must not
	// hold Go pointers - cgo forbids passing a pointer to Go memory
	// that itself contains Go pointers. circuit is passed BY VALUE, so
	// a pointer into the Go slice is fine there, with KeepAlive.
	cParams := C.NymAuthCParams{
		block_enc_hash:  C.uint32_t(params.BlockEncHash),
		block_enc_sig:   C.uint32_t(params.BlockEncSig),
		hash_circuit_id: a.str(params.HashCircuitID),
		sig_circuit_id:  a.str(params.SigCircuitID),
	}

	var errOut *C.char
	handle := C.nymauth_verifier_new(goBytes(circuit), &cParams, &errOut)
	runtime.KeepAlive(circuit)
	if handle == nil {
		return nil, fmt.Errorf("zknative: nymauth_verifier_new: %s", takeErrorString(errOut))
	}
	// Not expected alongside a valid handle, but takeErrorString frees
	// the owned string and is a no-op on nil - cheap insurance against
	// leaking native memory if that ever changes.
	_ = takeErrorString(errOut)
	return &Verifier{handle: handle}, nil
}

// Close releases the circuit handle. Safe to call more than once and
// concurrently; not safe to call while a Verify on the same Verifier is
// in flight.
func (v *Verifier) Close() error {
	if v == nil {
		return nil
	}
	v.closeOnce.Do(func() {
		if v.handle != nil {
			C.nymauth_verifier_free(v.handle)
			v.handle = nil
		}
	})
	return nil
}

// Verify checks proof against the verifier's own request and the
// pseudonym the holder claims, and returns the pseudonym the caller may
// use.
//
// The returned value is the ONLY one a caller may act on. It is equal
// to claimed on success, which is exactly the point: a pseudonym is a
// value the holder sent, and it means nothing until a proof has been
// checked against it. Reading it from the response instead would be
// reading an identifier the holder chose.
func (v *Verifier) Verify(req Request, claimed []byte, proof []byte) ([PseudonymBytes]byte, error) {
	var zero [PseudonymBytes]byte
	if v == nil || v.handle == nil {
		return zero, errors.New("zknative: verifier is closed or nil")
	}
	if len(claimed) != PseudonymBytes {
		return zero, fmt.Errorf("zknative: the claimed pseudonym is %d bytes, not %d", len(claimed), PseudonymBytes)
	}
	if len(proof) == 0 {
		return zero, errors.New("zknative: proof must not be empty")
	}

	var a arena
	defer a.free()

	// Passed BY POINTER - every field must be C memory. See NewVerifier.
	cReq := C.NymAuthCRequest{
		issuer_key_x:     a.bytes(req.IssuerKeyX),
		issuer_key_y:     a.bytes(req.IssuerKeyY),
		time:             a.str(req.Time),
		earliest:         a.str(req.Earliest),
		cutoff:           a.str(req.Cutoff),
		challenge_digest: a.bytes(req.ChallengeDigest),
		verifier_input:   a.bytes(req.VerifierInput),
		transcript_seed:  a.bytes(req.TranscriptSeed),
	}

	var errOut *C.char
	status := C.nymauth_verify(v.handle, &cReq, goBytes(claimed), goBytes(proof), &errOut)
	// claimed and proof are passed by value as NymAuthBytes carrying
	// pointers into their Go backing arrays; keep both alive across the
	// (synchronous) call regardless of what the compiler can prove
	// about the raw pointers.
	runtime.KeepAlive(claimed)
	runtime.KeepAlive(proof)
	if status != 0 {
		return zero, statusError("nymauth_verify", status, errOut)
	}
	_ = takeErrorString(errOut)

	var out [PseudonymBytes]byte
	copy(out[:], claimed)
	return out, nil
}

// VerifierInput is nymauth_verifier_input: SHA-256 of the client id.
// Bound so the pure-Go derivation in pkg/nymauth/verifier can be
// checked against the library's, rather than only against a vector.
func VerifierInput(clientID string) ([PseudonymBytes]byte, error) {
	var out [PseudonymBytes]byte
	var a arena
	defer a.free()
	var errOut *C.char
	status := C.nymauth_verifier_input(a.str(clientID), (*C.uint8_t)(unsafe.Pointer(&out[0])), &errOut)
	if status != 0 {
		return [PseudonymBytes]byte{}, statusError("nymauth_verifier_input", status, errOut)
	}
	_ = takeErrorString(errOut)
	return out, nil
}

// DeriveChallenge is nymauth_derive_challenge: the SessionTranscript
// this session's origin, nonce and docType produce, and its e2. A nil
// jwkThumbprint means the request advertised no encryption key.
func DeriveChallenge(origin, nonce, docType string, jwkThumbprint []byte) ([]byte, [PseudonymBytes]byte, error) {
	var digest [PseudonymBytes]byte
	var a arena
	defer a.free()

	var transcript *C.uint8_t
	var transcriptLen C.size_t
	var errOut *C.char
	status := C.nymauth_derive_challenge(
		a.str(origin), a.str(nonce), a.str(docType), a.bytes(jwkThumbprint),
		&transcript, &transcriptLen,
		(*C.uint8_t)(unsafe.Pointer(&digest[0])),
		&errOut,
	)
	if status != 0 {
		return nil, [PseudonymBytes]byte{}, statusError("nymauth_derive_challenge", status, errOut)
	}
	_ = takeErrorString(errOut)
	defer C.nymauth_free_buffer(transcript, transcriptLen)
	return C.GoBytes(unsafe.Pointer(transcript), C.int(transcriptLen)), digest, nil
}

// ChallengeDigest is nymauth_challenge_digest: e2 for a transcript the
// caller already holds.
func ChallengeDigest(sessionTranscript []byte, docType string) ([PseudonymBytes]byte, error) {
	var digest [PseudonymBytes]byte
	var a arena
	defer a.free()
	var errOut *C.char
	status := C.nymauth_challenge_digest(
		a.bytes(sessionTranscript), a.str(docType),
		(*C.uint8_t)(unsafe.Pointer(&digest[0])), &errOut,
	)
	if status != 0 {
		return [PseudonymBytes]byte{}, statusError("nymauth_challenge_digest", status, errOut)
	}
	_ = takeErrorString(errOut)
	return digest, nil
}

// arena owns the C copies one call needs, so the whole set is released
// together. Required wherever a pointer ends up in a struct passed to C
// by pointer; see NewVerifier.
type arena struct {
	ptrs []unsafe.Pointer
}

func (a *arena) bytes(b []byte) C.NymAuthBytes {
	if len(b) == 0 {
		// The header allows a NULL ptr only when len is 0, which is how
		// "no value" is spelled - an absent JWK thumbprint, for one.
		return C.NymAuthBytes{}
	}
	p := C.CBytes(b)
	a.ptrs = append(a.ptrs, p)
	return C.NymAuthBytes{ptr: (*C.uint8_t)(p), len: C.size_t(len(b))}
}

// str copies a Go string as UTF-8 WITHOUT a NUL terminator, because
// every text field of this ABI is a counted NymAuthBytes rather than a
// C string.
func (a *arena) str(s string) C.NymAuthBytes {
	return a.bytes([]byte(s))
}

func (a *arena) free() {
	for _, p := range a.ptrs {
		C.free(p)
	}
	a.ptrs = nil
}

// goBytes points a NymAuthBytes at a Go slice's backing array. Only for
// values passed to C BY VALUE, and only with a runtime.KeepAlive of the
// slice across the call; use arena.bytes for anything that lands in a
// struct passed by pointer.
func goBytes(b []byte) C.NymAuthBytes {
	if len(b) == 0 {
		return C.NymAuthBytes{}
	}
	return C.NymAuthBytes{ptr: (*C.uint8_t)(unsafe.Pointer(&b[0])), len: C.size_t(len(b))}
}

// statusError names what the status code means, and carries the
// library's own message when it wrote one.
//
// The codes are worth naming because -5 is a verification that ran and
// came out false, while the rest are a request or an artifact this
// process got wrong - two very different things to log, alert on, or
// show a user.
func statusError(call string, status C.int32_t, errOut *C.char) error {
	return fmt.Errorf("zknative: %s: %s (status=%d): %s", call, statusMeaning(int32(status)), int32(status), takeErrorString(errOut))
}

func statusMeaning(status int32) string {
	switch status {
	case -1:
		return "invalid input"
	case -2:
		return "bad circuit"
	case -3:
		return "unsupported circuit"
	case -4:
		return "malformed credential"
	case -5:
		return "the statement is not satisfied"
	case -6:
		return "prover failure"
	case -7:
		return "proof refused"
	case -100:
		return "an internal panic was caught at the boundary"
	default:
		return "unknown status"
	}
}

// takeErrorString converts and frees an owned error string written into
// an error_out out-parameter, and is a no-op on nil.
func takeErrorString(ptr *C.char) string {
	if ptr == nil {
		return "(no message)"
	}
	msg := C.GoString(ptr)
	C.nymauth_free_error_string(ptr)
	return msg
}
