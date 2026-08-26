//go:build bbsnative

// Package bbsnative is a cgo wrapper around zk-cred-bbs's plain C-ABI Go
// binding (src/go_ffi.rs / include/zk_cred_bbs_go.h in that crate). It is
// built only when the "bbsnative" build tag is set — see pkg/bbs for why,
// and the repository Makefile's `bbs-native-lib` target for how the
// library gets staged.
//
// Unlike zk-cred-longfellow's verifier binding, this exposes the ISSUER
// side too: an issuer offering BBS credentials must verify the holder's
// commitment and blind-sign it, and there is no pure-Go implementation of
// either.
//
// # Memory
//
// The C ABI has no handles — BBS has no proving key to load and no circuit
// to compile, so every call is bytes in, bytes out. The only owned
// allocations crossing back are the signature buffer and the error string,
// each freed here immediately after being copied into Go memory.
package bbsnative

/*
#cgo CFLAGS: -I${SRCDIR}/../../../third_party/zk-cred-bbs/include
#cgo LDFLAGS: -L${SRCDIR}/../../../third_party/zk-cred-bbs/lib -lzk_cred_bbs
#include <stdlib.h>
#include "zk_cred_bbs_go.h"
*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

// Backend is the cgo-backed implementation. Stateless; safe to share.
type Backend struct{}

// cBytes borrows a Go slice for the duration of one call. The Rust side
// never retains the pointer past the call, and runtime.KeepAlive on the
// caller's side keeps the backing array alive across it.
func cBytes(b []byte) (*C.uint8_t, C.size_t) {
	if len(b) == 0 {
		return nil, 0
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b))
}

// byteArrays copies a [][]byte into C memory as the (ptrs, lens, count)
// triple the ABI takes. Copying is required rather than merely tidy: Go
// pointers may not be stored in C-allocated memory.
func byteArrays(items [][]byte) (**C.uint8_t, *C.size_t, C.size_t, func()) {
	if len(items) == 0 {
		return nil, nil, 0, func() {}
	}
	ptrs := C.malloc(C.size_t(len(items)) * C.size_t(unsafe.Sizeof(uintptr(0))))
	lens := C.malloc(C.size_t(len(items)) * C.size_t(unsafe.Sizeof(C.size_t(0))))
	ptrSlice := unsafe.Slice((**C.uint8_t)(ptrs), len(items))
	lenSlice := unsafe.Slice((*C.size_t)(lens), len(items))
	copies := make([]unsafe.Pointer, len(items))
	for i, item := range items {
		if len(item) == 0 {
			// An empty message is legitimate (the reference vectors
			// include one), but it has no addressable first element.
			copies[i] = C.malloc(1)
			ptrSlice[i] = (*C.uint8_t)(copies[i])
			lenSlice[i] = 0
			continue
		}
		copies[i] = C.CBytes(item)
		ptrSlice[i] = (*C.uint8_t)(copies[i])
		lenSlice[i] = C.size_t(len(item))
	}
	return (**C.uint8_t)(ptrs), (*C.size_t)(lens), C.size_t(len(items)), func() {
		for _, p := range copies {
			C.free(p)
		}
		C.free(ptrs)
		C.free(lens)
	}
}

// takeError consumes an owned error string from the ABI.
func takeError(p *C.char) string {
	if p == nil {
		return ""
	}
	msg := C.GoString(p)
	C.zk_cred_bbs_free_error_string(p)
	return msg
}

// BlindSign implements the issuer half. See bbs.BlindSigner.
func (Backend) BlindSign(suite uint32, secretKey, publicKey, commitment, header []byte, messages [][]byte) ([]byte, int32, string) {
	msgPtrs, msgLens, msgCount, free := byteArrays(messages)
	defer free()

	skPtr, skLen := cBytes(secretKey)
	pkPtr, pkLen := cBytes(publicKey)
	comPtr, comLen := cBytes(commitment)
	hdrPtr, hdrLen := cBytes(header)

	var sigOut *C.uint8_t
	var sigLen C.size_t
	var errOut *C.char

	status := C.zk_cred_bbs_blind_sign(
		C.uint32_t(suite),
		skPtr, skLen, pkPtr, pkLen, comPtr, comLen, hdrPtr, hdrLen,
		msgPtrs, msgLens, msgCount,
		&sigOut, &sigLen, &errOut,
	)
	runtime.KeepAlive(secretKey)
	runtime.KeepAlive(publicKey)
	runtime.KeepAlive(commitment)
	runtime.KeepAlive(header)

	if status != C.ZK_CRED_BBS_OK {
		return nil, int32(status), takeError(errOut)
	}
	takeError(errOut)
	sig := C.GoBytes(unsafe.Pointer(sigOut), C.int(sigLen))
	C.zk_cred_bbs_free_buffer(sigOut, sigLen)
	return sig, int32(status), ""
}

// VerifyProof implements the verifier half. See bbs.ProofVerifier.
func (Backend) VerifyProof(suite uint32, publicKey, proof, header, presentationHeader []byte,
	issuerKnownMessages int, disclosedMessages [][]byte, disclosures []byte) (int32, string) {

	discPtrs, discLens, discCount, free := byteArrays(disclosedMessages)
	defer free()

	pkPtr, pkLen := cBytes(publicKey)
	prPtr, prLen := cBytes(proof)
	hdrPtr, hdrLen := cBytes(header)
	phPtr, phLen := cBytes(presentationHeader)
	codePtr, codeLen := cBytes(disclosures)

	var errOut *C.char
	status := C.zk_cred_bbs_blind_proof_verify(
		C.uint32_t(suite),
		pkPtr, pkLen, prPtr, prLen, hdrPtr, hdrLen, phPtr, phLen,
		C.size_t(issuerKnownMessages),
		discPtrs, discLens, discCount,
		codePtr, codeLen,
		&errOut,
	)
	runtime.KeepAlive(publicKey)
	runtime.KeepAlive(proof)
	runtime.KeepAlive(header)
	runtime.KeepAlive(presentationHeader)
	runtime.KeepAlive(disclosures)

	return int32(status), takeError(errOut)
}

// StatusPanic is the ABI's "a panic was caught crossing the boundary"
// code. Exposed so the wrapping package can distinguish it from an
// ordinary verification failure without duplicating the constant.
const StatusPanic int32 = C.ZK_CRED_BBS_PANIC

// StatusOK is the ABI's success code.
const StatusOK int32 = C.ZK_CRED_BBS_OK

// Describe renders a non-OK status for logs.
func Describe(status int32, msg string) string {
	if msg == "" {
		msg = "unknown error"
	}
	if status == StatusPanic {
		return fmt.Sprintf("panic across FFI boundary: %s", msg)
	}
	return msg
}
