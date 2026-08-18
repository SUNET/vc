//go:build zknative

// Package zknative is a cgo wrapper around zk-cred-longfellow's plain
// C-ABI Go verifier binding (src/go_ffi.rs / include/zk_cred_longfellow_go.h
// in that crate). It is built only when the "zknative" Go build tag is set
// (see pkg/mdoc/zk_native_cgo.go, the sole consumer within this repo, and
// this repo's Makefile targets `zk-native-lib`/`build-verifier-zknative`).
//
// This tag-gating exists because cgo requires CGO_ENABLED=1 and a C
// compiler/linker able to find the compiled zk-cred-longfellow shared
// library - the default vc-verifier build (CGO_ENABLED=0, fully static)
// must keep working without any of that, exactly like this repo's existing
// PKCS#11 support (pkg/pki/pkcs11.go, build tag "pkcs11") is opt-in for the
// same reason.
//
// Setup: run `make zk-native-lib` at the repo root (clones/builds
// zk-cred-longfellow's `go-cabi` target and stages the shared library +
// header under third_party/zk-cred-longfellow/), then build/test with
// `-tags zknative` and CGO_CFLAGS/CGO_LDFLAGS pointing at that directory -
// see the Makefile's `build-verifier-zknative` target for the exact
// invocation, and README.md's "Native ZK/PPID proof verification" section.
package zknative

/*
#cgo CFLAGS: -I${SRCDIR}/../../../third_party/zk-cred-longfellow/include
#cgo LDFLAGS: -L${SRCDIR}/../../../third_party/zk-cred-longfellow/lib -lzk_cred_longfellow
#include <stdlib.h>
#include "zk_cred_longfellow_go.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// Attribute is one disclosed claim: an element identifier and its
// CBOR-encoded value. Mirrors zk-cred-longfellow's CAttribute (and, one
// level up, its Rust Attribute type).
type Attribute struct {
	Identifier string
	ValueCBOR  []byte
}

// Verifier wraps an opaque, loaded/compiled zk-cred-longfellow circuit
// handle (C.MdocZkVerifier). Loading a circuit is expensive - construct
// one Verifier per distinct circuit (via NewVerifier) and reuse it across
// many VerifyWithPPID calls (safe to call concurrently from multiple
// goroutines: the underlying Rust type holds no interior mutability and
// every verify method takes a shared reference), rather than
// reconstructing it per verification. Callers needing that reuse across a
// whole process should keep a cache keyed by circuit identity (e.g. its
// catalog circuit_hash) - see pkg/mdoc/zk_native_cgo.go's cache for exactly
// that.
type Verifier struct {
	handle *C.MdocZkVerifier
}

// NewVerifier loads and compiles a circuit, returning a reusable Verifier.
//
// circuit must be the DECOMPRESSED circuit file bytes (zstd-decompress
// first if fetched from the zk-circuits catalog service - see
// pkg/mdoc/zkcircuit.Client.DownloadAndDecompress). version must be 6, 7,
// or 8; numAttributes must match exactly what every later VerifyWithPPID
// call using the returned Verifier will pass.
func NewVerifier(circuit []byte, version uint8, numAttributes uint8) (*Verifier, error) {
	if len(circuit) == 0 {
		return nil, errors.New("zknative: circuit must not be empty")
	}

	circuitPtr, circuitLen := bytesPtr(circuit)
	var errOut *C.char
	handle := C.rust_initialize_verifier(circuitPtr, circuitLen, C.uint8_t(version), C.uint8_t(numAttributes), &errOut)
	if handle == nil {
		return nil, fmt.Errorf("zknative: rust_initialize_verifier: %s", takeErrorString(errOut))
	}
	return &Verifier{handle: handle}, nil
}

// Close releases the underlying circuit handle. Not safe to call
// concurrently with an in-flight VerifyWithPPID call using the same
// Verifier, and not safe to call more than once.
func (v *Verifier) Close() error {
	if v == nil || v.handle == nil {
		return nil
	}
	C.rust_free_verifier(v.handle)
	v.handle = nil
	return nil
}

// VerifyWithPPIDArgs bundles rust_verify_with_ppid's real argument list.
type VerifyWithPPIDArgs struct {
	// IssuerPublicKeySEC1 is the issuer's EC public key, SEC1-encoded (as
	// found in the X.509 SubjectPublicKeyInfo).
	IssuerPublicKeySEC1 []byte
	// Attributes are the disclosed claims; the count must match the
	// numAttributes this Verifier was constructed with.
	Attributes []Attribute
	// DocType is the mdoc document type (e.g. "org.iso.18013.5.1.mDL").
	DocType string
	// DeviceNameSpacesBytes is the CBOR-encoded DeviceNameSpacesBytes from
	// the DeviceResponse (may be an empty CBOR map, e.g. 0xA0).
	DeviceNameSpacesBytes []byte
	// SessionTranscript is the CBOR-encoded ISO 18013-5 SessionTranscript.
	SessionTranscript []byte
	// Time is the current time, RFC 3339 format.
	Time string
	// VerifierContext is the 32-byte pseudonym-derivation context (see
	// pkg/mdoc.ComputeZkVerifierContext). Must be exactly 32 bytes.
	VerifierContext []byte
	// Proof is the serialized ZK proof bytes.
	Proof []byte
}

// VerifyWithPPID verifies a V8 proof of possession with pairwise-pseudonym
// (PPID) support, via zk-cred-longfellow's rust_verify_with_ppid. Returns
// nil on success, or an error carrying the real underlying error message on
// failure (a rejected/tampered proof, a wrong attribute count, etc. - not
// just a bare status code).
//
// This performs the crate's real cryptographic verification (transcript
// replay, Sumcheck, Ligero, MAC tag checks, PPID derivation) - it is a thin
// cgo marshaling wrapper, not a separate/weaker check.
func (v *Verifier) VerifyWithPPID(args VerifyWithPPIDArgs) error {
	if v == nil || v.handle == nil {
		return errors.New("zknative: verifier is closed or nil")
	}
	if len(args.VerifierContext) != 32 {
		return fmt.Errorf("zknative: verifier_context must be exactly 32 bytes, got %d", len(args.VerifierContext))
	}

	cDocType := C.CString(args.DocType)
	defer C.free(unsafe.Pointer(cDocType))
	cTime := C.CString(args.Time)
	defer C.free(unsafe.Pointer(cTime))

	// Per-attribute identifier/value pointers must be C-allocated copies:
	// cgo forbids a Go pointer (into a Go byte slice) being stored as a
	// FIELD of a struct (CAttribute.value_cbor) that is itself passed to C
	// by pointer, since the struct array's backing memory would then
	// contain a Go pointer. See zk-cred-longfellow's go-cabi-smoketest
	// (cBytesCopy's doc comment) for the same rule, confirmed against a
	// real cgo build.
	cAttrs := make([]C.CAttribute, len(args.Attributes))
	var toFree []unsafe.Pointer
	defer func() {
		for _, p := range toFree {
			C.free(p)
		}
	}()
	for i, attr := range args.Attributes {
		cID := C.CString(attr.Identifier)
		toFree = append(toFree, unsafe.Pointer(cID))
		valPtr, valLen := cBytesCopy(attr.ValueCBOR)
		if valPtr != nil {
			toFree = append(toFree, unsafe.Pointer(valPtr))
		}
		cAttrs[i] = C.CAttribute{
			identifier:     cID,
			value_cbor:     valPtr,
			value_cbor_len: valLen,
		}
	}
	var attrsPtr *C.CAttribute
	if len(cAttrs) > 0 {
		attrsPtr = &cAttrs[0]
	}

	issuerPtr, issuerLen := bytesPtr(args.IssuerPublicKeySEC1)
	dnsPtr, dnsLen := bytesPtr(args.DeviceNameSpacesBytes)
	transcriptPtr, transcriptLen := bytesPtr(args.SessionTranscript)
	vcPtr, vcLen := bytesPtr(args.VerifierContext)
	proofPtr, proofLen := bytesPtr(args.Proof)

	var errOut *C.char
	status := C.rust_verify_with_ppid(
		v.handle,
		issuerPtr, issuerLen,
		attrsPtr, C.size_t(len(cAttrs)),
		cDocType,
		dnsPtr, dnsLen,
		transcriptPtr, transcriptLen,
		cTime,
		vcPtr, vcLen,
		proofPtr, proofLen,
		&errOut,
	)
	if status != 0 {
		return fmt.Errorf("zknative: rust_verify_with_ppid failed (status=%d): %s", int32(status), takeErrorString(errOut))
	}
	return nil
}

// bytesPtr returns a pointer to the first byte of b and its length, or
// (nil, 0) for an empty slice. Only safe for pointers passed directly as
// top-level cgo call arguments (not stored inside a struct field that is
// itself passed by pointer) - see cBytesCopy for that case.
func bytesPtr(b []byte) (*C.uint8_t, C.size_t) {
	if len(b) == 0 {
		return nil, 0
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b))
}

// cBytesCopy copies b into newly C-allocated memory and returns a pointer
// into that copy plus its length, or (nil, 0) for an empty slice. The
// caller must C.free the returned pointer once no longer needed. Required
// wherever the pointer will be stored as a struct field passed to C by
// pointer (see VerifyWithPPID's CAttribute construction).
func cBytesCopy(b []byte) (*C.uint8_t, C.size_t) {
	if len(b) == 0 {
		return nil, 0
	}
	return (*C.uint8_t)(C.CBytes(b)), C.size_t(len(b))
}

// takeErrorString converts and frees an owned error string written into an
// error_out out-parameter by zk-cred-longfellow's C ABI, returning
// "(no message)" if ptr is nil.
func takeErrorString(ptr *C.char) string {
	if ptr == nil {
		return "(no message)"
	}
	msg := C.GoString(ptr)
	C.rust_free_error_string(ptr)
	return msg
}
