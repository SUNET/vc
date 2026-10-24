//go:build zknative

// Package zknative_vega is a cgo wrapper around zk-cred-vega's plain
// C-ABI nym_auth verifier (src/nymauth_go_ffi.rs /
// include/zk_cred_vega_nymauth_go.h in that crate). It is the Vega
// counterpart of pkg/nymauth/verifier/zknative, which wraps
// zk-cred-longfellow's nym_auth ABI instead.
//
// Two packages rather than one, for the same reason the mdoc path has
// two: they are different headers and different shared libraries, with
// different load shapes. Longfellow loads a circuit artifact plus four
// Ligero parameters; Vega loads R1CS SHAPES and derives its verifier
// key from them, which is why this one takes no parameters at all.
//
// Built only when the "zknative" Go build tag is set, same convention
// as every other cgo package here: the default vc-verifier build is
// CGO_ENABLED=0 and fully static.
//
// This package deliberately does NOT import pkg/nymauth/verifier: that
// package imports this one under the build tag, and the dependency has
// to run one way. Its arguments are therefore flat bytes and strings.
//
// Setup: `make zk-native-lib-vega` at the repo root stages the shared
// library and BOTH headers under third_party/zk-cred-vega/; then build
// or test with `-tags zknative` and LD_LIBRARY_PATH pointing at that
// lib directory.
//
// # What this does not wrap
//
// The ABI also offers zk_cred_vega_nymauth_verifier_input(), which
// computes SHA-256(client_id). That is NOT this Verifier's
// verifier_input: rulebook v0.4 hashes the configured verifier_id with
// its prefix ("x509_san_dns:" or "semantic_id:"), and vc computes it in
// pkg/nymauth. Wrapping the ABI's helper would offer a second, wrong
// answer to a question that already has one, so it is left alone - as
// are prove() and derive_challenge(), which belong to a prover and to
// pkg/nymauth/verifier/challenge.go respectively.
package zknative_vega

/*
#cgo CFLAGS: -I${SRCDIR}/../../../../third_party/zk-cred-vega/include
#cgo LDFLAGS: -L${SRCDIR}/../../../../third_party/zk-cred-vega/lib -lzk_cred_vega
#include <stdlib.h>
#include "zk_cred_vega_nymauth_go.h"
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

// The ABI's own argument caps (src/nymauth_go_ffi.rs). Checked here,
// before anything is copied into C memory, so an oversized argument is
// named rather than returned as a generic invalid-argument status.
const (
	MaxShapes = 64 << 20
	MaxProof  = 512<<10 + 1
	maxSmall  = 4096
)

// ErrClosed is a call on a verifier whose keys have been released.
var ErrClosed = errors.New("nymauth/vega: the verifier is closed")

// Statement is ZkNymStatement: the values the VERIFIER names.
//
// Every one of them is this verifier's own. Time comes from the
// presentation's proof_time only after the acceptance window has
// approved it; the rest never touch the holder's response at all.
// Taking any of them from the response would let the holder choose
// what it is proving.
type Statement struct {
	// IssuerKeyX and IssuerKeyY are the issuer's P-256 public key
	// coordinates, 32 bytes each, big-endian.
	IssuerKeyX, IssuerKeyY []byte

	// Time is T as the circuits write it: YYYY-MM-DDThh:mm:ssZ, 20
	// ASCII bytes.
	Time string

	// Earliest and Cutoff are the age window's birth-date bounds,
	// YYYY-MM-DD, with "0000-00-00" and "9999-12-31" disabling them.
	Earliest, Cutoff string

	// ChallengeDigest is e2 and VerifierInput is SHA-256 of the
	// configured verifier_id, 32 bytes each.
	ChallengeDigest []byte
	VerifierInput   []byte
}

// Verifier holds the keys derived from one circuit's shapes.
//
// Deriving them is the expensive step - roughly 12.5 MB of verifier key
// built from the shapes, a few hundred milliseconds - so a caller keeps
// one and reuses it rather than loading per proof.
type Verifier struct {
	// mu guards keys against a Close that races a Verify. The native
	// side has its own RWMutex, but a handle freed between our nil
	// check and the call would be a cgo use-after-free on this side,
	// which no lock over there can prevent.
	mu   sync.RWMutex
	keys *C.ZkNymKeys
}

// NewVerifier derives the verifier keys from DECOMPRESSED R1CS shapes.
//
// The shapes are the artifact the allowlist pinned by length and
// SHA-256, so by the time they arrive here they are the operator's
// approved bytes; the ABI refuses any shapes that are not an approved
// circuit with ZK_NYM_UNKNOWN_CIRCUIT.
func NewVerifier(shapes []byte) (*Verifier, error) {
	if len(shapes) == 0 {
		return nil, fmt.Errorf("nymauth/vega: no circuit shapes")
	}
	if len(shapes) > MaxShapes {
		return nil, fmt.Errorf("nymauth/vega: the circuit shapes are %d bytes; this ABI takes at most %d", len(shapes), MaxShapes)
	}

	var keys *C.ZkNymKeys
	status := C.zk_cred_vega_nymauth_load_keys(
		(*C.uint8_t)(unsafe.Pointer(&shapes[0])),
		C.size_t(len(shapes)),
		&keys,
	)
	runtime.KeepAlive(shapes)
	if err := statusError(status, "deriving the verifier keys from the circuit shapes"); err != nil {
		return nil, err
	}
	if keys == nil {
		// The ABI documents *keys_out as null on failure, so a null
		// handle with an OK status is a contract this build cannot
		// rely on. Refused rather than stored: every later Verify
		// would dereference it.
		return nil, fmt.Errorf("nymauth/vega: the library reported success but produced no keys")
	}
	return &Verifier{keys: keys}, nil
}

// Close releases the keys. Safe to call twice.
func (v *Verifier) Close() error {
	if v == nil {
		return nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.keys != nil {
		C.zk_cred_vega_nymauth_free_keys(v.keys)
		v.keys = nil
	}
	return nil
}

// Verify checks proof against the statement and returns the pseudonym
// the proof reveals.
//
// Callers must use the RETURNED pseudonym and never one that arrived in
// the holder's response. The two are equal whenever this returns nil,
// but the claimed value is the holder's until a proof has been checked
// against it, and this return is the only place that has happened.
//
// Unlike the Longfellow ABI this one takes no claimed pseudonym to
// compare against: it REVEALS the pseudonym, and comparing it with
// what the holder claimed is the caller's job.
func (v *Verifier) Verify(statement Statement, proof []byte) ([PseudonymBytes]byte, error) {
	var out [PseudonymBytes]byte

	if v == nil {
		return out, ErrClosed
	}
	if len(proof) == 0 {
		return out, fmt.Errorf("nymauth/vega: no proof")
	}
	if len(proof) > MaxProof {
		return out, fmt.Errorf("nymauth/vega: the proof is %d bytes; this ABI takes at most %d", len(proof), MaxProof)
	}
	if err := statement.check(); err != nil {
		return out, err
	}

	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.keys == nil {
		return out, ErrClosed
	}

	var arena arena
	defer arena.free()
	c := C.ZkNymStatement{
		issuer_key_x:     arena.bytes(statement.IssuerKeyX),
		issuer_key_y:     arena.bytes(statement.IssuerKeyY),
		time:             arena.str(statement.Time),
		earliest:         arena.str(statement.Earliest),
		cutoff:           arena.str(statement.Cutoff),
		challenge_digest: arena.bytes(statement.ChallengeDigest),
		verifier_input:   arena.bytes(statement.VerifierInput),
	}
	proofSlice := arena.bytes(proof)

	status := C.zk_cred_vega_nymauth_verify(
		v.keys,
		&c,
		proofSlice.ptr,
		proofSlice.len,
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
	)
	runtime.KeepAlive(v)
	if err := statusError(status, "verifying the proof"); err != nil {
		return [PseudonymBytes]byte{}, err
	}
	return out, nil
}

// check refuses a statement the ABI would reject, while the field that
// is wrong can still be named.
func (s Statement) check() error {
	for _, f := range []struct {
		name  string
		value []byte
		want  int
	}{
		{"issuer_key_x", s.IssuerKeyX, 32},
		{"issuer_key_y", s.IssuerKeyY, 32},
		{"challenge_digest", s.ChallengeDigest, PseudonymBytes},
		{"verifier_input", s.VerifierInput, PseudonymBytes},
	} {
		if len(f.value) != f.want {
			return fmt.Errorf("nymauth/vega: %s is %d bytes, not %d", f.name, len(f.value), f.want)
		}
	}
	for _, f := range []struct{ name, value string }{
		{"time", s.Time},
		{"earliest", s.Earliest},
		{"cutoff", s.Cutoff},
	} {
		if f.value == "" {
			return fmt.Errorf("nymauth/vega: %s is empty", f.name)
		}
		if len(f.value) > maxSmall {
			return fmt.Errorf("nymauth/vega: %s is %d bytes; this ABI takes at most %d", f.name, len(f.value), maxSmall)
		}
	}
	return nil
}

// Status is a ZK_NYM_* code of the C ABI.
type Status int32

// The statuses this verifier can see. The prove-only refusals
// (ZK_NYM_REFUSED_*) are included because the ABI shares one status
// enum, and a verifier that printed an unknown number would be less
// useful than one that names the code it got.
const (
	StatusOK                     Status = C.ZK_NYM_OK
	StatusInvalidArg             Status = C.ZK_NYM_INVALID_ARG
	StatusInvalidInput           Status = C.ZK_NYM_INVALID_INPUT
	StatusInvalidShapes          Status = C.ZK_NYM_INVALID_SHAPES
	StatusUnknownCircuit         Status = C.ZK_NYM_UNKNOWN_CIRCUIT
	StatusProverFailed           Status = C.ZK_NYM_PROVER_FAILED
	StatusProofInvalid           Status = C.ZK_NYM_PROOF_INVALID
	StatusMismatch               Status = C.ZK_NYM_MISMATCH
	StatusInternal               Status = C.ZK_NYM_INTERNAL
	StatusRefusedSeedMismatch    Status = C.ZK_NYM_REFUSED_SEED_MISMATCH
	StatusRefusedIssuerSignature Status = C.ZK_NYM_REFUSED_ISSUER_SIGNATURE
	StatusRefusedDeviceSignature Status = C.ZK_NYM_REFUSED_DEVICE_SIGNATURE
	StatusRefusedCredential      Status = C.ZK_NYM_REFUSED_CREDENTIAL
)

// Error is a non-OK status, carrying the code so a caller can tell a
// refused proof from a broken circuit without parsing a string.
type Error struct {
	Status Status
	During string
}

func (e *Error) Error() string {
	return fmt.Sprintf("nymauth/vega: %s: %s (status %d)", e.During, e.Status.describe(), int32(e.Status))
}

// StatusOf returns the ABI status behind err, or StatusInternal for an
// error that did not come from the library.
func StatusOf(err error) Status {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return StatusInternal
}

func (s Status) describe() string {
	switch s {
	case StatusOK:
		return "accepted"
	case StatusInvalidArg:
		return "an argument was null or past its cap"
	case StatusInvalidInput:
		return "a value was malformed - a range, an issuer key, or the proof's framing"
	case StatusInvalidShapes:
		return "the circuit shapes could not be parsed"
	case StatusUnknownCircuit:
		return "the circuit shapes are not an approved circuit"
	case StatusProverFailed:
		return "the prover failed"
	case StatusProofInvalid:
		return "the proof is not valid"
	case StatusMismatch:
		return "the proof verifies, but not for the values this verifier named"
	case StatusInternal:
		return "the library panicked"
	case StatusRefusedSeedMismatch:
		return "the secret seed does not open the credential's ssc"
	case StatusRefusedIssuerSignature:
		return "the issuer signature was refused"
	case StatusRefusedDeviceSignature:
		return "the device signature was refused"
	case StatusRefusedCredential:
		return "the credential was refused"
	default:
		return "an unrecognised status"
	}
}

func statusError(status C.int32_t, during string) error {
	if Status(status) == StatusOK {
		return nil
	}
	return &Error{Status: Status(status), During: during}
}

// arena copies Go bytes into C memory for the duration of one call.
//
// Copied rather than pinned because cgo forbids passing a Go pointer
// that itself holds Go pointers, and ZkNymStatement is seven slices at
// once; one free list is simpler to get right than seven pin lifetimes.
type arena struct{ allocated []unsafe.Pointer }

func (a *arena) bytes(b []byte) C.ZkNymSlice {
	if len(b) == 0 {
		return C.ZkNymSlice{}
	}
	p := C.CBytes(b)
	a.allocated = append(a.allocated, p)
	return C.ZkNymSlice{ptr: (*C.uint8_t)(p), len: C.size_t(len(b))}
}

func (a *arena) str(s string) C.ZkNymSlice { return a.bytes([]byte(s)) }

func (a *arena) free() {
	for _, p := range a.allocated {
		C.free(p)
	}
	a.allocated = nil
}
