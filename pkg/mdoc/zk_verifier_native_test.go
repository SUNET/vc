//go:build zknative

package mdoc

import (
	"errors"
	"strings"
	"testing"
)

// assertZkPPIDPathOutcome checks TestZkHandler_VerifyAndExtract_PPIDPath's
// result for the "zknative" build: nativeVerifyZkProofWithPPID is real, so
// this fixture (a self-signed test cert, a bogus one-byte "proof", and a
// deliberate circuit/attribute-count mismatch - see that test's doc
// comment) must fail for a REAL reason, not the stub error - confirming
// the PPID branch is actually reached and actually attempts native
// verification under this build, rather than accidentally still returning
// ErrNativeZkVerifyNotImplemented.
func assertZkPPIDPathOutcome(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("VerifyAndExtract() expected an error for a bogus fixture under real native verification, got nil")
	}
	if errors.Is(err, ErrNativeZkVerifyNotImplemented) {
		t.Errorf("VerifyAndExtract() error should be a real verification failure under the zknative build, not the stub error: %v", err)
	}
	if !strings.Contains(err.Error(), "attribute") {
		t.Errorf("expected an attribute-count mismatch error (this fixture's circuit id is the 1-attribute circuit but discloses 2 attributes), got: %v", err)
	}
}
