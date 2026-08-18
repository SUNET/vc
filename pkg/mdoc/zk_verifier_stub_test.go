//go:build !zknative

package mdoc

import (
	"errors"
	"testing"
)

// assertZkPPIDPathOutcome checks TestZkHandler_VerifyAndExtract_PPIDPath's
// result for the default (no "zknative" tag) build: nativeVerifyZkProofWithPPID
// is a stub, so the ONLY thing stopping full verification is the
// native-binding gap.
func assertZkPPIDPathOutcome(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrNativeZkVerifyNotImplemented) {
		t.Errorf("VerifyAndExtract() error = %v, want ErrNativeZkVerifyNotImplemented", err)
	}
}
