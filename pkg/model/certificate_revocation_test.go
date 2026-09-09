package model

import (
	"errors"
	"testing"

	"github.com/SUNET/vc/pkg/revocation"
	"github.com/sirosfoundation/go-trust/pkg/registry/rpcert"
	"github.com/stretchr/testify/assert"
)

func result(s revocation.Status) *revocation.CheckResult {
	return &revocation.CheckResult{Status: s}
}

// TestRevocationCheck_Evaluate is the table that matters: the difference
// between "revoked" and "could not determine", and the fact that warn
// proceeds while still reporting.
func TestRevocationCheck_Evaluate(t *testing.T) {
	tests := []struct {
		name        string
		mode        string
		result      *revocation.CheckResult
		err         error
		wantAllowed bool
		wantReason  bool
	}{
		{"warn: valid passes silently", "warn", result(revocation.StatusValid), nil, true, false},
		{"warn: revoked proceeds but reports", "warn", result(revocation.StatusInvalid), nil, true, true},
		{"warn: unreachable proceeds but reports", "warn", nil, errors.New("dial failed"), true, true},

		{"fail: valid passes", "fail", result(revocation.StatusValid), nil, true, false},
		{"fail: revoked stops", "fail", result(revocation.StatusInvalid), nil, false, true},
		{"fail: unreachable stops", "fail", nil, errors.New("dial failed"), false, true},

		{"off: revoked ignored", "off", result(revocation.StatusInvalid), nil, true, false},
		{"off: unreachable ignored", "off", nil, errors.New("dial failed"), true, false},

		// A typo must not silently disable the check.
		{"unrecognised mode behaves as warn", "wran", result(revocation.StatusInvalid), nil, true, true},
		// Unset defaults to warn.
		{"empty mode behaves as warn", "", result(revocation.StatusInvalid), nil, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := (&RevocationCheck{Mode: tt.mode}).Evaluate(tt.result, tt.err, "the access certificate")
			assert.Equal(t, tt.wantAllowed, d.Allowed)
			assert.Equal(t, tt.wantReason, d.Reason != "")
		})
	}
}

// TestRevocationCheck_SuspendedIsNotGood pins that a suspended certificate is
// not treated as valid. The authority has said something about it - just not
// that it is good.
func TestRevocationCheck_SuspendedIsNotGood(t *testing.T) {
	d := (&RevocationCheck{Mode: "fail"}).Evaluate(result(revocation.StatusSuspended), nil, "cert")
	assert.False(t, d.Allowed)
}

// TestRevocationCheck_UnknownIsNotAPass is the property the whole design
// turns on: an unreachable responder must never read as valid.
func TestRevocationCheck_UnknownIsNotAPass(t *testing.T) {
	d := (&RevocationCheck{Mode: "warn"}).Evaluate(result(revocation.StatusUnknown), nil, "cert")
	assert.True(t, d.Allowed, "warn proceeds")
	assert.NotEqual(t, rpcert.RevocationGood, d.State, "but not by calling it good")
	assert.Contains(t, d.Reason, "not evidence that it is valid")
}

func TestRevocationCheck_Enabled(t *testing.T) {
	var unset *RevocationCheck
	assert.False(t, unset.Enabled(), "no block configured means no check")
	assert.True(t, (&RevocationCheck{}).Enabled(), "an empty block defaults to warn")
	assert.True(t, (&RevocationCheck{Mode: "fail"}).Enabled())
	assert.False(t, (&RevocationCheck{Mode: "off"}).Enabled())
}
