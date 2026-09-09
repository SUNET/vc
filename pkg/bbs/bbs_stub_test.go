//go:build !bbsnative

package bbs

import (
	"errors"
	"testing"
)

// The default build must fail loudly rather than silently accepting
// anything. A stub that returned nil from VerifyProof would be a
// catastrophic default, so it is worth an explicit test.
func TestWithoutTagEverythingIsUnavailable(t *testing.T) {
	if Available() {
		t.Fatal("Available() must be false without the bbsnative tag")
	}
	n := Native()

	if _, err := n.BlindSign(SuiteSchnorr, nil, nil, nil, nil, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("BlindSign: want ErrUnavailable, got %v", err)
	}
	if err := n.VerifyProof(SuiteSchnorr, nil, nil, nil, nil, 0, nil, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("VerifyProof: want ErrUnavailable, got %v", err)
	}
	if _, err := n.Issue(IssueParams{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Issue: want ErrUnavailable, got %v", err)
	}
	if _, err := n.VerifyPresentation(SuiteSchnorr, "", nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("VerifyPresentation: want ErrUnavailable, got %v", err)
	}
}
