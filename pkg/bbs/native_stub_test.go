//go:build !bbsnative

package bbs

import (
	"errors"
	"testing"
)

func TestNativeStubReturnsErrNotBuilt(t *testing.T) {
	n := Native()

	tests := []struct {
		name string
		call func() error
	}{
		{"BlindSign", func() error {
			_, err := n.BlindSign(SuitePlain, nil, nil, nil, nil, nil)
			return err
		}},
		{"VerifyProof", func() error {
			return n.VerifyProof(SuitePlain, nil, nil, nil, nil, 0, nil, nil)
		}},
		{"Issue", func() error {
			_, err := n.Issue(IssueParams{})
			return err
		}},
		{"SkToPk", func() error {
			_, err := n.SkToPk(nil)
			return err
		}},
		{"VerifyPresentation", func() error {
			_, err := n.VerifyPresentation(SuitePlain, "", nil)
			return err
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); !errors.Is(err, ErrNotBuilt) {
				t.Fatalf("err = %v, want ErrNotBuilt", err)
			}
		})
	}
}
