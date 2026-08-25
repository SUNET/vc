package openid4vp

import (
	"reflect"
	"testing"
)

// TestCopyDCQL_PreservesClaimValues is a regression test for the bug where
// copyDCQL dropped ClaimQuery.Values when deep-copying a template's DCQL.
func TestCopyDCQL_PreservesClaimValues(t *testing.T) {
	strPtr := func(s string) *string { return &s }

	tests := []struct {
		name   string
		values []any
	}{
		{name: "nil values remains nil", values: nil},
		{name: "string values", values: []any{"DE", "SE", "FI"}},
		{name: "mixed types", values: []any{"foo", 42, true}},
		{name: "single value", values: []any{"only"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := &DCQL{
				Credentials: []CredentialQuery{
					{
						ID:     "cred1",
						Format: "vc+sd-jwt",
						Claims: []ClaimQuery{
							{
								ID:     "claim1",
								Path:   []*string{strPtr("nationality")},
								Values: tt.values,
							},
						},
					},
				},
			}

			dst := copyDCQL(src)
			if dst == nil {
				t.Fatal("copyDCQL returned nil")
			}
			if len(dst.Credentials) != 1 || len(dst.Credentials[0].Claims) != 1 {
				t.Fatalf("unexpected copy shape: %+v", dst)
			}

			gotValues := dst.Credentials[0].Claims[0].Values
			if !reflect.DeepEqual(gotValues, tt.values) {
				t.Errorf("Values mismatch: got %#v, want %#v", gotValues, tt.values)
			}
		})
	}
}

// TestCopyDCQL_ClaimValuesIsDeepCopy verifies that mutating the copied Values
// slice does not affect the source.
func TestCopyDCQL_ClaimValuesIsDeepCopy(t *testing.T) {
	strPtr := func(s string) *string { return &s }

	src := &DCQL{
		Credentials: []CredentialQuery{
			{
				ID:     "cred1",
				Format: "vc+sd-jwt",
				Claims: []ClaimQuery{
					{
						Path:   []*string{strPtr("nationality")},
						Values: []any{"DE", "SE"},
					},
				},
			},
		},
	}

	dst := copyDCQL(src)
	dst.Credentials[0].Claims[0].Values[0] = "MUTATED"

	if src.Credentials[0].Claims[0].Values[0] != "DE" {
		t.Errorf("source Values leaked mutation: got %v, want %q",
			src.Credentials[0].Claims[0].Values[0], "DE")
	}
}

// TestCopyDCQL_ValuesSurviveMarshal verifies that Values round-trip through
// JSON serialization after being copied.
func TestCopyDCQL_ValuesSurviveMarshal(t *testing.T) {
	strPtr := func(s string) *string { return &s }

	src := &DCQL{
		Credentials: []CredentialQuery{
			{
				ID:     "cred1",
				Format: "vc+sd-jwt",
				Claims: []ClaimQuery{
					{
						Path:   []*string{strPtr("nationality")},
						Values: []any{"DE", "SE"},
					},
				},
			},
		},
	}

	dst := copyDCQL(src)
	raw, err := dst.Credentials[0].Claims[0].MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	got := string(raw)
	want := `{"path":["nationality"],"values":["DE","SE"]}`
	if got != want {
		t.Errorf("marshaled ClaimQuery = %s, want %s", got, want)
	}
}
