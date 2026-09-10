package helpers

import (
	"errors"
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/go-playground/validator/v10"
)

// TestIssuancePolicyQueryTemplate pins the reserved and duplicate dimension
// rules. Both produce a rule shape no rule can match, which presents as a
// blanket issuance deny with nothing in the config looking wrong.
func TestIssuancePolicyQueryTemplate(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}

	dim := func(d, c string) model.QueryDimension { return model.QueryDimension{Dimension: d, Claim: c} }

	for _, tc := range []struct {
		name    string
		tmpl    []model.QueryDimension
		wantTag string
	}{
		{
			name:    "scope is reserved and auto-populated",
			tmpl:    []model.QueryDimension{dim("scope", "sub"), dim("acr", "acr")},
			wantTag: "query_template_scope_is_reserved",
		},
		{
			name:    "a repeated dimension is rejected",
			tmpl:    []model.QueryDimension{dim("acr", "acr"), dim("acr", "amr")},
			wantTag: "query_template_duplicate_dimension",
		},
		{
			name:    "an empty dimension name is rejected",
			tmpl:    []model.QueryDimension{dim("", "acr")},
			wantTag: "required",
		},
		{
			name:    "a dimension with no claim is rejected",
			tmpl:    []model.QueryDimension{dim("acr", "")},
			wantTag: "required",
		},
		{
			name: "a well-formed template is accepted",
			tmpl: []model.QueryDimension{dim("acr", "acr"), dim("org_id", "organization_id")},
		},
		{
			// The claim-driven mode: dimensions are not statically known.
			name: "an absent template is accepted",
			tmpl: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Struct(model.IssuancePolicy{QueryTemplate: tc.tmpl})
			if tc.wantTag == "" {
				if err != nil {
					t.Fatalf("expected acceptance, got: %v", err)
				}
				return
			}
			var verrs validator.ValidationErrors
			if !errors.As(err, &verrs) {
				t.Fatalf("expected validation errors, got %T: %v", err, err)
			}
			for _, ve := range verrs {
				if ve.Tag() == tc.wantTag {
					return
				}
			}
			t.Fatalf("expected a %q failure, got: %v", tc.wantTag, err)
		})
	}
}
