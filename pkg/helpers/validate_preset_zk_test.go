package helpers

import (
	"errors"
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/go-playground/validator/v10"
)

// TestVerificationPresetScopeZKSystemType pins the "mso_mdoc_zk needs a
// zk_system_type" rule that VerificationPresetScope.ZKSystemType's doc
// comment has always claimed.
//
// Without it the failure surfaced much later, as a DCQL query carrying a ZK
// format and no system type - which a wallet reads as "no ZK system offered",
// indistinguishable from a wallet that cannot do ZK at all.
func TestVerificationPresetScopeZKSystemType(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}

	spec := []openid4vp.ZKSystemTypeSpec{{ID: "vega-mc-p256-v1-r12", System: "vega-mc-p256-v1"}}

	for _, tc := range []struct {
		name    string
		scope   model.VerificationPresetScope
		wantTag string
	}{
		{
			name:    "zk format without a system type is rejected",
			scope:   model.VerificationPresetScope{Format: openid4vp.FormatMsoMdocZk},
			wantTag: "zk_system_type_required_for_mso_mdoc_zk",
		},
		{
			// Inert rather than wrong-but-applied: a zk_system_type only
			// reaches the query through the ZK format.
			name:    "system type without the zk format is rejected",
			scope:   model.VerificationPresetScope{ZKSystemType: spec},
			wantTag: "zk_system_type_requires_mso_mdoc_zk_format",
		},
		{
			name:  "zk format with a system type is accepted",
			scope: model.VerificationPresetScope{Format: openid4vp.FormatMsoMdocZk, ZKSystemType: spec},
		},
		{
			name:  "neither is accepted - the override is optional",
			scope: model.VerificationPresetScope{},
		},
		{
			name:  "a non-ZK format override needs no system type",
			scope: model.VerificationPresetScope{Format: "mso_mdoc"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Struct(tc.scope)
			if tc.wantTag == "" {
				if err != nil {
					t.Fatalf("expected acceptance, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected rejection")
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
