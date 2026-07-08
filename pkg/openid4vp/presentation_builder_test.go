package openid4vp_test

import (
	"slices"
	"testing"

	"github.com/SUNET/vc/pkg/configuration"
	"github.com/SUNET/vc/pkg/openid4vp"
)

func TestPresentationBuilder_BuildFromScopes(t *testing.T) {
	ctx := t.Context()

	// Load test templates
	config, err := configuration.LoadPresentationRequestsFromFile(ctx, "../configuration/testdata/multi_template.yaml")
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}

	// Note: gopls may show a false positive error here due to interface analysis limitations
	// The code compiles and runs correctly - the interface is properly satisfied at runtime
	builder := openid4vp.NewPresentationBuilder(config.GetEnabledTemplates())

	tests := []struct {
		name        string
		scopes      []string
		expectError bool
		expectedID  string
	}{
		{
			name:        "PID scope",
			scopes:      []string{"openid", "pid"},
			expectError: false,
			expectedID:  "basic_pid",
		},
		{
			name:        "EHIC scope",
			scopes:      []string{"openid", "ehic"},
			expectError: false,
			expectedID:  "basic_ehic",
		},
		{
			name:        "No scopes",
			scopes:      []string{},
			expectError: true,
		},
		{
			name:        "Unknown scope",
			scopes:      []string{"unknown_scope"},
			expectError: true,
		},
		{
			name:        "Only standard OIDC scopes matched via pid",
			scopes:      []string{"openid", "profile", "pid"},
			expectError: false,
			expectedID:  "basic_pid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dcql, template, err := builder.BuildFromScopes(ctx, tt.scopes)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if dcql == nil {
				t.Error("Expected DCQL query but got nil")
				return
			}

			if template == nil {
				t.Error("Expected template but got nil")
				return
			}

			if template.GetID() != tt.expectedID {
				t.Errorf("Expected template ID %s, got %s", tt.expectedID, template.GetID())
			}

			// Also check that DCQL has credentials with VCT values
			if len(dcql.Credentials) > 0 {
				t.Logf("BuildFromScopes - Credential: %+v", dcql.Credentials[0])
				t.Logf("BuildFromScopes - VCT Values: %+v", dcql.Credentials[0].Meta.VCTValues)
			}
		})
	}
}

func TestPresentationBuilder_BuildFromTemplate(t *testing.T) {
	ctx := t.Context()

	config, err := configuration.LoadPresentationRequestsFromFile(ctx, "../configuration/testdata/multi_template.yaml")
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}

	builder := openid4vp.NewPresentationBuilder(config.GetEnabledTemplates())

	tests := []struct {
		name        string
		templateID  string
		expectError bool
	}{
		{
			name:        "Valid PID template",
			templateID:  "basic_pid",
			expectError: false,
		},
		{
			name:        "Valid EHIC template",
			templateID:  "basic_ehic",
			expectError: false,
		},
		{
			name:        "Non-existent template",
			templateID:  "does_not_exist",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dcql, template, err := builder.BuildFromTemplate(ctx, tt.templateID)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if dcql == nil {
				t.Error("Expected DCQL query but got nil")
				return
			}

			if template == nil {
				t.Error("Expected template but got nil")
				return
			}

			if template.GetID() != tt.templateID {
				t.Errorf("Expected template ID %s, got %s", tt.templateID, template.GetID())
			}
		})
	}
}

func TestPresentationBuilder_BuildDCQLQuery(t *testing.T) {
	ctx := t.Context()

	config, err := configuration.LoadPresentationRequestsFromFile(ctx, "../configuration/testdata/multi_template.yaml")
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}

	builder := openid4vp.NewPresentationBuilder(config.GetEnabledTemplates())

	tests := []struct {
		name           string
		scopes         []string
		expectError    bool
		expectGeneric  bool
		minCredentials int
		checkVCTValues bool
	}{
		{
			name:           "PID scope creates DCQL with template",
			scopes:         []string{"openid", "pid"},
			expectError:    false,
			expectGeneric:  false,
			minCredentials: 1,
			checkVCTValues: true,
		},
		{
			name:           "EHIC scope creates DCQL with template",
			scopes:         []string{"openid", "ehic"},
			expectError:    false,
			expectGeneric:  false,
			minCredentials: 1,
			checkVCTValues: true,
		},
		{
			name:           "Only standard scopes creates generic DCQL",
			scopes:         []string{"openid", "profile"},
			expectError:    false,
			expectGeneric:  true,
			minCredentials: 1,
			checkVCTValues: false,
		},
		{
			name:           "Unknown scope creates generic DCQL",
			scopes:         []string{"openid", "unknown_scope"},
			expectError:    false,
			expectGeneric:  true,
			minCredentials: 1,
			checkVCTValues: false,
		},
		{
			name:           "Empty scopes creates generic DCQL",
			scopes:         []string{},
			expectError:    false,
			expectGeneric:  true,
			minCredentials: 1,
			checkVCTValues: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dcql, err := builder.BuildDCQLQuery(ctx, tt.scopes)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if dcql == nil {
				t.Error("Expected DCQL but got nil")
				return
			}

			if len(dcql.Credentials) < tt.minCredentials {
				t.Errorf("Expected at least %d credentials, got %d",
					tt.minCredentials, len(dcql.Credentials))
			}

			if tt.expectGeneric {
				// Generic DCQL should have generic credential ID
				if dcql.Credentials[0].ID != "credential_generic" {
					t.Errorf("Expected generic credential ID, got %s", dcql.Credentials[0].ID)
				}
			}

			if tt.checkVCTValues {
				// Template-based DCQL should have VCT values
				if len(dcql.Credentials) == 0 {
					t.Error("Expected at least one credential")
				} else {
					t.Logf("DCQL Credentials: %+v", dcql.Credentials)
					t.Logf("VCT Values: %+v", dcql.Credentials[0].Meta.VCTValues)
					if len(dcql.Credentials[0].Meta.VCTValues) == 0 {
						t.Errorf("Expected VCT values from template, got credential: %+v", dcql.Credentials[0])
					}
				}
			}
		})
	}
}

func TestPresentationBuilder_ListTemplates(t *testing.T) {
	ctx := t.Context()

	config, err := configuration.LoadPresentationRequestsFromFile(ctx, "../configuration/testdata/multi_template.yaml")
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}

	builder := openid4vp.NewPresentationBuilder(config.GetEnabledTemplates())

	templates := builder.ListTemplates()
	if len(templates) == 0 {
		t.Error("Expected templates but got none")
	}

	// Should have at least PID and EHIC templates
	if len(templates) < 2 {
		t.Errorf("Expected at least 2 templates, got %d", len(templates))
	}
}

func TestPresentationBuilder_GetTemplate(t *testing.T) {
	ctx := t.Context()

	config, err := configuration.LoadPresentationRequestsFromFile(ctx, "../configuration/testdata/multi_template.yaml")
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}

	builder := openid4vp.NewPresentationBuilder(config.GetEnabledTemplates())

	template, err := builder.GetTemplate("basic_pid")
	if err != nil {
		t.Errorf("Failed to get template: %v", err)
	}

	if template == nil {
		t.Error("Expected template but got nil")
	}

	if template != nil && template.GetID() != "basic_pid" {
		t.Errorf("Expected template ID 'basic_pid', got %s", template.GetID())
	}

	// Test non-existent template
	_, err = builder.GetTemplate("does_not_exist")
	if err == nil {
		t.Error("Expected error for non-existent template")
	}
}

// TestPresentationBuilder_ScopePriority tests that non-standard scopes are prioritized
// over standard OIDC scopes. This prevents "openid" (which typically appears first in
// OIDC requests) from always being selected when both standard and non-standard scopes
// are configured with templates.
//
// The test fixture (scope_priority_test.yaml) includes an "openid" template to ensure
// the prioritization logic is actually exercised - without it, pid/ehic would be selected
// simply because there's no openid template to compete with.
func TestPresentationBuilder_ScopePriority(t *testing.T) {
	ctx := t.Context()

	// Use dedicated fixture with openid template for proper priority testing
	config, err := configuration.LoadPresentationRequestsFromFile(ctx, "../configuration/testdata/scope_priority_test.yaml")
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}

	builder := openid4vp.NewPresentationBuilder(config.GetEnabledTemplates())

	// Verify the fixture has an openid template (this test is meaningless without it)
	templates := config.GetEnabledTemplates()
	hasOpenIDTemplate := false
	for _, tmpl := range templates {
		if slices.Contains(tmpl.OIDCScopes, "openid") {
			hasOpenIDTemplate = true
		}
	}
	if !hasOpenIDTemplate {
		t.Fatal("Test fixture must include an 'openid' template to properly test priority behavior")
	}

	// Even though "openid" appears first AND has a matching template,
	// "pid" should be selected because non-standard scopes take priority
	scopes := []string{"openid", "pid"}
	dcql, err := builder.BuildDCQLQuery(ctx, scopes)
	if err != nil {
		t.Fatalf("BuildDCQLQuery failed: %v", err)
	}

	if dcql == nil {
		t.Fatal("Expected DCQL but got nil")
	}

	// Should select pid_credential, NOT openid_credential
	if len(dcql.Credentials) == 0 {
		t.Fatal("Expected at least one credential")
	}

	if dcql.Credentials[0].ID != "pid_credential" {
		t.Errorf("Expected pid_credential to be selected (non-standard scope priority), got %s",
			dcql.Credentials[0].ID)
	}

	// Verify that openid-only requests still work and select the openid template
	scopes = []string{"openid"}
	dcql, err = builder.BuildDCQLQuery(ctx, scopes)
	if err != nil {
		t.Fatalf("BuildDCQLQuery failed for openid-only: %v", err)
	}
	if dcql != nil && len(dcql.Credentials) > 0 && dcql.Credentials[0].ID != "openid_credential" {
		t.Errorf("Expected openid_credential for openid-only request, got %s", dcql.Credentials[0].ID)
	}

	// Also test with multiple non-standard scopes - first non-standard scope wins
	scopes = []string{"openid", "profile", "ehic", "pid"}
	dcql, err = builder.BuildDCQLQuery(ctx, scopes)
	if err != nil {
		t.Fatalf("BuildDCQLQuery failed: %v", err)
	}

	// "ehic" appears before "pid" in the list, so ehic_credential should be selected
	if dcql.Credentials[0].ID != "ehic_credential" {
		t.Errorf("Expected ehic_credential (first non-standard scope), got %s",
			dcql.Credentials[0].ID)
	}
}

// TestPresentationBuilder_MdocDoctypeValue verifies that copyDCQL preserves
// DoctypeValue for mso_mdoc format templates (and TypeValues for W3C VC).
// This is a regression test for the bug where copyDCQL only copied VCTValues,
// producing an empty/invalid meta object for non-SD-JWT formats.
func TestPresentationBuilder_MdocDoctypeValue(t *testing.T) {
	ctx := t.Context()

	config, err := configuration.LoadPresentationRequestsFromFile(ctx, "../configuration/testdata/mdoc_template.yaml")
	if err != nil {
		t.Fatalf("Failed to load mdoc test config: %v", err)
	}

	builder := openid4vp.NewPresentationBuilder(config.GetEnabledTemplates())

	// Build DCQL from the mdl scope
	dcql, err := builder.BuildDCQLQuery(ctx, []string{"openid", "mdl"})
	if err != nil {
		t.Fatalf("BuildDCQLQuery failed: %v", err)
	}

	if dcql == nil {
		t.Fatal("Expected DCQL but got nil")
	}

	if len(dcql.Credentials) == 0 {
		t.Fatal("Expected at least one credential")
	}

	cred := dcql.Credentials[0]

	if cred.Format != "mso_mdoc" {
		t.Errorf("Expected format mso_mdoc, got %s", cred.Format)
	}

	if cred.Meta.DoctypeValue != "org.iso.18013.5.1.mDL" {
		t.Errorf("Expected DoctypeValue 'org.iso.18013.5.1.mDL', got %q", cred.Meta.DoctypeValue)
	}

	// Validate the copied DCQL passes format-specific validation
	if err := openid4vp.ValidateCredentialQuery(cred); err != nil {
		t.Errorf("Copied mdoc credential query failed validation: %v", err)
	}
}
