package configuration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/openid4vp"
)

func TestLoadTemplateFile_SingleTemplate(t *testing.T) {
	templates, err := loadTemplateFile("testdata/eudi_pid_basic.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(templates) != 1 {
		t.Fatalf("expected 1 template, got %d", len(templates))
	}
	if templates[0].ID != "eudi_pid_basic" {
		t.Errorf("expected ID 'eudi_pid_basic', got %q", templates[0].ID)
	}
	if !templates[0].Enabled {
		t.Error("expected template to be enabled")
	}
}

func TestLoadTemplateFile_SingleTemplateDefaultEnabled(t *testing.T) {
	templates, err := loadTemplateFile("testdata/single_template_no_enabled.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(templates) != 1 {
		t.Fatalf("expected 1 template, got %d", len(templates))
	}
	if templates[0].ID != "auto_enabled" {
		t.Errorf("expected ID 'auto_enabled', got %q", templates[0].ID)
	}
	if !templates[0].Enabled {
		t.Error("expected template to be enabled by default")
	}
}

func TestLoadTemplateFile_MultiTemplate(t *testing.T) {
	templates, err := loadTemplateFile("testdata/multi_template.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(templates) != 2 {
		t.Fatalf("expected 2 templates, got %d", len(templates))
	}
	if templates[0].ID != "basic_pid" {
		t.Errorf("expected first template ID 'basic_pid', got %q", templates[0].ID)
	}
	if templates[1].ID != "basic_ehic" {
		t.Errorf("expected second template ID 'basic_ehic', got %q", templates[1].ID)
	}
	for i, tmpl := range templates {
		if !tmpl.Enabled {
			t.Errorf("expected template %d to be enabled", i)
		}
	}
}

func TestLoadTemplateFile_MultiTemplateDefaultEnabled(t *testing.T) {
	templates, err := loadTemplateFile("testdata/multi_template_no_enabled.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(templates) != 2 {
		t.Fatalf("expected 2 templates, got %d", len(templates))
	}
	for i, tmpl := range templates {
		if !tmpl.Enabled {
			t.Errorf("expected template %d to be enabled by default", i)
		}
	}
}

func TestLoadTemplateFile_MultiTemplateFirstMissingID(t *testing.T) {
	// First template has no ID, second has a valid ID.
	// The function should still return templates because at least one has an ID.
	templates, err := loadTemplateFile("testdata/multi_template_first_missing_id.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(templates) != 2 {
		t.Fatalf("expected 2 templates, got %d", len(templates))
	}
	if templates[0].ID != "" {
		t.Errorf("expected first template ID to be empty, got %q", templates[0].ID)
	}
	if templates[1].ID != "valid_second" {
		t.Errorf("expected second template ID 'valid_second', got %q", templates[1].ID)
	}
}

func TestLoadTemplateFile_MultiTemplateAllMissingID(t *testing.T) {
	// All templates in the list are missing their ID — should return an error.
	_, err := loadTemplateFile("testdata/multi_template_all_missing_id.yaml")
	if err == nil {
		t.Fatal("expected error when all templates are missing id, got nil")
	}
	if !strings.Contains(err.Error(), "templates list present but all entries missing id") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestLoadTemplateFile_FileNotFound(t *testing.T) {
	_, err := loadTemplateFile("testdata/nonexistent.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
	if !strings.Contains(err.Error(), "failed to read file") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestLoadTemplateFile_InvalidYAML(t *testing.T) {
	_, err := loadTemplateFile("testdata/invalid_yaml.yaml")
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
	if !strings.Contains(err.Error(), "failed to unmarshal YAML") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// --- Getter tests ---

func newTestTemplate() *PresentationRequestTemplate {
	return &PresentationRequestTemplate{
		ID:         "test_id",
		Name:       "Test",
		OIDCScopes: []string{"scope1", "scope2"},
		DCQLQuery:  &openid4vp.DCQL{},
		ClaimMappings: map[string]string{
			"a": "b",
		},
		ClaimTransforms: map[string]ClaimTransform{
			"a": {Type: "uppercase"},
		},
		Enabled: true,
	}
}

func TestGetID(t *testing.T) {
	tmpl := newTestTemplate()
	if got := tmpl.GetID(); got != "test_id" {
		t.Errorf("GetID() = %q, want %q", got, "test_id")
	}
}

func TestGetOIDCScopes(t *testing.T) {
	tmpl := newTestTemplate()
	scopes := tmpl.GetOIDCScopes()
	if len(scopes) != 2 || scopes[0] != "scope1" {
		t.Errorf("GetOIDCScopes() = %v, want [scope1, scope2]", scopes)
	}
}

func TestGetDCQLQuery(t *testing.T) {
	tmpl := newTestTemplate()
	if tmpl.GetDCQLQuery() == nil {
		t.Error("GetDCQLQuery() returned nil")
	}
}

func TestGetClaimMappings(t *testing.T) {
	tmpl := newTestTemplate()
	m := tmpl.GetClaimMappings()
	if m["a"] != "b" {
		t.Errorf("GetClaimMappings() = %v, want map[a:b]", m)
	}
}

func TestGetClaimTransforms(t *testing.T) {
	tmpl := newTestTemplate()
	ct := tmpl.GetClaimTransforms()
	if ct["a"].Type != "uppercase" {
		t.Errorf("GetClaimTransforms() type = %q, want %q", ct["a"].Type, "uppercase")
	}
}

// --- Config method tests ---

func newTestConfig() *PresentationRequestConfig {
	return &PresentationRequestConfig{
		Templates: []*PresentationRequestTemplate{
			{ID: "pid", Name: "PID", OIDCScopes: []string{"pid"}, Enabled: true, ClaimMappings: map[string]string{"a": "b"}},
			{ID: "ehic", Name: "EHIC", OIDCScopes: []string{"ehic"}, Enabled: true, ClaimMappings: map[string]string{"c": "d"}},
			{ID: "disabled", Name: "Disabled", OIDCScopes: []string{"dis"}, Enabled: false, ClaimMappings: map[string]string{}},
		},
		DefaultTemplate: "pid",
	}
}

func TestGetEnabledTemplates(t *testing.T) {
	cfg := newTestConfig()
	enabled := cfg.GetEnabledTemplates()
	if len(enabled) != 2 {
		t.Fatalf("expected 2 enabled templates, got %d", len(enabled))
	}
}

func TestListEnabledTemplates(t *testing.T) {
	cfg := newTestConfig()
	enabled := cfg.ListEnabledTemplates()
	if len(enabled) != 2 {
		t.Fatalf("expected 2 enabled templates, got %d", len(enabled))
	}
}

func TestGetTemplateByID(t *testing.T) {
	cfg := newTestConfig()

	tmpl, err := cfg.GetTemplateByID("pid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tmpl.ID != "pid" {
		t.Errorf("expected ID 'pid', got %q", tmpl.ID)
	}

	// Disabled template should not be found
	_, err = cfg.GetTemplateByID("disabled")
	if err == nil {
		t.Error("expected error for disabled template, got nil")
	}

	// Non-existent template
	_, err = cfg.GetTemplateByID("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent template, got nil")
	}
}

func TestGetTemplateByScope(t *testing.T) {
	cfg := newTestConfig()

	tmpl, err := cfg.GetTemplateByScope("ehic")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tmpl.ID != "ehic" {
		t.Errorf("expected ID 'ehic', got %q", tmpl.ID)
	}

	// Disabled scope
	_, err = cfg.GetTemplateByScope("dis")
	if err == nil {
		t.Error("expected error for disabled template scope, got nil")
	}

	// Unknown scope
	_, err = cfg.GetTemplateByScope("unknown")
	if err == nil {
		t.Error("expected error for unknown scope, got nil")
	}
}

func TestGetTemplateByScopes(t *testing.T) {
	cfg := newTestConfig()

	// Match first scope
	tmpl, err := cfg.GetTemplateByScopes([]string{"ehic", "pid"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tmpl.ID != "ehic" {
		t.Errorf("expected ID 'ehic', got %q", tmpl.ID)
	}

	// No match — falls back to default template
	tmpl, err = cfg.GetTemplateByScopes([]string{"unknown"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tmpl.ID != "pid" {
		t.Errorf("expected default template 'pid', got %q", tmpl.ID)
	}

	// No match, no default
	cfg2 := newTestConfig()
	cfg2.DefaultTemplate = ""
	_, err = cfg2.GetTemplateByScopes([]string{"unknown"})
	if err == nil {
		t.Error("expected error when no scope matches and no default, got nil")
	}
}

// --- Validation tests ---

func TestValidateUniqueIDs(t *testing.T) {
	cfg := newTestConfig()
	if err := cfg.validateUniqueIDs(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Add duplicate
	cfg.Templates = append(cfg.Templates, &PresentationRequestTemplate{ID: "pid"})
	if err := cfg.validateUniqueIDs(); err == nil {
		t.Error("expected error for duplicate IDs, got nil")
	}
}

func TestValidateNoDuplicateScopes(t *testing.T) {
	cfg := newTestConfig()
	if err := cfg.validateNoDuplicateScopes(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Add duplicate scope
	cfg.Templates = append(cfg.Templates, &PresentationRequestTemplate{ID: "dup", OIDCScopes: []string{"pid"}})
	if err := cfg.validateNoDuplicateScopes(); err == nil {
		t.Error("expected error for duplicate scopes, got nil")
	}
}

// --- LoadPresentationRequests tests ---

func TestLoadPresentationRequests_EmptyPath(t *testing.T) {
	_, err := LoadPresentationRequests(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestLoadPresentationRequests_NonexistentDir(t *testing.T) {
	_, err := LoadPresentationRequests(context.Background(), "/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

func TestLoadPresentationRequests_NotADirectory(t *testing.T) {
	_, err := LoadPresentationRequests(context.Background(), "testdata/eudi_pid_basic.yaml")
	if err == nil {
		t.Fatal("expected error when path is a file, not a dir")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadPresentationRequests_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadPresentationRequests(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error for empty directory")
	}
	if !strings.Contains(err.Error(), "no YAML files found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadPresentationRequests_ValidDir(t *testing.T) {
	// Create a temp dir with a single valid template
	dir := t.TempDir()
	content := `id: "test1"
name: "Test1"
oidc_scopes: ["s1"]
dcql:
  credentials:
    - id: "c1"
      format: "vc+sd-jwt"
claim_mappings:
  a: "b"
`
	if err := os.WriteFile(filepath.Join(dir, "t1.yaml"), []byte(content), 0644); err != nil { // #nosec G306
		t.Fatal(err)
	}
	cfg, err := LoadPresentationRequests(context.Background(), dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Templates) != 1 {
		t.Fatalf("expected 1 template, got %d", len(cfg.Templates))
	}
}

func TestLoadPresentationRequests_DuplicateIDs(t *testing.T) {
	dir := t.TempDir()
	tmpl := `id: "dup"
name: "Dup"
oidc_scopes: ["%s"]
dcql:
  credentials:
    - id: "c"
      format: "vc+sd-jwt"
claim_mappings:
  a: "b"
`
	os.WriteFile(filepath.Join(dir, "t1.yaml"), []byte(strings.Replace(tmpl, "%s", "s1", 1)), 0644) // #nosec G104 G306
	os.WriteFile(filepath.Join(dir, "t2.yaml"), []byte(strings.Replace(tmpl, "%s", "s2", 1)), 0644) // #nosec G104 G306

	_, err := LoadPresentationRequests(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error for duplicate IDs across files")
	}
	if !strings.Contains(err.Error(), "duplicate template ID") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadPresentationRequests_DuplicateScopes(t *testing.T) {
	dir := t.TempDir()
	t1 := `id: "t1"
name: "T1"
oidc_scopes: ["shared"]
dcql:
  credentials:
    - id: "c"
      format: "vc+sd-jwt"
claim_mappings:
  a: "b"
`
	t2 := `id: "t2"
name: "T2"
oidc_scopes: ["shared"]
dcql:
  credentials:
    - id: "c"
      format: "vc+sd-jwt"
claim_mappings:
  a: "b"
`
	os.WriteFile(filepath.Join(dir, "t1.yaml"), []byte(t1), 0644) // #nosec G104 G306
	os.WriteFile(filepath.Join(dir, "t2.yaml"), []byte(t2), 0644) // #nosec G104 G306

	_, err := LoadPresentationRequests(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error for duplicate scopes")
	}
	if !strings.Contains(err.Error(), "scope shared is defined in both") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadPresentationRequests_InvalidFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("{{invalid"), 0644) // #nosec G104 G306

	_, err := LoadPresentationRequests(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error for invalid YAML file in dir")
	}
}

// --- LoadPresentationRequestsFromFile tests ---

func TestLoadPresentationRequestsFromFile_EmptyPath(t *testing.T) {
	_, err := LoadPresentationRequestsFromFile(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestLoadPresentationRequestsFromFile_NonexistentFile(t *testing.T) {
	_, err := LoadPresentationRequestsFromFile(context.Background(), "/nonexistent.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoadPresentationRequestsFromFile_Valid(t *testing.T) {
	cfg, err := LoadPresentationRequestsFromFile(context.Background(), "testdata/multi_template.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Templates) != 2 {
		t.Fatalf("expected 2 templates, got %d", len(cfg.Templates))
	}
}

func TestLoadPresentationRequestsFromFile_InvalidYAML(t *testing.T) {
	_, err := LoadPresentationRequestsFromFile(context.Background(), "testdata/invalid_yaml.yaml")
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadPresentationRequestsFromFile_DuplicateIDs(t *testing.T) {
	dir := t.TempDir()
	content := `templates:
  - id: "dup"
    name: "A"
    oidc_scopes: ["s1"]
    claim_mappings:
      a: "b"
  - id: "dup"
    name: "B"
    oidc_scopes: ["s2"]
    claim_mappings:
      c: "d"
`
	p := filepath.Join(dir, "dup.yaml")
	os.WriteFile(p, []byte(content), 0644) // #nosec G104 G306

	_, err := LoadPresentationRequestsFromFile(context.Background(), p)
	if err == nil {
		t.Fatal("expected error for duplicate IDs")
	}
}

func TestLoadPresentationRequestsFromFile_DuplicateScopes(t *testing.T) {
	dir := t.TempDir()
	content := `templates:
  - id: "a"
    name: "A"
    oidc_scopes: ["shared"]
    claim_mappings:
      a: "b"
  - id: "b"
    name: "B"
    oidc_scopes: ["shared"]
    claim_mappings:
      c: "d"
`
	p := filepath.Join(dir, "dup_scope.yaml")
	os.WriteFile(p, []byte(content), 0644) // #nosec G104 G306

	_, err := LoadPresentationRequestsFromFile(context.Background(), p)
	if err == nil {
		t.Fatal("expected error for duplicate scopes")
	}
}
