package spocputil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sirosfoundation/go-spocp/pkg/sexp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildTaggedQuery_MissingValueEmitsEmptyDimension(t *testing.T) {
	query := BuildTaggedQuery("vc", []string{"service", "scope"}, map[string]string{
		"service": "apigw",
	})

	list, ok := query.(*sexp.List)
	require.True(t, ok)
	assert.Equal(t, "vc", list.Tag)
	require.Len(t, list.Elements, 2)

	service, ok := list.Elements[0].(*sexp.List)
	require.True(t, ok)
	assert.Equal(t, "service", service.Tag)
	require.Len(t, service.Elements, 1)

	scope, ok := list.Elements[1].(*sexp.List)
	require.True(t, ok)
	assert.Equal(t, "scope", scope.Tag)
	assert.Empty(t, scope.Elements, "missing value should emit an empty (wildcard) dimension")
}

func TestValidateRuleElement_RequireValue(t *testing.T) {
	dims := []string{"service", "scope"}

	tests := []struct {
		name    string
		rule    string
		wantErr string
	}{
		{"valid", "(vc (service apigw)(scope pid))", ""},
		{"wildcard atom ok", "(vc (service apigw)(scope *))", ""},
		{"empty dimension rejected", "(vc (service apigw)(scope))", "must have exactly 1 value, got 0"},
		{"multi-value rejected", "(vc (service apigw)(scope pid ehic))", "must have exactly 1 value, got 2"},
		{"wrong tag", "(other (service apigw)(scope pid))", `must have tag "vc"`},
		{"wrong part count", "(vc (service apigw))", "must have exactly 2 parts, got 1"},
		{"wrong part order", "(vc (scope pid)(service apigw))", "must be (service ...)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			elem, err := ParseAdvancedSExp(tt.rule)
			require.NoError(t, err)

			err = ValidateRuleElement(elem, "vc", dims, true, "test rule")
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestValidateRuleElement_NotRequireValue(t *testing.T) {
	dims := []string{"scope", "acr"}

	tests := []struct {
		name    string
		rule    string
		wantErr string
	}{
		{"empty dimension allowed", "(credential (scope pid)(acr))", ""},
		{"one value still allowed", "(credential (scope pid)(acr loa3))", ""},
		{"multi-value still rejected", "(credential (scope pid)(acr loa3 loa4))", "must have at most 1 value, got 2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			elem, err := ParseAdvancedSExp(tt.rule)
			require.NoError(t, err)

			err = ValidateRuleElement(elem, "credential", dims, false, "test rule")
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestBuildEngine_NoRulesReturnsNil(t *testing.T) {
	engine, err := BuildEngine("vc", []string{"scope"}, true, "test", nil, "")
	require.NoError(t, err)
	assert.Nil(t, engine)
}

func TestBuildEngine_InlineRuleValidationError(t *testing.T) {
	_, err := BuildEngine("vc", []string{"service", "scope"}, true, "test",
		[]string{"(vc (service apigw)(scope))"}, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must have exactly 1 value, got 0")
}

func TestBuildEngine_InlineParseError(t *testing.T) {
	_, err := BuildEngine("vc", []string{"service", "scope"}, true, "test",
		[]string{"not a valid s-expression"}, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid inline test rule #1")
}

func TestBuildEngine_FileRuleValidated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.spocp")
	require.NoError(t, os.WriteFile(path, []byte("(vc (service apigw)(scope))\n"), 0o600))

	_, err := BuildEngine("vc", []string{"service", "scope"}, true, "test", nil, path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must have exactly 1 value, got 0")
}

func TestBuildEngine_QueryElement(t *testing.T) {
	engine, err := BuildEngine("vc", []string{"service", "scope"}, true, "test",
		[]string{"(vc (service apigw)(scope pid))"}, "")
	require.NoError(t, err)
	require.NotNil(t, engine)

	assert.True(t, engine.QueryElement(BuildTaggedQuery("vc", []string{"service", "scope"}, map[string]string{
		"service": "apigw", "scope": "pid",
	})))
	assert.False(t, engine.QueryElement(BuildTaggedQuery("vc", []string{"service", "scope"}, map[string]string{
		"service": "apigw", "scope": "ehic",
	})))
	assert.Equal(t, 1, engine.RuleCount())
	assert.Len(t, engine.ExportRules(), 1)
}
