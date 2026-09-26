package spocputil

import (
	"testing"

	"github.com/sirosfoundation/go-spocp/pkg/sexp"
	"github.com/sirosfoundation/go-spocp/pkg/starform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAdvancedSExp_SimpleList(t *testing.T) {
	elem, err := ParseAdvancedSExp("(credential (scope pid)(acr loa3))")
	require.NoError(t, err)

	list, ok := elem.(*sexp.List)
	require.True(t, ok)
	assert.Equal(t, "credential", list.Tag)
	assert.Len(t, list.Elements, 2)
}

func TestParseAdvancedSExp_EmptySublist(t *testing.T) {
	elem, err := ParseAdvancedSExp("(credential (scope pid)(org_id))")
	require.NoError(t, err)

	list := elem.(*sexp.List)
	assert.Len(t, list.Elements, 2)

	// org_id should be a list with no child elements (wildcard dimension)
	orgIDList := list.Elements[1].(*sexp.List)
	assert.Equal(t, "org_id", orgIDList.Tag)
	assert.Len(t, orgIDList.Elements, 0)
}

func TestParseAdvancedSExp_Wildcard(t *testing.T) {
	elem, err := ParseAdvancedSExp("(credential (scope pid)(acr (*)))")
	require.NoError(t, err)

	list := elem.(*sexp.List)
	acrList := list.Elements[1].(*sexp.List)
	_, ok := acrList.Elements[0].(*starform.Wildcard)
	assert.True(t, ok)
}

func TestParseAdvancedSExp_Prefix(t *testing.T) {
	elem, err := ParseAdvancedSExp("(credential (acr (* prefix urn:example:)))")
	require.NoError(t, err)

	list := elem.(*sexp.List)
	acrList := list.Elements[0].(*sexp.List)
	prefix, ok := acrList.Elements[0].(*starform.Prefix)
	require.True(t, ok)
	assert.Equal(t, "urn:example:", prefix.Value)
}

func TestParseAdvancedSExp_Suffix(t *testing.T) {
	elem, err := ParseAdvancedSExp("(credential (email (* suffix @example.com)))")
	require.NoError(t, err)

	list := elem.(*sexp.List)
	emailList := list.Elements[0].(*sexp.List)
	suffix, ok := emailList.Elements[0].(*starform.Suffix)
	require.True(t, ok)
	assert.Equal(t, "@example.com", suffix.Value)
}

func TestParseAdvancedSExp_Set(t *testing.T) {
	elem, err := ParseAdvancedSExp("(credential (acr (* set loa3 loa4 loa5)))")
	require.NoError(t, err)

	list := elem.(*sexp.List)
	acrList := list.Elements[0].(*sexp.List)
	set, ok := acrList.Elements[0].(*starform.Set)
	require.True(t, ok)
	assert.Len(t, set.Elements, 3)
}

func TestParseAdvancedSExp_Empty(t *testing.T) {
	_, err := ParseAdvancedSExp("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty S-expression")
}

func TestParseAdvancedSExp_Unclosed(t *testing.T) {
	_, err := ParseAdvancedSExp("(credential (scope pid)")
	assert.Error(t, err)
}

func TestParseAdvancedSExp_TrailingInput(t *testing.T) {
	_, err := ParseAdvancedSExp("(credential) extra")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected trailing input")
}
