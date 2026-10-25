package openid4vci

import (
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/pkg/claimpath"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// The refusal has to point somewhere a caller can actually go.
//
// It used to say "omit the match to prepare an unbound issuance", which
// cannot work: PrepareIssuance marks identity_match required, so omitting
// it is refused as a missing field rather than honoured as a choice. A
// caller following that advice gets a second error and no unbound
// issuance. The thing it was describing is the pre-authorized grant,
// which is a different request.
func TestIdentityMatchRefusalNamesTheRightAlternative(t *testing.T) {
	err := (&IdentityMatch{}).Validate()
	require.Error(t, err)

	assert.Contains(t, err.Error(), "pre-authorized grant",
		"the refusal must name the request that does provide an unbound issuance")
	assert.NotContains(t, err.Error(), "omit the match",
		"omitting identity_match is refused as a missing field, so it is not advice")

	// A nil rule is the same refusal, and must carry the same guidance.
	var nilMatch *IdentityMatch
	nilErr := nilMatch.Validate()
	require.Error(t, nilErr)
	assert.Equal(t, err.Error(), nilErr.Error())
}

// Dotted claim paths must not become BSON field names; MongoDB < 5.0
// refuses "." in them.
func TestIdentityMatchBSONKeepsDottedPathsOutOfFieldNames(t *testing.T) {
	m := &IdentityMatch{Claims: ClaimMatches{
		{Path: dotted(t, "org.iso.18013.5.1.family_name"), ClaimTest: ClaimTest{Equals: "Andersson"}},
		{Path: claimpath.Keys("org.iso.18013.5.1", "given_name"), ClaimTest: ClaimTest{Equals: "Anna"}},
	}}

	data, err := bson.Marshal(struct {
		M *IdentityMatch `bson:"identity_match"`
	}{m})
	require.NoError(t, err)

	var walk func(raw bson.Raw)
	walk = func(raw bson.Raw) {
		elems, err := raw.Elements()
		require.NoError(t, err)
		for _, e := range elems {
			assert.NotContains(t, e.Key(), ".", "field name %q", e.Key())
			if doc, ok := e.Value().DocumentOK(); ok {
				walk(doc)
			}
			if arr, ok := e.Value().ArrayOK(); ok {
				walk(bson.Raw(arr))
			}
		}
	}
	walk(data)

	var got struct {
		M *IdentityMatch `bson:"identity_match"`
	}
	require.NoError(t, bson.Unmarshal(data, &got))
	assert.Equal(t, m, got.M)
}

// A context stored before the entry-list shape still loads.
func TestIdentityMatchBSONReadsTheMapShape(t *testing.T) {
	data, err := bson.Marshal(bson.M{"claims": bson.M{"given_name": bson.M{"equals": "Anna"}}})
	require.NoError(t, err)

	var got IdentityMatch
	require.NoError(t, bson.Unmarshal(data, &got))
	assert.Equal(t, ClaimMatches{{Path: dotted(t, "given_name"), ClaimTest: ClaimTest{Equals: "Anna"}}}, got.Claims)
}

// A caller may send the claims as a list of pointers or dotted names, or
// in the earlier object form, which reads as dotted names.
func TestIdentityMatchJSONForms(t *testing.T) {
	want := ClaimMatches{
		{Path: dotted(t, "family_name"), ClaimTest: ClaimTest{Equals: "Andersson"}},
		{Path: dotted(t, "given_name"), ClaimTest: ClaimTest{Equals: "Anna"}},
	}
	for name, body := range map[string]string{
		"object form":       `{"claims": {"given_name": {"equals": "Anna"}, "family_name": {"equals": "Andersson"}}}`,
		"list, dotted name": `{"claims": [{"path": "family_name", "equals": "Andersson"}, {"path": "given_name", "equals": "Anna"}]}`,
	} {
		var got IdentityMatch
		require.NoError(t, json.Unmarshal([]byte(body), &got), name)
		assert.Equal(t, want, got.Claims, name)
	}

	var got IdentityMatch
	require.NoError(t, json.Unmarshal([]byte(`{"claims": [{"path": ["address", null, 0], "equals": "x"}]}`), &got))
	assert.Equal(t, claimpath.New(claimpath.Key("address"), claimpath.All(), claimpath.Index(0)), got.Claims[0].Path)
}

func dotted(t *testing.T, name string) claimpath.Pointer {
	t.Helper()
	p, err := claimpath.Dotted(name)
	require.NoError(t, err)
	return p
}
