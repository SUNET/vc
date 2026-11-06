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
// refuses "." in them. A stored rule holds dotted names, which a replica
// of the earlier release reads, or pointers.
func TestIdentityMatchBSONKeepsDottedPathsOutOfFieldNames(t *testing.T) {
	rule := &IdentityMatch{Claims: []ClaimMatch{
		{Path: claimpath.Keys("org.iso.18013.5.1", "family_name"), ClaimTest: ClaimTest{Equals: "Andersson"}},
		{Path: claimpath.Keys("given_name"), ClaimTest: ClaimTest{Equals: "Anna"}},
	}}
	named := rule.Store(func(p claimpath.Pointer) (string, bool) {
		keys, _ := p.KeyNames()
		name := keys[0]
		for _, key := range keys[1:] {
			name += "." + key
		}
		return name, true
	})
	for form, stored := range map[string]*StoredIdentityMatch{"names": named, "pointers": rule.Store(nil)} {
		data, err := bson.Marshal(struct {
			M *StoredIdentityMatch `bson:"identity_match"`
		}{stored})
		require.NoError(t, err, form)

		var walk func(raw bson.Raw)
		walk = func(raw bson.Raw) {
			elems, err := raw.Elements()
			require.NoError(t, err)
			for _, e := range elems {
				assert.NotContains(t, e.Key(), ".", "%s: field name %q", form, e.Key())
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
			M *StoredIdentityMatch `bson:"identity_match"`
		}
		require.NoError(t, bson.Unmarshal(data, &got), form)
		assert.Equal(t, stored, got.M, form)
	}
}

// A context stored before the entry-list shape still loads, and its names
// read in the shape of the presented credential.
func TestIdentityMatchBSONReadsTheMapShape(t *testing.T) {
	data, err := bson.Marshal(bson.M{"claims": bson.M{"given_name": bson.M{"equals": "Anna"}}})
	require.NoError(t, err)

	var got StoredIdentityMatch
	require.NoError(t, bson.Unmarshal(data, &got))
	rule, err := got.Rule(func(name string) (claimpath.Pointer, error) { return claimpath.Keys("read", name), nil })
	require.NoError(t, err)
	assert.Equal(t, []ClaimMatch{{Path: claimpath.Keys("read", "given_name"), ClaimTest: ClaimTest{Equals: "Anna"}}}, rule.Claims)
}

// A stored claim names a claim.
func TestIdentityMatchBSONRefusesAnEmptyPath(t *testing.T) {
	data, err := bson.Marshal(bson.M{"claims": bson.A{bson.M{"path": bson.A{}, "test": bson.M{"equals": "Anna"}}}})
	require.NoError(t, err)
	var got StoredIdentityMatch
	assert.ErrorContains(t, bson.Unmarshal(data, &got), "a stored claim has no path")
}

// A request lists claims as pointers. The dotted string inside the list
// form was never released, so it is refused.
func TestIdentityMatchJSON(t *testing.T) {
	var got IdentityMatch
	require.NoError(t, json.Unmarshal([]byte(`{"claims": [{"path": ["address", null, 0], "equals": "x"}]}`), &got))
	assert.Equal(t, []ClaimMatch{{Path: claimpath.New(claimpath.Key("address"), claimpath.All(), claimpath.Index(0)), ClaimTest: ClaimTest{Equals: "x"}}}, got.Claims)

	err := json.Unmarshal([]byte(`{"claims": [{"path": "family_name", "equals": "Andersson"}]}`), &got)
	var stringErr *claimpath.StringError
	assert.ErrorAs(t, err, &stringErr)
}
