package credential

import (
	"reflect"
	"testing"

	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/require"
)

func TestFilterAgainstVCTM(t *testing.T) {
	vctm := &sdjwtvc.VCTM{Claims: []sdjwtvc.Claim{
		{Path: claimpath.Keys("age_over_13")},
		{Path: claimpath.Keys("age_over_18")},
		{Path: claimpath.Keys("date_of_issuance")},
		{Path: claimpath.Keys("date_of_expiry")},
		{Path: claimpath.Keys("address", "locality")}, // nested path — only address.locality allowed
	}}
	doc := map[string]any{
		"age_over_13":      true,
		"age_over_18":      true,
		"date_of_issuance": "2026-09-28",
		"date_of_expiry":   "2027-09-28",
		"given_name":       "Alice",
		"family_name":      "Smith",
		"birthdate":        "1996-01-30",
		"address":          map[string]any{"locality": "Stockholm", "street": "Kungsgatan 1"},
	}
	got, err := FilterAgainstVCTM(doc, vctm)
	if err != nil {
		t.Fatal(err)
	}

	for _, k := range []string{"age_over_13", "age_over_18", "date_of_issuance", "date_of_expiry", "address"} {
		if _, ok := got[k]; !ok {
			t.Errorf("expected key %q to survive filter", k)
		}
	}
	for _, k := range []string{"given_name", "family_name", "birthdate"} {
		if _, ok := got[k]; ok {
			t.Errorf("expected key %q to be filtered out", k)
		}
	}
	addr, ok := got["address"].(map[string]any)
	if !ok {
		t.Fatalf("expected address to be a map, got %T", got["address"])
	}
	if _, ok := addr["locality"]; !ok {
		t.Errorf("expected address.locality to survive")
	}
	if _, ok := addr["street"]; ok {
		t.Errorf("expected undeclared sibling address.street to be filtered out")
	}
}

func TestFilterAgainstVCTM_NilVCTM(t *testing.T) {
	doc := map[string]any{"anything": 1}
	got, err := FilterAgainstVCTM(doc, nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("expected empty result for nil VCTM, got %v", got)
	}
}

func TestFilterAgainstVCTM_EmptyDoc(t *testing.T) {
	vctm := &sdjwtvc.VCTM{Claims: []sdjwtvc.Claim{
		{Path: claimpath.Keys("age_over_13")},
	}}
	got, err := FilterAgainstVCTM(map[string]any{}, vctm)
	if err != nil || len(got) != 0 {
		t.Fatalf("expected empty result for empty doc, got %v", got)
	}
}

func TestFilterAgainstVCTM_SkipsEmptyOrWildcardPath(t *testing.T) {
	vctm := &sdjwtvc.VCTM{Claims: []sdjwtvc.Claim{
		{},                                     // defensive: skipped
		{Path: claimpath.EmptyArray()},         // defensive: skipped
		{Path: claimpath.New(claimpath.All())}, // wildcard head: skipped
		{Path: claimpath.Keys("kept")},
	}}
	doc := map[string]any{"kept": 1, "dropped": 2}
	got, err := FilterAgainstVCTM(doc, vctm)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["kept"]; !ok {
		t.Fatalf("expected 'kept' to survive: %v", got)
	}
	if _, ok := got["dropped"]; ok {
		t.Fatalf("expected 'dropped' to be filtered: %v", got)
	}
}

// filterSource is the document the index tables filter.
func filterSource() map[string]any {
	return map[string]any{
		"nationalities": []any{"SE", "FI", "NO"},
		"degrees": []any{
			map[string]any{"type": "BSc", "university": "KTH"},
			map[string]any{"type": "MSc", "university": "LiU"},
			map[string]any{"type": "PhD", "university": "UU"},
		},
		"matrix": []any{[]any{"a", "b"}, []any{"c", "d"}},
		"mixed":  []any{"x", map[string]any{"k": "v"}},
	}
}

// key, all and index build claims path components.
var (
	key   = claimpath.Key
	all   = claimpath.All
	index = claimpath.Index
)

// Every VCTM path with an index selects the same claims in the filtered
// document as in the source: an indexed array keeps each element at its
// index, and a declared element with nothing left before a kept one
// stays as its empty form.
func TestFilterAgainstVCTM_KeepsIndexedClaimsAtTheirIndex(t *testing.T) {
	for name, paths := range map[string][]claimpath.Pointer{
		"the first elements": {
			claimpath.New(key("nationalities"), index(0)), claimpath.New(key("nationalities"), index(1)),
		},
		"a key of each declared element": {
			claimpath.New(key("degrees"), index(0), key("type")), claimpath.New(key("degrees"), index(1), key("university")),
		},
		"an element with nothing left before a kept one": {
			claimpath.New(key("degrees"), index(0), key("grade")), claimpath.New(key("degrees"), index(1), key("type")),
		},
		"a scalar where an object is declared": {
			claimpath.New(key("mixed"), index(0), key("k")), claimpath.New(key("mixed"), index(1), key("k")),
		},
		"null with an index past the others": {
			claimpath.New(key("degrees"), all(), key("type")), claimpath.New(key("degrees"), index(2), key("university")),
		},
		"nested arrays": {
			claimpath.New(key("matrix"), index(0), index(0)), claimpath.New(key("matrix"), index(1), index(0)), claimpath.New(key("matrix"), index(1), index(1)),
		},
	} {
		t.Run(name, func(t *testing.T) {
			vctm := &sdjwtvc.VCTM{}
			for _, path := range paths {
				vctm.Claims = append(vctm.Claims, sdjwtvc.Claim{Path: path})
			}
			filtered, err := FilterAgainstVCTM(filterSource(), vctm)
			require.NoError(t, err)
			for _, path := range paths {
				if !hasIndex(t, path) {
					continue
				}
				want, wantErr := path.Select(filterSource())
				got, gotErr := path.Select(filtered)
				if wantErr != nil {
					require.Error(t, gotErr, "%s selects nothing in the source", path)
					continue
				}
				require.NoError(t, gotErr, "%s", path)
				require.Equal(t, want, got, "%s", path)
			}
		})
	}
}

// hasIndex reports whether path has an index.
func hasIndex(t *testing.T, path claimpath.Pointer) bool {
	t.Helper()
	components, err := path.Components()
	require.NoError(t, err)
	for _, component := range components {
		if _, ok := component.IndexValue(); ok {
			return true
		}
	}
	return false
}

// An array whose declared indices leave a gap before the last one is
// refused, by CheckFilterable and by the filter, unless null selects every
// element.
func TestCheckFilterable_RefusesAGapInTheIndices(t *testing.T) {
	gap := &sdjwtvc.VCTM{Claims: []sdjwtvc.Claim{{Path: claimpath.New(key("nationalities"), index(1))}}}
	err := CheckFilterable(gap)
	require.ErrorContains(t, err, `elements [1] of the array ["nationalities"]`)
	_, filterErr := FilterAgainstVCTM(filterSource(), gap)
	require.Equal(t, err, filterErr)

	gap.Claims = append(gap.Claims, sdjwtvc.Claim{Path: claimpath.New(key("nationalities"), all())})
	require.NoError(t, CheckFilterable(gap))
}

// An array the VCTM selects only with null filters as the earlier release
// filtered it: each element by the null subtree, keeping the elements with
// something left, in order. The expected documents follow that release's
// filterArray.
func TestFilterAgainstVCTM_NullOnlyArrays(t *testing.T) {
	for name, tc := range map[string]struct {
		paths []claimpath.Pointer
		doc   map[string]any
		want  map[string]any
	}{
		"every element whole": {
			paths: []claimpath.Pointer{claimpath.New(key("nationalities"), all())},
			doc:   map[string]any{"nationalities": []any{"SE", "FI"}},
			want:  map[string]any{"nationalities": []any{"SE", "FI"}},
		},
		"a string slice": {
			paths: []claimpath.Pointer{claimpath.New(key("nationalities"), all())},
			doc:   map[string]any{"nationalities": []string{"SE"}},
			want:  map[string]any{"nationalities": []any{"SE"}},
		},
		"an element with nothing left is dropped": {
			paths: []claimpath.Pointer{claimpath.New(key("degrees"), all(), key("type"))},
			doc: map[string]any{"degrees": []any{
				map[string]any{"type": "BSc", "university": "KTH"},
				map[string]any{"university": "LiU"},
				map[string]any{"type": "PhD"},
			}},
			want: map[string]any{"degrees": []any{map[string]any{"type": "BSc"}, map[string]any{"type": "PhD"}}},
		},
		"an array with nothing left is dropped": {
			paths: []claimpath.Pointer{claimpath.New(key("degrees"), all(), key("type"))},
			doc:   map[string]any{"degrees": []any{map[string]any{"university": "LiU"}}},
			want:  map[string]any{},
		},
		"the whole array declared as well": {
			paths: []claimpath.Pointer{claimpath.Keys("degrees"), claimpath.New(key("degrees"), all(), key("type"))},
			doc:   map[string]any{"degrees": []any{map[string]any{"type": "BSc", "university": "KTH"}}},
			want:  map[string]any{"degrees": []any{map[string]any{"type": "BSc"}}},
		},
		"a scalar where an array is declared": {
			paths: []claimpath.Pointer{claimpath.New(key("nationalities"), all())},
			doc:   map[string]any{"nationalities": "SE"},
			want:  map[string]any{},
		},
	} {
		t.Run(name, func(t *testing.T) {
			vctm := &sdjwtvc.VCTM{}
			for _, path := range tc.paths {
				vctm.Claims = append(vctm.Claims, sdjwtvc.Claim{Path: path})
			}
			got, err := FilterAgainstVCTM(tc.doc, vctm)
			require.NoError(t, err)
			if !reflect.DeepEqual(tc.want, got) {
				t.Fatalf("want %v, got %v", tc.want, got)
			}
		})
	}
}
