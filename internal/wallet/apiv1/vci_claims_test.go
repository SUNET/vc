package apiv1

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/SUNET/vc/internal/wallet/credential"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func disclosure(t *testing.T, fields ...any) (raw, digest string) {
	t.Helper()
	b, err := json.Marshal(fields)
	require.NoError(t, err)
	raw = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(raw))
	return raw, base64.RawURLEncoding.EncodeToString(sum[:])
}

// testSDJWT has given_name, birthdate and nationalities (one element) as
// disclosures, address.locality nested inside a disclosed address, and a
// plain vct.
func testSDJWT(t *testing.T) (raw string, d map[string]string) {
	t.Helper()
	d = map[string]string{}
	var digests = map[string]string{}
	for _, c := range []struct {
		name  string
		value any
	}{{"given_name", "Erika"}, {"birthdate", "1990-01-01"}} {
		d[c.name], digests[c.name] = disclosure(t, "salt-"+c.name, c.name, c.value)
	}
	d["nationality_se"], digests["nationality_se"] = disclosure(t, "salt-se", "SE")
	d["locality"], digests["locality"] = disclosure(t, "salt-loc", "locality", "Stockholm")
	d["address"], digests["address"] = disclosure(t, "salt-addr", "address", map[string]any{"_sd": []any{digests["locality"]}})

	payload, err := json.Marshal(map[string]any{
		"vct":           "urn:test",
		"_sd":           []any{digests["given_name"], digests["birthdate"], digests["address"]},
		"nationalities": []any{map[string]any{"...": digests["nationality_se"]}},
	})
	require.NoError(t, err)
	jwt := "eyJhbGciOiJFUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
	raw = jwt + "~" + strings.Join([]string{d["given_name"], d["birthdate"], d["nationality_se"], d["address"], d["locality"]}, "~") + "~"
	return raw, d
}

func presentedDisclosures(presentation string) []string {
	parts := strings.Split(strings.TrimSuffix(presentation, "~"), "~")
	return parts[1:]
}

func TestSelectClaims_OnlyTheRequestedClaimIsDisclosed(t *testing.T) {
	raw, d := testSDJWT(t)
	got, ok := selectClaims(raw, openid4vp.CredentialQuery{
		Claims: []openid4vp.ClaimQuery{{Path: openid4vp.StringPath("given_name")}},
	})
	require.True(t, ok)
	assert.Equal(t, []string{d["given_name"]}, presentedDisclosures(got))
}

func TestSelectClaims_NoClaimsDisclosesNothing(t *testing.T) {
	raw, _ := testSDJWT(t)
	got, ok := selectClaims(raw, openid4vp.CredentialQuery{})
	require.True(t, ok)
	assert.Empty(t, presentedDisclosures(got))
}

func TestSelectClaims_NestedAndArrayPaths(t *testing.T) {
	raw, d := testSDJWT(t)
	got, ok := selectClaims(raw, openid4vp.CredentialQuery{
		Claims: []openid4vp.ClaimQuery{
			{Path: openid4vp.StringPath("address", "locality")},
			{Path: []*string{new("nationalities"), nil}},
		},
	})
	require.True(t, ok)
	assert.ElementsMatch(t, []string{d["address"], d["locality"], d["nationality_se"]}, presentedDisclosures(got))
}

func TestSelectClaims_MissingClaimDoesNotMatch(t *testing.T) {
	raw, _ := testSDJWT(t)
	_, ok := selectClaims(raw, openid4vp.CredentialQuery{
		Claims: []openid4vp.ClaimQuery{{Path: openid4vp.StringPath("family_name")}},
	})
	assert.False(t, ok)
}

func TestSelectClaims_Values(t *testing.T) {
	raw, d := testSDJWT(t)

	_, ok := selectClaims(raw, openid4vp.CredentialQuery{
		Claims: []openid4vp.ClaimQuery{{Path: openid4vp.StringPath("given_name"), Values: []any{"Max"}}},
	})
	assert.False(t, ok, "a value outside values does not satisfy the claim")

	got, ok := selectClaims(raw, openid4vp.CredentialQuery{
		Claims: []openid4vp.ClaimQuery{{Path: openid4vp.StringPath("given_name"), Values: []any{"Max", "Erika"}}},
	})
	require.True(t, ok)
	assert.Equal(t, []string{d["given_name"]}, presentedDisclosures(got))
}

func TestSelectClaims_FirstSatisfiedClaimSet(t *testing.T) {
	raw, d := testSDJWT(t)
	got, ok := selectClaims(raw, openid4vp.CredentialQuery{
		Claims: []openid4vp.ClaimQuery{
			{ID: "family", Path: openid4vp.StringPath("family_name")},
			{ID: "given", Path: openid4vp.StringPath("given_name")},
			{ID: "dob", Path: openid4vp.StringPath("birthdate")},
		},
		ClaimSet: [][]string{{"family", "dob"}, {"given"}, {"given", "dob"}},
	})
	require.True(t, ok)
	assert.Equal(t, []string{d["given_name"]}, presentedDisclosures(got),
		"the first satisfiable claim set is used, and only its claims are disclosed")

	_, ok = selectClaims(raw, openid4vp.CredentialQuery{
		Claims:   []openid4vp.ClaimQuery{{ID: "family", Path: openid4vp.StringPath("family_name")}},
		ClaimSet: [][]string{{"family"}},
	})
	assert.False(t, ok)
}

// A credential missing a required claim is not answerable, so a
// credential-set alternative is chosen instead.
func TestMatchingCredentials_ClaimConstraintsDecideAnswerability(t *testing.T) {
	raw, d := testSDJWT(t)
	candidates := []*credential.StoredCredential{{Format: "dc+sd-jwt", VCT: "urn:test", RawCredential: raw}}

	missing := openid4vp.CredentialQuery{ID: "a", Format: "dc+sd-jwt", Claims: []openid4vp.ClaimQuery{{Path: openid4vp.StringPath("family_name")}}}
	present := openid4vp.CredentialQuery{ID: "b", Format: "dc+sd-jwt", Claims: []openid4vp.ClaimQuery{{Path: openid4vp.StringPath("birthdate")}}}

	assert.Empty(t, matchingCredentials(candidates, missing))
	matched := matchingCredentials(candidates, present)
	require.Len(t, matched, 1)
	assert.Equal(t, []string{d["birthdate"]}, presentedDisclosures(matched[0].RawCredential))
	assert.Equal(t, raw, candidates[0].RawCredential, "the stored credential is not modified")

	answerable := map[string][]*credential.StoredCredential{}
	for _, q := range []openid4vp.CredentialQuery{missing, present} {
		if m := matchingCredentials(candidates, q); len(m) > 0 {
			answerable[q.ID] = m
		}
	}
	selected, err := selectCredentialQueries(&openid4vp.DCQL{
		Credentials:    []openid4vp.CredentialQuery{missing, present},
		CredentialSets: []openid4vp.CredentialSetQuery{{Options: [][]string{{"a"}, {"b"}}}},
	}, answerable)
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"b": true}, selected)
}

// This wallet cannot build an mdoc DeviceResponse, so an mdoc never
// matches - with or without claims - and a credential-set alternative it
// can present is chosen instead.
func TestMatchingCredentials_MdocNeverMatches(t *testing.T) {
	mdoc := []*credential.StoredCredential{{Format: "mso_mdoc", VCT: "org.iso.18013.5.1.mDL", RawCredential: "o2d2ZXJzaW9u"}}
	withClaims := openid4vp.CredentialQuery{ID: "mdl", Format: "mso_mdoc", Claims: []openid4vp.ClaimQuery{{Path: openid4vp.StringPath("org.iso.18013.5.1", "family_name")}}}
	assert.Empty(t, matchingCredentials(mdoc, withClaims))

	unconstrained := openid4vp.CredentialQuery{ID: "mdl", Format: "mso_mdoc", Meta: openid4vp.MetaQuery{DoctypeValue: "org.iso.18013.5.1.mDL"}}
	assert.Empty(t, matchingCredentials(mdoc, unconstrained), "a doctype match alone does not make an mdoc presentable")

	raw, _ := testSDJWT(t)
	sdjwt := []*credential.StoredCredential{{Format: "dc+sd-jwt", VCT: "urn:test", RawCredential: raw}}
	pid := openid4vp.CredentialQuery{ID: "pid", Format: "dc+sd-jwt", Meta: openid4vp.MetaQuery{VCTValues: []string{"urn:test"}}}

	pool := append(mdoc, sdjwt...)
	answerable := map[string][]*credential.StoredCredential{}
	for _, q := range []openid4vp.CredentialQuery{unconstrained, pid} {
		if m := matchingCredentials(pool, q); len(m) > 0 {
			answerable[q.ID] = m
		}
	}
	selected, err := selectCredentialQueries(&openid4vp.DCQL{
		Credentials:    []openid4vp.CredentialQuery{unconstrained, pid},
		CredentialSets: []openid4vp.CredentialSetQuery{{Options: [][]string{{"mdl"}, {"pid"}}}},
	}, answerable)
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"pid": true}, selected, "the preferred mdoc option must yield to the SD-JWT one")
}

// An array element whose disclosure is absent - not held, or a decoy - has
// no value, so a wildcard over the array must not be satisfied by it.
func TestSelectClaims_UndisclosedArrayPlaceholderIsNotAValue(t *testing.T) {
	_, held := disclosure(t, "salt-se", "SE")
	payload, err := json.Marshal(map[string]any{
		"vct":           "urn:test",
		"nationalities": []any{map[string]any{"...": "decoy-digest"}, map[string]any{"...": held}},
	})
	require.NoError(t, err)
	// Neither disclosure is present: one is a decoy, the other was not kept.
	raw := "eyJhbGciOiJFUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(payload) + ".sig~"

	wildcard := openid4vp.CredentialQuery{
		ID:     "nat",
		Format: "dc+sd-jwt",
		Claims: []openid4vp.ClaimQuery{{Path: []*string{new("nationalities"), nil}}},
	}
	_, ok := selectClaims(raw, wildcard)
	assert.False(t, ok, "an unresolved placeholder must not satisfy a terminal wildcard")

	alternative, _ := testSDJWT(t)
	candidates := []*credential.StoredCredential{
		{ID: "placeholders-only", Format: "dc+sd-jwt", VCT: "urn:test", RawCredential: raw},
	}
	other := []*credential.StoredCredential{
		{ID: "has-given-name", Format: "dc+sd-jwt", VCT: "urn:test", RawCredential: alternative},
	}
	given := openid4vp.CredentialQuery{ID: "given", Format: "dc+sd-jwt", Claims: []openid4vp.ClaimQuery{{Path: openid4vp.StringPath("given_name")}}}

	answerable := map[string][]*credential.StoredCredential{}
	if m := matchingCredentials(candidates, wildcard); len(m) > 0 {
		answerable["nat"] = m
	}
	if m := matchingCredentials(other, given); len(m) > 0 {
		answerable["given"] = m
	}
	selected, err := selectCredentialQueries(&openid4vp.DCQL{
		Credentials:    []openid4vp.CredentialQuery{wildcard, given},
		CredentialSets: []openid4vp.CredentialSetQuery{{Options: [][]string{{"nat"}, {"given"}}}},
	}, answerable)
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"given": true}, selected,
		"the unsatisfiable option must not be chosen over a valid alternative")
}
