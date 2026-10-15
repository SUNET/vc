package apiv1

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/credential"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// decodedMdocValue round-trips v through the same CBOR path a verified mdoc
// presentation takes (IssuerSignedItem.ElementValue decoded into `any`), so
// the tests see what VerificationDirectPost really sees - e.g. a full-date
// as cbor.Tag{1004, "..."}, not a string.
func decodedMdocValue(t *testing.T, v any) any {
	t.Helper()
	enc, err := mdoc.NewCBOREncoder()
	require.NoError(t, err)
	b, err := enc.Marshal(mdoc.IssuerSignedItem{DigestID: 1, Random: make([]byte, 16), ElementIdentifier: "x", ElementValue: v})
	require.NoError(t, err)
	var back mdoc.IssuerSignedItem
	require.NoError(t, cbor.Unmarshal(b, &back))
	return back.ElementValue
}

func mdocPresented(t *testing.T, docType string, ns map[string]map[string]any) map[string]any {
	t.Helper()
	decoded := make(map[string]map[string]any, len(ns))
	for n, items := range ns {
		decoded[n] = map[string]any{}
		for k, v := range items {
			decoded[n][k] = decodedMdocValue(t, v)
		}
	}
	claims, err := mdocClaimsFromResult(&mdoc.MDocVerificationResult{Valid: true, Documents: map[string]*mdoc.MDocDocumentClaims{
		docType: {DocType: docType, Namespaces: decoded},
	}})
	require.NoError(t, err)
	return claims
}

func nymAuthTarget(t *testing.T) *model.CredentialMetadata {
	t.Helper()
	raw, err := os.ReadFile("testdata/nym_auth.mdoc.json")
	require.NoError(t, err)
	schema, err := mdoc.LoadMDDLSchema(raw)
	require.NoError(t, err)
	return &model.CredentialMetadata{Format: "mso_mdoc", MDDL: schema}
}

// The five nym_auth authentication credentials, each in the shape its
// verified claims really have, with the auth_scopes entry sirosid-dev's
// values-base.yaml renders for it.
func TestNymAuthBirthDateIsCopiedAndNormalisedFromEveryAuthScope(t *testing.T) {
	sdjwtPID := func(vct string) map[string]any {
		return map[string]any{"vct": vct, "given_name": "Alice", "family_name": "Wonderland", "birthdate": "1990-01-15"}
	}
	sdjwtEntry := model.AuthScopeEntry{
		AuthClaims:         []string{"given_name", "family_name", "birthdate"},
		IdentityAttributes: map[string]string{"birthdate": "birth_date"},
		DocumentClaims:     map[string]string{"birthdate": "birth_date"},
	}
	cases := map[string]struct {
		format    string
		presented map[string]any
		entry     model.AuthScopeEntry
	}{
		"pid_1_8": {"dc+sd-jwt", sdjwtPID("urn:eudi:pid:arf-1.8:1"), sdjwtEntry},
		"pid_1_5": {"dc+sd-jwt", sdjwtPID("urn:eudi:pid:arf-1.5:1"), sdjwtEntry},
		"pid_mdoc": {"mso_mdoc", mdocPresented(t, "eu.europa.ec.eudi.pid.1", map[string]map[string]any{
			"eu.europa.ec.eudi.pid.1": {"given_name": "Alice", "family_name": "Wonderland", "birth_date": mdoc.FullDate("1990-01-15")},
		}), model.AuthScopeEntry{
			AuthClaims: []string{"eu.europa.ec.eudi.pid.1.given_name", "eu.europa.ec.eudi.pid.1.family_name"},
			IdentityAttributes: map[string]string{
				"eu.europa.ec.eudi.pid.1.given_name":  "given_name",
				"eu.europa.ec.eudi.pid.1.family_name": "family_name",
			},
			DocumentClaims: map[string]string{"eu.europa.ec.eudi.pid.1.birth_date": "birth_date"},
		}},
		"mdl": {"mso_mdoc", mdocPresented(t, "org.iso.18013.5.1.mDL", map[string]map[string]any{
			"org.iso.18013.5.1": {"given_name": "Alice", "family_name": "Wonderland", "birth_date": mdoc.FullDate("1990-01-15")},
		}), model.AuthScopeEntry{
			AuthClaims:     []string{"given_name", "family_name"},
			DocumentClaims: map[string]string{"birth_date": "birth_date"},
		}},
		"photoid": {"mso_mdoc", mdocPresented(t, "eu.europa.ec.eudi.photoid.1", map[string]map[string]any{
			"org.iso.23220.1": {"given_name_unicode": "Alice", "family_name_unicode": "Wonderland", "birth_date": mdoc.FullDate("1990-01-15")},
		}), model.AuthScopeEntry{
			AuthClaims: []string{"org.iso.23220.1.given_name_unicode", "org.iso.23220.1.family_name_unicode"},
			IdentityAttributes: map[string]string{
				"org.iso.23220.1.given_name_unicode":  "given_name",
				"org.iso.23220.1.family_name_unicode": "family_name",
			},
			DocumentClaims: map[string]string{"org.iso.23220.1.birth_date": "birth_date"},
		}},
	}
	target := nymAuthTarget(t)
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// What vc main does today: refuses every mdoc birth date (a
			// cbor.Tag, not a string) and finds no unqualified name for
			// pid_mdoc/photoid.
			if tc.format == "mso_mdoc" {
				_, isTag := tc.presented[firstKey(tc.entry.DocumentClaims)].(cbor.Tag)
				require.True(t, isTag, "an mdoc full-date must reach the handler as cbor.Tag 1004")
			}

			ids, err := extractAuthScopeIdentity(tc.format, tc.presented, tc.entry)
			require.NoError(t, err)
			require.Equal(t, "Alice", ids["given_name"])
			require.Equal(t, "Wonderland", ids["family_name"])
			if tc.format == "dc+sd-jwt" {
				require.Equal(t, "1990-01-15", ids["birth_date"], "the SD-JWT birthdate is matched as the mapping's birth_date")
			}

			copied, err := presentedDocumentClaims(tc.format, tc.presented, tc.entry, target)
			require.NoError(t, err)
			require.Equal(t, map[string]any{"birth_date": "1990-01-15"}, copied)

			docs := applyPresentedDocumentClaims(map[string]*model.CompleteDocument{
				"d": {DocumentData: map[string]any{"birth_date": "1900-01-01", "ssc": "AAAA"}},
			}, copied)
			require.Equal(t, "1990-01-15", docs["d"].DocumentData["birth_date"])
			require.Equal(t, "AAAA", docs["d"].DocumentData["ssc"])
		})
	}
}

func firstKey(m map[string]string) string {
	for k := range m {
		return k
	}
	return ""
}

func TestPresentedDocumentClaimsFailsClosed(t *testing.T) {
	target := nymAuthTarget(t)
	entry := model.AuthScopeEntry{AuthClaims: []string{"given_name"}, DocumentClaims: map[string]string{"birth_date": "birth_date"}}
	// pid_mdoc as sirosid-dev vendors it today: no birth_date at all.
	presented := mdocPresented(t, "eu.europa.ec.eudi.pid.1", map[string]map[string]any{
		"eu.europa.ec.eudi.pid.1": {"given_name": "Alice"},
	})
	_, err := presentedDocumentClaims("mso_mdoc", presented, entry, target)
	require.Error(t, err)

	_, err = presentedDocumentClaims("dc+sd-jwt", map[string]any{"birth_date": "15/01/1990"}, entry, target)
	require.Error(t, err, "a date in no RFC 3339 shape is refused, not issued")
	_, err = presentedDocumentClaims("dc+sd-jwt", map[string]any{"birth_date": "1990-02-30"}, entry, target)
	require.Error(t, err, "an impossible date is refused")
}

func TestNormaliseFullDateShapes(t *testing.T) {
	for in, want := range map[string]any{
		"plain string":       "1990-01-15",
		"date-time string":   "1990-01-15T00:00:00Z",
		"tag 1004":           cbor.Tag{Number: 1004, Content: "1990-01-15"},
		"tag 0":              cbor.Tag{Number: 0, Content: "1990-01-15T10:00:00Z"},
		"tag 1 epoch":        cbor.Tag{Number: 1, Content: uint64(632361600)},
		"time.Time":          time.Date(1990, 1, 15, 12, 0, 0, 0, time.UTC),
		"mdoc.FullDate":      mdoc.FullDate("1990-01-15"),
		"decoded mdoc value": decodedMdocValue(t, mdoc.FullDate("1990-01-15")),
	} {
		got, err := normaliseFullDate(want)
		require.NoError(t, err, in)
		require.Equal(t, "1990-01-15", got, in)
	}
}

func TestIssuanceAuthDCQLRequestsTheCopiedClaims(t *testing.T) {
	cfg := &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
		"mdl": {Format: "mso_mdoc", Doctype: "org.iso.18013.5.1.mDL", MDDL: &mdoc.MDDLSchema{DocType: "org.iso.18013.5.1.mDL"}},
	}}}
	dcql, err := buildIssuanceAuthDCQL(&model.OpenID4VPCredentialAuth{AuthScopes: map[string]model.AuthScopeEntry{
		"mdl": {AuthClaims: []string{"given_name", "family_name"}, DocumentClaims: map[string]string{"birth_date": "birth_date"}},
	}}, cfg)
	require.NoError(t, err)
	var paths [][]string
	for _, c := range dcql.Credentials[0].Claims {
		var p []string
		for _, s := range c.Path {
			p = append(p, *s)
		}
		paths = append(paths, p)
	}
	require.Contains(t, paths, []string{"org.iso.18013.5.1", "birth_date"})
	require.Equal(t, openid4vp.FormatMsoMdoc, dcql.Credentials[0].Format)
}

// A CBOR container must become something the document can carry.
//
// A verified mdoc claim arrives CBOR-decoded, so a container is a
// map[any]any. Copying it unchanged made json.Marshal of the assembled
// document fail with "unsupported type" at the END of issuance, so a
// valid presentation of driving_privileges could not be issued from at
// all - and the failure read as a broken credential rather than an
// unconvertible claim.
func TestPresentedContainerClaimsAreJSONEncodable(t *testing.T) {
	presented := mdocPresented(t, "org.iso.18013.5.1.mDL", map[string]map[string]any{
		"org.iso.18013.5.1": {
			"driving_privileges": []any{
				map[string]any{
					"vehicle_category_code": "B",
					"issue_date":            mdoc.FullDate("2020-01-01"),
				},
			},
		},
	})

	entry := model.AuthScopeEntry{
		AuthClaims:     []string{"org.iso.18013.5.1.driving_privileges"},
		DocumentClaims: map[string]string{"org.iso.18013.5.1.driving_privileges": "driving_privileges"},
	}

	copied, err := presentedDocumentClaims("mso_mdoc", presented, entry, nymAuthTarget(t))
	require.NoError(t, err, "a valid mdoc container must be copyable")

	// The whole point: the assembled document marshals.
	encoded, err := json.Marshal(map[string]any{"document_data": copied})
	require.NoError(t, err, "the copied claim must survive the json.Marshal issuance does")
	require.Contains(t, string(encoded), `"vehicle_category_code":"B"`)
	require.Contains(t, string(encoded), `"issue_date":"2020-01-01"`,
		"a date tag inside a container must not be written as its CBOR struct")

	// And it is a map[string]any, not the CBOR map json.Marshal refuses.
	list, ok := copied["driving_privileges"].([]any)
	require.True(t, ok)
	_, ok = list[0].(map[string]any)
	require.True(t, ok, "a CBOR map must be converted, not passed through")
}

// A copied claim REPLACES the datastore's, it does not merge with it.
//
// Destinations are top-level element names, and the configuration says the
// value comes from the presentation. Merging an object-valued source left
// datastore-only members inside it, so one claim carried a mixture of what
// was proved and what was stored.
func TestCopiedObjectClaimReplacesTheStoredOne(t *testing.T) {
	docs := map[string]*model.CompleteDocument{
		"d": {DocumentData: map[string]any{
			"address": map[string]any{
				"country":        "SE",
				"street_address": "from the datastore",
			},
			"untouched": "kept",
		}},
	}

	out := applyPresentedDocumentClaims(docs, map[string]any{
		"address": map[string]any{"country": "DK"},
	})

	address, ok := out["d"].DocumentData["address"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, map[string]any{"country": "DK"}, address,
		"the presented object must replace the stored one outright")
	require.NotContains(t, address, "street_address",
		"a datastore-only member must not survive inside a presented claim")
	require.Equal(t, "kept", out["d"].DocumentData["untouched"],
		"claims the presentation did not name are left alone")

	// The datastore's own document is not mutated.
	stored := docs["d"].DocumentData["address"].(map[string]any)
	require.Equal(t, "from the datastore", stored["street_address"])
}

// A derivation must not replace what the holder proved.
//
// Derivations run over the assembled document during issuance, after the
// presented claims were copied in at verification time. A derivation
// writing birth_date from another stored field silently replaced a
// verified date, and the credential asserted something never presented.
func TestDerivationsCannotReplacePresentedClaims(t *testing.T) {
	docData := map[string]any{
		"birth_date":  "1990-01-01", // from the presentation
		"family_name": "stored",
	}
	proved := provedClaims(docData, []string{"birth_date"})
	require.Equal(t, map[string]any{"birth_date": "1990-01-01"}, proved)

	// A derivation computes a different birth_date, and something else.
	derived := map[string]any{"birth_date": "1970-01-01", "age_over_18": true}
	for k, v := range derived {
		docData[k] = v
	}

	conflicts := restoreProvedClaims(docData, derived, proved)

	require.Equal(t, "1990-01-01", docData["birth_date"],
		"the verified value must win over the derived one")
	require.Equal(t, true, docData["age_over_18"],
		"a derivation that does not collide is left alone")
	require.Equal(t, []string{"birth_date"}, conflicts,
		"the collision must be reported, not resolved in silence")
}

// The snapshot must not share nested maps with the document.
//
// MergeNestedClaims writes INTO existing nested maps, so a snapshot that
// shares them is changed by the very derivations it exists to survive: a
// derivation adding address.street_address appeared in the "proved" value
// too, and restoring it restored the derived object rather than the
// presented one.
func TestProvedClaimsSurviveTheRecursiveMerge(t *testing.T) {
	docData := map[string]any{
		"address": map[string]any{"country": "DK"}, // from the presentation
	}
	proved := provedClaims(docData, []string{"address"})

	// A derivation that writes inside the object, through the same
	// recursive merge issuance uses.
	derived := map[string]any{"address": map[string]any{
		"country":        "SE",
		"street_address": "derived from the datastore",
	}}
	credential.MergeNestedClaims(docData, derived)

	restoreProvedClaims(docData, derived, proved)

	address, ok := docData["address"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, map[string]any{"country": "DK"}, address,
		"the presented object must be restored whole, not the merged one")
	require.NotContains(t, address, "street_address",
		"a member a derivation added inside it must not survive restoration")
}

// The provenance has to be PERSISTED, and the replace has to carry the
// identifier.
//
// Two separate hazards, modelled the way the handler really meets them.
// The handler holds a context it loaded BEFORE SetIdentifier wrote the
// resolved identity straight to the store, so its copy does not have it -
// and Update is a full replace, not a merge.
func TestPresentedClaimsPersistenceCarriesTheIdentifier(t *testing.T) {
	ctx := t.Context()
	const session = "s1"

	newStore := func(t *testing.T) *cache.MemoryStore {
		t.Helper()
		store := cache.NewMemoryStore(time.Minute)
		require.NoError(t, store.Create(ctx, &cache.AuthorizationContext{
			SessionID: session, ExpiresAt: time.Now().Add(time.Hour).Unix(),
		}))
		require.NoError(t, store.SetIdentifier(ctx, &cache.AuthorizationContext{SessionID: session}, "mapping-1"))
		return store
	}

	// What the handler has: a context loaded before SetIdentifier ran, so
	// Identifier is empty on it even though the store has one.
	handlerContext := func() *cache.AuthorizationContext {
		return &cache.AuthorizationContext{
			SessionID: session, ExpiresAt: time.Now().Add(time.Hour).Unix(),
		}
	}

	t.Run("a replace that does not carry the identifier erases it", func(t *testing.T) {
		store := newStore(t)
		stale := handlerContext()
		stale.PresentedClaims = []string{"birth_date"}

		require.NoError(t, store.Update(ctx, stale))

		back, err := store.GetByID(ctx, session)
		require.NoError(t, err)
		require.Empty(t, back.Identifier,
			"Update replaces the stored context; it does not merge into it")
	})

	t.Run("carrying it keeps both", func(t *testing.T) {
		store := newStore(t)
		carried := handlerContext()
		carried.PresentedClaims = []string{"birth_date"}
		carried.Identifier = "mapping-1"

		require.NoError(t, store.Update(ctx, carried))

		back, err := store.GetByID(ctx, session)
		require.NoError(t, err)
		require.Equal(t, []string{"birth_date"}, back.PresentedClaims,
			"issuance must be able to read the provenance back")
		require.Equal(t, "mapping-1", back.Identifier,
			"and the identity just resolved must survive the replace")
	})
}
