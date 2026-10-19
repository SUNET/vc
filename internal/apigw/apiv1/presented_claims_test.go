package apiv1

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"math/big"
	"os"
	"testing"
	"time"

	apigwcache "github.com/SUNET/vc/internal/apigw/cache"
	"github.com/SUNET/vc/pkg/credential"
	"github.com/SUNET/vc/pkg/credential/primitives"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"

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

// The provenance travels INSIDE the document it describes.
//
// Published beside it, on the authorization context, it was a second
// write that could interleave with the document's: two direct-post
// requests matching auth scopes with different document_claims could
// leave one request's document paired with the other's provenance, and a
// verified claim unpinned. One write cannot disagree with itself.
func TestProvenanceTravelsWithTheDocument(t *testing.T) {
	docs := map[string]*model.CompleteDocument{
		"d": {DocumentData: map[string]any{"birth_date": "1970-01-01", "other": "x"}},
	}

	out := applyPresentedDocumentClaims(docs, map[string]any{"birth_date": "2010-01-01"})

	require.Equal(t, []string{"birth_date"}, out["d"].PresentedClaims,
		"the copy records which claims it took from the presentation")
	require.Equal(t, "2010-01-01", out["d"].DocumentData["birth_date"],
		"and carries the value in the same object")

	// Issuance reads the provenance from the document it is issuing from,
	// so the two cannot be mismatched.
	proved := provedClaims(out["d"].DocumentData, out["d"].PresentedClaims)
	require.Equal(t, map[string]any{"birth_date": "2010-01-01"}, proved)

	// The datastore's own document is untouched, provenance included.
	require.Nil(t, docs["d"].PresentedClaims)
}

// A number the issued document cannot carry exactly is refused, whichever
// format it arrived in.
//
// An mdoc claim arrives CBOR-decoded, so an integer is exact until the
// issuer parses the document JSON into map[string]any and every number
// becomes a float64: uint64(9007199254740993) was issued as ...992. An
// SD-JWT claim never gets that far - Token.Parse and disclosure decoding
// unmarshal into `any`, so it is ALREADY a float64 when it is copied, and
// walked past an integer-only guard untouched. Two formats, one guard.
func TestPresentedNumbersThatCannotSurviveAreRefused(t *testing.T) {
	fromMdoc := func(t *testing.T, v any) (map[string]any, error) {
		t.Helper()
		return copiedMdocClaim(t, "big", v)
	}

	t.Run("mdoc integers beyond float64's exact range", func(t *testing.T) {
		for _, v := range []any{uint64(9007199254740993), int64(-9007199254740993)} {
			_, err := fromMdoc(t, v)
			require.Errorf(t, err, "%v must not be issued as a different number", v)
			require.Contains(t, err.Error(), "cannot be carried exactly")
		}
	})

	t.Run("an SD-JWT number, which is already a float64", func(t *testing.T) {
		sdEntry := model.AuthScopeEntry{
			AuthClaims:     []string{"big"},
			DocumentClaims: map[string]string{"big": "big"},
		}
		// What Token.Parse hands over: JSON decoded into `any`.
		presented := map[string]any{"big": float64(9007199254740993)}
		_, err := presentedDocumentClaims("dc+sd-jwt", presented, sdEntry, nymAuthTarget(t))
		require.Error(t, err, "an unsafe-range float64 must not slip past the integer guards")
		require.Contains(t, err.Error(), "exceeds the range")
	})

	t.Run("ordinary numbers still copy", func(t *testing.T) {
		copied, err := fromMdoc(t, uint64(9007199254740991))
		require.NoError(t, err, "the largest exact integer must still be copyable")
		encoded, err := json.Marshal(copied)
		require.NoError(t, err)
		require.Contains(t, string(encoded), "9007199254740991")

		sdEntry := model.AuthScopeEntry{
			AuthClaims:     []string{"n"},
			DocumentClaims: map[string]string{"n": "n"},
		}
		out, err := presentedDocumentClaims("dc+sd-jwt", map[string]any{"n": float64(42)}, sdEntry, nymAuthTarget(t))
		require.NoError(t, err)
		require.Equal(t, float64(42), out["n"])
	})
}

// The issued date must not depend on where the service runs.
//
// A decoded CBOR tag-1 timestamp arrives as a local-zone time.Time -
// the HOST's zone, not anything the holder presented - so extracting
// its date without normalising renders the day before on any host west
// of UTC. epochFullDate already said .UTC() explicitly; the time.Time
// branch did not, and a birth date silently off by one day is exactly
// what copying the presented claim exists to prevent.
//
// Pinned under a non-UTC zone, because under UTC the bug is invisible.
func TestAFullDateDoesNotDependOnTheHostTimezone(t *testing.T) {
	// 1990-01-15T00:00:00Z. West of UTC this instant is still the 14th
	// locally, which is what made it the wrong answer.
	const epoch = 632361600
	utc := time.Unix(epoch, 0).UTC()
	require.Equal(t, "1990-01-15", utc.Format(time.DateOnly), "the premise: this instant is the 15th in UTC")

	for _, zone := range []string{"America/Los_Angeles", "Pacific/Kiritimati", "UTC"} {
		loc, err := time.LoadLocation(zone)
		if err != nil {
			t.Skipf("zone database unavailable: %v", err)
		}
		t.Run(zone, func(t *testing.T) {
			// What the CBOR decoder hands over on a host in this zone.
			decoded := time.Unix(epoch, 0).In(loc)
			got, err := normaliseFullDate(decoded)
			require.NoError(t, err)
			require.Equal(t, "1990-01-15", got,
				"the host's timezone must not change the date the holder proved")

			// And the tag-1 route, which already said UTC, must agree
			// with it - the two must not drift apart again.
			viaTag, err := normaliseFullDate(cbor.Tag{Number: 1, Content: int64(epoch)})
			require.NoError(t, err)
			require.Equal(t, got, viaTag)
		})
	}
}

// A copied byte string must read the same way on both cache backends.
//
// The same divergence as a timestamp, and the only other type that
// changes shape across the cache: the memory store hands back []byte
// while the Mongo-backed store round-trips through JSON and hands back
// the base64 string, so a trim derivation fails on one backend and
// succeeds on the other.
func TestACopiedByteStringDerivesTheSameOnBothCacheBackends(t *testing.T) {
	raw := []byte{0x01, 0x02, 0xfe, 0xff}

	copied, err := copiedMdocClaim(t, "odd", raw)
	require.NoError(t, err)
	claim, ok := copied["odd"].(string)
	require.Truef(t, ok, "a cached claim must not depend on the backend; got %T", copied["odd"])
	require.Equal(t, base64.StdEncoding.EncodeToString(raw), claim,
		"and must be exactly what the JSON round trip would have produced")

	doc := &model.CompleteDocument{DocumentData: map[string]any{"odd": copied["odd"]}}
	stored, err := json.Marshal(doc)
	require.NoError(t, err)
	var reloaded model.CompleteDocument
	require.NoError(t, json.Unmarshal(stored, &reloaded))

	trim := []primitives.Derivation{{Trim: &primitives.TrimArgs{Input: "odd", Output: "odd"}}}
	fromMemory, err := credential.ApplyDerivations(trim, map[string]any{"odd": copied["odd"]}, time.Now())
	require.NoError(t, err, "the memory-backed path must derive")
	fromMongo, err := credential.ApplyDerivations(trim, reloaded.DocumentData, time.Now())
	require.NoError(t, err, "and so must the HA path")
	require.Equal(t, fromMemory["odd"], fromMongo["odd"])

	// Nested, and the null case, which must stay null rather than
	// becoming an empty string.
	nested, err := copiedMdocClaim(t, "odd", map[any]any{"inner": raw, "absent": []byte(nil)})
	require.NoError(t, err)
	obj := nested["odd"].(map[string]any)
	require.Equal(t, base64.StdEncoding.EncodeToString(raw), obj["inner"])
	require.Nil(t, obj["absent"], "a null byte string stays null")
}

// A copied timestamp must read the same way on both cache backends.
//
// This PR has lost to memory-vs-HA divergence three times already, and
// a time.Time leaf is the same trap once more: MemoryStore hands back
// the value it was given, so a derivation reading the claim sees a
// time.Time, while the Mongo-backed store round-trips the document
// through JSON and hands back a string. A trim derivation then works
// on one backend and fails with "must be a string or []string" on the
// other - under HA only, which is where it is hardest to see.
//
// So the normalisation happens before anything is cached, and this
// asserts the derivation input on BOTH sides of the round trip.
func TestACopiedTimestampDerivesTheSameOnBothCacheBackends(t *testing.T) {
	when := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)

	copied, err := copiedMdocClaim(t, "odd", when)
	require.NoError(t, err)
	claim, ok := copied["odd"].(string)
	require.Truef(t, ok, "a cached claim must not depend on the backend; got %T", copied["odd"])

	// The same instant, rendered as RFC 3339 - which is what the JSON
	// round trip would have produced from the decoded value, so the two
	// backends cannot disagree about the value either. Compared as an
	// instant rather than as text because the CBOR decode hands back a
	// local-zone time, so the literal depends on the host's zone.
	parsed, err := time.Parse(time.RFC3339Nano, claim)
	require.NoError(t, err, "the claim must be a timestamp a verifier can read back")
	require.True(t, parsed.Equal(when), "and the same instant the holder presented")

	// What MongoCache.marshalEntry does to a cached document: json, not
	// bson.
	doc := &model.CompleteDocument{DocumentData: map[string]any{"odd": copied["odd"]}}
	stored, err := json.Marshal(doc)
	require.NoError(t, err)
	var reloaded model.CompleteDocument
	require.NoError(t, json.Unmarshal(stored, &reloaded))

	// The derivation is the thing that actually breaks, so it is what
	// the test runs - on the memory-backed value and the HA one.
	trim := []primitives.Derivation{{Trim: &primitives.TrimArgs{Input: "odd", Output: "odd"}}}
	fromMemory, err := credential.ApplyDerivations(trim, map[string]any{"odd": copied["odd"]}, when)
	require.NoError(t, err, "the memory-backed path must derive")
	fromMongo, err := credential.ApplyDerivations(trim, reloaded.DocumentData, when)
	require.NoError(t, err, "and so must the HA path, or the deployment fails only under HA")
	require.Equal(t, fromMemory["odd"], fromMongo["odd"],
		"a derivation must not depend on which cache backend is configured")
}

// A CBOR bignum must be refused unless it survives the issuer's round
// trip, and "it serialises" is not that test.
//
// Tags 2 and 3 decode to a big.Int, which reaches neither integer
// guard. Both shapes were verified before the fix rather than reasoned
// about, under this repo's own GOEXPERIMENT=jsonv2:
//
//	big.Int value  -> {"c":{}}                   (an empty object!)
//	*big.Int       -> {"c":18446744073709551617}
//	                   issuer round trip ->  ...552000
//
// The value case is the sharp one: MarshalJSON is on the POINTER
// receiver, so a non-addressable big.Int inside an `any` never reaches
// it and the claim is emitted as an empty object where the holder
// proved a number. Neither case is caught by asking whether the value
// serialises, which is why the guard is on the round trip instead.
func TestCBORBignumsAreRefusedUnlessTheySurvive(t *testing.T) {
	tooBig, ok := new(big.Int).SetString("18446744073709551617", 10)
	require.True(t, ok)

	// The premises, both of them, so this test cannot pass by pinning
	// some other behaviour.
	encoded, err := json.Marshal(map[string]any{"c": *tooBig})
	require.NoError(t, err, "a big.Int value serialises cleanly, which is the trap")
	require.Contains(t, string(encoded), `"c":{}`, "and emits an empty object where a number was proved")

	encoded, err = json.Marshal(map[string]any{"c": tooBig})
	require.NoError(t, err)
	var roundTripped map[string]any
	require.NoError(t, json.Unmarshal(encoded, &roundTripped), "what the issuer does to the document")
	again, err := json.Marshal(roundTripped)
	require.NoError(t, err)
	require.NotContains(t, string(again), "18446744073709551617",
		"the premise of the bug: the issuer's float64 parse changes the number")

	for _, shape := range []struct {
		name  string
		value any
	}{
		{"a bignum value", *tooBig},
		{"a bignum pointer", tooBig},
		{"inside a copied object", map[any]any{"inner": tooBig}},
		{"inside a copied array", []any{*tooBig}},
	} {
		t.Run(shape.name, func(t *testing.T) {
			copied, err := copiedMdocClaim(t, "odd", shape.value)
			require.Error(t, err, "a number the document cannot carry must be refused, not published")
			require.Nil(t, copied)
		})
	}

	// json.Number takes the same rule, tested against documentValue
	// directly: a CBOR presentation cannot carry one - json.Number is a
	// string type, so it would encode as text and decode as a string -
	// and this case is defensive, for a decoder set to UseNumber.
	t.Run("a json.Number beyond the exact range", func(t *testing.T) {
		_, err := documentValue(json.Number("18446744073709551617"))
		require.Error(t, err, "the literal survives this hop and is rounded at the next one")
	})
	t.Run("a json.Number in range", func(t *testing.T) {
		got, err := documentValue(json.Number("42"))
		require.NoError(t, err)
		require.Equal(t, int64(42), got)
	})
	t.Run("a json.Number that is not a number", func(t *testing.T) {
		_, err := documentValue(json.Number("not a number"))
		require.Error(t, err)
	})

	// A bignum inside the exact range is an ordinary number and still
	// copies, or this guard would be "refuse every bignum".
	for _, shape := range []struct {
		name  string
		value any
	}{
		{"a bignum value in range", *big.NewInt(9007199254740991)},
		{"a bignum pointer in range", big.NewInt(-9007199254740991)},
	} {
		t.Run(shape.name, func(t *testing.T) {
			copied, err := copiedMdocClaim(t, "odd", shape.value)
			require.NoError(t, err)
			out, err := json.Marshal(copied)
			require.NoError(t, err)
			require.NotContains(t, string(out), "{}", "a carried number must not become an object")
		})
	}
}

// A CBOR map key that is not a string must be refused, not stringified.
//
// CBOR allows any type as a map key, JSON allows only strings. Writing
// such a key into the credential as fmt's rendering of it would put a
// claim under a name nobody presented - and the holder proved a claim
// at the key 1, not at the key "1". Found by probing: the guard existed
// and nothing exercised it.
func TestNonStringCBORMapKeysAreRefused(t *testing.T) {
	fromMdoc := func(t *testing.T, v any) (map[string]any, error) {
		t.Helper()
		return copiedMdocClaim(t, "odd", v)
	}

	for _, shape := range []struct {
		name  string
		value any
	}{
		{"an integer key", map[any]any{uint64(1): "value"}},
		{"a boolean key", map[any]any{true: "value"}},
		{"nested under a string key", map[any]any{"inner": map[any]any{uint64(2): "value"}}},
		{"inside an array", []any{map[any]any{uint64(3): "value"}}},
	} {
		t.Run(shape.name, func(t *testing.T) {
			copied, err := fromMdoc(t, shape.value)
			require.Error(t, err, "a key JSON has no member name for must be refused, not invented")
			require.Nil(t, copied)
			require.Contains(t, err.Error(), "cannot be a JSON member name")
		})
	}

	// String keys still copy, so the guard is not "refuse every map".
	copied, err := fromMdoc(t, map[any]any{"inner": "value"})
	require.NoError(t, err)
	require.Contains(t, fmt.Sprintf("%v", copied), "value")
}

// A decoded CBOR timestamp must be refused when it cannot be carried.
//
// CBOR tag 1 decodes to a time.Time. For a target other than full-date
// nothing converts it, so it reached the fallback unchanged - and
// time.Time.MarshalJSON refuses a year outside 0001-9999, which is where
// epoch 253402300800 lands. Under HA that refusal is SILENT:
// MongoCache.upsertAt logs the marshal error and drops the document
// write while direct-post still returns a successful redirect.
//
// The guard is on SERIALISABILITY rather than on time.Time, because the
// type enumeration is what kept being incomplete - this is the second
// shape to reach the same fallback holding something JSON cannot carry.
func TestUnserialisableDecodedCBORValuesAreRefused(t *testing.T) {
	fromMdoc := func(t *testing.T, v any) (map[string]any, error) {
		t.Helper()
		return copiedMdocClaim(t, "odd", v)
	}

	// What a CBOR tag 1 of 253402300800 decodes to.
	tooLate := time.Unix(253402300800, 0).UTC()
	require.Equal(t, 10000, tooLate.Year(), "the premise: this is the year the format cannot express")
	_, err := json.Marshal(tooLate)
	require.Error(t, err, "and the premise of the bug: encoding/json refuses it")

	for _, shape := range []struct {
		name  string
		value any
	}{
		{"directly", tooLate},
		{"inside a copied object", map[any]any{"inner": tooLate}},
		{"inside a copied array", []any{"ok", tooLate}},
		{"nested two deep", map[any]any{"a": []any{map[any]any{"b": tooLate}}}},
	} {
		t.Run(shape.name, func(t *testing.T) {
			copied, err := fromMdoc(t, shape.value)
			require.Error(t, err, "a value the document cannot carry must be refused, not published")
			require.Nil(t, copied)
			require.Contains(t, err.Error(), "cannot be carried in the issued document")
		})
	}

	// And an ordinary timestamp still copies, or the guard above would be
	// "refuse every time".
	copied, err := fromMdoc(t, time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC))
	require.NoError(t, err, "a representable timestamp must still be copyable")
	encoded, err := json.Marshal(copied)
	require.NoError(t, err)
	require.Contains(t, string(encoded), "2020-01-02")
}

// A non-finite float must be refused before anything is published.
//
// NaN is the value a range guard cannot catch: every comparison with it
// is false, so "n > max || n < -max" is false for NaN and it travels on
// into the issued document. There encoding/json refuses it - and under
// HA that refusal is SILENT: MongoCache.upsertAt logs the marshal error
// and drops the write while the direct_post handler still returns a
// successful redirect, so the caller is told a presentation was published
// that was never stored.
//
// Infinities take the same route into the document; they are caught by
// the range guard, but with a message about exact ranges, so they are
// pinned here too.
func TestNonFinitePresentedNumbersAreRefused(t *testing.T) {
	fromMdoc := func(t *testing.T, v any) (map[string]any, error) {
		t.Helper()
		return copiedMdocClaim(t, "odd", v)
	}

	// What makes this a publication bug rather than a formatting one.
	_, err := json.Marshal(map[string]any{"odd": math.NaN()})
	require.Error(t, err, "the premise of this test: a NaN claim cannot be serialised at all")

	for _, shape := range []struct {
		name  string
		value any
	}{
		{"directly", math.NaN()},
		{"inside a copied object", map[any]any{"inner": math.NaN()}},
		{"inside a copied array", []any{float64(1), math.NaN()}},
		{"nested two deep", map[any]any{"a": []any{map[any]any{"b": math.NaN()}}}},
		{"positive infinity", math.Inf(1)},
		{"negative infinity", math.Inf(-1)},
	} {
		t.Run(shape.name, func(t *testing.T) {
			copied, err := fromMdoc(t, shape.value)
			require.Errorf(t, err, "%v must be refused, not published", shape.value)
			require.Nil(t, copied, "nothing may be returned alongside the refusal")
			require.Contains(t, err.Error(), "JSON can carry")
		})
	}

	// An SD-JWT NaN reaches the same guard by the other route: the claim
	// is already a float64 when it is copied.
	sdEntry := model.AuthScopeEntry{
		AuthClaims:     []string{"odd"},
		DocumentClaims: map[string]string{"odd": "odd"},
	}
	_, err = presentedDocumentClaims("dc+sd-jwt", map[string]any{"odd": math.NaN()}, sdEntry, nymAuthTarget(t))
	require.Error(t, err, "an SD-JWT NaN must be refused as well")
	require.Contains(t, err.Error(), "JSON can carry")
}

// The provenance must survive the cache's serialisation.
//
// The document cache is Mongo-backed under HA and serialises through
// MongoCache.marshalEntry, which calls json.Marshal - not bson. A
// json:"-" field was therefore dropped on exactly that path, so issuance
// read no pinned claims and a derivation was free to replace a verified
// birth date, while the memory-backed path kept working.
func TestProvenanceSurvivesCacheSerialisation(t *testing.T) {
	docs := map[string]*model.CompleteDocument{
		"d": {
			Meta:            &model.MetaData{AuthenticSource: "SUNET"},
			DocumentData:    map[string]any{"birth_date": "2010-01-01"},
			PresentedClaims: []string{"birth_date"},
		},
	}

	// What MongoCache.marshalEntry does to the cached value.
	encoded, err := json.Marshal(docs)
	require.NoError(t, err)

	var back map[string]*model.CompleteDocument
	require.NoError(t, json.Unmarshal(encoded, &back))

	require.Equal(t, []string{"birth_date"}, back["d"].PresentedClaims,
		"issuance reads this after the round trip; losing it unpins every verified claim")
	require.Equal(t, "2010-01-01", back["d"].DocumentData["birth_date"])
}

// The handler must decorate the documents it publishes, and refuse
// before publishing anything when it cannot.
//
// The helper tests above all pass with the handler's call to them
// removed: they prove applyPresentedDocumentClaims works, not that
// issuance ever sees its result. This pins the wiring - a decorated
// document carries the overrides AND the provenance, and a source claim
// the presentation does not have is an error rather than a quiet
// fallback to datastore values.
// What reaches the CACHE is what was decorated, and a refusal publishes
// nothing.
//
// The AST wiring guard can see that decorateWithPresentedClaims is
// called; it cannot see that its RESULT is what is published. Discarding
// the return value compiled and left every test in this package green
// while the overrides and their provenance were silently dropped - so
// this test drives publication and reads the cache back, and then runs
// the issuance-side derivation against what it finds there.
func TestPublishedDocumentsAreTheDecoratedOnes(t *testing.T) {
	newClient := func(t *testing.T) (*Client, *apigwcache.Service) {
		t.Helper()
		cacheService := &apigwcache.Service{
			Document: apigwcache.NewTestMemoryCache[map[string]*model.CompleteDocument](10 * time.Minute),
		}
		return &Client{
			log: logger.NewSimple("test"),
			cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
				"nym_auth": {Format: openid4vp.FormatSDJWTVC, VCTM: &sdjwtvc.VCTM{VCT: "urn:x"}},
			}}},
			cacheService: cacheService,
		}, cacheService
	}
	docs := func() map[string]*model.CompleteDocument {
		return map[string]*model.CompleteDocument{
			"d": {DocumentData: map[string]any{"birth_date": "1970-01-01", "family_name": "stored"}},
		}
	}
	entry := model.AuthScopeEntry{
		AuthClaims:     []string{"birthdate"},
		DocumentClaims: map[string]string{"birthdate": "birth_date"},
	}

	t.Run("the cached document carries the override and its provenance", func(t *testing.T) {
		c, cacheService := newClient(t)

		require.NoError(t, c.publishPresentedDocuments(t.Context(), "sess-1", docs(),
			openid4vp.FormatSDJWTVC, map[string]any{"birthdate": "2010-01-01"}, entry, "nym_auth", "nym_auth"))

		cached, ok := cacheService.Document.Get(t.Context(), "sess-1")
		require.True(t, ok, "the session's documents must have been published")
		require.Equal(t, "2010-01-01", cached["d"].DocumentData["birth_date"],
			"the cache must hold the DECORATED document, not the one read from the datastore")
		require.Equal(t, []string{"birth_date"}, cached["d"].PresentedClaims,
			"and its provenance, or issuance has nothing to pin")

		// The issuance side, run against what was actually published: a
		// derivation that would overwrite the presented claim must lose
		// to it. This is the pairing the handler exists to guarantee,
		// and it cannot be checked without the cached document.
		//
		// The three steps in the order issuance runs them, because the
		// pin alone is not the guarantee: ApplyDerivationsPinned
		// deliberately LEAVES the attempt in its output - that is how a
		// caller sees which derivations tried - so restoreProvedClaims
		// is what makes the proved value the issued one, and reports
		// the conflict.
		docData := cached["d"].DocumentData
		proved := provedClaims(docData, cached["d"].PresentedClaims)
		require.Equal(t, map[string]any{"birth_date": "2010-01-01"}, proved,
			"the provenance must name the presented claim and its proved value")

		conflicting := []primitives.Derivation{{
			Trim: &primitives.TrimArgs{Input: "family_name", Output: "birth_date"},
		}}
		derived, err := credential.ApplyDerivationsPinned(conflicting, docData, time.Now(), proved)
		require.NoError(t, err)
		require.Equal(t, "stored", derived["birth_date"],
			"the attempt is reported, which is what makes the conflict visible")

		conflicts := restoreProvedClaims(docData, derived, proved)
		require.Equal(t, []string{"birth_date"}, conflicts, "and the conflict is named")
		require.Equal(t, "2010-01-01", docData["birth_date"],
			"what is ISSUED is the claim the holder proved, not the derivation's")
	})

	t.Run("a refusal publishes nothing at all", func(t *testing.T) {
		c, cacheService := newClient(t)

		err := c.publishPresentedDocuments(t.Context(), "sess-2", docs(),
			openid4vp.FormatSDJWTVC, map[string]any{"something_else": "x"}, entry, "nym_auth", "nym_auth")
		require.Error(t, err, "issuing from datastore values would assert what was never presented")

		_, ok := cacheService.Document.Get(t.Context(), "sess-2")
		require.False(t, ok,
			"nothing may be published when the presentation cannot be honoured; a stale document here is issued from")
	})
}

func TestHandlerDecoratesDocumentsOrRefuses(t *testing.T) {
	c := &Client{
		log: logger.NewSimple("test"),
		cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
			"nym_auth": {Format: openid4vp.FormatSDJWTVC, VCTM: &sdjwtvc.VCTM{VCT: "urn:x"}},
		}}},
	}
	docs := func() map[string]*model.CompleteDocument {
		return map[string]*model.CompleteDocument{
			"d": {DocumentData: map[string]any{"birth_date": "1970-01-01", "family_name": "stored"}},
		}
	}
	entry := model.AuthScopeEntry{
		AuthClaims:     []string{"birthdate"},
		DocumentClaims: map[string]string{"birthdate": "birth_date"},
	}

	t.Run("the published document carries the override and the provenance", func(t *testing.T) {
		out, err := c.decorateWithPresentedClaims(docs(), openid4vp.FormatSDJWTVC,
			map[string]any{"birthdate": "2010-01-01"}, entry, "nym_auth", "nym_auth")
		require.NoError(t, err)
		require.Equal(t, "2010-01-01", out["d"].DocumentData["birth_date"],
			"the verified value must reach the cached document")
		require.Equal(t, []string{"birth_date"}, out["d"].PresentedClaims,
			"and so must the provenance, or issuance cannot pin it")
		require.Equal(t, "stored", out["d"].DocumentData["family_name"],
			"claims the presentation did not name are left alone")
	})

	t.Run("a missing source claim refuses, before anything is published", func(t *testing.T) {
		out, err := c.decorateWithPresentedClaims(docs(), openid4vp.FormatSDJWTVC,
			map[string]any{"something_else": "x"}, entry, "nym_auth", "nym_auth")
		require.Error(t, err, "issuing from datastore values would assert what was never presented")
		require.Nil(t, out, "nothing to publish when the presentation cannot be honoured")
		require.Contains(t, err.Error(), "presented claim copy failed")
	})

	t.Run("an unconvertible source claim refuses too", func(t *testing.T) {
		_, err := c.decorateWithPresentedClaims(docs(), openid4vp.FormatSDJWTVC,
			map[string]any{"birthdate": float64(1 << 60)}, entry, "nym_auth", "nym_auth")
		require.Error(t, err)
	})

	t.Run("no configured claims is not an error", func(t *testing.T) {
		out, err := c.decorateWithPresentedClaims(docs(), openid4vp.FormatSDJWTVC,
			map[string]any{}, model.AuthScopeEntry{}, "nym_auth", "nym_auth")
		require.NoError(t, err)
		require.Nil(t, out["d"].PresentedClaims, "nothing was taken from the presentation")
	})
}

// A date conversion must fail rather than produce a different date.
//
// uint64 is not int64: 18446744073709551615 wrapped to -1 and dated to
// 1969-12-31 - a verified birth date silently replaced by a plausible
// one. A negative fraction truncated toward zero, so -0.5 became
// 1970-01-01 when the second it falls in is 1969-12-31. And 253402300800
// formatted happily as "10000-01-01", which the RFC 3339 grammar cannot
// express, so no verifier reading it gets the presented date.
func TestEpochAndRangeBoundariesAreRefused(t *testing.T) {
	epoch := func(v any) (string, error) { return normaliseFullDate(cbor.Tag{Number: 1, Content: v}) }

	t.Run("a uint64 that would wrap", func(t *testing.T) {
		_, err := epoch(uint64(18446744073709551615))
		require.Error(t, err, "wrapping to -1 would date this to 1969-12-31")
		require.Contains(t, err.Error(), "representable range")
	})

	t.Run("a negative fraction floors, it does not truncate", func(t *testing.T) {
		got, err := epoch(float64(-0.5))
		require.NoError(t, err)
		require.Equal(t, "1969-12-31", got, "-0.5 falls in the second before the epoch")
	})

	t.Run("a year the format cannot express", func(t *testing.T) {
		_, err := epoch(int64(253402300800))
		require.Error(t, err, `"10000-01-01" is not an RFC 3339 full-date`)
		require.Contains(t, err.Error(), "outside the range")
	})

	t.Run("the same range check applies to a time.Time", func(t *testing.T) {
		_, err := normaliseFullDate(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC))
		require.Error(t, err, "every shape needs the range check, not just the epoch")
	})

	t.Run("not a number", func(t *testing.T) {
		_, err := epoch(math.NaN())
		require.Error(t, err)
	})

	t.Run("ordinary epochs still convert", func(t *testing.T) {
		for _, tc := range []struct {
			in   any
			want string
		}{
			{int64(0), "1970-01-01"},
			{uint64(1262304000), "2010-01-01"},
			{float64(1262304000.9), "2010-01-01"},
			{int64(-1), "1969-12-31"},
		} {
			got, err := epoch(tc.in)
			require.NoErrorf(t, err, "%v", tc.in)
			require.Equalf(t, tc.want, got, "%v", tc.in)
		}
	})
}

// The handlers must actually call the helpers these tests exercise.
//
// This is the gap one level up from the previous test, and the same one
// review found before it: a unit test proves a helper works, never that
// its caller runs it. Extracting decorateWithPresentedClaims made the
// helper testable and left the CALL unpinned, and the issuer side was
// never pinned at all - so the whole feature could be disconnected with
// every test still green.
//
// callsMadeBy names every function called inside fn, read from the
// source of file.
//
// Fails closed: a function it cannot find is a failure, not an empty
// set that every assertion would then fail on for the wrong reason.
func callsMadeBy(t *testing.T, file, fn string) map[string]bool {
	t.Helper()

	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
	require.NoError(t, err)

	var body *ast.FuncDecl
	ast.Inspect(parsed, func(n ast.Node) bool {
		decl, ok := n.(*ast.FuncDecl)
		if ok && decl.Name.Name == fn {
			body = decl
		}
		return body == nil
	})
	require.NotNilf(t, body, "no %s in %s; this guard is not looking at anything", fn, file)

	called := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch callee := call.Fun.(type) {
		case *ast.Ident:
			called[callee.Name] = true
		case *ast.SelectorExpr:
			called[callee.Sel.Name] = true
		}
		return true
	})
	return called
}

// copiedMdocClaim presents one mdoc element carrying v and returns the
// claims copied into the issued document.
//
// Shared by every test that asks "what happens when a presented value is
// X": the setup is the same each time and only the value differs, so a
// copy per test was four places to keep in step.
func copiedMdocClaim(t *testing.T, element string, v any) (map[string]any, error) {
	t.Helper()
	qualified := "org.iso.18013.5.1." + element
	entry := model.AuthScopeEntry{
		AuthClaims:     []string{qualified},
		DocumentClaims: map[string]string{qualified: element},
	}
	presented := mdocPresented(t, "org.iso.18013.5.1.mDL", map[string]map[string]any{
		"org.iso.18013.5.1": {element: v},
	})
	return presentedDocumentClaims("mso_mdoc", presented, entry, nymAuthTarget(t))
}

// Checked against the source, because that is the only thing that shows
// a missing call. Fails closed: a function it cannot find is a failure,
// not a pass.
func TestTheHandlersAreWiredToTheseHelpers(t *testing.T) {
	for _, tc := range []struct {
		file, fn string
		calls    []string
	}{
		// The decoration moved when main extracted the shared consumer:
		// VerificationDirectPost delegates, and the copy happens inside
		// consumeIssuanceAuthPresentation - which is where both channels
		// now reach it. So the guard pins the CHAIN rather than one
		// function: the endpoint must still reach the consumer, and the
		// consumer must still decorate. Pinning only the old call site
		// would have gone green again by deleting the delegation.
		{
			file: "handlers_verifier.go", fn: "VerificationDirectPost",
			calls: []string{"consumeIssuanceAuthPresentation"},
		},
		{
			file: "handlers_verifier.go", fn: "consumeIssuanceAuthPresentation",
			calls: []string{"publishPresentedDocuments"},
		},
		{
			file: "handlers_verifier.go", fn: "publishPresentedDocuments",
			calls: []string{"decorateWithPresentedClaims"},
		},
		{
			file: "handlers_issuer.go", fn: "VCICredential",
			calls: []string{"provedClaims", "restoreProvedClaims", "ApplyDerivationsPinned"},
		},
	} {
		t.Run(tc.fn, func(t *testing.T) {
			called := callsMadeBy(t, tc.file, tc.fn)
			for _, name := range tc.calls {
				require.Truef(t, called[name],
					"%s does not call %s: the helper's own tests would still pass, and a verified claim would reach the credential unpinned",
					tc.fn, name)
			}
		})
	}
}
