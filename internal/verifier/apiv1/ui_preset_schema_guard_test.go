package apiv1

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/SUNET/vc/pkg/openid4vp"
)

func presentationDefinitionJS(t *testing.T) string {
	t.Helper()
	source, err := os.ReadFile(filepath.Join("..", "staticembed", "presentation-definition.js"))
	require.NoError(t, err)
	return string(source)
}

// between returns the slice of js from the first occurrence of start to
// the first occurrence of end after it, failing if either is missing.
//
// The region matters: searching the whole file would let a field declared
// in ONE schema satisfy a check meant for another, which is exactly the
// shape of every bug this guards against.
func between(t *testing.T, js, start, end string) string {
	t.Helper()
	from := strings.Index(js, start)
	require.NotEqualf(t, -1, from, "presentation-definition.js no longer contains %q; this guard is reading the wrong file", start)
	rest := js[from+len(start):]
	to := strings.Index(rest, end)
	require.NotEqualf(t, -1, to, "no %q after %q; this guard can no longer find the region it checks", end, start)
	return rest[:to]
}

// The picker parses the preset metadata through a valibot schema before
// anything else reads it, and v.object() STRIPS what the schema does not
// declare - silently, leaving a well-formed request, so the failure
// surfaces as a wallet that returned nothing.
//
// This has now happened three times: doctype_value, zk_system_type, and
// req. Each was found by someone noticing an empty response. The guard is
// derived from the struct tags rather than written as a list, because a
// list is the thing that goes stale: a fourth field added to
// UIPresetCredential fails this test on the commit that adds it.
func TestEveryPublishedPresetFieldSurvivesTheBrowserSchema(t *testing.T) {
	// Only the preset schema. The DCQL schema below it covers the subset
	// that goes on the wire, and which fields belong to that subset is a
	// judgement the Go types do not encode - validations, for one, is read
	// by the UI and never sent.
	schema := between(t, presentationDefinitionJS(t), "presets: v.optional(", "/** @typedef")

	for _, tc := range []struct {
		what string
		of   reflect.Type
	}{
		{"UIPresetCredential", reflect.TypeOf(UIPresetCredential{})},
		{"UIPresetMeta", reflect.TypeOf(UIPresetMeta{})},
	} {
		for i := 0; i < tc.of.NumField(); i++ {
			name, _, _ := strings.Cut(tc.of.Field(i).Tag.Get("json"), ",")
			if name == "" || name == "-" {
				continue
			}
			t.Run(tc.what+"."+name, func(t *testing.T) {
				require.Containsf(t, schema, name+":",
					"%s.%s is published to the picker, but the preset schema in presentation-definition.js never names it, so valibot strips it before the query is built",
					tc.what, name)
			})
		}
	}
}

// Surviving the preset schema is half of it. The query the browser posts
// back is assembled field by field from the parsed preset, so a field can
// pass the schema and still never reach the wallet - and then has to pass
// a second schema on the way out.
//
// The member is named DIFFERENTLY on the two wires, which is the whole
// difficulty: /ui/metadata serves UIPresetCredential.Req as "req", and the
// DCQL query that is posted names the same list CredentialQuery.Req, which
// is "_req". Both names are taken from the struct tags here rather than
// written out, because a guard that spells them itself is a guard that can
// agree with neither side - which is how the picker came to post "req",
// a member pkg/openid4vp refuses as req_missing_or_empty.
//
// Spelled out as to WHICH fields rather than derived, because which ones
// are DCQL-relevant is not something the Go types say: validations
// deliberately goes no further than the UI.
func TestCircuitZkReqReachesThePostedQuery(t *testing.T) {
	js := presentationDefinitionJS(t)

	uiName := jsonName(t, reflect.TypeOf(UIPresetCredential{}), "Req")
	wireName := jsonName(t, reflect.TypeOf(openid4vp.CredentialQuery{}), "Req")
	require.NotEqual(t, uiName, wireName,
		"this test exists because the two wires name the list differently; if they no longer do, simplify it")

	preset := between(t, js, "presets: v.optional(", "/** @typedef")
	require.True(t, declaresMember(preset, uiName),
		"the preset schema must declare %q, the name /ui/metadata serves it under", uiName)

	dcql := between(t, js, "const dcqlQueryCredentialSchema = v.object({", "const credentialSetQuerySchema")
	require.True(t, declaresMember(dcql, wireName),
		"the DCQL schema must declare %q, or v.object strips the list on the way out", wireName)
	require.False(t, declaresMember(dcql, uiName),
		"the DCQL schema declares %q, the metadata name; the posted query's member is %q and %q is refused as req_missing_or_empty",
		uiName, wireName, uiName)

	// The copy itself. It moved to preset-helpers.js so it could be tested
	// under `node --test` without Alpine - see dcqlCredentialFromPreset
	// there and its tests - so what is checked here is that the picker
	// still goes through it rather than growing a second copy inline.
	copied := between(t, js, "async handleSelectPredefinedPresentationDefinition(id)", "v.safeParse(dcqlQuerySchema")
	require.Contains(t, copied, "dcqlCredentialFromPreset",
		"the preset-to-query copy must go through dcqlCredentialFromPreset, which is the tested one")

	helpers, err := os.ReadFile(filepath.Join("..", "staticembed", "preset-helpers.js"))
	require.NoError(t, err)
	require.Containsf(t, string(helpers), "c."+wireName+" = cred."+uiName,
		"dcqlCredentialFromPreset must map the metadata's %q onto the query's %q", uiName, wireName)
}

// jsonName is a field's wire name, from its json tag.
func jsonName(t *testing.T, of reflect.Type, field string) string {
	t.Helper()
	f, ok := of.FieldByName(field)
	require.Truef(t, ok, "%s has no field %s; this guard is reading the wrong type", of.Name(), field)
	name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
	require.NotEmptyf(t, name, "%s.%s has no json name", of.Name(), field)
	return name
}

// declaresMember reports whether a valibot object schema declares exactly
// this member.
//
// Exactly, because "_req" CONTAINS "req": a plain substring search is
// satisfied by the other name and so can never tell the two apart, which
// is precisely the confusion this file is here to catch.
func declaresMember(schema, name string) bool {
	return regexp.MustCompile(`(^|[^\w$])` + regexp.QuoteMeta(name) + `\s*:`).MatchString(schema)
}
