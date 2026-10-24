package apiv1

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
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
// Spelled out rather than derived, because which fields are DCQL-relevant
// is not something the Go types say: validations deliberately goes no
// further than the UI.
func TestCircuitZkReqReachesThePostedQuery(t *testing.T) {
	js := presentationDefinitionJS(t)

	dcql := between(t, js, "const dcqlQueryCredentialSchema = v.object({", "const credentialSetQuerySchema")
	require.Contains(t, dcql, "req:",
		"the DCQL schema must declare req, or the query is stripped again on the way out")

	copied := between(t, js, "async handleSelectPredefinedPresentationDefinition(id)", "v.safeParse(dcqlQuerySchema")
	require.Contains(t, copied, "cred.req",
		"the preset-to-query copy must carry req, or a circuit_zk query asks the wallet for nothing")
}
